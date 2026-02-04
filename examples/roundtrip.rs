//! End-to-end demo mirroring `mempool_encryption_spec.md`.
//!
//! This example walks through the full protocol:
//! 1. **DKG (Pedersen VSS)**:
//!    - Each party samples secret polynomials `f_j(z)` and `r_j(z)` and
//!      broadcasts commitments `C_{j,k} = g2^{a_{j,k}} h2^{b_{j,k}}`.
//!    - Each party privately sends shares `(f_j(i), r_j(i))`.
//!    - Parties verify shares against commitments and broadcast complaints.
//!    - Accused dealers respond by opening their share; invalid opens disqualify.
//!    - The QUAL set is formed from dealers without valid complaints.
//!    - Each party sums qualified shares to obtain its secret share `x_i`.
//! 2. **Threshold BLS Signatures**:
//!    - For a tag `tg`, each party computes a partial signature
//!      `sigma_i = H(tg)^{x_i}` and can be verified by the public share `PK_i`.
//!    - Any `t` partials are combined via Lagrange interpolation to form
//!      a full BLS signature `sigma = H(tg)^x`.
//! 3. **KEM + AEAD Encryption**:
//!    - Encryptor chooses random `r` and computes `U = g2^r`.
//!    - Derives `W = e(H(tg), PK)^r` and uses HKDF to mask a symmetric key.
//!    - Payload is encrypted with AEAD using associated data `enc(tg, U, PK)`.
//! 4. **Public Release / Decryption**:
//!    - Once `sigma` is published, anyone can compute `W' = e(sigma, U)` and
//!      recover the symmetric key to decrypt the payload.
//!
//! Notes:
//! - In this demo we simulate a single round of messaging by directly delivering
//!   messages in-memory. A real system would use authenticated transport.
//! - We also reconstruct `PK` from the collected `PK_i` shares using Lagrange
//!   interpolation, as in Pedersen VSS the commitments alone do not reveal `PK`.
//! - The DKG implementation signs all messages and computes a transcript hash.
//!   This hash can be used for auditability or to bind later protocol steps.

use mempool_encryption::dkg::{BlsDkgScheme, DkgState, compute_pk_from_shares};
use mempool_encryption::kem::{BlsPlaintext, BlsTag};
use mempool_encryption::scheme::{SetupProtocol, ThresholdRelease};
use mempool_encryption::types::{Params, PartyInfo};
use rand_core::SeedableRng;

fn main() {
    // Parameters: n parties, threshold t.
    let params = Params { n: 3, t: 2 };
    let parties: Vec<PartyInfo> = (1..=params.n).map(|id| PartyInfo { id }).collect();

    // Initialize local DKG state for each party.
    let mut states: Vec<DkgState> = parties
        .iter()
        .map(|me| BlsDkgScheme::init(params, *me))
        .collect();

    // Simulated message delivery queues.
    let mut inboxes: Vec<Vec<(u32, mempool_encryption::dkg::DkgMessage)>> =
        vec![Vec::new(); params.n as usize];

    // Round 1: broadcast commitments + private shares.
    for (idx, state) in states.iter().enumerate() {
        let me = parties[idx];
        let out = state.initial_messages().expect("initial_messages");
        for (to, msg) in out {
            let slot = (to - 1) as usize;
            inboxes[slot].push((me.id, msg));
        }
    }

    for i in 0..states.len() {
        let inbox = std::mem::take(&mut inboxes[i]);
        for (from, msg) in inbox {
            let _ =
                BlsDkgScheme::handle_message(&mut states[i], from, msg).expect("handle_message");
        }
    }

    // Verify shares and handle any complaints (none expected in this demo).
    for state in states.iter_mut() {
        let complaints = state.verify_shares().expect("verify_shares");
        if !complaints.is_empty() {
            panic!("unexpected complaints");
        }
    }

    // Finalize DKG: output public params and secret share for each party.
    let mut outputs = Vec::new();
    for state in states.into_iter() {
        let out = BlsDkgScheme::finalize(state).expect("finalize");
        outputs.push(out);
    }

    // Aggregate PK shares from all parties and reconstruct group PK.
    let (mut pp, sk1) = outputs[0].clone();
    let (_, sk2) = outputs[1].clone();
    for (pp_i, _) in outputs.iter() {
        for (id, pk_i) in pp_i.pk_shares.iter() {
            if !pp.pk_shares.iter().any(|(x, _)| x == id) {
                pp.pk_shares.push((*id, *pk_i));
            }
        }
    }
    pp.pk = compute_pk_from_shares(&pp.pk_shares).expect("compute pk");

    // Tag binds the ciphertext to a release condition (event, time, etc.).
    let tag = BlsTag(b"demo-tag".to_vec());
    let pt = BlsPlaintext(b"hello".to_vec());
    let mut rng = rand_chacha::ChaCha20Rng::from_entropy();

    // Encrypt under (PK, tag).
    let ct =
        <BlsDkgScheme as ThresholdRelease>::encrypt(&pp, &tag, &pt, &mut rng).expect("encrypt");

    // Parties produce partial signatures for the tag.
    let sig1 = <BlsDkgScheme as ThresholdRelease>::partial_release(&pp, &sk1, &tag).expect("sig1");
    let sig2 = <BlsDkgScheme as ThresholdRelease>::partial_release(&pp, &sk2, &tag).expect("sig2");

    // Combine t partials to obtain the full signature.
    let full =
        <BlsDkgScheme as ThresholdRelease>::combine(&pp, &tag, &[(sk1.id, sig1), (sk2.id, sig2)])
            .expect("combine");

    // Anyone can decrypt once the full signature is published.
    let out = <BlsDkgScheme as ThresholdRelease>::decrypt(&pp, &tag, &ct, &full).expect("decrypt");

    assert_eq!(out.0, pt.0);
    println!("ok: {}", String::from_utf8_lossy(&out.0));
}
