use mempool_encryption::dkg::{compute_pk_from_shares, BlsDkgScheme, DkgState};
use mempool_encryption::kem::{BlsPlaintext, BlsTag};
use mempool_encryption::scheme::{SetupProtocol, ThresholdRelease};
use mempool_encryption::types::{Params, PartyInfo};
use rand_core::SeedableRng;

fn main() {
    let params = Params { n: 3, t: 2 };
    let parties: Vec<PartyInfo> = (1..=params.n)
        .map(|id| PartyInfo { id })
        .collect();

    let mut states: Vec<DkgState> = parties
        .iter()
        .map(|me| BlsDkgScheme::init(params, *me))
        .collect();

    let mut inboxes: Vec<Vec<(u32, mempool_encryption::dkg::DkgMessage)>> =
        vec![Vec::new(); params.n as usize];

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
            let _ = BlsDkgScheme::handle_message(&mut states[i], from, msg)
                .expect("handle_message");
        }
    }

    for state in states.iter_mut() {
        let complaints = state.verify_shares().expect("verify_shares");
        if !complaints.is_empty() {
            panic!("unexpected complaints");
        }
    }

    let mut outputs = Vec::new();
    for state in states.into_iter() {
        let out = BlsDkgScheme::finalize(state).expect("finalize");
        outputs.push(out);
    }

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

    let tag = BlsTag(b"demo-tag".to_vec());
    let pt = BlsPlaintext(b"hello".to_vec());
    let mut rng = rand_chacha::ChaCha20Rng::from_entropy();

    let ct = <BlsDkgScheme as ThresholdRelease>::encrypt(&pp, &tag, &pt, &mut rng)
        .expect("encrypt");

    let sig1 = <BlsDkgScheme as ThresholdRelease>::partial_release(&pp, &sk1, &tag)
        .expect("sig1");
    let sig2 = <BlsDkgScheme as ThresholdRelease>::partial_release(&pp, &sk2, &tag)
        .expect("sig2");

    let full = <BlsDkgScheme as ThresholdRelease>::combine(&pp, &tag, &[(sk1.id, sig1), (sk2.id, sig2)])
        .expect("combine");

    let out = <BlsDkgScheme as ThresholdRelease>::decrypt(&pp, &tag, &ct, &full)
        .expect("decrypt");

    assert_eq!(out.0, pt.0);
    println!("ok: {}", String::from_utf8_lossy(&out.0));
}
