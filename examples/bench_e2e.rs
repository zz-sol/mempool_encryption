//! End-to-end timing for both BLS-DKG and TESS schemes.

use std::time::Instant;

use mempool_encryption::dkg::{BlsDkgScheme, DkgMessage, DkgState, compute_pk_from_shares};
use mempool_encryption::kem::{BlsPlaintext, BlsTag};
use mempool_encryption::scheme::{SetupProtocol, ThresholdRelease};
use mempool_encryption::types::{Params, PartyInfo};
use rand_core::SeedableRng;

use tess::{PairingEngine, SilentThresholdScheme, ThresholdEncryption};

#[cfg(feature = "parallel")]
use rayon::prelude::*;
fn main() {
    // Parameters.
    let n = 2048u32;
    let t = 1400u32;
    let payload_len = 10 * 1024;

    println!("e2e timing: n={n}, t={t}, payload={} bytes", payload_len);
    println!();

    bench_bls_dkg(n, t, payload_len);
    println!();
    bench_tess(n as usize, t as usize, payload_len);
}

fn bench_bls_dkg(n: u32, t: u32, payload_len: usize) {
    println!("== BLS-DKG ==");
    let params = Params { n, t };
    let parties: Vec<PartyInfo> = (1..=params.n).map(|id| PartyInfo { id }).collect();

    let start = Instant::now();
    #[cfg(feature = "parallel")]
    let mut states: Vec<DkgState> = parties
        .par_iter()
        .map(|me| BlsDkgScheme::init(params, *me))
        .collect();
    #[cfg(not(feature = "parallel"))]
    let mut states: Vec<DkgState> = parties
        .iter()
        .map(|me| BlsDkgScheme::init(params, *me))
        .collect();
    let init_elapsed = start.elapsed();
    println!("setup.init_states: {:?}", init_elapsed);

    let start = Instant::now();
    #[cfg(feature = "parallel")]
    let deliveries: Vec<(u32, u32, DkgMessage)> = states
        .par_iter_mut()
        .enumerate()
        .flat_map_iter(|(idx, state)| {
            let me = parties[idx];
            state
                .initial_messages()
                .expect("initial_messages")
                .into_iter()
                .map(move |(to, msg)| (to, me.id, msg))
        })
        .collect();
    #[cfg(not(feature = "parallel"))]
    let deliveries: Vec<(u32, u32, DkgMessage)> = states
        .iter_mut()
        .enumerate()
        .flat_map(|(idx, state)| {
            let me = parties[idx];
            state
                .initial_messages()
                .expect("initial_messages")
                .into_iter()
                .map(move |(to, msg)| (to, me.id, msg))
        })
        .collect();

    let mut inboxes: Vec<Vec<(u32, DkgMessage)>> = vec![Vec::new(); params.n as usize];
    for (to, from, msg) in deliveries {
        let slot = (to - 1) as usize;
        inboxes[slot].push((from, msg));
    }
    let initial_msgs_elapsed = start.elapsed();
    println!("setup.initial_messages: {:?}", initial_msgs_elapsed);

    let start = Instant::now();
    #[cfg(feature = "parallel")]
    states
        .par_iter_mut()
        .zip(inboxes.par_iter_mut())
        .for_each(|(state, inbox)| {
            let inbox = std::mem::take(inbox);
            for (from, msg) in inbox {
                let _ = BlsDkgScheme::handle_message(state, from, msg).expect("handle_message");
            }
        });
    #[cfg(not(feature = "parallel"))]
    for i in 0..states.len() {
        let inbox = std::mem::take(&mut inboxes[i]);
        for (from, msg) in inbox {
            let _ =
                BlsDkgScheme::handle_message(&mut states[i], from, msg).expect("handle_message");
        }
    }
    let handle_elapsed = start.elapsed();
    println!("setup.handle_messages: {:?}", handle_elapsed);

    let start = Instant::now();
    #[cfg(feature = "parallel")]
    let complaints: Vec<Vec<(u32, DkgMessage)>> = states
        .par_iter_mut()
        .map(|state| state.verify_shares().expect("verify_shares"))
        .collect();
    #[cfg(not(feature = "parallel"))]
    let complaints: Vec<Vec<(u32, DkgMessage)>> = states
        .iter_mut()
        .map(|state| state.verify_shares().expect("verify_shares"))
        .collect();
    for c in complaints {
        assert!(c.is_empty(), "unexpected complaints");
    }
    let verify_elapsed = start.elapsed();
    println!("setup.verify_shares: {:?}", verify_elapsed);

    let start = Instant::now();
    #[cfg(feature = "parallel")]
    let outputs: Vec<_> = states
        .into_par_iter()
        .map(|state| BlsDkgScheme::finalize(state).expect("finalize"))
        .collect();
    #[cfg(not(feature = "parallel"))]
    let outputs: Vec<_> = states
        .into_iter()
        .map(|state| BlsDkgScheme::finalize(state).expect("finalize"))
        .collect();
    let finalize_elapsed = start.elapsed();
    println!("setup.finalize: {:?}", finalize_elapsed);

    let start = Instant::now();
    let (mut pp, _) = outputs[0].clone();
    let mut sks = Vec::with_capacity(outputs.len());
    for (pp_i, _) in outputs.iter() {
        for (id, pk_i) in pp_i.pk_shares.iter() {
            if !pp.pk_shares.iter().any(|(x, _)| x == id) {
                pp.pk_shares.push((*id, *pk_i));
            }
        }
    }
    for (_, sk_i) in outputs.iter() {
        sks.push(sk_i.clone());
    }
    pp.pk = Some(compute_pk_from_shares(&pp.pk_shares).expect("compute pk"));
    let pk_elapsed = start.elapsed();
    println!("setup.reconstruct_pk: {:?}", pk_elapsed);

    let tag = BlsTag(b"bench-tag".to_vec());
    let pt = BlsPlaintext(vec![7u8; payload_len]);
    let mut rng = rand_chacha::ChaCha20Rng::from_entropy();

    let start = Instant::now();
    let ct =
        <BlsDkgScheme as ThresholdRelease>::encrypt(&pp, &tag, &pt, &mut rng).expect("encrypt");
    let enc_elapsed = start.elapsed();
    println!("encrypt: {:?}", enc_elapsed);

    let start = Instant::now();
    let share_count = t as usize;
    let mut partials = Vec::with_capacity(share_count);
    for sk_i in sks.iter().take(share_count) {
        let sig =
            <BlsDkgScheme as ThresholdRelease>::partial_release(&pp, sk_i, &tag, &ct).expect("sig");
        partials.push((sk_i.id, sig));
    }
    let partial_elapsed = start.elapsed();
    println!(
        "partial_release ({} shares): {:?}",
        share_count, partial_elapsed
    );

    let start = Instant::now();
    let full =
        <BlsDkgScheme as ThresholdRelease>::combine(&pp, &tag, &ct, &partials).expect("combine");
    let combine_elapsed = start.elapsed();
    println!("combine: {:?}", combine_elapsed);

    let start = Instant::now();
    let out = <BlsDkgScheme as ThresholdRelease>::decrypt(&pp, &tag, &ct, &full).expect("decrypt");
    let dec_elapsed = start.elapsed();
    println!("decrypt: {:?}", dec_elapsed);

    assert_eq!(out.0, pt.0);
}

fn bench_tess(parties: usize, threshold: usize, payload_len: usize) {
    println!("== TESS ==");
    let scheme = SilentThresholdScheme::<PairingEngine>::new();
    let mut rng = rand_chacha::ChaCha20Rng::from_entropy();

    let start = Instant::now();
    let params = scheme
        .param_gen(&mut rng, parties, threshold)
        .expect("param_gen");
    let param_elapsed = start.elapsed();
    println!("setup.param_gen: {:?}", param_elapsed);

    let start = Instant::now();
    let keys = scheme
        .keygen_unsafe(&mut rng, parties, &params)
        .expect("keygen_unsafe");
    let keygen_elapsed = start.elapsed();
    println!("setup.keygen_unsafe: {:?}", keygen_elapsed);

    let start = Instant::now();
    let agg_key = scheme
        .aggregate_public_key(&keys.public_keys, &params, parties)
        .expect("aggregate_public_key");
    let agg_elapsed = start.elapsed();
    println!("setup.aggregate_public_key: {:?}", agg_elapsed);

    let payload = vec![7u8; payload_len];

    let start = Instant::now();
    let ct = scheme
        .encrypt(&mut rng, &agg_key, &params, threshold, &payload)
        .expect("encrypt");
    let enc_elapsed = start.elapsed();
    println!("encrypt: {:?}", enc_elapsed);

    let start = Instant::now();
    let partials: Vec<_> = keys
        .secret_keys
        .iter()
        .take(threshold)
        .map(|sk| scheme.partial_decrypt(sk, &ct).expect("partial_decrypt"))
        .collect();
    let partial_elapsed = start.elapsed();
    println!(
        "partial_decrypt ({} shares): {:?}",
        threshold, partial_elapsed
    );

    let start = Instant::now();
    let mut selector = vec![false; parties];
    selector[0] = true;
    for p in partials.iter() {
        selector[p.participant_id] = true;
    }
    let res = scheme
        .aggregate_decrypt(&ct, &partials, &selector, &agg_key)
        .expect("aggregate_decrypt");
    let dec_elapsed = start.elapsed();
    println!("aggregate_decrypt: {:?}", dec_elapsed);

    assert_eq!(res.plaintext.expect("plaintext"), payload);
}
