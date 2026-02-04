use group::Group;
use mempool_encryption::dkg::{BlsDkgScheme, DkgState, compute_pk_from_shares};
use mempool_encryption::kem::{BlsCiphertext, BlsPlaintext, BlsTag};
use mempool_encryption::scheme::{SetupProtocol, ThresholdRelease};
use mempool_encryption::types::Wire;
use mempool_encryption::types::{Error, Params, PartyInfo};
use rand_core::SeedableRng;

fn setup_pp_and_sks(
    params: Params,
) -> (
    mempool_encryption::dkg::DkgPublicParams,
    Vec<mempool_encryption::dkg::DkgPartySecret>,
) {
    let parties: Vec<PartyInfo> = (1..=params.n).map(|id| PartyInfo { id }).collect();
    let mut states: Vec<DkgState> = parties
        .iter()
        .map(|me| BlsDkgScheme::init(params, *me))
        .collect();

    let mut deliveries = Vec::new();
    for (idx, state) in states.iter().enumerate() {
        let dealer_id = (idx + 1) as u32;
        let out = state.initial_messages().expect("initial_messages");
        for (to, msg) in out {
            deliveries.push((to, dealer_id, msg));
        }
    }
    for (to, from, msg) in deliveries {
        let slot = (to - 1) as usize;
        let _ = states[slot]
            .handle_message(from, msg)
            .expect("handle_message");
    }

    for state in states.iter_mut() {
        let complaints = state.verify_shares().expect("verify_shares");
        assert!(complaints.is_empty(), "unexpected complaints");
    }

    let mut outputs = Vec::new();
    for state in states.into_iter() {
        let out = BlsDkgScheme::finalize(state).expect("finalize");
        outputs.push(out);
    }

    let (mut pp, _) = outputs[0].clone();
    let mut sks = Vec::new();
    for (pp_i, sk_i) in outputs.iter() {
        for (id, pk_i) in pp_i.pk_shares.iter() {
            if !pp.pk_shares.iter().any(|(x, _)| x == id) {
                pp.pk_shares.push((*id, *pk_i));
            }
        }
        sks.push(sk_i.clone());
    }
    pp.pk = compute_pk_from_shares(&pp.pk_shares).expect("compute pk");
    (pp, sks)
}

#[test]
fn decrypt_fails_with_wrong_tag() {
    let params = Params { n: 3, t: 2 };
    let (pp, sks) = setup_pp_and_sks(params);
    let tag = BlsTag(b"tag-1".to_vec());
    let bad_tag = BlsTag(b"tag-2".to_vec());
    let pt = BlsPlaintext(b"hello".to_vec());
    let mut rng = rand_chacha::ChaCha20Rng::from_entropy();
    let ct =
        <BlsDkgScheme as ThresholdRelease>::encrypt(&pp, &tag, &pt, &mut rng).expect("encrypt");
    let sig1 =
        <BlsDkgScheme as ThresholdRelease>::partial_release(&pp, &sks[0], &tag).expect("sig1");
    let sig2 =
        <BlsDkgScheme as ThresholdRelease>::partial_release(&pp, &sks[1], &tag).expect("sig2");
    let full = <BlsDkgScheme as ThresholdRelease>::combine(
        &pp,
        &tag,
        &[(sks[0].id, sig1), (sks[1].id, sig2)],
    )
    .expect("combine");
    let res = <BlsDkgScheme as ThresholdRelease>::decrypt(&pp, &bad_tag, &ct, &full);
    assert!(matches!(res, Err(Error::InvalidParams)));
}

#[test]
fn decrypt_fails_with_wrong_witness() {
    let params = Params { n: 3, t: 2 };
    let (pp, sks) = setup_pp_and_sks(params);
    let tag = BlsTag(b"tag-1".to_vec());
    let pt = BlsPlaintext(b"hello".to_vec());
    let mut rng = rand_chacha::ChaCha20Rng::from_entropy();
    let ct =
        <BlsDkgScheme as ThresholdRelease>::encrypt(&pp, &tag, &pt, &mut rng).expect("encrypt");
    let sig1 =
        <BlsDkgScheme as ThresholdRelease>::partial_release(&pp, &sks[0], &tag).expect("sig1");
    let sig2 =
        <BlsDkgScheme as ThresholdRelease>::partial_release(&pp, &sks[1], &tag).expect("sig2");
    let full = <BlsDkgScheme as ThresholdRelease>::combine(
        &pp,
        &tag,
        &[(sks[0].id, sig1), (sks[1].id, sig2)],
    )
    .expect("combine");

    // Tamper witness by flipping a bit in encoding.
    let mut enc = full.encode();
    enc[0] ^= 0x01;
    let bad = <BlsDkgScheme as ThresholdRelease>::FullWitness::decode(&enc);
    match bad {
        Ok(bad_w) => {
            let res = <BlsDkgScheme as ThresholdRelease>::decrypt(&pp, &tag, &ct, &bad_w);
            assert!(matches!(res, Err(Error::DecryptionFailed)));
        }
        Err(_) => {}
    }
}

#[test]
fn verify_partial_fails_with_wrong_public_share() {
    let params = Params { n: 3, t: 2 };
    let (mut pp, sks) = setup_pp_and_sks(params);
    let tag = BlsTag(b"tag-1".to_vec());
    let sig1 =
        <BlsDkgScheme as ThresholdRelease>::partial_release(&pp, &sks[0], &tag).expect("sig1");
    // Corrupt pk_share for party 1
    let pk1 = pp
        .pk_shares
        .iter_mut()
        .find(|(id, _)| *id == sks[0].id)
        .unwrap();
    pk1.1 = pk1.1 + blstrs::G2Projective::generator();
    let res = <BlsDkgScheme as ThresholdRelease>::verify_partial(&pp, &tag, sks[0].id, &sig1);
    assert!(matches!(res, Err(Error::InvalidSignature)));
}

#[test]
fn ciphertext_decode_rejects_bad_lengths() {
    let bad = vec![0u8; 10];
    let res = BlsCiphertext::decode(&bad);
    assert!(res.is_err());
}

#[test]
fn combine_with_duplicate_party_ids_fails() {
    let params = Params { n: 3, t: 2 };
    let (pp, sks) = setup_pp_and_sks(params);
    let tag = BlsTag(b"tag-1".to_vec());
    let sig1 =
        <BlsDkgScheme as ThresholdRelease>::partial_release(&pp, &sks[0], &tag).expect("sig1");
    let res = <BlsDkgScheme as ThresholdRelease>::combine(
        &pp,
        &tag,
        &[(sks[0].id, sig1.clone()), (sks[0].id, sig1)],
    );
    assert!(res.is_err());
}

#[test]
fn finalize_fails_when_too_few_qual() {
    let params = Params { n: 3, t: 3 };
    let mut state = DkgState::new(params, PartyInfo { id: 1 });
    // Only self data; missing others should trigger complaints and reduce QUAL.
    let _ = state.verify_shares().expect("verify_shares");
    let res = state.finalize();
    assert!(matches!(res, Err(Error::InvalidParams)));
}
