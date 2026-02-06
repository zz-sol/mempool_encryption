use mempool_encryption::dkg::DkgState;
use mempool_encryption::encoding::enc_len;
use mempool_encryption::types::{Params, PartyInfo};

#[test]
fn enc_len_rejects_oversize() {
    let big = (u32::MAX as usize) + 1;
    assert!(enc_len(big).is_err());
}

#[test]
fn invalid_params_rejected() {
    let params = Params { n: 0, t: 0 };
    let me = PartyInfo { id: 1 };
    let mut state = DkgState::new(params, me);
    let res = state.initial_messages();
    assert!(res.is_err());
}
