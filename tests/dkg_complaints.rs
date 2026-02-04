use blstrs::Scalar;
use mempool_encryption::dkg::{DkgMessage, DkgState};
use mempool_encryption::types::{Error, Params, PartyInfo};

fn init_states(params: Params) -> Vec<DkgState> {
    (1..=params.n)
        .map(|id| DkgState::new(params, PartyInfo { id }))
        .collect()
}

#[test]
fn complaint_is_broadcast_on_bad_share() {
    let params = Params { n: 3, t: 2 };
    let mut states = init_states(params);

    let mut deliveries = Vec::new();
    for (idx, state) in states.iter().enumerate() {
        let dealer_id = (idx + 1) as u32;
        let out = state.initial_messages().expect("initial_messages");
        for (to, mut msg) in out {
            if dealer_id == 2 && to == 1 {
                if let DkgMessage::Share(ref mut share) = msg {
                    share.f_i = Scalar::from(7u64);
                    share.r_i = Scalar::from(9u64);
                }
            }
            deliveries.push((to, dealer_id, msg));
        }
    }
    for (to, from, msg) in deliveries {
        let slot = (to - 1) as usize;
        let _ = states[slot]
            .handle_message(from, msg)
            .expect("handle_message");
    }

    let complaints = states[0].verify_shares().expect("verify_shares");
    assert_eq!(complaints.len(), params.n as usize);
    for (to, msg) in complaints {
        assert!(to >= 1 && to <= params.n);
        match msg {
            DkgMessage::Complaint(c) => {
                assert_eq!(c.against, 2);
            }
            _ => panic!("expected complaint"),
        }
    }
}

#[test]
fn complaints_from_disqualify_dealers() {
    let params = Params { n: 3, t: 2 };
    let mut states = init_states(params);

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

    // Party 3 receives complaints that disqualify dealers 1 and 2.
    let _ = states[2]
        .handle_message(
            1,
            DkgMessage::Complaint(mempool_encryption::dkg::DkgComplaint {
                from: 1,
                against: 1,
            }),
        )
        .expect("complaint 1");
    let _ = states[2]
        .handle_message(
            2,
            DkgMessage::Complaint(mempool_encryption::dkg::DkgComplaint {
                from: 2,
                against: 2,
            }),
        )
        .expect("complaint 2");

    let res = states.remove(2).finalize();
    assert!(matches!(res, Err(Error::InvalidParams)));
}

#[test]
fn self_share_no_loopback_needed() {
    let params = Params { n: 1, t: 1 };
    let mut state = DkgState::new(params, PartyInfo { id: 1 });
    let complaints = state.verify_shares().expect("verify_shares");
    assert!(complaints.is_empty());
}
