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
    for (idx, state) in states.iter_mut().enumerate() {
        let dealer_id = (idx + 1) as u32;
        let out = state.initial_messages().expect("initial_messages");
        for (to, msg) in out {
            // Drop dealer 2's share to party 1 to trigger complaint.
            if dealer_id == 2
                && to == 1
                && let DkgMessage::Share(_) = msg
            {
                continue;
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
    for (idx, state) in states.iter_mut().enumerate() {
        let dealer_id = (idx + 1) as u32;
        let out = state.initial_messages().expect("initial_messages");
        for (to, msg) in out {
            if dealer_id == 1
                && to == 2
                && let DkgMessage::Share(_) = msg
            {
                continue;
            }
            if dealer_id == 2
                && to == 1
                && let DkgMessage::Share(_) = msg
            {
                continue;
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

    let complaints1 = states[0].verify_shares().expect("verify_shares 1");
    let complaints2 = states[1].verify_shares().expect("verify_shares 2");

    for (to, msg) in complaints1.into_iter().chain(complaints2.into_iter()) {
        if to == 3 {
            let from = match &msg {
                DkgMessage::Complaint(c) => c.from,
                _ => 0,
            };
            let _ = states[2]
                .handle_message(from, msg)
                .expect("handle complaint");
        }
    }

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
