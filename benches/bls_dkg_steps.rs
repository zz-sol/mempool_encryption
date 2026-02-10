use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use mempool_encryption::dkg::{BlsDkgScheme, DkgMessage, DkgState, compute_pk_from_shares};
use mempool_encryption::scheme::SetupProtocol;
use mempool_encryption::types::{Params, PartyId, PartyInfo};
use std::time::Duration;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

fn parties(n: u32) -> Vec<PartyInfo> {
    (1..=n).map(|id| PartyInfo { id }).collect()
}

fn init_states(params: Params, parties: &[PartyInfo]) -> Vec<DkgState> {
    #[cfg(feature = "parallel")]
    let states = parties
        .par_iter()
        .map(|me| BlsDkgScheme::init(params, *me))
        .collect();

    #[cfg(not(feature = "parallel"))]
    let states = parties
        .iter()
        .map(|me| BlsDkgScheme::init(params, *me))
        .collect();

    states
}

fn build_initial_deliveries(
    states: &mut [DkgState],
    parties: &[PartyInfo],
) -> Vec<(PartyId, PartyId, DkgMessage)> {
    #[cfg(feature = "parallel")]
    let deliveries = {
        let nested: Vec<Vec<(PartyId, PartyId, DkgMessage)>> = states
            .par_iter_mut()
            .enumerate()
            .map(|(idx, state)| {
                let from = parties[idx].id;
                state
                    .initial_messages()
                    .expect("initial_messages")
                    .into_iter()
                    .map(|(to, msg)| (to, from, msg))
                    .collect()
            })
            .collect();
        nested.into_iter().flatten().collect()
    };

    #[cfg(not(feature = "parallel"))]
    let deliveries = {
        let mut deliveries = Vec::new();
        for (idx, state) in states.iter_mut().enumerate() {
            let from = parties[idx].id;
            for (to, msg) in state.initial_messages().expect("initial_messages") {
                deliveries.push((to, from, msg));
            }
        }
        deliveries
    };

    deliveries
}

fn build_inboxes(
    n: u32,
    deliveries: Vec<(PartyId, PartyId, DkgMessage)>,
) -> Vec<Vec<(PartyId, DkgMessage)>> {
    let mut inboxes: Vec<Vec<(PartyId, DkgMessage)>> = vec![Vec::new(); n as usize];
    for (to, from, msg) in deliveries {
        inboxes[(to - 1) as usize].push((from, msg));
    }
    inboxes
}

fn apply_inboxes(states: &mut [DkgState], inboxes: Vec<Vec<(PartyId, DkgMessage)>>) {
    #[cfg(feature = "parallel")]
    {
        let mut inboxes = inboxes;
        states
            .par_iter_mut()
            .zip(inboxes.par_iter_mut())
            .for_each(|(state, inbox)| {
                let inbox = std::mem::take(inbox);
                for (from, msg) in inbox {
                    let _ = BlsDkgScheme::handle_message(state, from, msg).expect("handle_message");
                }
            });
    }

    #[cfg(not(feature = "parallel"))]
    for (state, inbox) in states.iter_mut().zip(inboxes.into_iter()) {
        for (from, msg) in inbox {
            let _ = BlsDkgScheme::handle_message(state, from, msg).expect("handle_message");
        }
    }
}

fn setup_to_handle(params: Params, parties: &[PartyInfo]) -> Vec<DkgState> {
    let mut states = init_states(params, parties);
    let deliveries = build_initial_deliveries(&mut states, parties);
    let inboxes = build_inboxes(params.n, deliveries);
    apply_inboxes(&mut states, inboxes);
    states
}

fn setup_to_finalize(params: Params, parties: &[PartyInfo]) -> Vec<DkgState> {
    let mut states = setup_to_handle(params, parties);

    #[cfg(feature = "parallel")]
    {
        let complaints: Vec<Vec<(PartyId, DkgMessage)>> = states
            .par_iter_mut()
            .map(|state| state.verify_shares().expect("verify_shares"))
            .collect();
        for c in complaints {
            assert!(c.is_empty(), "unexpected complaint in bench setup");
        }
    }

    #[cfg(not(feature = "parallel"))]
    for state in states.iter_mut() {
        let complaints = state.verify_shares().expect("verify_shares");
        assert!(complaints.is_empty(), "unexpected complaint in bench setup");
    }
    states
}

fn bench_bls_dkg_steps(c: &mut Criterion) {
    // Keep defaults modest so stage benches complete quickly.
    let params = Params { n: 64, t: 43 };
    let ps = parties(params.n);

    let mut group = c.benchmark_group("bls_dkg_setup_stages_n64_t43");
    group.sample_size(10);
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(2));

    group.bench_function("stage1_init_states", |b| {
        b.iter(|| {
            let _states = init_states(params, &ps);
        });
    });

    group.bench_function("stage2_initial_messages", |b| {
        b.iter_batched(
            || init_states(params, &ps),
            |mut states| {
                let _deliveries = build_initial_deliveries(&mut states, &ps);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("stage3_handle_messages", |b| {
        b.iter_batched(
            || {
                let mut states = init_states(params, &ps);
                let deliveries = build_initial_deliveries(&mut states, &ps);
                let inboxes = build_inboxes(params.n, deliveries);
                (states, inboxes)
            },
            |(mut states, inboxes)| {
                apply_inboxes(&mut states, inboxes);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("stage4_verify_shares", |b| {
        b.iter_batched(
            || setup_to_handle(params, &ps),
            |mut states| {
                for state in states.iter_mut() {
                    let _complaints = state.verify_shares().expect("verify_shares");
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("stage5_finalize", |b| {
        b.iter_batched(
            || setup_to_finalize(params, &ps),
            |states| {
                #[cfg(feature = "parallel")]
                let _outputs: Vec<_> = states
                    .into_par_iter()
                    .map(|state| BlsDkgScheme::finalize(state).expect("finalize"))
                    .collect();

                #[cfg(not(feature = "parallel"))]
                let _outputs: Vec<_> = states
                    .into_iter()
                    .map(|state| BlsDkgScheme::finalize(state).expect("finalize"))
                    .collect();
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("stage6_reconstruct_pk", |b| {
        b.iter_batched(
            || {
                let states = setup_to_finalize(params, &ps);
                #[cfg(feature = "parallel")]
                let outputs = states
                    .into_par_iter()
                    .map(|state| BlsDkgScheme::finalize(state).expect("finalize"))
                    .collect::<Vec<_>>();

                #[cfg(not(feature = "parallel"))]
                let outputs = states
                    .into_iter()
                    .map(|state| BlsDkgScheme::finalize(state).expect("finalize"))
                    .collect::<Vec<_>>();

                outputs
            },
            |outputs| {
                let mut pk_shares = Vec::with_capacity(outputs.len());
                for (pp_i, _) in outputs.iter() {
                    for (id, pk_i) in pp_i.pk_shares.iter() {
                        if !pk_shares.iter().any(|(x, _)| x == id) {
                            pk_shares.push((*id, *pk_i));
                        }
                    }
                }
                let _pk = compute_pk_from_shares(&pk_shares).expect("compute_pk_from_shares");
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, bench_bls_dkg_steps);
criterion_main!(benches);
