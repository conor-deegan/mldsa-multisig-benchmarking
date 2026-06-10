use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use policy::Policy;
use sp1_prover::{build_stdin, GUEST_ELF};
use sp1_sdk::blocking::{ProveRequest, Prover, ProverClient};

// Times core-proof generation for a 6-of-10 policy. NOTE: proving time is
// MacBook-relative, not a deployable cost figure. sample_size is the Criterion
// minimum (10) because each proof takes seconds.
fn bench_prove(c: &mut Criterion) {
    let policy = Policy::new(6, 10);
    let client = ProverClient::from_env();
    let pk = client.setup(GUEST_ELF).expect("setup");

    let mut group = c.benchmark_group("prove");
    group.sample_size(10);
    group.bench_function("prove 6-of-10", |b| {
        b.iter_batched(
            || build_stdin(&policy, false),
            |stdin| client.prove(&pk, stdin).run().unwrap(),
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

criterion_group!(benches, bench_prove);
criterion_main!(benches);
