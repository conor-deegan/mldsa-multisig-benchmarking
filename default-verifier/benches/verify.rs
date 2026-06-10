use criterion::{criterion_group, criterion_main, Criterion};
use policy::Policy;

fn bench_verify(c: &mut Criterion) {
    let policy = Policy::new(6, 10);
    let (sigs, keys, msg) = signing::sign(&policy);
    c.bench_function("verify_all 6-of-10", |b| {
        b.iter(|| default_verifier::verify_all(&policy, &sigs, &keys, &msg))
    });
}

criterion_group!(benches, bench_verify);
criterion_main!(benches);
