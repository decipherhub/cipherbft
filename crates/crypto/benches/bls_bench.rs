//! BLS12-381 benchmarks

use criterion::{criterion_group, criterion_main, Criterion};

fn bench_bls_sign(_c: &mut Criterion) {
    // Placeholder
}

fn bench_bls_verify(_c: &mut Criterion) {
    // Placeholder
}

fn bench_bls_aggregate(_c: &mut Criterion) {
    // Placeholder
}

criterion_group!(
    benches,
    bench_bls_sign,
    bench_bls_verify,
    bench_bls_aggregate
);
criterion_main!(benches);
