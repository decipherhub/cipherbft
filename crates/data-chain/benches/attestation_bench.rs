//! Attestation aggregation benchmarks

use criterion::{criterion_group, criterion_main, Criterion};

fn bench_attestation_aggregation(_c: &mut Criterion) {
    // Placeholder - will implement after core types work
}

fn bench_attestation_verification(_c: &mut Criterion) {
    // Placeholder
}

criterion_group!(
    benches,
    bench_attestation_aggregation,
    bench_attestation_verification
);
criterion_main!(benches);
