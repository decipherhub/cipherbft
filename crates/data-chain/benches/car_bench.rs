//! Car creation benchmarks

use criterion::{criterion_group, criterion_main, Criterion};

fn bench_car_creation(_c: &mut Criterion) {
    // Placeholder - will implement after core types work
}

fn bench_car_signing_bytes(_c: &mut Criterion) {
    // Placeholder
}

criterion_group!(benches, bench_car_creation, bench_car_signing_bytes);
criterion_main!(benches);
