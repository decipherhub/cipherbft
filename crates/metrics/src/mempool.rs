//! Mempool metrics.

use once_cell::sync::Lazy;
use prometheus::{Counter, CounterVec, Gauge, HistogramVec, Registry};

// Pool Size
pub static MEMPOOL_TRANSACTIONS_PENDING: Lazy<Gauge> = Lazy::new(|| {
    Gauge::new(
        "cipherbft_mempool_transactions_pending",
        "Transactions ready to include",
    )
    .expect("metric can be created")
});

pub static MEMPOOL_TRANSACTIONS_QUEUED: Lazy<Gauge> = Lazy::new(|| {
    Gauge::new(
        "cipherbft_mempool_transactions_queued",
        "Transactions with future nonce",
    )
    .expect("metric can be created")
});

pub static MEMPOOL_SIZE_BYTES: Lazy<Gauge> = Lazy::new(|| {
    Gauge::new(
        "cipherbft_mempool_size_bytes",
        "Total memory usage of mempool",
    )
    .expect("metric can be created")
});

// Throughput
pub static MEMPOOL_TRANSACTIONS_RECEIVED: Lazy<Counter> = Lazy::new(|| {
    Counter::new(
        "cipherbft_mempool_transactions_received_total",
        "Total transactions received",
    )
    .expect("metric can be created")
});

pub static MEMPOOL_TRANSACTIONS_INCLUDED: Lazy<Counter> = Lazy::new(|| {
    Counter::new(
        "cipherbft_mempool_transactions_included_total",
        "Total transactions included in blocks",
    )
    .expect("metric can be created")
});

pub static MEMPOOL_TRANSACTIONS_EVICTED: Lazy<CounterVec> = Lazy::new(|| {
    CounterVec::new(
        prometheus::opts!(
            "cipherbft_mempool_transactions_evicted_total",
            "Total transactions evicted"
        ),
        &["reason"], // "pool_full", "expired", "replaced"
    )
    .expect("metric can be created")
});

pub static MEMPOOL_TRANSACTIONS_REJECTED: Lazy<CounterVec> = Lazy::new(|| {
    CounterVec::new(
        prometheus::opts!(
            "cipherbft_mempool_transactions_rejected_total",
            "Total transactions rejected"
        ),
        &["reason"], // "invalid_signature", "nonce_too_low", "insufficient_funds"
    )
    .expect("metric can be created")
});

// Validation
pub static MEMPOOL_VALIDATION_TIME: Lazy<HistogramVec> = Lazy::new(|| {
    HistogramVec::new(
        prometheus::histogram_opts!(
            "cipherbft_mempool_validation_time_seconds",
            "Transaction validation time",
            vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05]
        ),
        &[],
    )
    .expect("metric can be created")
});

pub static MEMPOOL_INVALID_NONCE: Lazy<Counter> = Lazy::new(|| {
    Counter::new(
        "cipherbft_mempool_invalid_nonce_total",
        "Transactions rejected for invalid nonce",
    )
    .expect("metric can be created")
});

pub static MEMPOOL_INSUFFICIENT_BALANCE: Lazy<Counter> = Lazy::new(|| {
    Counter::new(
        "cipherbft_mempool_insufficient_balance_total",
        "Transactions rejected for insufficient balance",
    )
    .expect("metric can be created")
});

pub static MEMPOOL_DUPLICATE: Lazy<Counter> = Lazy::new(|| {
    Counter::new(
        "cipherbft_mempool_duplicate_total",
        "Duplicate transactions received",
    )
    .expect("metric can be created")
});

pub static MEMPOOL_GAS_PRICE_TOO_LOW: Lazy<Counter> = Lazy::new(|| {
    Counter::new(
        "cipherbft_mempool_gas_price_too_low_total",
        "Transactions rejected for gas price too low",
    )
    .expect("metric can be created")
});

/// Register all mempool metrics with the given registry.
pub fn register_metrics(registry: &Registry) {
    registry
        .register(Box::new(MEMPOOL_TRANSACTIONS_PENDING.clone()))
        .ok();
    registry
        .register(Box::new(MEMPOOL_TRANSACTIONS_QUEUED.clone()))
        .ok();
    registry.register(Box::new(MEMPOOL_SIZE_BYTES.clone())).ok();
    registry
        .register(Box::new(MEMPOOL_TRANSACTIONS_RECEIVED.clone()))
        .ok();
    registry
        .register(Box::new(MEMPOOL_TRANSACTIONS_INCLUDED.clone()))
        .ok();
    registry
        .register(Box::new(MEMPOOL_TRANSACTIONS_EVICTED.clone()))
        .ok();
    registry
        .register(Box::new(MEMPOOL_TRANSACTIONS_REJECTED.clone()))
        .ok();
    registry
        .register(Box::new(MEMPOOL_VALIDATION_TIME.clone()))
        .ok();
    registry
        .register(Box::new(MEMPOOL_INVALID_NONCE.clone()))
        .ok();
    registry
        .register(Box::new(MEMPOOL_INSUFFICIENT_BALANCE.clone()))
        .ok();
    registry.register(Box::new(MEMPOOL_DUPLICATE.clone())).ok();
    registry
        .register(Box::new(MEMPOOL_GAS_PRICE_TOO_LOW.clone()))
        .ok();
}
