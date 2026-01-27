//! Storage (MDBX) metrics.

use once_cell::sync::Lazy;
use prometheus::{Counter, Gauge, GaugeVec, HistogramVec, Registry};

// Operation Latency
pub static STORAGE_READ_LATENCY: Lazy<HistogramVec> = Lazy::new(|| {
    HistogramVec::new(
        prometheus::histogram_opts!(
            "cipherbft_storage_read_latency_seconds",
            "Storage read latency",
            vec![0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01]
        ),
        &["table"],
    )
    .expect("metric can be created")
});

pub static STORAGE_WRITE_LATENCY: Lazy<HistogramVec> = Lazy::new(|| {
    HistogramVec::new(
        prometheus::histogram_opts!(
            "cipherbft_storage_write_latency_seconds",
            "Storage write latency",
            vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1]
        ),
        &["table"],
    )
    .expect("metric can be created")
});

pub static STORAGE_BATCH_COMMIT: Lazy<HistogramVec> = Lazy::new(|| {
    HistogramVec::new(
        prometheus::histogram_opts!(
            "cipherbft_storage_batch_commit_seconds",
            "Batch commit duration",
            vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]
        ),
        &[],
    )
    .expect("metric can be created")
});

// Database Size
pub static STORAGE_SIZE_BYTES: Lazy<GaugeVec> = Lazy::new(|| {
    GaugeVec::new(
        prometheus::opts!("cipherbft_storage_size_bytes", "Storage size per table"),
        &["table"],
    )
    .expect("metric can be created")
});

pub static STORAGE_TOTAL_SIZE_BYTES: Lazy<Gauge> = Lazy::new(|| {
    Gauge::new("cipherbft_storage_total_size_bytes", "Total storage size")
        .expect("metric can be created")
});

// Cache
pub static STORAGE_CACHE_HITS: Lazy<Counter> = Lazy::new(|| {
    Counter::new("cipherbft_storage_cache_hits_total", "Cache hits").expect("metric can be created")
});

pub static STORAGE_CACHE_MISSES: Lazy<Counter> = Lazy::new(|| {
    Counter::new("cipherbft_storage_cache_misses_total", "Cache misses")
        .expect("metric can be created")
});

pub static STORAGE_CACHE_SIZE_BYTES: Lazy<Gauge> = Lazy::new(|| {
    Gauge::new("cipherbft_storage_cache_size_bytes", "Cache size in bytes")
        .expect("metric can be created")
});

// Compaction
pub static STORAGE_COMPACTION: Lazy<Counter> = Lazy::new(|| {
    Counter::new(
        "cipherbft_storage_compaction_total",
        "Total compaction events",
    )
    .expect("metric can be created")
});

pub static STORAGE_COMPACTION_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    HistogramVec::new(
        prometheus::histogram_opts!(
            "cipherbft_storage_compaction_duration_seconds",
            "Compaction duration",
            vec![0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0]
        ),
        &[],
    )
    .expect("metric can be created")
});

/// Register all storage metrics with the given registry.
pub fn register_metrics(registry: &Registry) {
    registry
        .register(Box::new(STORAGE_READ_LATENCY.clone()))
        .ok();
    registry
        .register(Box::new(STORAGE_WRITE_LATENCY.clone()))
        .ok();
    registry
        .register(Box::new(STORAGE_BATCH_COMMIT.clone()))
        .ok();
    registry.register(Box::new(STORAGE_SIZE_BYTES.clone())).ok();
    registry
        .register(Box::new(STORAGE_TOTAL_SIZE_BYTES.clone()))
        .ok();
    registry.register(Box::new(STORAGE_CACHE_HITS.clone())).ok();
    registry
        .register(Box::new(STORAGE_CACHE_MISSES.clone()))
        .ok();
    registry
        .register(Box::new(STORAGE_CACHE_SIZE_BYTES.clone()))
        .ok();
    registry.register(Box::new(STORAGE_COMPACTION.clone())).ok();
    registry
        .register(Box::new(STORAGE_COMPACTION_DURATION.clone()))
        .ok();
}
