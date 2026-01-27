//! Data Chain Layer (DCL) metrics - Autobahn BFT.

use once_cell::sync::Lazy;
use prometheus::{CounterVec, Gauge, HistogramVec, Registry};

// Worker Metrics
pub static DCL_WORKER_BATCHES_CREATED: Lazy<CounterVec> = Lazy::new(|| {
    CounterVec::new(
        prometheus::opts!(
            "cipherbft_dcl_worker_batches_created_total",
            "Total batches created by workers"
        ),
        &["worker_id"],
    )
    .expect("metric can be created")
});

pub static DCL_WORKER_BATCH_SIZE_BYTES: Lazy<HistogramVec> = Lazy::new(|| {
    HistogramVec::new(
        prometheus::histogram_opts!(
            "cipherbft_dcl_worker_batch_size_bytes",
            "Size of batches in bytes",
            prometheus::exponential_buckets(1024.0, 2.0, 15).unwrap()
        ),
        &["worker_id"],
    )
    .expect("metric can be created")
});

pub static DCL_WORKER_BATCH_TX_COUNT: Lazy<HistogramVec> = Lazy::new(|| {
    HistogramVec::new(
        prometheus::histogram_opts!(
            "cipherbft_dcl_worker_batch_tx_count",
            "Number of transactions per batch",
            vec![1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0]
        ),
        &["worker_id"],
    )
    .expect("metric can be created")
});

pub static DCL_WORKER_BATCH_LATENCY: Lazy<HistogramVec> = Lazy::new(|| {
    HistogramVec::new(
        prometheus::histogram_opts!(
            "cipherbft_dcl_worker_batch_latency_seconds",
            "Time to form a batch",
            vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5]
        ),
        &["worker_id"],
    )
    .expect("metric can be created")
});

// Primary Metrics
pub static DCL_PRIMARY_CARS_CREATED: Lazy<Gauge> = Lazy::new(|| {
    Gauge::new(
        "cipherbft_dcl_primary_cars_created_total",
        "Total CARs (Certificate of Availability) created",
    )
    .expect("metric can be created")
});

pub static DCL_PRIMARY_CUTS_CREATED: Lazy<Gauge> = Lazy::new(|| {
    Gauge::new(
        "cipherbft_dcl_primary_cuts_created_total",
        "Total cuts created",
    )
    .expect("metric can be created")
});

pub static DCL_PRIMARY_CUT_LATENCY: Lazy<HistogramVec> = Lazy::new(|| {
    HistogramVec::new(
        prometheus::histogram_opts!(
            "cipherbft_dcl_primary_cut_latency_seconds",
            "Time to form a cut",
            vec![0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
        ),
        &[],
    )
    .expect("metric can be created")
});

// Attestation Metrics
pub static DCL_ATTESTATIONS_SENT: Lazy<Gauge> = Lazy::new(|| {
    Gauge::new(
        "cipherbft_dcl_attestations_sent_total",
        "Total attestations sent",
    )
    .expect("metric can be created")
});

pub static DCL_ATTESTATIONS_RECEIVED: Lazy<Gauge> = Lazy::new(|| {
    Gauge::new(
        "cipherbft_dcl_attestations_received_total",
        "Total attestations received",
    )
    .expect("metric can be created")
});

pub static DCL_ATTESTATION_COLLECTION: Lazy<HistogramVec> = Lazy::new(|| {
    HistogramVec::new(
        prometheus::histogram_opts!(
            "cipherbft_dcl_attestation_collection_seconds",
            "Time to collect f+1 attestations",
            vec![0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
        ),
        &[],
    )
    .expect("metric can be created")
});

pub static DCL_QUORUM_REACHED: Lazy<Gauge> = Lazy::new(|| {
    Gauge::new(
        "cipherbft_dcl_quorum_reached_total",
        "Total successful quorum events",
    )
    .expect("metric can be created")
});

// DAG Metrics
pub static DCL_DAG_DEPTH: Lazy<Gauge> = Lazy::new(|| {
    Gauge::new("cipherbft_dcl_dag_depth", "Current DAG depth").expect("metric can be created")
});

pub static DCL_DAG_PENDING_BATCHES: Lazy<Gauge> = Lazy::new(|| {
    Gauge::new(
        "cipherbft_dcl_dag_pending_batches",
        "Batches awaiting inclusion",
    )
    .expect("metric can be created")
});

pub static DCL_DAG_CERTIFICATES: Lazy<Gauge> = Lazy::new(|| {
    Gauge::new(
        "cipherbft_dcl_dag_certificates_total",
        "Total DAG certificates",
    )
    .expect("metric can be created")
});

// Synchronization
pub static DCL_SYNC_REQUESTS: Lazy<Gauge> = Lazy::new(|| {
    Gauge::new(
        "cipherbft_dcl_sync_requests_total",
        "Total sync requests sent",
    )
    .expect("metric can be created")
});

pub static DCL_SYNC_RESPONSES: Lazy<Gauge> = Lazy::new(|| {
    Gauge::new(
        "cipherbft_dcl_sync_responses_total",
        "Total sync responses received",
    )
    .expect("metric can be created")
});

pub static DCL_SYNC_LAG_BLOCKS: Lazy<Gauge> = Lazy::new(|| {
    Gauge::new("cipherbft_dcl_sync_lag_blocks", "Blocks behind network")
        .expect("metric can be created")
});

/// Register all DCL metrics with the given registry.
pub fn register_metrics(registry: &Registry) {
    registry
        .register(Box::new(DCL_WORKER_BATCHES_CREATED.clone()))
        .ok();
    registry
        .register(Box::new(DCL_WORKER_BATCH_SIZE_BYTES.clone()))
        .ok();
    registry
        .register(Box::new(DCL_WORKER_BATCH_TX_COUNT.clone()))
        .ok();
    registry
        .register(Box::new(DCL_WORKER_BATCH_LATENCY.clone()))
        .ok();
    registry
        .register(Box::new(DCL_PRIMARY_CARS_CREATED.clone()))
        .ok();
    registry
        .register(Box::new(DCL_PRIMARY_CUTS_CREATED.clone()))
        .ok();
    registry
        .register(Box::new(DCL_PRIMARY_CUT_LATENCY.clone()))
        .ok();
    registry
        .register(Box::new(DCL_ATTESTATIONS_SENT.clone()))
        .ok();
    registry
        .register(Box::new(DCL_ATTESTATIONS_RECEIVED.clone()))
        .ok();
    registry
        .register(Box::new(DCL_ATTESTATION_COLLECTION.clone()))
        .ok();
    registry.register(Box::new(DCL_QUORUM_REACHED.clone())).ok();
    registry.register(Box::new(DCL_DAG_DEPTH.clone())).ok();
    registry
        .register(Box::new(DCL_DAG_PENDING_BATCHES.clone()))
        .ok();
    registry
        .register(Box::new(DCL_DAG_CERTIFICATES.clone()))
        .ok();
    registry.register(Box::new(DCL_SYNC_REQUESTS.clone())).ok();
    registry.register(Box::new(DCL_SYNC_RESPONSES.clone())).ok();
    registry
        .register(Box::new(DCL_SYNC_LAG_BLOCKS.clone()))
        .ok();
}
