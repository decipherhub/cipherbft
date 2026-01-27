//! CipherBFT Prometheus metrics infrastructure.
//!
//! This crate provides centralized metric definitions for all CipherBFT components.
//! Metrics are organized by subsystem: consensus, DCL, execution, mempool, storage, network.

pub mod consensus;
pub mod dcl;
pub mod execution;
pub mod mempool;
pub mod network;
pub mod server;
pub mod storage;

pub use server::{spawn_metrics_server, start_metrics_server};

use once_cell::sync::Lazy;
use prometheus::Registry;

/// Global Prometheus registry for all CipherBFT metrics.
pub static REGISTRY: Lazy<Registry> = Lazy::new(|| {
    let registry = Registry::new();

    // Register all metric collectors
    consensus::register_metrics(&registry);
    dcl::register_metrics(&registry);
    execution::register_metrics(&registry);
    mempool::register_metrics(&registry);
    storage::register_metrics(&registry);
    network::register_metrics(&registry);

    registry
});

/// Initialize all metrics. Call once at startup.
pub fn init() {
    Lazy::force(&REGISTRY);
    tracing::info!("CipherBFT metrics initialized");
}
