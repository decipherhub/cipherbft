//! Sync layer metrics

use once_cell::sync::Lazy;
use prometheus::{
    register_counter_vec, register_gauge, register_histogram,
    CounterVec, Gauge, Histogram,
};

/// Current sync phase (0=Discovery, 1=SnapSync, 2=BlockSync, 3=Complete)
pub static SYNC_PHASE: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!("sync_phase", "Current sync phase (0=Discovery, 1=SnapSync, 2=BlockSync, 3=Complete)")
        .expect("Failed to register sync_phase metric")
});

/// Overall sync progress percentage (0-100)
pub static SYNC_PROGRESS_PERCENT: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!("sync_progress_percent", "Overall sync progress percentage")
        .expect("Failed to register sync_progress_percent metric")
});

/// Target snapshot height
pub static SYNC_TARGET_HEIGHT: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!("sync_target_height", "Target snapshot height for sync")
        .expect("Failed to register sync_target_height metric")
});

/// Current synced height
pub static SYNC_CURRENT_HEIGHT: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!("sync_current_height", "Current synced block height")
        .expect("Failed to register sync_current_height metric")
});

/// Number of connected sync peers
pub static SYNC_PEER_COUNT: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!("sync_peer_count", "Number of connected sync peers")
        .expect("Failed to register sync_peer_count metric")
});

/// Accounts downloaded during snap sync
pub static SYNC_ACCOUNTS_DOWNLOADED: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!("sync_accounts_downloaded", "Number of accounts downloaded")
        .expect("Failed to register sync_accounts_downloaded metric")
});

/// Storage slots downloaded during snap sync
pub static SYNC_STORAGE_SLOTS_DOWNLOADED: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!("sync_storage_slots_downloaded", "Number of storage slots downloaded")
        .expect("Failed to register sync_storage_slots_downloaded metric")
});

/// Bytes downloaded during sync
pub static SYNC_BYTES_DOWNLOADED: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!("sync_bytes_downloaded", "Total bytes downloaded during sync")
        .expect("Failed to register sync_bytes_downloaded metric")
});

/// Blocks executed during block sync
pub static SYNC_BLOCKS_EXECUTED: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!("sync_blocks_executed", "Number of blocks executed during sync")
        .expect("Failed to register sync_blocks_executed metric")
});

/// Sync request latency histogram
pub static SYNC_REQUEST_LATENCY: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "sync_request_latency_seconds",
        "Sync request latency in seconds",
        vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    )
    .expect("Failed to register sync_request_latency metric")
});

/// Sync requests by type and status
pub static SYNC_REQUESTS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "sync_requests_total",
        "Total sync requests by type and status",
        &["type", "status"]
    )
    .expect("Failed to register sync_requests metric")
});

/// Sync errors by type
pub static SYNC_ERRORS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "sync_errors_total",
        "Total sync errors by type",
        &["type"]
    )
    .expect("Failed to register sync_errors metric")
});

/// Update sync phase metric
pub fn set_sync_phase(phase: u8) {
    SYNC_PHASE.set(phase as f64);
}

/// Update sync progress
pub fn set_sync_progress(percent: f64) {
    SYNC_PROGRESS_PERCENT.set(percent);
}

/// Update target height
pub fn set_target_height(height: u64) {
    SYNC_TARGET_HEIGHT.set(height as f64);
}

/// Update current height
pub fn set_current_height(height: u64) {
    SYNC_CURRENT_HEIGHT.set(height as f64);
}

/// Update peer count
pub fn set_peer_count(count: usize) {
    SYNC_PEER_COUNT.set(count as f64);
}

/// Update accounts downloaded
pub fn set_accounts_downloaded(count: u64) {
    SYNC_ACCOUNTS_DOWNLOADED.set(count as f64);
}

/// Update storage slots downloaded
pub fn set_storage_slots_downloaded(count: u64) {
    SYNC_STORAGE_SLOTS_DOWNLOADED.set(count as f64);
}

/// Update bytes downloaded
pub fn set_bytes_downloaded(bytes: u64) {
    SYNC_BYTES_DOWNLOADED.set(bytes as f64);
}

/// Update blocks executed
pub fn set_blocks_executed(count: u64) {
    SYNC_BLOCKS_EXECUTED.set(count as f64);
}

/// Record a sync request
pub fn record_request(request_type: &str, success: bool) {
    let status = if success { "success" } else { "failure" };
    SYNC_REQUESTS.with_label_values(&[request_type, status]).inc();
}

/// Record request latency
pub fn record_latency(seconds: f64) {
    SYNC_REQUEST_LATENCY.observe(seconds);
}

/// Record a sync error
pub fn record_error(error_type: &str) {
    SYNC_ERRORS.with_label_values(&[error_type]).inc();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phase_metric() {
        set_sync_phase(1);
        assert_eq!(SYNC_PHASE.get(), 1.0);
    }

    #[test]
    fn test_progress_metric() {
        set_sync_progress(50.0);
        assert_eq!(SYNC_PROGRESS_PERCENT.get(), 50.0);
    }

    #[test]
    fn test_request_counter() {
        record_request("account_range", true);
        // Counter incremented
    }
}
