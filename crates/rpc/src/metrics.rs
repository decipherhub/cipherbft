//! Prometheus metrics for RPC server observability.

use prometheus::{
    register_counter_vec, register_gauge, register_gauge_vec, register_histogram_vec, CounterVec,
    Gauge, GaugeVec, HistogramVec,
};

use once_cell::sync::Lazy;

/// Total RPC requests counter, labeled by method and status.
pub static RPC_REQUESTS_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "rpc_requests_total",
        "Total number of RPC requests",
        &["method", "status"]
    )
    .expect("Failed to register rpc_requests_total metric")
});

/// RPC request duration histogram, labeled by method.
pub static RPC_REQUEST_DURATION_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "rpc_request_duration_seconds",
        "RPC request duration in seconds",
        &["method"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    )
    .expect("Failed to register rpc_request_duration_seconds metric")
});

/// Active connections gauge, labeled by transport (http/ws).
pub static RPC_ACTIVE_CONNECTIONS: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "rpc_active_connections",
        "Number of active RPC connections",
        &["transport"]
    )
    .expect("Failed to register rpc_active_connections metric")
});

/// Active WebSocket subscriptions gauge, labeled by subscription kind.
pub static RPC_WS_SUBSCRIPTIONS_ACTIVE: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "rpc_ws_subscriptions_active",
        "Number of active WebSocket subscriptions",
        &["kind"]
    )
    .expect("Failed to register rpc_ws_subscriptions_active metric")
});

/// RPC rate limit rejections counter.
pub static RPC_RATE_LIMIT_REJECTIONS: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(
        "rpc_rate_limit_rejections_total",
        "Total number of rate limit rejections"
    )
    .expect("Failed to register rpc_rate_limit_rejections_total metric")
});

/// Record a successful RPC request.
pub fn record_request_success(method: &str, duration_secs: f64) {
    RPC_REQUESTS_TOTAL
        .with_label_values(&[method, "success"])
        .inc();
    RPC_REQUEST_DURATION_SECONDS
        .with_label_values(&[method])
        .observe(duration_secs);
}

/// Record a failed RPC request.
pub fn record_request_error(method: &str, duration_secs: f64) {
    RPC_REQUESTS_TOTAL
        .with_label_values(&[method, "error"])
        .inc();
    RPC_REQUEST_DURATION_SECONDS
        .with_label_values(&[method])
        .observe(duration_secs);
}

/// Increment active connections for a transport.
pub fn inc_active_connections(transport: &str) {
    RPC_ACTIVE_CONNECTIONS
        .with_label_values(&[transport])
        .inc();
}

/// Decrement active connections for a transport.
pub fn dec_active_connections(transport: &str) {
    RPC_ACTIVE_CONNECTIONS
        .with_label_values(&[transport])
        .dec();
}

/// Set the number of active subscriptions for a kind.
pub fn set_active_subscriptions(kind: &str, count: f64) {
    RPC_WS_SUBSCRIPTIONS_ACTIVE
        .with_label_values(&[kind])
        .set(count);
}

/// Record a rate limit rejection.
pub fn record_rate_limit_rejection() {
    RPC_RATE_LIMIT_REJECTIONS.inc();
}
