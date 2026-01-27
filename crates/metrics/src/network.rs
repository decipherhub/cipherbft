//! Network / P2P metrics.

use once_cell::sync::Lazy;
use prometheus::{Counter, CounterVec, Gauge, GaugeVec, HistogramVec, Registry};

// Peer Connections
pub static P2P_PEERS_CONNECTED: Lazy<Gauge> = Lazy::new(|| {
    Gauge::new("cipherbft_p2p_peers_connected", "Current connected peers")
        .expect("metric can be created")
});

pub static P2P_PEERS_INBOUND: Lazy<Gauge> = Lazy::new(|| {
    Gauge::new("cipherbft_p2p_peers_inbound", "Inbound peer connections")
        .expect("metric can be created")
});

pub static P2P_PEERS_OUTBOUND: Lazy<Gauge> = Lazy::new(|| {
    Gauge::new("cipherbft_p2p_peers_outbound", "Outbound peer connections")
        .expect("metric can be created")
});

// Message Traffic
pub static P2P_MESSAGES_SENT: Lazy<CounterVec> = Lazy::new(|| {
    CounterVec::new(
        prometheus::opts!("cipherbft_p2p_messages_sent_total", "Total messages sent"),
        &["message_type"],
    )
    .expect("metric can be created")
});

pub static P2P_MESSAGES_RECEIVED: Lazy<CounterVec> = Lazy::new(|| {
    CounterVec::new(
        prometheus::opts!(
            "cipherbft_p2p_messages_received_total",
            "Total messages received"
        ),
        &["message_type"],
    )
    .expect("metric can be created")
});

pub static P2P_BYTES_SENT: Lazy<Counter> = Lazy::new(|| {
    Counter::new("cipherbft_p2p_bytes_sent_total", "Total bytes sent")
        .expect("metric can be created")
});

pub static P2P_BYTES_RECEIVED: Lazy<Counter> = Lazy::new(|| {
    Counter::new("cipherbft_p2p_bytes_received_total", "Total bytes received")
        .expect("metric can be created")
});

// Latency
pub static P2P_MESSAGE_LATENCY: Lazy<HistogramVec> = Lazy::new(|| {
    HistogramVec::new(
        prometheus::histogram_opts!(
            "cipherbft_p2p_message_latency_seconds",
            "Message delivery latency",
            vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5]
        ),
        &["message_type"],
    )
    .expect("metric can be created")
});

pub static P2P_PEER_RTT: Lazy<GaugeVec> = Lazy::new(|| {
    GaugeVec::new(
        prometheus::opts!("cipherbft_p2p_peer_rtt_seconds", "Peer round-trip time"),
        &["peer"],
    )
    .expect("metric can be created")
});

// Errors
pub static P2P_CONNECTION_ERRORS: Lazy<Counter> = Lazy::new(|| {
    Counter::new(
        "cipherbft_p2p_connection_errors_total",
        "Total connection errors",
    )
    .expect("metric can be created")
});

pub static P2P_MESSAGE_DECODE_ERRORS: Lazy<Counter> = Lazy::new(|| {
    Counter::new(
        "cipherbft_p2p_message_decode_errors_total",
        "Total message decode errors",
    )
    .expect("metric can be created")
});

/// Register all network metrics with the given registry.
pub fn register_metrics(registry: &Registry) {
    registry
        .register(Box::new(P2P_PEERS_CONNECTED.clone()))
        .ok();
    registry.register(Box::new(P2P_PEERS_INBOUND.clone())).ok();
    registry.register(Box::new(P2P_PEERS_OUTBOUND.clone())).ok();
    registry.register(Box::new(P2P_MESSAGES_SENT.clone())).ok();
    registry
        .register(Box::new(P2P_MESSAGES_RECEIVED.clone()))
        .ok();
    registry.register(Box::new(P2P_BYTES_SENT.clone())).ok();
    registry.register(Box::new(P2P_BYTES_RECEIVED.clone())).ok();
    registry
        .register(Box::new(P2P_MESSAGE_LATENCY.clone()))
        .ok();
    registry.register(Box::new(P2P_PEER_RTT.clone())).ok();
    registry
        .register(Box::new(P2P_CONNECTION_ERRORS.clone()))
        .ok();
    registry
        .register(Box::new(P2P_MESSAGE_DECODE_ERRORS.clone()))
        .ok();
}
