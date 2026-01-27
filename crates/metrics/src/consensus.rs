//! Consensus layer metrics (Malachite + CipherBFT).

use once_cell::sync::Lazy;
use prometheus::{CounterVec, Gauge, HistogramVec, Registry};

// Round & Block Metrics
pub static CONSENSUS_HEIGHT: Lazy<Gauge> = Lazy::new(|| {
    Gauge::new("cipherbft_consensus_height", "Current consensus height")
        .expect("metric can be created")
});

pub static CONSENSUS_ROUND: Lazy<Gauge> = Lazy::new(|| {
    Gauge::new("cipherbft_consensus_round", "Current round within height")
        .expect("metric can be created")
});

pub static CONSENSUS_ROUND_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    HistogramVec::new(
        prometheus::histogram_opts!(
            "cipherbft_consensus_round_duration_seconds",
            "Time per consensus round",
            vec![0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
        ),
        &["outcome"], // "success", "timeout"
    )
    .expect("metric can be created")
});

pub static CONSENSUS_BLOCK_FINALIZATION: Lazy<HistogramVec> = Lazy::new(|| {
    HistogramVec::new(
        prometheus::histogram_opts!(
            "cipherbft_consensus_block_finalization_seconds",
            "Time from proposal to finalization",
            vec![0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0]
        ),
        &[],
    )
    .expect("metric can be created")
});

// Voting Metrics
pub static CONSENSUS_PREVOTES_RECEIVED: Lazy<CounterVec> = Lazy::new(|| {
    CounterVec::new(
        prometheus::opts!(
            "cipherbft_consensus_prevotes_received_total",
            "Total prevotes received"
        ),
        &["validator"],
    )
    .expect("metric can be created")
});

pub static CONSENSUS_PRECOMMITS_RECEIVED: Lazy<CounterVec> = Lazy::new(|| {
    CounterVec::new(
        prometheus::opts!(
            "cipherbft_consensus_precommits_received_total",
            "Total precommits received"
        ),
        &["validator"],
    )
    .expect("metric can be created")
});

pub static CONSENSUS_PROPOSALS_RECEIVED: Lazy<Gauge> = Lazy::new(|| {
    Gauge::new(
        "cipherbft_consensus_proposals_received_total",
        "Total proposals received",
    )
    .expect("metric can be created")
});

pub static CONSENSUS_TIMEOUTS: Lazy<CounterVec> = Lazy::new(|| {
    CounterVec::new(
        prometheus::opts!(
            "cipherbft_consensus_timeouts_total",
            "Total consensus timeouts"
        ),
        &["timeout_type"], // "propose", "prevote", "precommit"
    )
    .expect("metric can be created")
});

// Validator Participation
pub static CONSENSUS_VALIDATOR_PARTICIPATION: Lazy<Gauge> = Lazy::new(|| {
    Gauge::new(
        "cipherbft_consensus_validator_participation",
        "Percentage of validators participating",
    )
    .expect("metric can be created")
});

pub static CONSENSUS_MISSING_VOTES: Lazy<CounterVec> = Lazy::new(|| {
    CounterVec::new(
        prometheus::opts!(
            "cipherbft_consensus_missing_votes_total",
            "Total missing votes by validator"
        ),
        &["validator"],
    )
    .expect("metric can be created")
});

pub static CONSENSUS_BYZANTINE_EVIDENCE: Lazy<Gauge> = Lazy::new(|| {
    Gauge::new(
        "cipherbft_consensus_byzantine_evidence_total",
        "Total byzantine evidence detected",
    )
    .expect("metric can be created")
});

// Proposer Metrics
pub static CONSENSUS_PROPOSALS_MADE: Lazy<Gauge> = Lazy::new(|| {
    Gauge::new(
        "cipherbft_consensus_proposals_made_total",
        "Total proposals made by this node",
    )
    .expect("metric can be created")
});

pub static CONSENSUS_PROPOSAL_SIZE: Lazy<HistogramVec> = Lazy::new(|| {
    HistogramVec::new(
        prometheus::histogram_opts!(
            "cipherbft_consensus_proposal_size_bytes",
            "Size of proposals in bytes",
            prometheus::exponential_buckets(1024.0, 2.0, 15).unwrap()
        ),
        &[],
    )
    .expect("metric can be created")
});

/// Register all consensus metrics with the given registry.
pub fn register_metrics(registry: &Registry) {
    registry.register(Box::new(CONSENSUS_HEIGHT.clone())).ok();
    registry.register(Box::new(CONSENSUS_ROUND.clone())).ok();
    registry
        .register(Box::new(CONSENSUS_ROUND_DURATION.clone()))
        .ok();
    registry
        .register(Box::new(CONSENSUS_BLOCK_FINALIZATION.clone()))
        .ok();
    registry
        .register(Box::new(CONSENSUS_PREVOTES_RECEIVED.clone()))
        .ok();
    registry
        .register(Box::new(CONSENSUS_PRECOMMITS_RECEIVED.clone()))
        .ok();
    registry
        .register(Box::new(CONSENSUS_PROPOSALS_RECEIVED.clone()))
        .ok();
    registry.register(Box::new(CONSENSUS_TIMEOUTS.clone())).ok();
    registry
        .register(Box::new(CONSENSUS_VALIDATOR_PARTICIPATION.clone()))
        .ok();
    registry
        .register(Box::new(CONSENSUS_MISSING_VOTES.clone()))
        .ok();
    registry
        .register(Box::new(CONSENSUS_BYZANTINE_EVIDENCE.clone()))
        .ok();
    registry
        .register(Box::new(CONSENSUS_PROPOSALS_MADE.clone()))
        .ok();
    registry
        .register(Box::new(CONSENSUS_PROPOSAL_SIZE.clone()))
        .ok();
}
