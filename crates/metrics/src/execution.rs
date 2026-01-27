//! Execution layer (EVM) metrics.

use once_cell::sync::Lazy;
use prometheus::{Counter, CounterVec, Gauge, HistogramVec, Registry};

// Block Execution
pub static EXECUTION_BLOCKS_EXECUTED: Lazy<Counter> = Lazy::new(|| {
    Counter::new(
        "cipherbft_execution_blocks_executed_total",
        "Total blocks executed",
    )
    .expect("metric can be created")
});

pub static EXECUTION_BLOCK_TIME: Lazy<HistogramVec> = Lazy::new(|| {
    HistogramVec::new(
        prometheus::histogram_opts!(
            "cipherbft_execution_block_time_seconds",
            "Time to execute a block",
            vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
        ),
        &[],
    )
    .expect("metric can be created")
});

pub static EXECUTION_TXS_PER_BLOCK: Lazy<HistogramVec> = Lazy::new(|| {
    HistogramVec::new(
        prometheus::histogram_opts!(
            "cipherbft_execution_txs_per_block",
            "Transactions per block",
            vec![1.0, 10.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0]
        ),
        &[],
    )
    .expect("metric can be created")
});

pub static EXECUTION_GAS_PER_BLOCK: Lazy<HistogramVec> = Lazy::new(|| {
    HistogramVec::new(
        prometheus::histogram_opts!(
            "cipherbft_execution_gas_per_block",
            "Gas used per block",
            prometheus::exponential_buckets(21000.0, 2.0, 15).unwrap()
        ),
        &[],
    )
    .expect("metric can be created")
});

pub static EXECUTION_GAS_UTILIZATION: Lazy<Gauge> = Lazy::new(|| {
    Gauge::new(
        "cipherbft_execution_gas_utilization_ratio",
        "Gas used / gas limit ratio",
    )
    .expect("metric can be created")
});

// Transaction Execution
pub static EXECUTION_TX_TIME: Lazy<HistogramVec> = Lazy::new(|| {
    HistogramVec::new(
        prometheus::histogram_opts!(
            "cipherbft_execution_tx_time_seconds",
            "Per-transaction execution time",
            vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1]
        ),
        &["tx_type"], // "transfer", "contract_call", "contract_create"
    )
    .expect("metric can be created")
});

pub static EXECUTION_TX_SUCCESS: Lazy<Counter> = Lazy::new(|| {
    Counter::new(
        "cipherbft_execution_tx_success_total",
        "Total successful transactions",
    )
    .expect("metric can be created")
});

pub static EXECUTION_TX_FAILED: Lazy<CounterVec> = Lazy::new(|| {
    CounterVec::new(
        prometheus::opts!(
            "cipherbft_execution_tx_failed_total",
            "Total failed transactions"
        ),
        &["reason"], // "out_of_gas", "revert", "invalid_opcode"
    )
    .expect("metric can be created")
});

pub static EXECUTION_TX_REVERTED: Lazy<Counter> = Lazy::new(|| {
    Counter::new(
        "cipherbft_execution_tx_reverted_total",
        "Total reverted transactions",
    )
    .expect("metric can be created")
});

// State Operations
pub static EXECUTION_STATE_READS: Lazy<Counter> = Lazy::new(|| {
    Counter::new(
        "cipherbft_execution_state_reads_total",
        "Total state read operations",
    )
    .expect("metric can be created")
});

pub static EXECUTION_STATE_WRITES: Lazy<Counter> = Lazy::new(|| {
    Counter::new(
        "cipherbft_execution_state_writes_total",
        "Total state write operations",
    )
    .expect("metric can be created")
});

pub static EXECUTION_STATE_ROOT_TIME: Lazy<HistogramVec> = Lazy::new(|| {
    HistogramVec::new(
        prometheus::histogram_opts!(
            "cipherbft_execution_state_root_time_seconds",
            "Time to compute state root",
            vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25]
        ),
        &[],
    )
    .expect("metric can be created")
});

pub static EXECUTION_ACCOUNT_READS: Lazy<Counter> = Lazy::new(|| {
    Counter::new(
        "cipherbft_execution_account_reads_total",
        "Total account read operations",
    )
    .expect("metric can be created")
});

pub static EXECUTION_STORAGE_READS: Lazy<Counter> = Lazy::new(|| {
    Counter::new(
        "cipherbft_execution_storage_reads_total",
        "Total storage slot read operations",
    )
    .expect("metric can be created")
});

pub static EXECUTION_STORAGE_WRITES: Lazy<Counter> = Lazy::new(|| {
    Counter::new(
        "cipherbft_execution_storage_writes_total",
        "Total storage slot write operations",
    )
    .expect("metric can be created")
});

// Contract Operations
pub static EXECUTION_CONTRACT_DEPLOYMENTS: Lazy<Counter> = Lazy::new(|| {
    Counter::new(
        "cipherbft_execution_contract_deployments_total",
        "Total contract deployments",
    )
    .expect("metric can be created")
});

pub static EXECUTION_CONTRACT_CALLS: Lazy<Counter> = Lazy::new(|| {
    Counter::new(
        "cipherbft_execution_contract_calls_total",
        "Total contract calls",
    )
    .expect("metric can be created")
});

pub static EXECUTION_PRECOMPILE_CALLS: Lazy<CounterVec> = Lazy::new(|| {
    CounterVec::new(
        prometheus::opts!(
            "cipherbft_execution_precompile_calls_total",
            "Total precompile calls"
        ),
        &["address"], // "0x01", "0x02", ..., "0x100" (staking)
    )
    .expect("metric can be created")
});

// Staking Precompile Specific
pub static STAKING_VALIDATORS_REGISTERED: Lazy<Counter> = Lazy::new(|| {
    Counter::new(
        "cipherbft_staking_validators_registered_total",
        "Total validators registered",
    )
    .expect("metric can be created")
});

pub static STAKING_VALIDATORS_DEREGISTERED: Lazy<Counter> = Lazy::new(|| {
    Counter::new(
        "cipherbft_staking_validators_deregistered_total",
        "Total validators deregistered",
    )
    .expect("metric can be created")
});

pub static STAKING_STAKE_DELEGATED: Lazy<Gauge> = Lazy::new(|| {
    Gauge::new(
        "cipherbft_staking_stake_delegated_total",
        "Total stake delegated (in wei)",
    )
    .expect("metric can be created")
});

pub static STAKING_REWARDS_DISTRIBUTED: Lazy<Counter> = Lazy::new(|| {
    Counter::new(
        "cipherbft_staking_rewards_distributed_total",
        "Total rewards distributed",
    )
    .expect("metric can be created")
});

/// Register all execution metrics with the given registry.
pub fn register_metrics(registry: &Registry) {
    registry
        .register(Box::new(EXECUTION_BLOCKS_EXECUTED.clone()))
        .ok();
    registry
        .register(Box::new(EXECUTION_BLOCK_TIME.clone()))
        .ok();
    registry
        .register(Box::new(EXECUTION_TXS_PER_BLOCK.clone()))
        .ok();
    registry
        .register(Box::new(EXECUTION_GAS_PER_BLOCK.clone()))
        .ok();
    registry
        .register(Box::new(EXECUTION_GAS_UTILIZATION.clone()))
        .ok();
    registry.register(Box::new(EXECUTION_TX_TIME.clone())).ok();
    registry
        .register(Box::new(EXECUTION_TX_SUCCESS.clone()))
        .ok();
    registry
        .register(Box::new(EXECUTION_TX_FAILED.clone()))
        .ok();
    registry
        .register(Box::new(EXECUTION_TX_REVERTED.clone()))
        .ok();
    registry
        .register(Box::new(EXECUTION_STATE_READS.clone()))
        .ok();
    registry
        .register(Box::new(EXECUTION_STATE_WRITES.clone()))
        .ok();
    registry
        .register(Box::new(EXECUTION_STATE_ROOT_TIME.clone()))
        .ok();
    registry
        .register(Box::new(EXECUTION_ACCOUNT_READS.clone()))
        .ok();
    registry
        .register(Box::new(EXECUTION_STORAGE_READS.clone()))
        .ok();
    registry
        .register(Box::new(EXECUTION_STORAGE_WRITES.clone()))
        .ok();
    registry
        .register(Box::new(EXECUTION_CONTRACT_DEPLOYMENTS.clone()))
        .ok();
    registry
        .register(Box::new(EXECUTION_CONTRACT_CALLS.clone()))
        .ok();
    registry
        .register(Box::new(EXECUTION_PRECOMPILE_CALLS.clone()))
        .ok();
    registry
        .register(Box::new(STAKING_VALIDATORS_REGISTERED.clone()))
        .ok();
    registry
        .register(Box::new(STAKING_VALIDATORS_DEREGISTERED.clone()))
        .ok();
    registry
        .register(Box::new(STAKING_STAKE_DELEGATED.clone()))
        .ok();
    registry
        .register(Box::new(STAKING_REWARDS_DISTRIBUTED.clone()))
        .ok();
}
