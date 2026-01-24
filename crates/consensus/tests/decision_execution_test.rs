//! Integration test for decision-to-execution wiring.
//!
//! This test verifies that when consensus decides on a Cut,
//! the execution callback is triggered correctly.

#![cfg(feature = "malachite")]

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

use cipherbft_consensus::context::CipherBftContext;
use cipherbft_consensus::validator_set::ConsensusValidatorSet;
use cipherbft_consensus::{
    ConsensusConfig, ConsensusHeight, ConsensusValidator, ConsensusValue, DecisionHandler,
    ExecutingDecisionHandler, ExecutionCallback, ReceiptStore,
};
use cipherbft_crypto::Ed25519KeyPair;
use cipherbft_data_chain::Cut;
use informalsystems_malachitebft_core_types::{CommitCertificate, Round};
use rand::rngs::StdRng;
use rand::SeedableRng;

/// Test execution callback that tracks calls and simulates execution.
struct TestExecutionCallback {
    call_count: AtomicUsize,
    last_height: AtomicU64,
    simulate_failure: bool,
}

impl TestExecutionCallback {
    fn new() -> Self {
        Self {
            call_count: AtomicUsize::new(0),
            last_height: AtomicU64::new(0),
            simulate_failure: false,
        }
    }

    fn with_failure() -> Self {
        Self {
            call_count: AtomicUsize::new(0),
            last_height: AtomicU64::new(0),
            simulate_failure: true,
        }
    }

    fn call_count(&self) -> usize {
        self.call_count.load(Ordering::SeqCst)
    }

    fn last_height(&self) -> u64 {
        self.last_height.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ExecutionCallback for TestExecutionCallback {
    async fn execute(&self, height: u64, cut: &Cut) -> Result<(String, u64), String> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        self.last_height.store(height, Ordering::SeqCst);

        if self.simulate_failure {
            return Err("simulated execution failure".to_string());
        }

        // Simulate successful execution
        let state_root = format!("0x{:064x}", height * 1000);
        let gas_used = cut.cars.len() as u64 * 21000; // Base gas per car

        Ok((state_root, gas_used))
    }
}

/// Test receipt store that records all stored receipts.
#[allow(dead_code)]
struct TestReceiptStore {
    receipts: RwLock<std::collections::HashMap<u64, Vec<u8>>>,
}

#[allow(dead_code)]
impl TestReceiptStore {
    fn new() -> Self {
        Self {
            receipts: RwLock::new(std::collections::HashMap::new()),
        }
    }
}

#[async_trait]
impl ReceiptStore for TestReceiptStore {
    async fn put_receipts(&self, block_number: u64, receipts: &[u8]) -> Result<(), String> {
        self.receipts
            .write()
            .await
            .insert(block_number, receipts.to_vec());
        Ok(())
    }

    async fn get_receipts(&self, block_number: u64) -> Option<Vec<u8>> {
        self.receipts.read().await.get(&block_number).cloned()
    }
}

fn make_validator(id: u8, power: u64) -> ConsensusValidator {
    let mut rng = StdRng::seed_from_u64(id as u64);
    let keypair = Ed25519KeyPair::generate(&mut rng);
    let validator_id = keypair.validator_id();
    ConsensusValidator::new(validator_id, keypair.public_key, power)
}

fn make_context() -> CipherBftContext {
    let validators: Vec<ConsensusValidator> = (1..=4).map(|i| make_validator(i, 100)).collect();
    let config = ConsensusConfig::new("test-chain");
    let validator_set = ConsensusValidatorSet::new(validators);
    CipherBftContext::new(config, validator_set, ConsensusHeight(1))
}

fn make_certificate(height: ConsensusHeight) -> CommitCertificate<CipherBftContext> {
    let cut = Cut::new(height.0);
    let value = ConsensusValue::from(cut);
    let value_id = informalsystems_malachitebft_core_types::Value::id(&value);

    CommitCertificate {
        height,
        round: Round::new(0),
        value_id,
        commit_signatures: Vec::new(),
    }
}

/// Test that a decided Cut triggers the execution callback.
#[tokio::test]
async fn test_decision_triggers_execution() {
    let callback = Arc::new(TestExecutionCallback::new());
    let handler = ExecutingDecisionHandler::new(callback.clone(), 100);

    let _ctx = make_context();
    let height = ConsensusHeight(1);
    let cut = Cut::new(1);
    let value = ConsensusValue::from(cut);
    let certificate = make_certificate(height);

    // Trigger decision
    let result = handler
        .on_decided(height, Round::new(0), value, certificate)
        .await;

    // Verify execution was triggered
    assert!(result.is_ok(), "on_decided should succeed");
    assert_eq!(callback.call_count(), 1, "Execution should be called once");
    assert_eq!(callback.last_height(), 1, "Height should match");
    assert_eq!(handler.latest_block(), 1, "Latest block should be updated");
}

/// Test that multiple decisions are processed sequentially.
#[tokio::test]
async fn test_multiple_decisions() {
    let callback = Arc::new(TestExecutionCallback::new());
    let handler = ExecutingDecisionHandler::new(callback.clone(), 100);

    let _ctx = make_context();

    // Process 5 decisions
    for i in 1..=5 {
        let height = ConsensusHeight(i);
        let cut = Cut::new(i);
        let value = ConsensusValue::from(cut);
        let certificate = make_certificate(height);

        handler
            .on_decided(height, Round::new(0), value, certificate)
            .await
            .expect("on_decided should succeed");
    }

    // Verify all executions occurred
    assert_eq!(
        callback.call_count(),
        5,
        "All decisions should trigger execution"
    );
    assert_eq!(callback.last_height(), 5, "Last height should be 5");
    assert_eq!(handler.latest_block(), 5, "Latest block should be 5");
}

/// Test that execution failures don't break the handler.
#[tokio::test]
async fn test_execution_failure_graceful() {
    let callback = Arc::new(TestExecutionCallback::with_failure());
    let handler = ExecutingDecisionHandler::new(callback.clone(), 100);

    let _ctx = make_context();
    let height = ConsensusHeight(1);
    let cut = Cut::new(1);
    let value = ConsensusValue::from(cut);
    let certificate = make_certificate(height);

    // Trigger decision with failing execution
    let result = handler
        .on_decided(height, Round::new(0), value, certificate)
        .await;

    // Handler should still succeed (consensus decided, even if execution failed)
    assert!(
        result.is_ok(),
        "on_decided should succeed even with execution failure"
    );
    assert_eq!(callback.call_count(), 1, "Execution was attempted");

    // Latest block should NOT be updated on failure
    assert_eq!(
        handler.latest_block(),
        0,
        "Latest block should not update on failure"
    );
}

/// Test that history queries work correctly.
#[tokio::test]
async fn test_history_queries() {
    let callback = Arc::new(TestExecutionCallback::new());
    let handler = ExecutingDecisionHandler::new(callback, 100);

    let _ctx = make_context();

    // Add some decisions
    for i in 1..=3 {
        let height = ConsensusHeight(i);
        let cut = Cut::new(i);
        let value = ConsensusValue::from(cut);
        let certificate = make_certificate(height);

        handler
            .on_decided(height, Round::new(0), value, certificate)
            .await
            .unwrap();
    }

    // Query stored decisions
    let stored = handler.get_decided_value(ConsensusHeight(2)).await.unwrap();
    assert!(stored.is_some(), "Decision at height 2 should exist");

    let stored = handler
        .get_decided_value(ConsensusHeight(10))
        .await
        .unwrap();
    assert!(stored.is_none(), "Decision at height 10 should not exist");

    // Check history min height
    let min = handler.get_history_min_height().await.unwrap();
    assert_eq!(min, ConsensusHeight(1), "Min height should be 1");
}

/// Test the backward-compatible channel mode.
#[tokio::test]
async fn test_channel_mode() {
    let callback = Arc::new(TestExecutionCallback::new());
    let (tx, mut rx) = tokio::sync::mpsc::channel(10);
    let handler = ExecutingDecisionHandler::new(callback, 100).with_decided_channel(tx);

    let _ctx = make_context();
    let height = ConsensusHeight(1);
    let cut = Cut::new(1);
    let value = ConsensusValue::from(cut);
    let certificate = make_certificate(height);

    handler
        .on_decided(height, Round::new(0), value, certificate)
        .await
        .unwrap();

    // Verify event was sent to channel
    let (recv_height, recv_cut) = rx.try_recv().expect("Should receive event");
    assert_eq!(recv_height, height);
    assert_eq!(recv_cut.height, 1);
}
