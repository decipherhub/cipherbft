//! Integration tests for ExecutionBridge
//!
//! These tests verify that the ExecutionBridge correctly converts DCL Cuts
//! to BlockInputs with proper transaction ordering.

use async_trait::async_trait;
use cipherbft_data_chain::{Batch, BatchDigest, Car, Cut as DclCut};
use cipherbft_execution::bridge::{BatchFetcher, ExecutionBridge};
use cipherbft_execution::{ExecutionError, Result};
use cipherbft_types::{Hash, ValidatorId, VALIDATOR_ID_SIZE};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

/// In-memory batch store for testing
struct TestBatchStore {
    batches: RwLock<HashMap<Hash, Batch>>,
}

impl TestBatchStore {
    fn new() -> Self {
        Self {
            batches: RwLock::new(HashMap::new()),
        }
    }

    fn insert(&self, batch: Batch) {
        let hash = batch.digest().digest;
        self.batches.write().insert(hash, batch);
    }
}

#[async_trait]
impl BatchFetcher for TestBatchStore {
    async fn get_batch(&self, digest: &Hash) -> Result<Option<Batch>> {
        Ok(self.batches.read().get(digest).cloned())
    }
}

fn make_validator_id(id: u8) -> ValidatorId {
    let mut bytes = [0u8; VALIDATOR_ID_SIZE];
    bytes[0] = id;
    ValidatorId::from_bytes(bytes)
}

fn make_batch(worker_id: u8, transactions: Vec<Vec<u8>>) -> Batch {
    Batch::new(worker_id, transactions, 0)
}

#[tokio::test]
async fn test_bridge_converts_cut_to_block_input() {
    // Setup: Create mock batch store with test data
    let store = Arc::new(TestBatchStore::new());

    // Create batches for two validators
    let batch1 = make_batch(0, vec![vec![0x01, 0x02], vec![0x03, 0x04]]);
    let batch2 = make_batch(0, vec![vec![0x05, 0x06]]);
    let batch3 = make_batch(1, vec![vec![0x07, 0x08, 0x09]]);

    let digest1 = batch1.digest();
    let digest2 = batch2.digest();
    let digest3 = batch3.digest();

    store.insert(batch1);
    store.insert(batch2);
    store.insert(batch3);

    // Create Cars with batch digests
    // Validator A (lower ID) should have its transactions come first
    let validator_a = make_validator_id(0x01);
    let validator_b = make_validator_id(0x10);

    let car_a = Car::new(validator_a, 0, vec![digest1, digest2], None);
    let car_b = Car::new(validator_b, 0, vec![digest3], None);

    // Create Cut with both Cars
    let mut cut = DclCut::new(1);
    cut.cars.insert(validator_a, car_a);
    cut.cars.insert(validator_b, car_b);

    // Execute: Convert Cut to BlockInput
    let bridge = ExecutionBridge::new(store);
    let block_input = bridge
        .convert_cut(&cut, 42, alloy_primitives::B256::ZERO)
        .await
        .expect("convert_cut should succeed");

    // Verify: Check BlockInput has correct transactions in deterministic order
    assert_eq!(block_input.block_number, 42);

    // Validator A (0x01) comes before Validator B (0x10) due to ordering
    // Validator A has 2 batches: batch1 (2 txs) + batch2 (1 tx) = 3 txs
    // Validator B has 1 batch: batch3 (1 tx)
    // Total: 4 transactions
    assert_eq!(block_input.transactions.len(), 4);

    // Transactions should be in order:
    // 1. batch1 tx1: [0x01, 0x02]
    // 2. batch1 tx2: [0x03, 0x04]
    // 3. batch2 tx1: [0x05, 0x06]
    // 4. batch3 tx1: [0x07, 0x08, 0x09]
    assert_eq!(block_input.transactions[0].as_ref(), &[0x01, 0x02]);
    assert_eq!(block_input.transactions[1].as_ref(), &[0x03, 0x04]);
    assert_eq!(block_input.transactions[2].as_ref(), &[0x05, 0x06]);
    assert_eq!(block_input.transactions[3].as_ref(), &[0x07, 0x08, 0x09]);
}

#[tokio::test]
async fn test_bridge_handles_empty_cut() {
    let store = Arc::new(TestBatchStore::new());
    let bridge = ExecutionBridge::new(store);

    let cut = DclCut::new(1);
    let block_input = bridge
        .convert_cut(&cut, 1, alloy_primitives::B256::ZERO)
        .await
        .expect("empty cut should convert successfully");

    assert_eq!(block_input.block_number, 1);
    assert!(block_input.transactions.is_empty());
}

#[tokio::test]
async fn test_bridge_returns_error_for_missing_batch() {
    let store = Arc::new(TestBatchStore::new());
    let bridge = ExecutionBridge::new(store);

    // Create a digest for a non-existent batch
    let missing_digest = BatchDigest::new(0, Hash::compute(b"nonexistent"), 1, 100);

    let validator = make_validator_id(1);
    let car = Car::new(validator, 0, vec![missing_digest], None);

    let mut cut = DclCut::new(1);
    cut.cars.insert(validator, car);

    let result = bridge
        .convert_cut(&cut, 1, alloy_primitives::B256::ZERO)
        .await;

    assert!(result.is_err());
    match result {
        Err(ExecutionError::Internal(msg)) => {
            assert!(msg.contains("not found in storage"));
        }
        _ => panic!("Expected Internal error for missing batch"),
    }
}

#[tokio::test]
async fn test_bridge_ordering_is_deterministic() {
    let store = Arc::new(TestBatchStore::new());

    // Create batches
    let batch_a = make_batch(0, vec![vec![0xAA]]);
    let batch_b = make_batch(0, vec![vec![0xBB]]);
    let batch_c = make_batch(0, vec![vec![0xCC]]);

    let digest_a = batch_a.digest();
    let digest_b = batch_b.digest();
    let digest_c = batch_c.digest();

    store.insert(batch_a);
    store.insert(batch_b);
    store.insert(batch_c);

    // Create validators with specific IDs
    let v1 = make_validator_id(0x05);
    let v2 = make_validator_id(0x01);
    let v3 = make_validator_id(0x0A);

    let car1 = Car::new(v1, 0, vec![digest_a], None);
    let car2 = Car::new(v2, 0, vec![digest_b], None);
    let car3 = Car::new(v3, 0, vec![digest_c], None);

    // Create two cuts with cars inserted in different orders
    let mut cut1 = DclCut::new(1);
    cut1.cars.insert(v1, car1.clone());
    cut1.cars.insert(v2, car2.clone());
    cut1.cars.insert(v3, car3.clone());

    let mut cut2 = DclCut::new(1);
    cut2.cars.insert(v3, car3);
    cut2.cars.insert(v1, car1);
    cut2.cars.insert(v2, car2);

    let bridge = ExecutionBridge::new(store);

    let result1 = bridge
        .convert_cut(&cut1, 1, alloy_primitives::B256::ZERO)
        .await
        .unwrap();
    let result2 = bridge
        .convert_cut(&cut2, 1, alloy_primitives::B256::ZERO)
        .await
        .unwrap();

    // Both results should have identical transaction order
    assert_eq!(result1.transactions, result2.transactions);

    // Order should be: v2 (0x01) < v1 (0x05) < v3 (0x0A)
    // So: batch_b (0xBB), batch_a (0xAA), batch_c (0xCC)
    assert_eq!(result1.transactions.len(), 3);
    assert_eq!(result1.transactions[0].as_ref(), &[0xBB]); // v2's tx
    assert_eq!(result1.transactions[1].as_ref(), &[0xAA]); // v1's tx
    assert_eq!(result1.transactions[2].as_ref(), &[0xCC]); // v3's tx
}
