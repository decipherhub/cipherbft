//! Execution bridge for converting finalized Cuts to executable blocks.
//!
//! The ExecutionBridge converts DCL Cuts (containing batch digest references) into
//! executable BlockInputs by fetching actual batch data from storage.
//!
//! # Architecture
//!
//! The bridge sits between the consensus layer (DCL) and the execution layer:
//! 1. DCL finalizes a Cut containing Cars with batch digests (references)
//! 2. ExecutionBridge fetches actual Batch data from storage
//! 3. Bridge flattens all transactions into ordered `Vec<Bytes>`
//! 4. Execution layer receives a BlockInput for deterministic execution
//!
//! # Determinism
//!
//! The bridge guarantees deterministic transaction ordering:
//! - Cars are iterated in ValidatorId ascending order (via `Cut::ordered_cars()`)
//! - Within each Car, batch digests are processed in order
//! - Within each Batch, transactions are processed in order
//!
//! This ensures all validators produce identical BlockInputs from the same Cut.

use crate::error::ExecutionError;
use crate::types::BlockInput;
use crate::Result;
use alloy_primitives::{Address, Bytes, B256};
use async_trait::async_trait;
use cipherbft_data_chain::{Batch, Cut as DclCut};
use cipherbft_types::Hash;
use std::sync::Arc;

/// Trait for fetching batches by digest hash.
///
/// This trait abstracts batch storage access for the ExecutionBridge.
/// It can be implemented by any storage backend that stores transaction batches.
#[async_trait]
pub trait BatchFetcher: Send + Sync {
    /// Fetch a batch by its digest hash.
    ///
    /// # Arguments
    /// * `digest` - SHA-256 hash of the batch contents
    ///
    /// # Returns
    /// * `Ok(Some(batch))` if found
    /// * `Ok(None)` if batch not found
    /// * `Err(...)` on storage error
    async fn get_batch(&self, digest: &Hash) -> Result<Option<Batch>>;
}

/// Bridge between consensus (DCL Cut) and execution (BlockInput).
///
/// The ExecutionBridge is responsible for:
/// - Fetching batch data referenced by finalized Cuts
/// - Ordering transactions deterministically
/// - Constructing BlockInputs for the execution layer
///
/// # Type Parameters
///
/// * `S` - Storage backend implementing `BatchFetcher`
///
/// # Example
///
/// ```ignore
/// use cipherbft_execution::bridge::{ExecutionBridge, BatchFetcher};
/// use std::sync::Arc;
///
/// let store: Arc<dyn BatchFetcher> = /* ... */;
/// let bridge = ExecutionBridge::new(store);
///
/// // Convert a finalized Cut to BlockInput
/// let block_input = bridge.convert_cut(&cut, 42, parent_hash).await?;
/// ```
pub struct ExecutionBridge<S: BatchFetcher> {
    batch_fetcher: Arc<S>,
}

impl<S: BatchFetcher> ExecutionBridge<S> {
    /// Create a new execution bridge.
    ///
    /// # Arguments
    /// * `batch_fetcher` - Storage backend for fetching batches
    pub fn new(batch_fetcher: Arc<S>) -> Self {
        Self { batch_fetcher }
    }

    /// Convert a finalized DCL Cut to an executable BlockInput.
    ///
    /// Fetches all batch data referenced by the Cut and orders transactions
    /// deterministically by validator ID, then by batch order within each Car.
    ///
    /// # Arguments
    /// * `cut` - The finalized DCL Cut from consensus
    /// * `block_number` - The block number for this execution
    /// * `parent_hash` - The parent block hash (B256::ZERO for genesis)
    ///
    /// # Returns
    /// * `Ok(BlockInput)` containing all transactions in deterministic order
    /// * `Err(ExecutionError::Internal)` if a referenced batch is not found
    ///
    /// # Determinism
    ///
    /// The transaction order is guaranteed to be deterministic:
    /// 1. Cars are processed in ValidatorId ascending order
    /// 2. Batch digests within each Car are processed in order
    /// 3. Transactions within each Batch are processed in order
    pub async fn convert_cut(
        &self,
        cut: &DclCut,
        block_number: u64,
        parent_hash: B256,
    ) -> Result<BlockInput> {
        let mut all_transactions = Vec::new();

        // Iterate Cars in deterministic order (by ValidatorId ascending)
        for (_, car) in cut.ordered_cars() {
            for batch_digest in &car.batch_digests {
                // Fetch batch from storage
                let batch = self
                    .batch_fetcher
                    .get_batch(&batch_digest.digest)
                    .await?
                    .ok_or_else(|| {
                        ExecutionError::Internal(format!(
                            "Batch {} not found in storage",
                            hex::encode(batch_digest.digest.as_bytes())
                        ))
                    })?;

                // Add transactions (convert Vec<u8> to Bytes)
                for tx in batch.transactions {
                    all_transactions.push(Bytes::from(tx));
                }
            }
        }

        Ok(BlockInput {
            block_number,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            transactions: all_transactions,
            parent_hash,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(1_000_000_000),
            beneficiary: cut.proposer_address.unwrap_or(Address::ZERO),
        })
    }

    /// Convert a finalized DCL Cut to an executable BlockInput with custom parameters.
    ///
    /// This is a more flexible version of `convert_cut` that allows specifying
    /// additional block parameters.
    ///
    /// # Arguments
    /// * `cut` - The finalized DCL Cut from consensus
    /// * `block_number` - The block number for this execution
    /// * `timestamp` - Block timestamp (Unix timestamp in seconds)
    /// * `parent_hash` - The parent block hash
    /// * `gas_limit` - Block gas limit
    /// * `base_fee_per_gas` - Base fee per gas (EIP-1559)
    pub async fn convert_cut_with_params(
        &self,
        cut: &DclCut,
        block_number: u64,
        timestamp: u64,
        parent_hash: B256,
        gas_limit: u64,
        base_fee_per_gas: Option<u64>,
    ) -> Result<BlockInput> {
        let mut all_transactions = Vec::new();

        // Iterate Cars in deterministic order (by ValidatorId ascending)
        for (_, car) in cut.ordered_cars() {
            for batch_digest in &car.batch_digests {
                // Fetch batch from storage
                let batch = self
                    .batch_fetcher
                    .get_batch(&batch_digest.digest)
                    .await?
                    .ok_or_else(|| {
                        ExecutionError::Internal(format!(
                            "Batch {} not found in storage",
                            hex::encode(batch_digest.digest.as_bytes())
                        ))
                    })?;

                // Add transactions (convert Vec<u8> to Bytes)
                for tx in batch.transactions {
                    all_transactions.push(Bytes::from(tx));
                }
            }
        }

        Ok(BlockInput {
            block_number,
            timestamp,
            transactions: all_transactions,
            parent_hash,
            gas_limit,
            base_fee_per_gas,
            beneficiary: cut.proposer_address.unwrap_or(Address::ZERO),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbft_data_chain::{Batch, BatchDigest, Car, Cut as DclCut};
    use cipherbft_types::{Hash, ValidatorId, VALIDATOR_ID_SIZE};
    use parking_lot::RwLock;
    use std::collections::HashMap;

    /// In-memory batch store for testing
    struct MockBatchFetcher {
        batches: RwLock<HashMap<Hash, Batch>>,
    }

    impl MockBatchFetcher {
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
    impl BatchFetcher for MockBatchFetcher {
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
    async fn test_bridge_converts_empty_cut() {
        let store = Arc::new(MockBatchFetcher::new());
        let bridge = ExecutionBridge::new(store);

        let cut = DclCut::new(1);
        let result = bridge.convert_cut(&cut, 1, B256::ZERO).await.unwrap();

        assert_eq!(result.block_number, 1);
        assert!(result.transactions.is_empty());
        assert_eq!(result.parent_hash, B256::ZERO);
    }

    #[tokio::test]
    async fn test_bridge_converts_cut_with_single_car() {
        let store = Arc::new(MockBatchFetcher::new());

        // Create a batch with 2 transactions
        let batch = make_batch(0, vec![vec![1, 2, 3], vec![4, 5, 6]]);
        let batch_digest = batch.digest();
        store.insert(batch);

        // Create a Car with the batch digest
        let validator_id = make_validator_id(1);
        let car = Car::new(validator_id, 0, vec![batch_digest], None);

        // Create a Cut with the Car
        let mut cut = DclCut::new(1);
        cut.cars.insert(validator_id, car);

        let bridge = ExecutionBridge::new(store);
        let result = bridge.convert_cut(&cut, 42, B256::ZERO).await.unwrap();

        assert_eq!(result.block_number, 42);
        assert_eq!(result.transactions.len(), 2);
        assert_eq!(result.transactions[0].as_ref(), &[1, 2, 3]);
        assert_eq!(result.transactions[1].as_ref(), &[4, 5, 6]);
    }

    #[tokio::test]
    async fn test_bridge_converts_cut_with_multiple_cars() {
        let store = Arc::new(MockBatchFetcher::new());

        // Create batches for two validators
        let batch1 = make_batch(0, vec![vec![1, 1, 1]]);
        let batch2 = make_batch(0, vec![vec![2, 2, 2]]);
        let digest1 = batch1.digest();
        let digest2 = batch2.digest();
        store.insert(batch1);
        store.insert(batch2);

        // Create Cars for two validators
        // Validator 2 has lower ID, should come first
        let validator1 = make_validator_id(10);
        let validator2 = make_validator_id(5);

        let car1 = Car::new(validator1, 0, vec![digest1], None);
        let car2 = Car::new(validator2, 0, vec![digest2], None);

        // Create Cut with both Cars
        let mut cut = DclCut::new(1);
        cut.cars.insert(validator1, car1);
        cut.cars.insert(validator2, car2);

        let bridge = ExecutionBridge::new(store);
        let result = bridge.convert_cut(&cut, 1, B256::ZERO).await.unwrap();

        // Transactions should be ordered by ValidatorId
        // validator2 (5) comes before validator1 (10)
        assert_eq!(result.transactions.len(), 2);
        assert_eq!(result.transactions[0].as_ref(), &[2, 2, 2]); // validator2's tx
        assert_eq!(result.transactions[1].as_ref(), &[1, 1, 1]); // validator1's tx
    }

    #[tokio::test]
    async fn test_bridge_converts_cut_with_multiple_batches_per_car() {
        let store = Arc::new(MockBatchFetcher::new());

        // Create two batches
        let batch1 = make_batch(0, vec![vec![1]]);
        let batch2 = make_batch(1, vec![vec![2]]);
        let digest1 = batch1.digest();
        let digest2 = batch2.digest();
        store.insert(batch1);
        store.insert(batch2);

        // Create a Car with both batch digests
        let validator_id = make_validator_id(1);
        let car = Car::new(validator_id, 0, vec![digest1, digest2], None);

        let mut cut = DclCut::new(1);
        cut.cars.insert(validator_id, car);

        let bridge = ExecutionBridge::new(store);
        let result = bridge.convert_cut(&cut, 1, B256::ZERO).await.unwrap();

        // Transactions should be in batch order
        assert_eq!(result.transactions.len(), 2);
        assert_eq!(result.transactions[0].as_ref(), &[1]);
        assert_eq!(result.transactions[1].as_ref(), &[2]);
    }

    #[tokio::test]
    async fn test_bridge_fails_on_missing_batch() {
        let store = Arc::new(MockBatchFetcher::new());

        // Create a batch digest without storing the batch
        let missing_digest = BatchDigest::new(0, Hash::compute(b"missing"), 1, 100);

        let validator_id = make_validator_id(1);
        let car = Car::new(validator_id, 0, vec![missing_digest], None);

        let mut cut = DclCut::new(1);
        cut.cars.insert(validator_id, car);

        let bridge = ExecutionBridge::new(store);
        let result = bridge.convert_cut(&cut, 1, B256::ZERO).await;

        assert!(result.is_err());
        match result {
            Err(ExecutionError::Internal(msg)) => {
                assert!(msg.contains("not found in storage"));
            }
            _ => panic!("Expected Internal error"),
        }
    }

    #[tokio::test]
    async fn test_bridge_preserves_block_parameters() {
        let store = Arc::new(MockBatchFetcher::new());
        let bridge = ExecutionBridge::new(store);

        let cut = DclCut::new(1);
        let parent_hash = B256::from([0xab; 32]);

        let result = bridge
            .convert_cut_with_params(
                &cut,
                100,
                1234567890,
                parent_hash,
                15_000_000,
                Some(2_000_000_000),
            )
            .await
            .unwrap();

        assert_eq!(result.block_number, 100);
        assert_eq!(result.timestamp, 1234567890);
        assert_eq!(result.parent_hash, parent_hash);
        assert_eq!(result.gas_limit, 15_000_000);
        assert_eq!(result.base_fee_per_gas, Some(2_000_000_000));
    }

    #[tokio::test]
    async fn test_bridge_determinism() {
        let store = Arc::new(MockBatchFetcher::new());

        // Create batches
        let batch1 = make_batch(0, vec![vec![1]]);
        let batch2 = make_batch(0, vec![vec![2]]);
        let digest1 = batch1.digest();
        let digest2 = batch2.digest();
        store.insert(batch1);
        store.insert(batch2);

        // Create Cars
        let v1 = make_validator_id(1);
        let v2 = make_validator_id(2);
        let car1 = Car::new(v1, 0, vec![digest1], None);
        let car2 = Car::new(v2, 0, vec![digest2], None);

        // Create Cut - insert in different order each time
        let mut cut1 = DclCut::new(1);
        cut1.cars.insert(v1, car1.clone());
        cut1.cars.insert(v2, car2.clone());

        let mut cut2 = DclCut::new(1);
        cut2.cars.insert(v2, car2);
        cut2.cars.insert(v1, car1);

        let bridge = ExecutionBridge::new(store);

        // Both should produce identical results
        let result1 = bridge
            .convert_cut_with_params(&cut1, 1, 0, B256::ZERO, 30_000_000, None)
            .await
            .unwrap();
        let result2 = bridge
            .convert_cut_with_params(&cut2, 1, 0, B256::ZERO, 30_000_000, None)
            .await
            .unwrap();

        assert_eq!(result1.transactions, result2.transactions);
    }
}
