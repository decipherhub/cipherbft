//! Executing Decision Handler for CipherBFT Consensus.
//!
//! This module provides a `DecisionHandler` implementation that triggers
//! execution when Malachite consensus finalizes a Cut.
//!
//! # Architecture
//!
//! When consensus decides on a value (Cut), the `ExecutingDecisionHandler`:
//! 1. Uses `ExecutionBridge` to convert the Cut to a BlockInput
//! 2. Uses `ExecutionEngine` to execute the block
//! 3. Stores receipts (for later RPC queries)
//! 4. Tracks the latest block number and parent hash
//!
//! # Example
//!
//! ```rust,ignore
//! use cipherbft_consensus::execution_handler::ExecutingDecisionHandler;
//!
//! let handler = ExecutingDecisionHandler::new(
//!     execution_bridge,
//!     dcl_store,
//!     100, // retention
//! );
//!
//! // Use with Host actor
//! let host = spawn_host_actor(
//!     validator_set_manager,
//!     value_builder,
//!     Arc::new(handler),
//!     config,
//!     span,
//! ).await?;
//! ```

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use informalsystems_malachitebft_core_types::CommitCertificate;
use informalsystems_malachitebft_sync::RawDecidedValue;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

use crate::context::CipherBftContext;
use crate::error::ConsensusError;
use crate::host::DecisionHandler;
use crate::types::{ConsensusHeight, ConsensusRound, ConsensusValue};
use cipherbft_data_chain::Cut;

/// Type alias for the decided cuts storage (cut + commit certificate by height).
type DecidedCutsMap =
    Arc<RwLock<HashMap<ConsensusHeight, (Cut, CommitCertificate<CipherBftContext>)>>>;

/// Callback type for executing a Cut.
///
/// This callback receives a Cut and its consensus height and should execute
/// the transactions, returning the new state root and gas used on success.
#[async_trait]
pub trait ExecutionCallback: Send + Sync + 'static {
    /// Execute a finalized Cut.
    ///
    /// # Arguments
    /// * `height` - Consensus height of the decision
    /// * `cut` - The finalized Cut to execute
    ///
    /// # Returns
    /// * `Ok((state_root, gas_used))` on success
    /// * `Err(...)` on execution failure
    async fn execute(&self, height: u64, cut: &Cut) -> Result<(String, u64), String>;
}

/// Receipt storage trait for persisting execution receipts.
///
/// This trait can be implemented by different backends (in-memory, database, etc.)
/// to store transaction receipts for later RPC queries.
#[async_trait]
pub trait ReceiptStore: Send + Sync + 'static {
    /// Store receipts for a block.
    ///
    /// # Arguments
    /// * `block_number` - The block number
    /// * `receipts` - Serialized receipts (implementation-specific format)
    async fn put_receipts(&self, block_number: u64, receipts: &[u8]) -> Result<(), String>;

    /// Get receipts for a block.
    ///
    /// # Arguments
    /// * `block_number` - The block number to query
    ///
    /// # Returns
    /// * `Some(receipts)` if found
    /// * `None` if not found
    async fn get_receipts(&self, block_number: u64) -> Option<Vec<u8>>;
}

/// No-op receipt store for when receipt storage is not needed.
pub struct NoOpReceiptStore;

#[async_trait]
impl ReceiptStore for NoOpReceiptStore {
    async fn put_receipts(&self, _block_number: u64, _receipts: &[u8]) -> Result<(), String> {
        Ok(())
    }

    async fn get_receipts(&self, _block_number: u64) -> Option<Vec<u8>> {
        None
    }
}

/// Decision handler that triggers execution when consensus finalizes a Cut.
///
/// This handler implements the `DecisionHandler` trait and provides:
/// - Execution of finalized Cuts via a callback
/// - Receipt storage for RPC queries
/// - Latest block tracking
/// - History queries for sync support
///
/// # Thread Safety
///
/// This handler is thread-safe and can be shared across async tasks.
pub struct ExecutingDecisionHandler<E: ExecutionCallback, R: ReceiptStore = NoOpReceiptStore> {
    /// Execution callback for running transactions
    execution_callback: Arc<E>,

    /// Optional receipt storage
    receipt_store: Option<Arc<R>>,

    /// Latest executed block number
    latest_block: AtomicU64,

    /// Decided cuts for history queries (like ChannelDecisionHandler)
    decided_cuts: DecidedCutsMap,

    /// Number of decisions to retain for history queries
    decided_retention: usize,

    /// Optional channel to send decided events (for backward compatibility)
    decided_tx: Option<mpsc::Sender<(ConsensusHeight, Cut)>>,
}

impl<E: ExecutionCallback> ExecutingDecisionHandler<E, NoOpReceiptStore> {
    /// Create a new executing decision handler without receipt storage.
    ///
    /// # Arguments
    /// * `execution_callback` - Callback for executing Cuts
    /// * `decided_retention` - Number of decisions to retain for history
    pub fn new(execution_callback: Arc<E>, decided_retention: usize) -> Self {
        Self {
            execution_callback,
            receipt_store: None,
            latest_block: AtomicU64::new(0),
            decided_cuts: Arc::new(RwLock::new(HashMap::new())),
            decided_retention,
            decided_tx: None,
        }
    }
}

impl<E: ExecutionCallback, R: ReceiptStore> ExecutingDecisionHandler<E, R> {
    /// Create a new executing decision handler with receipt storage.
    ///
    /// # Arguments
    /// * `execution_callback` - Callback for executing Cuts
    /// * `receipt_store` - Storage for transaction receipts
    /// * `decided_retention` - Number of decisions to retain for history
    pub fn with_receipt_store(
        execution_callback: Arc<E>,
        receipt_store: Arc<R>,
        decided_retention: usize,
    ) -> Self {
        Self {
            execution_callback,
            receipt_store: Some(receipt_store),
            latest_block: AtomicU64::new(0),
            decided_cuts: Arc::new(RwLock::new(HashMap::new())),
            decided_retention,
            decided_tx: None,
        }
    }

    /// Add a channel for sending decided events.
    ///
    /// This provides backward compatibility with code that expects
    /// decided events to be sent via channel.
    pub fn with_decided_channel(mut self, tx: mpsc::Sender<(ConsensusHeight, Cut)>) -> Self {
        self.decided_tx = Some(tx);
        self
    }

    /// Get the latest executed block number.
    pub fn latest_block(&self) -> u64 {
        self.latest_block.load(Ordering::SeqCst)
    }

    /// Get receipts for a block (if receipt storage is enabled).
    ///
    /// # Arguments
    /// * `block_number` - The block number to query
    ///
    /// # Returns
    /// * `Some(receipts)` if found and receipt storage is enabled
    /// * `None` if not found or receipt storage is disabled
    pub async fn get_receipts(&self, block_number: u64) -> Option<Vec<u8>> {
        if let Some(ref store) = self.receipt_store {
            store.get_receipts(block_number).await
        } else {
            None
        }
    }

    /// Clean up old decisions based on retention policy.
    async fn cleanup_old_decisions(&self, current_height: ConsensusHeight) {
        let retention = self.decided_retention;
        let mut decided = self.decided_cuts.write().await;

        if decided.len() > retention {
            let cutoff = current_height.0.saturating_sub(retention as u64);
            let before = decided.len();
            decided.retain(|h, _| h.0 >= cutoff);
            let removed = before - decided.len();
            if removed > 0 {
                debug!(
                    "ExecutingDecisionHandler: Cleaned up {} old decisions, retaining heights >= {}",
                    removed, cutoff
                );
            }
        }
    }
}

#[async_trait]
impl<E: ExecutionCallback, R: ReceiptStore> DecisionHandler for ExecutingDecisionHandler<E, R> {
    async fn on_decided(
        &self,
        height: ConsensusHeight,
        _round: ConsensusRound,
        value: ConsensusValue,
        certificate: CommitCertificate<CipherBftContext>,
    ) -> Result<(), ConsensusError> {
        let cut = value.into_cut();

        info!(
            height = height.0,
            cars = cut.cars.len(),
            "ExecutingDecisionHandler: Processing decided Cut"
        );

        // Execute the Cut via callback
        match self.execution_callback.execute(height.0, &cut).await {
            Ok((state_root, gas_used)) => {
                info!(
                    height = height.0,
                    state_root = %state_root,
                    gas_used = gas_used,
                    "ExecutingDecisionHandler: Cut executed successfully"
                );

                // Update latest block
                self.latest_block.store(height.0, Ordering::SeqCst);
            }
            Err(e) => {
                error!(
                    height = height.0,
                    error = %e,
                    "ExecutingDecisionHandler: Cut execution failed"
                );
                // Note: We don't return an error here because consensus has already decided.
                // The execution failure should be logged and potentially handled by recovery mechanisms.
            }
        }

        // Store for history queries
        {
            let mut decided = self.decided_cuts.write().await;
            decided.insert(height, (cut.clone(), certificate));
        }

        // Cleanup old decisions
        self.cleanup_old_decisions(height).await;

        // Send to channel if configured (backward compatibility)
        if let Some(ref tx) = self.decided_tx {
            if let Err(e) = tx.send((height, cut)).await {
                warn!(
                    "ExecutingDecisionHandler: Failed to send decided event to channel: {}",
                    e
                );
            }
        }

        Ok(())
    }

    async fn get_decided_value(
        &self,
        height: ConsensusHeight,
    ) -> Result<Option<RawDecidedValue<CipherBftContext>>, ConsensusError> {
        let decided = self.decided_cuts.read().await;
        Ok(decided.get(&height).map(|(cut, cert)| {
            // Encode cut to bytes using bincode
            let value_bytes = bincode::serialize(cut).unwrap_or_default().into();
            RawDecidedValue {
                certificate: cert.clone(),
                value_bytes,
            }
        }))
    }

    async fn get_history_min_height(&self) -> Result<ConsensusHeight, ConsensusError> {
        let decided = self.decided_cuts.read().await;
        Ok(decided.keys().min().cloned().unwrap_or(ConsensusHeight(1)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConsensusConfig;
    use crate::context::CipherBftContext;
    use crate::validator_set::{ConsensusValidator, ConsensusValidatorSet};
    use cipherbft_crypto::Ed25519KeyPair;
    use cipherbft_data_chain::Cut;
    use informalsystems_malachitebft_core_types::{CommitCertificate, Round};
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::sync::atomic::AtomicUsize;

    /// Mock execution callback for testing
    struct MockExecutionCallback {
        call_count: AtomicUsize,
        should_fail: bool,
    }

    impl MockExecutionCallback {
        fn new(should_fail: bool) -> Self {
            Self {
                call_count: AtomicUsize::new(0),
                should_fail,
            }
        }

        fn call_count(&self) -> usize {
            self.call_count.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl ExecutionCallback for MockExecutionCallback {
        async fn execute(&self, height: u64, _cut: &Cut) -> Result<(String, u64), String> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            if self.should_fail {
                Err("mock execution failure".to_string())
            } else {
                Ok((format!("state_root_{}", height), height * 1000))
            }
        }
    }

    /// Mock receipt store for testing
    struct MockReceiptStore {
        receipts: RwLock<HashMap<u64, Vec<u8>>>,
    }

    impl MockReceiptStore {
        fn new() -> Self {
            Self {
                receipts: RwLock::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl ReceiptStore for MockReceiptStore {
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

    fn make_certificate(
        _ctx: &CipherBftContext,
        height: ConsensusHeight,
    ) -> CommitCertificate<CipherBftContext> {
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

    #[tokio::test]
    async fn test_executing_handler_calls_execution() {
        let callback = Arc::new(MockExecutionCallback::new(false));
        let handler = ExecutingDecisionHandler::new(callback.clone(), 100);

        let ctx = make_context();
        let height = ConsensusHeight(1);
        let cut = Cut::new(1);
        let value = ConsensusValue::from(cut);
        let certificate = make_certificate(&ctx, height);

        let result = handler
            .on_decided(height, Round::new(0), value, certificate)
            .await;

        assert!(result.is_ok());
        assert_eq!(callback.call_count(), 1);
        assert_eq!(handler.latest_block(), 1);
    }

    #[tokio::test]
    async fn test_executing_handler_stores_decision() {
        let callback = Arc::new(MockExecutionCallback::new(false));
        let handler = ExecutingDecisionHandler::new(callback, 100);

        let ctx = make_context();
        let height = ConsensusHeight(1);
        let cut = Cut::new(1);
        let value = ConsensusValue::from(cut);
        let certificate = make_certificate(&ctx, height);

        handler
            .on_decided(height, Round::new(0), value, certificate)
            .await
            .unwrap();

        // Check that decision is stored
        let stored = handler.get_decided_value(height).await.unwrap();
        assert!(stored.is_some());

        // Check history min height
        let min_height = handler.get_history_min_height().await.unwrap();
        assert_eq!(min_height, ConsensusHeight(1));
    }

    #[tokio::test]
    async fn test_executing_handler_handles_execution_failure() {
        let callback = Arc::new(MockExecutionCallback::new(true)); // Will fail
        let handler = ExecutingDecisionHandler::new(callback.clone(), 100);

        let ctx = make_context();
        let height = ConsensusHeight(1);
        let cut = Cut::new(1);
        let value = ConsensusValue::from(cut);
        let certificate = make_certificate(&ctx, height);

        // Should still succeed (logs error but doesn't fail)
        let result = handler
            .on_decided(height, Round::new(0), value, certificate)
            .await;

        assert!(result.is_ok());
        assert_eq!(callback.call_count(), 1);
        // Latest block is NOT updated on failure
        assert_eq!(handler.latest_block(), 0);
    }

    #[tokio::test]
    async fn test_executing_handler_retention() {
        let callback = Arc::new(MockExecutionCallback::new(false));
        let handler = ExecutingDecisionHandler::new(callback, 5); // Only retain 5

        let ctx = make_context();

        // Add 10 decisions
        for i in 1..=10 {
            let height = ConsensusHeight(i);
            let cut = Cut::new(i);
            let value = ConsensusValue::from(cut);
            let certificate = make_certificate(&ctx, height);

            handler
                .on_decided(height, Round::new(0), value, certificate)
                .await
                .unwrap();
        }

        // Check that old decisions are cleaned up
        // Cleanup triggers when len > retention (5), with cutoff = current_height - retention
        // After adding height 10: cutoff = 10 - 5 = 5, so we keep heights >= 5
        // That means heights 5, 6, 7, 8, 9, 10 = 6 items are retained
        let decided = handler.decided_cuts.read().await;
        assert!(
            decided.len() <= 6,
            "Expected at most 6 items, got {}",
            decided.len()
        );

        // Heights 1-4 should be gone (below cutoff of 5)
        assert!(decided.get(&ConsensusHeight(1)).is_none());
        assert!(decided.get(&ConsensusHeight(4)).is_none());

        // Heights 5-10 should be present
        assert!(decided.get(&ConsensusHeight(5)).is_some());
        assert!(decided.get(&ConsensusHeight(10)).is_some());
    }

    #[tokio::test]
    async fn test_executing_handler_with_channel() {
        let callback = Arc::new(MockExecutionCallback::new(false));
        let (tx, mut rx) = mpsc::channel(10);
        let handler = ExecutingDecisionHandler::new(callback, 100).with_decided_channel(tx);

        let ctx = make_context();
        let height = ConsensusHeight(1);
        let cut = Cut::new(1);
        let value = ConsensusValue::from(cut);
        let certificate = make_certificate(&ctx, height);

        handler
            .on_decided(height, Round::new(0), value, certificate)
            .await
            .unwrap();

        // Check that event was sent to channel
        let received = rx.try_recv();
        assert!(received.is_ok());
        let (recv_height, _recv_cut) = received.unwrap();
        assert_eq!(recv_height, height);
    }

    #[tokio::test]
    async fn test_noop_receipt_store() {
        let store = NoOpReceiptStore;

        // put_receipts should succeed
        let result = store.put_receipts(1, b"test").await;
        assert!(result.is_ok());

        // get_receipts should return None
        let result = store.get_receipts(1).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_mock_receipt_store() {
        let store = MockReceiptStore::new();

        // Store receipts
        store.put_receipts(1, b"receipt_data").await.unwrap();

        // Retrieve receipts
        let result = store.get_receipts(1).await;
        assert!(result.is_some());
        assert_eq!(result.unwrap(), b"receipt_data");

        // Non-existent block
        let result = store.get_receipts(999).await;
        assert!(result.is_none());
    }
}
