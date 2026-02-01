//! Block execution integration for sync
//!
//! Provides the bridge between downloaded blocks and the execution engine.

#![allow(dead_code)] // Will be used by node integration

use crate::error::{Result, SyncError};
use alloy_primitives::{Address, Bytes, B256};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Block data ready for execution
///
/// This is the format blocks are stored in for sync purposes,
/// containing all data needed to replay the block.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncBlock {
    /// Block height
    pub block_number: u64,
    /// Block timestamp (unix seconds)
    pub timestamp: u64,
    /// Parent block hash
    pub parent_hash: B256,
    /// Transactions (RLP-encoded)
    pub transactions: Vec<Bytes>,
    /// Block gas limit
    pub gas_limit: u64,
    /// Base fee per gas (EIP-1559)
    pub base_fee_per_gas: Option<u64>,
    /// Block beneficiary (proposer address for rewards)
    pub beneficiary: Address,
}

impl SyncBlock {
    /// Create a new sync block
    pub fn new(
        block_number: u64,
        timestamp: u64,
        parent_hash: B256,
        transactions: Vec<Bytes>,
        gas_limit: u64,
        base_fee_per_gas: Option<u64>,
        beneficiary: Address,
    ) -> Self {
        Self {
            block_number,
            timestamp,
            parent_hash,
            transactions,
            gas_limit,
            base_fee_per_gas,
            beneficiary,
        }
    }

    /// Serialize to bytes for network transfer
    pub fn to_bytes(&self) -> Result<Bytes> {
        bincode::serialize(self)
            .map(Bytes::from)
            .map_err(|e| SyncError::Storage(format!("serialization error: {}", e)))
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data)
            .map_err(|e| SyncError::Storage(format!("deserialization error: {}", e)))
    }
}

/// Result of executing a sync block
#[derive(Clone, Debug)]
pub struct SyncExecutionResult {
    /// Block number that was executed
    pub block_number: u64,
    /// State root after execution (may be None if not at checkpoint)
    pub state_root: Option<B256>,
    /// Block hash after execution
    pub block_hash: B256,
    /// Gas used in this block
    pub gas_used: u64,
    /// Number of transactions executed
    pub transaction_count: usize,
}

/// Trait for executing blocks during sync
///
/// Implemented by the node to provide execution capability to the sync manager.
#[async_trait]
pub trait SyncExecutor: Send + Sync {
    /// Execute a block and return the result
    ///
    /// The executor should:
    /// 1. Validate the block can be executed (parent hash matches)
    /// 2. Execute all transactions
    /// 3. Return state root if at checkpoint interval
    /// 4. Store the block and receipts
    async fn execute_block(&self, block: SyncBlock) -> Result<SyncExecutionResult>;

    /// Get the last executed block hash
    async fn last_block_hash(&self) -> B256;

    /// Get the last executed block number
    async fn last_block_number(&self) -> u64;

    /// Verify the state root at a checkpoint height
    async fn verify_state_root(&self, height: u64, expected: B256) -> Result<bool>;
}

/// A no-op executor for testing
#[derive(Clone, Debug, Default)]
pub struct MockSyncExecutor {
    last_hash: B256,
    last_number: u64,
}

impl MockSyncExecutor {
    /// Create a new mock executor
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with initial state
    pub fn with_state(last_number: u64, last_hash: B256) -> Self {
        Self {
            last_hash,
            last_number,
        }
    }
}

#[async_trait]
impl SyncExecutor for MockSyncExecutor {
    async fn execute_block(&self, block: SyncBlock) -> Result<SyncExecutionResult> {
        // Mock execution - just return success
        Ok(SyncExecutionResult {
            block_number: block.block_number,
            state_root: if block.block_number.is_multiple_of(100) {
                Some(B256::repeat_byte(0xab))
            } else {
                None
            },
            block_hash: B256::repeat_byte(0xcd),
            gas_used: 21000 * block.transactions.len() as u64,
            transaction_count: block.transactions.len(),
        })
    }

    async fn last_block_hash(&self) -> B256 {
        self.last_hash
    }

    async fn last_block_number(&self) -> u64 {
        self.last_number
    }

    async fn verify_state_root(&self, _height: u64, _expected: B256) -> Result<bool> {
        Ok(true)
    }
}

/// State root checkpoint interval (matches execution layer)
pub const STATE_ROOT_CHECKPOINT_INTERVAL: u64 = 100;

/// Check if a block height is a state root checkpoint
pub fn is_state_root_checkpoint(height: u64) -> bool {
    height > 0 && height.is_multiple_of(STATE_ROOT_CHECKPOINT_INTERVAL)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_block_serialization() {
        let block = SyncBlock::new(
            100,
            1234567890,
            B256::repeat_byte(0x01),
            vec![Bytes::from(vec![0x02, 0x03])],
            30_000_000,
            Some(1_000_000_000),
            Address::repeat_byte(0x04),
        );

        let bytes = block.to_bytes().unwrap();
        let decoded = SyncBlock::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.block_number, 100);
        assert_eq!(decoded.timestamp, 1234567890);
        assert_eq!(decoded.transactions.len(), 1);
    }

    #[test]
    fn test_checkpoint_detection() {
        assert!(!is_state_root_checkpoint(0));
        assert!(!is_state_root_checkpoint(50));
        assert!(is_state_root_checkpoint(100));
        assert!(!is_state_root_checkpoint(150));
        assert!(is_state_root_checkpoint(200));
    }

    #[tokio::test]
    async fn test_mock_executor() {
        let executor = MockSyncExecutor::new();

        let block = SyncBlock::new(
            100,
            0,
            B256::ZERO,
            vec![Bytes::from(vec![0x01])],
            30_000_000,
            None,
            Address::ZERO,
        );

        let result = executor.execute_block(block).await.unwrap();

        assert_eq!(result.block_number, 100);
        assert!(result.state_root.is_some()); // 100 is a checkpoint
        assert_eq!(result.transaction_count, 1);
    }
}
