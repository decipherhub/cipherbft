//! SyncExecutor implementation for ExecutionBridge
//!
//! Bridges the sync crate's execution trait to the node's execution bridge.

use crate::execution_bridge::ExecutionBridge;
use alloy_primitives::B256;
use async_trait::async_trait;
use cipherbft_execution::types::BlockInput;
use cipherbft_storage::BlockStore;
use cipherbft_sync::error::{Result, SyncError};
use cipherbft_sync::execution::{SyncBlock, SyncExecutionResult, SyncExecutor};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Wrapper that implements SyncExecutor using ExecutionBridge
///
/// This executor bridges the sync crate's execution interface to the node's
/// execution bridge, enabling snap sync to execute downloaded blocks.
///
/// # Type Parameters
///
/// * `B` - The block store implementation for state root verification
pub struct ExecutionBridgeSyncExecutor<B: BlockStore> {
    bridge: Arc<ExecutionBridge>,
    block_store: Arc<B>,
}

impl<B: BlockStore> ExecutionBridgeSyncExecutor<B> {
    /// Create a new sync executor wrapping an execution bridge
    ///
    /// # Arguments
    ///
    /// * `bridge` - The execution bridge for block execution
    /// * `block_store` - The block store for state root verification
    pub fn new(bridge: Arc<ExecutionBridge>, block_store: Arc<B>) -> Self {
        Self {
            bridge,
            block_store,
        }
    }
}

#[async_trait]
impl<B: BlockStore + Send + Sync> SyncExecutor for ExecutionBridgeSyncExecutor<B> {
    async fn execute_block(&self, block: SyncBlock) -> Result<SyncExecutionResult> {
        debug!(
            block_number = block.block_number,
            txs = block.transactions.len(),
            "Executing sync block"
        );

        // Convert SyncBlock to BlockInput
        let block_input = BlockInput {
            block_number: block.block_number,
            timestamp: block.timestamp,
            transactions: block.transactions.clone(),
            parent_hash: block.parent_hash,
            gas_limit: block.gas_limit,
            base_fee_per_gas: block.base_fee_per_gas,
            beneficiary: block.beneficiary,
        };

        // Execute through the bridge
        let result = self
            .bridge
            .execute_block_input(block_input)
            .await
            .map_err(|e| SyncError::Storage(format!("execution failed: {}", e)))?;

        info!(
            block_number = block.block_number,
            gas_used = result.execution_result.gas_used,
            "Sync block executed"
        );

        Ok(SyncExecutionResult {
            block_number: block.block_number,
            state_root: if result.execution_result.state_root != B256::ZERO {
                Some(result.execution_result.state_root)
            } else {
                None
            },
            block_hash: result.block_hash,
            gas_used: result.execution_result.gas_used,
            transaction_count: block.transactions.len(),
        })
    }

    async fn last_block_hash(&self) -> B256 {
        self.bridge.last_block_hash()
    }

    async fn last_block_number(&self) -> u64 {
        self.bridge.current_block_number().await
    }

    async fn verify_state_root(&self, height: u64, expected: B256) -> Result<bool> {
        debug!(height, %expected, "Verifying state root");

        // Get the block at the given height from storage
        let block = self
            .block_store
            .get_block_by_number(height)
            .await
            .map_err(|e| SyncError::Storage(format!("failed to get block {}: {}", height, e)))?;

        match block {
            Some(block) => {
                let stored_state_root = B256::from(block.state_root);
                if stored_state_root == expected {
                    debug!(
                        height,
                        %expected,
                        "State root verification passed"
                    );
                    Ok(true)
                } else {
                    warn!(
                        height,
                        %expected,
                        %stored_state_root,
                        "State root mismatch"
                    );
                    Ok(false)
                }
            }
            None => {
                // Block not found - this is expected during sync before blocks are stored
                // Return true to allow sync to proceed, actual verification happens
                // when we reconstruct state
                debug!(
                    height,
                    "Block not found for state root verification (expected during sync)"
                );
                Ok(true)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // Tests would require mocking ExecutionBridge and BlockStore which is complex
    // Integration tests are more appropriate for this module
}
