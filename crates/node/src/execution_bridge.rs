//! Execution layer integration bridge
//!
//! This module provides the bridge between the consensus layer (data-chain)
//! and the execution layer, enabling transaction validation and Cut execution.

use cipherbft_data_chain::worker::TransactionValidator;
use cipherbft_execution::{
    ChainConfig, ExecutionLayer, ExecutionResult, Bytes, Cut as ExecutionCut, Car as ExecutionCar,
    B256, U256,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

/// Bridge between consensus and execution layers
pub struct ExecutionBridge {
    /// Execution layer instance
    execution: Arc<RwLock<ExecutionLayer>>,
}

impl ExecutionBridge {
    /// Create a new execution bridge
    ///
    /// # Arguments
    ///
    /// * `config` - Chain configuration for the execution layer
    pub fn new(config: ChainConfig) -> anyhow::Result<Self> {
        let execution = ExecutionLayer::new(config)?;

        Ok(Self {
            execution: Arc::new(RwLock::new(execution)),
        })
    }

    /// Validate a transaction for mempool CheckTx
    ///
    /// This is called by workers before accepting transactions into batches.
    ///
    /// # Arguments
    ///
    /// * `tx` - Transaction bytes to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if valid, or an error describing the validation failure.
    pub async fn check_tx(&self, tx: &[u8]) -> anyhow::Result<()> {
        let execution = self.execution.read().await;
        let tx_bytes = Bytes::copy_from_slice(tx);

        execution
            .validate_transaction(&tx_bytes)
            .map_err(|e| anyhow::anyhow!("Transaction validation failed: {}", e))
    }

    /// Execute a finalized Cut from consensus
    ///
    /// This is called when the Primary produces a CutReady event.
    ///
    /// # Arguments
    ///
    /// * `consensus_cut` - Finalized Cut with ordered transactions from consensus layer
    ///
    /// # Returns
    ///
    /// Returns execution result with state root and receipts.
    pub async fn execute_cut(
        &self,
        consensus_cut: cipherbft_data_chain::Cut,
    ) -> anyhow::Result<ExecutionResult> {
        info!(
            height = consensus_cut.height,
            cars = consensus_cut.cars.len(),
            "Executing Cut"
        );

        // Convert consensus Cut to execution Cut
        let execution_cut = self.convert_cut(consensus_cut)?;

        let mut execution = self.execution.write().await;

        execution
            .execute_cut(execution_cut)
            .map_err(|e| anyhow::anyhow!("Cut execution failed: {}", e))
    }

    /// Convert a consensus Cut to an execution Cut
    ///
    /// This converts the data-chain Cut format to the execution layer format.
    fn convert_cut(&self, consensus_cut: cipherbft_data_chain::Cut) -> anyhow::Result<ExecutionCut> {
        // Convert Cars from HashMap to sorted Vec
        let mut execution_cars = Vec::new();

        for (validator_id, car) in consensus_cut.ordered_cars() {
            // Extract transactions from batches
            let transactions = Vec::new();
            for _batch_digest in &car.batch_digests {
                // Note: In a full implementation, we would fetch the actual batch
                // from storage and extract its transactions. For now, this is a placeholder.
                // The actual batch lookup will be implemented when integrating with the worker storage.
            }

            let execution_car = ExecutionCar {
                validator_id: U256::from_be_slice(validator_id.as_bytes()),
                transactions,
            };

            execution_cars.push(execution_car);
        }

        Ok(ExecutionCut {
            block_number: consensus_cut.height,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            parent_hash: B256::ZERO, // TODO: Track parent hash properly
            cars: execution_cars,
            gas_limit: 30_000_000, // Default gas limit
            base_fee_per_gas: Some(1_000_000_000), // Default base fee
        })
    }

    /// Get a shared reference to the execution bridge for use across workers
    pub fn shared(self) -> Arc<Self> {
        Arc::new(self)
    }
}

/// Create a default execution bridge for testing/development
///
/// Uses default chain configuration.
pub fn create_default_bridge() -> anyhow::Result<ExecutionBridge> {
    let config = ChainConfig::default();
    ExecutionBridge::new(config)
}

/// Implement TransactionValidator trait for ExecutionBridge
#[async_trait::async_trait]
impl TransactionValidator for ExecutionBridge {
    async fn validate_transaction(&self, tx: &[u8]) -> Result<(), String> {
        self.check_tx(tx)
            .await
            .map_err(|e| format!("Validation failed: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_bridge() {
        let bridge = create_default_bridge();
        assert!(bridge.is_ok());
    }

    #[tokio::test]
    async fn test_check_tx_placeholder() {
        let bridge = create_default_bridge().unwrap();

        // Currently returns error since validate_transaction is not implemented
        let result = bridge.check_tx(&[0x01, 0x02, 0x03]).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_transaction_validator_trait() {
        use cipherbft_data_chain::worker::TransactionValidator;

        let bridge = create_default_bridge().unwrap();

        // Test TransactionValidator trait implementation
        let result = bridge.validate_transaction(&[0x01, 0x02, 0x03]).await;
        assert!(result.is_err());
    }
}
