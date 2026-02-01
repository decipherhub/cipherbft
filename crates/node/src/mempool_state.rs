//! State provider for mempool transaction validation.
//!
//! This module provides the bridge between the mempool's transaction validation
//! and the execution layer's state. It implements the `ExecutionLayerValidator`
//! trait to enable mempool validation against the current execution state.

use cipherbft_execution::{Bytes, ExecutionLayer, InMemoryProvider, Provider};
use cipherbft_mempool::ExecutionLayerValidator;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Validates transactions against execution layer state.
///
/// This validator wraps the execution layer and provides async validation
/// for transactions entering the mempool. It ensures transactions are
/// validated against the current state (balance, nonce, gas limits) before
/// being accepted into the pool.
#[derive(Debug)]
pub struct ExecutionStateValidator<P: Provider + Clone + std::fmt::Debug = InMemoryProvider> {
    execution: Arc<RwLock<ExecutionLayer<P>>>,
}

impl<P: Provider + Clone + std::fmt::Debug> ExecutionStateValidator<P> {
    /// Create a new execution state validator.
    ///
    /// # Arguments
    ///
    /// * `execution` - Shared reference to the execution layer
    ///
    /// # Returns
    ///
    /// A new `ExecutionStateValidator` that can validate transactions
    /// against the execution layer's current state.
    pub fn new(execution: Arc<RwLock<ExecutionLayer<P>>>) -> Self {
        Self { execution }
    }
}

#[async_trait::async_trait]
impl<P: Provider + Clone + Send + Sync + std::fmt::Debug + 'static> ExecutionLayerValidator
    for ExecutionStateValidator<P>
{
    async fn validate_transaction(&self, tx_bytes: &[u8]) -> Result<(), String> {
        let execution = self.execution.read().await;
        execution
            .validate_transaction(&Bytes::from(tx_bytes.to_vec()))
            .map_err(|e| format!("Execution validation failed: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbft_execution::ChainConfig;

    #[tokio::test]
    async fn test_execution_state_validator_creation() {
        let config = ChainConfig::default();
        let execution = ExecutionLayer::new(config).expect("create execution layer");
        let execution = Arc::new(RwLock::new(execution));
        let validator = ExecutionStateValidator::new(execution);

        // Verify the validator was created (Debug trait works)
        let debug_str = format!("{:?}", validator);
        assert!(debug_str.contains("ExecutionStateValidator"));
    }

    #[tokio::test]
    async fn test_validate_invalid_transaction() {
        let config = ChainConfig::default();
        let execution = ExecutionLayer::new(config).expect("create execution layer");
        let execution = Arc::new(RwLock::new(execution));
        let validator = ExecutionStateValidator::new(execution);

        // Empty bytes should fail validation
        let result = validator.validate_transaction(&[]).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Execution validation failed"));
    }

    #[tokio::test]
    async fn test_validate_malformed_transaction() {
        let config = ChainConfig::default();
        let execution = ExecutionLayer::new(config).expect("create execution layer");
        let execution = Arc::new(RwLock::new(execution));
        let validator = ExecutionStateValidator::new(execution);

        // Random bytes should fail validation
        let result = validator.validate_transaction(&[0x01, 0x02, 0x03]).await;
        assert!(result.is_err());
    }
}
