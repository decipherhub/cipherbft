//! Adapter for integrating StakingPrecompile with revm's precompile system.
//!
//! This module provides the bridge between our custom StakingPrecompile
//! and revm's ContextPrecompile trait, allowing the staking precompile
//! to be registered and called through the EVM handler system.

use crate::precompiles::StakingPrecompile;
use alloy_primitives::Bytes;
use revm::{
    precompile::PrecompileResult, ContextStatefulPrecompile, Database, InnerEvmContext,
};
use std::sync::Arc;

/// Adapter that bridges StakingPrecompile to revm's precompile system.
///
/// This adapter extracts the necessary context (caller, value, block number)
/// from the EVM environment and delegates to the underlying StakingPrecompile.
///
/// Implements `ContextStatefulPrecompile` to integrate with revm 19's precompile system.
#[derive(Clone)]
pub struct StakingPrecompileAdapter {
    /// The underlying staking precompile instance.
    ///
    /// Uses Arc to allow sharing across multiple EVM instances while
    /// maintaining a single source of truth for validator state.
    inner: Arc<StakingPrecompile>,
}

impl StakingPrecompileAdapter {
    /// Create a new adapter wrapping a StakingPrecompile instance.
    ///
    /// # Arguments
    /// * `inner` - The StakingPrecompile to wrap
    pub fn new(inner: Arc<StakingPrecompile>) -> Self {
        Self { inner }
    }

    /// Get a reference to the underlying StakingPrecompile.
    ///
    /// Useful for tests and state inspection.
    pub fn inner(&self) -> &Arc<StakingPrecompile> {
        &self.inner
    }
}

/// Implement the ContextStatefulPrecompile trait for database-generic precompile integration.
///
/// This implementation allows the staking precompile to be called within revm's execution flow
/// while having access to the full EVM context (environment, state, database).
impl<DB: Database> ContextStatefulPrecompile<DB> for StakingPrecompileAdapter {
    /// Execute the staking precompile with access to EVM context.
    ///
    /// # Arguments
    /// * `bytes` - Call data (function selector + encoded arguments)
    /// * `gas_limit` - Maximum gas available for this call
    /// * `evmctx` - EVM context containing environment, state, and database
    ///
    /// # Returns
    /// Precompile execution result with gas used and output bytes.
    fn call(
        &self,
        bytes: &Bytes,
        gas_limit: u64,
        evmctx: &mut InnerEvmContext<DB>,
    ) -> PrecompileResult {
        // Extract context from EVM environment
        let caller = evmctx.env.tx.caller;
        let value = evmctx.env.tx.value;
        let block_number = evmctx.env.block.number.try_into().unwrap_or(0u64);

        // Delegate to the underlying StakingPrecompile
        self.inner.run(bytes, gas_limit, caller, value, block_number)
    }
}

#[cfg(test)]
mod tests {
    // Note: Adapter tests require constructing an InnerEvmContext which is complex.
    // The adapter functionality will be tested through integration tests instead.
    //
    // TODO: Add adapter-specific unit tests using mock InnerEvmContext if needed.
}
