//! Custom precompile provider for CipherBFT.
//!
//! MIGRATION(revm33): Implements PrecompileProvider trait pattern for stateful precompiles.
//! This replaces the previous adapter pattern which assumed a non-existent Precompile::Standard enum.
//!
//! The PrecompileProvider trait allows precompiles to access full transaction and block context,
//! which is essential for our staking precompile that needs caller address, transaction value,
//! and block number.

use crate::precompiles::StakingPrecompile;
use alloy_primitives::Address;
use revm::{
    context_interface::{
        result::InvalidTransaction, Block, Cfg, CfgGetter, Transaction, TransactionGetter,
    },
    handler::{mainnet::MainnetPrecompileProvider as EthPrecompileProvider, PrecompileProvider},
    interpreter::{
        CallInputs, CallOutcome, Gas, InstructionResult, InterpreterResult, SharedMemory,
    },
    primitives::hardfork::SpecId,
};
use std::sync::Arc;

/// Staking precompile address (0x0000000000000000000000000000000000000100).
pub const STAKING_PRECOMPILE_ADDRESS: Address = Address::new([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00,
]);

/// CipherBFT precompile provider that handles both standard Ethereum precompiles
/// and our custom staking precompile at address 0x100.
///
/// This provider intercepts calls to the staking precompile address and delegates
/// all other addresses to the standard Ethereum precompile set.
pub struct CipherBftPrecompileProvider {
    /// Standard Ethereum precompiles (ecrecover, sha256, etc.)
    inner: EthPrecompileProvider,
    /// Custom staking precompile instance
    staking: Arc<StakingPrecompile>,
}

impl CipherBftPrecompileProvider {
    /// Create a new precompile provider with the given staking precompile.
    ///
    /// # Arguments
    /// * `staking` - The staking precompile instance to register at 0x100
    /// * `spec_id` - The Ethereum hardfork specification (e.g., CANCUN)
    pub fn new(staking: Arc<StakingPrecompile>, spec_id: SpecId) -> Self {
        Self {
            inner: EthPrecompileProvider::new(spec_id),
            staking,
        }
    }

    /// Get a reference to the staking precompile for testing/inspection.
    pub fn staking(&self) -> &Arc<StakingPrecompile> {
        &self.staking
    }
}

/// Implement the PrecompileProvider trait for context-aware precompile execution.
///
/// MIGRATION(revm33): This is the correct pattern for stateful precompiles.
/// The trait provides access to the full execution context via the CTX type parameter,
/// allowing precompiles to read transaction data and block information.
impl<CTX> PrecompileProvider<CTX> for CipherBftPrecompileProvider
where
    CTX: TransactionGetter + Block + CfgGetter,
    <CTX as CfgGetter>::Cfg: Cfg<Spec = SpecId>,
{
    type Output = CallOutcome;

    /// Run a precompile for the given address with full context access.
    ///
    /// # Arguments
    /// * `context` - Full execution context with access to tx, block, and state
    /// * `inputs` - Call inputs containing address, input bytes, gas limit, etc.
    ///
    /// # Returns
    /// * `Ok(Some(outcome))` - Precompile executed successfully
    /// * `Ok(None)` - Address is not a precompile
    /// * `Err(error)` - Execution failed with error
    fn run(
        &mut self,
        context: &mut CTX,
        inputs: &CallInputs,
        shared_memory: &mut SharedMemory,
    ) -> Result<Option<Self::Output>, InvalidTransaction> {
        // Check if this is our staking precompile
        if inputs.bytecode_address == STAKING_PRECOMPILE_ADDRESS {
            return Ok(Some(run_staking_precompile(
                &self.staking,
                context,
                inputs,
                shared_memory,
            )?));
        }

        // Delegate to standard Ethereum precompiles
        self.inner.run(context, inputs, shared_memory)
    }

    /// Get an iterator over addresses that should be warmed up.
    ///
    /// This includes both standard Ethereum precompiles and our custom staking precompile.
    fn warm_addresses(&self) -> impl Iterator<Item = Address> {
        let mut addrs = vec![STAKING_PRECOMPILE_ADDRESS];
        addrs.extend(self.inner.warm_addresses());
        addrs.into_iter()
    }

    /// Check if an address is a precompile.
    fn contains(&self, address: &Address) -> bool {
        *address == STAKING_PRECOMPILE_ADDRESS || self.inner.contains(address)
    }
}

/// Execute the staking precompile with full context access.
///
/// MIGRATION(revm33): This function bridges between revm's PrecompileProvider API
/// and our StakingPrecompile::run() method by extracting context from the CTX parameter.
///
/// # Arguments
/// * `staking` - The staking precompile instance
/// * `context` - Execution context providing access to tx/block data
/// * `inputs` - Call inputs with address, gas limit, and input bytes
/// * `shared_memory` - Shared memory buffer for efficient data passing
///
/// # Returns
/// CallOutcome with the execution result
fn run_staking_precompile<CTX>(
    staking: &StakingPrecompile,
    context: &mut CTX,
    inputs: &CallInputs,
    shared_memory: &mut SharedMemory,
) -> Result<CallOutcome, InvalidTransaction>
where
    CTX: TransactionGetter + Block,
{
    // Extract input bytes from CallInputs
    // MIGRATION(revm33): Input can be either direct bytes or a shared memory buffer slice
    let input_bytes = inputs.input.as_ref();

    // Extract transaction context
    // MIGRATION(revm33): Context access via trait methods instead of direct field access
    let caller = context.tx().caller();
    let value = context.tx().value();
    let block_number = context.block().number().to::<u64>();

    // Call the staking precompile with extracted context
    let result = staking
        .run(input_bytes, inputs.gas_limit, caller, value, block_number)
        .map_err(|e| {
            // Convert precompile errors to InvalidTransaction
            // This is a simplification - in production you might want more granular error handling
            InvalidTransaction::CallGasCostMoreThanGasLimit
        })?;

    // Convert PrecompileResult to CallOutcome
    // MIGRATION(revm33): Return type changed from PrecompileResult to CallOutcome
    let interpreter_result = InterpreterResult {
        result: if result.reverted {
            InstructionResult::Revert
        } else {
            InstructionResult::Return
        },
        gas: Gas::new(inputs.gas_limit).record_cost(result.gas_used),
        output: result.bytes.into(),
    };

    Ok(CallOutcome {
        result: interpreter_result,
        memory_offset: inputs.return_memory_offset.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::precompiles::StakingPrecompile;

    /// Test that the provider correctly identifies the staking precompile address.
    #[test]
    fn test_provider_contains_staking_address() {
        let staking = Arc::new(StakingPrecompile::new());
        let provider = CipherBftPrecompileProvider::new(staking, SpecId::CANCUN);

        assert!(
            provider.contains(&STAKING_PRECOMPILE_ADDRESS),
            "Provider should contain staking precompile address"
        );
    }

    /// Test that the provider includes standard precompiles.
    #[test]
    fn test_provider_contains_standard_precompiles() {
        let staking = Arc::new(StakingPrecompile::new());
        let provider = CipherBftPrecompileProvider::new(staking, SpecId::CANCUN);

        // Address 0x01 is ecrecover, a standard precompile
        let ecrecover_address = Address::new([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ]);

        assert!(
            provider.contains(&ecrecover_address),
            "Provider should contain standard ecrecover precompile"
        );
    }

    /// Test that warm_addresses includes the staking precompile.
    #[test]
    fn test_warm_addresses_includes_staking() {
        let staking = Arc::new(StakingPrecompile::new());
        let provider = CipherBftPrecompileProvider::new(staking, SpecId::CANCUN);

        let warm_addrs: Vec<Address> = provider.warm_addresses().collect();

        assert!(
            warm_addrs.contains(&STAKING_PRECOMPILE_ADDRESS),
            "Warm addresses should include staking precompile"
        );
    }
}
