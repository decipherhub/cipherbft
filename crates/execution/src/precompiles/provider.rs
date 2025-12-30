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
    context::Cfg,
    context_interface::{Block, ContextTr, LocalContextTr, Transaction},
    handler::{EthPrecompiles, PrecompileProvider},
    interpreter::{CallInputs, Gas, InstructionResult, InterpreterResult},
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
    inner: EthPrecompiles,
    /// Custom staking precompile instance
    staking: Arc<StakingPrecompile>,
}

impl CipherBftPrecompileProvider {
    /// Create a new precompile provider with the given staking precompile.
    ///
    /// # Arguments
    /// * `staking` - The staking precompile instance to register at 0x100
    /// * `spec_id` - The Ethereum hardfork specification (e.g., CANCUN)
    pub fn new(staking: Arc<StakingPrecompile>, _spec_id: SpecId) -> Self {
        let inner = EthPrecompiles::default();
        // Note: spec is set automatically when the provider is first called
        Self { inner, staking }
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
    CTX: ContextTr,
{
    type Output = InterpreterResult;

    /// Sets the spec id and returns true if the spec id was changed.
    fn set_spec(&mut self, spec: <CTX::Cfg as Cfg>::Spec) -> bool {
        <EthPrecompiles as PrecompileProvider<CTX>>::set_spec(&mut self.inner, spec)
    }

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
    ) -> Result<Option<Self::Output>, String> {
        // Check if this is our staking precompile
        if inputs.bytecode_address == STAKING_PRECOMPILE_ADDRESS {
            return Ok(Some(run_staking_precompile(&self.staking, context, inputs)?));
        }

        // Delegate to standard Ethereum precompiles
        self.inner.run(context, inputs)
    }

    /// Get an iterator over addresses that should be warmed up.
    ///
    /// This includes both standard Ethereum precompiles and our custom staking precompile.
    fn warm_addresses(&self) -> Box<impl Iterator<Item = Address>> {
        let mut addrs = vec![STAKING_PRECOMPILE_ADDRESS];
        addrs.extend(self.inner.warm_addresses());
        Box::new(addrs.into_iter())
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
///
/// # Returns
/// InterpreterResult with the execution result
fn run_staking_precompile<CTX>(
    staking: &StakingPrecompile,
    context: &mut CTX,
    inputs: &CallInputs,
) -> Result<InterpreterResult, String>
where
    CTX: ContextTr,
{
    // Extract input bytes from CallInputs
    // MIGRATION(revm33): Input is accessed via the CallInputs enum
    // We need to copy to owned Bytes due to lifetime constraints
    let input_bytes_owned = match &inputs.input {
        revm::interpreter::CallInput::SharedBuffer(range) => {
            // Access shared memory through context.local()
            if let Some(slice) = context.local().shared_memory_buffer_slice(range.clone()) {
                alloy_primitives::Bytes::copy_from_slice(slice.as_ref())
            } else {
                alloy_primitives::Bytes::new()
            }
        }
        revm::interpreter::CallInput::Bytes(bytes) => {
            alloy_primitives::Bytes::copy_from_slice(bytes.0.iter().as_slice())
        }
    };

    // Extract transaction context
    // MIGRATION(revm33): Context access via trait methods instead of direct field access
    let caller = context.tx().caller();
    let value = context.tx().value();
    let block_number = context.block().number().to::<u64>();

    // Call the staking precompile with extracted context
    let result = staking
        .run(&input_bytes_owned, inputs.gas_limit, caller, value, block_number)
        .map_err(|e| format!("Staking precompile error: {:?}", e))?;

    // Convert PrecompileResult to InterpreterResult
    // MIGRATION(revm33): Return type changed from PrecompileResult to InterpreterResult
    let mut interpreter_result = InterpreterResult {
        result: if result.reverted {
            InstructionResult::Revert
        } else {
            InstructionResult::Return
        },
        gas: Gas::new(inputs.gas_limit),
        output: result.bytes.into(),
    };

    // Record gas usage
    interpreter_result.gas.record_cost(result.gas_used);

    Ok(interpreter_result)
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
