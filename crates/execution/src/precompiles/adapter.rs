//! Adapter for integrating StakingPrecompile with revm's precompile system.
//!
//! MIGRATION(revm33): Refactored from trait-based to function factory pattern.
//! - Revm 19 used ContextStatefulPrecompile<DB> trait with InnerEvmContext
//! - Revm 33 uses function closures with &Env parameter
//! - Core StakingPrecompile::run() logic remains unchanged

use crate::precompiles::StakingPrecompile;
use revm::precompile::{Precompile, PrecompileResult};
use revm_primitives::{Bytes, Env};
use std::sync::Arc;

/// Create a staking precompile for revm 33's precompile system.
///
/// MIGRATION(revm33): This replaces the StakingPrecompileAdapter trait impl.
/// Instead of implementing ContextStatefulPrecompile<DB>, we now return a
/// function closure that matches revm 33's precompile signature.
///
/// # Arguments
/// * `staking` - Shared reference to StakingPrecompile instance
///
/// # Returns
/// A `Precompile::Standard` closure that:
/// - Takes `(&Bytes, u64, &Env)` as parameters
/// - Extracts context from `&Env` (caller, value, block number)
/// - Delegates to `StakingPrecompile::run()`
///
/// # Why Function Factory Pattern?
/// Revm 33 requires `'static` lifetime and `Send + Sync` for precompile closures.
/// The function factory pattern allows us to:
/// 1. Capture Arc<StakingPrecompile> by value (not reference)
/// 2. Return a closure with 'static lifetime
/// 3. Maintain thread safety via Arc
///
/// # Example
/// ```rust,ignore
/// let staking = Arc::new(StakingPrecompile::new());
/// let precompile = create_staking_precompile(staking);
///
/// // Register in EVM via handler hook
/// handler.pre_execution.load_precompiles = Arc::new(move |_| {
///     let mut precompiles = Precompiles::new(PrecompileSpecId::CANCUN);
///     precompiles.extend([(STAKING_PRECOMPILE_ADDRESS, precompile.clone())]);
///     precompiles
/// });
/// ```
pub fn create_staking_precompile(staking: Arc<StakingPrecompile>) -> Precompile {
    // MIGRATION(revm33): Use Precompile::Standard instead of trait impl
    Precompile::Standard(Arc::new(
        move |input: &Bytes, gas_limit: u64, env: &Env| -> PrecompileResult {
            // MIGRATION(revm33): Extract context from &Env instead of &mut InnerEvmContext<DB>
            // - Revm 19: evmctx.env.tx.caller
            // - Revm 33: env.tx.caller (simpler!)
            let caller = env.tx.caller;
            let value = env.tx.value;
            let block_number = env.block.number.try_into().unwrap_or(0u64);

            // Delegate to unchanged StakingPrecompile::run()
            // The signature already matches what revm 33 expects:
            // fn run(&self, input: &Bytes, gas_limit: u64, caller: Address, value: U256, block_number: u64) -> PrecompileResult
            staking.run(input, gas_limit, caller, value, block_number)
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::precompiles::StakingPrecompile;
    use alloy_primitives::{Address, U256};
    use revm_primitives::{BlockEnv, CfgEnv, Env, TxEnv};

    /// Test that the factory creates a valid precompile closure.
    #[test]
    fn test_create_staking_precompile() {
        let staking = Arc::new(StakingPrecompile::new());
        let precompile = create_staking_precompile(staking);

        // Verify it's a Standard precompile
        match precompile {
            Precompile::Standard(_) => {}
            _ => panic!("Expected Precompile::Standard variant"),
        }
    }

    /// Test that the precompile can be called with a mock environment.
    #[test]
    fn test_precompile_call() {
        let staking = Arc::new(StakingPrecompile::new());
        let precompile = create_staking_precompile(staking);

        // Create test environment
        let env = Env {
            cfg: CfgEnv::default(),
            block: BlockEnv {
                number: U256::from(100),
                ..Default::default()
            },
            tx: TxEnv {
                caller: Address::from([1u8; 20]),
                value: U256::from(1000),
                ..Default::default()
            },
        };

        // Call the precompile (will fail due to invalid function selector, but proves it's callable)
        let input = Bytes::from(vec![0x00, 0x01, 0x02, 0x03]);
        let gas_limit = 50_000;

        match precompile {
            Precompile::Standard(func) => {
                let result = func(&input, gas_limit, &env);
                // Expect error due to invalid selector, but call should succeed
                assert!(result.is_err(), "Should error on invalid selector");
            }
            _ => panic!("Expected Standard precompile"),
        }
    }
}
