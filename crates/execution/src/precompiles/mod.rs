//! Custom precompiled contracts for CipherBFT.
//!
//! This module provides custom precompiles beyond Ethereum's standard set:
//! - Staking precompile at address 0x100 for validator management
//! - Provider: PrecompileProvider implementation for revm integration
//!
//! MIGRATION(revm33): Integration pattern changed from adapter to provider
//! - Revm 19: StakingPrecompileAdapter (ContextStatefulPrecompile trait)
//! - Revm 33: CipherBftPrecompileProvider (PrecompileProvider trait)
//! - Key change: Provider receives full context (tx, block) via trait methods

pub mod provider;
pub mod staking;

pub use provider::{CipherBftPrecompileProvider, STAKING_PRECOMPILE_ADDRESS};
pub use staking::{StakingPrecompile, StakingState, ValidatorInfo};
