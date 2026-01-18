//! Custom precompiled contracts for CipherBFT.
//!
//! This module provides custom precompiles beyond Ethereum's standard set:
//! - Staking precompile at address 0x100 for validator management
//! - CipherBftPrecompileProvider: PrecompileProvider implementation for revm integration

pub mod provider;
pub mod staking;

pub use provider::{CipherBftPrecompileProvider, STAKING_PRECOMPILE_ADDRESS};
pub use staking::{StakingPrecompile, StakingState, ValidatorInfo};
