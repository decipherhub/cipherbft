//! Custom precompiled contracts for CipherBFT.
//!
//! This module provides custom precompiles beyond Ethereum's standard set:
//! - Staking precompile at address 0x100 for validator management
//! - Adapter: Integration layer with revm's precompile system

pub mod adapter;
pub mod staking;

pub use adapter::StakingPrecompileAdapter;
pub use staking::{StakingPrecompile, StakingState, ValidatorInfo};
