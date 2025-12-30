//! Custom precompiled contracts for CipherBFT.
//!
//! This module provides custom precompiles beyond Ethereum's standard set:
//! - Staking precompile at address 0x100 for validator management

pub mod staking;

pub use staking::{StakingPrecompile, StakingState, ValidatorInfo};
