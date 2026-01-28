//! Staking precompile at address 0x100.
//!
//! Provides validator staking operations:
//! - registerValidator(bytes32 blsPubkey)
//! - deregisterValidator()
//! - getValidatorSet() returns (address[], uint256[])
//! - getStake(address) returns uint256
//! - slash(address, uint256) - system-only
//!
//! Based on ADR-009: Staking Precompile

use alloy_primitives::{address, Address, Bytes, U256};
use alloy_sol_types::sol;
use cipherbft_metrics::execution::{
    STAKING_REWARDS_DISTRIBUTED, STAKING_STAKE_DELEGATED, STAKING_VALIDATORS_DEREGISTERED,
    STAKING_VALIDATORS_REGISTERED,
};
use parking_lot::RwLock;
use revm::precompile::{PrecompileError, PrecompileOutput, PrecompileResult};
use std::{collections::HashMap, sync::Arc};

/// Minimum validator stake (1 CPH = 1e18 wei).
/// CPH is the native token of the CipherBFT network (symbol: $CPH).
pub const MIN_VALIDATOR_STAKE: u128 = 1_000_000_000_000_000_000;

/// System address allowed to call slash function.
///
/// This is the consensus layer's system account used for privileged operations
/// like slashing validators. Using Address::ZERO is a security vulnerability
/// because it's the null/burn address that could be accidentally matched.
///
/// We use 0xfffffffffffffffffffffffffffffffffffffffe which follows the Ethereum
/// convention for system addresses (similar to the beacon chain deposit contract).
pub const SYSTEM_ADDRESS: Address = address!("fffffffffffffffffffffffffffffffffffffffe");

/// Gas costs for staking operations.
pub mod gas {
    /// Gas cost for registerValidator.
    pub const REGISTER_VALIDATOR: u64 = 50_000;

    /// Gas cost for deregisterValidator.
    pub const DEREGISTER_VALIDATOR: u64 = 25_000;

    /// Base gas cost for getValidatorSet.
    pub const GET_VALIDATOR_SET_BASE: u64 = 2_100;

    /// Per-validator gas cost for getValidatorSet.
    pub const GET_VALIDATOR_SET_PER_VALIDATOR: u64 = 100;

    /// Gas cost for getStake.
    pub const GET_STAKE: u64 = 2_100;

    /// Gas cost for slash (system-only).
    pub const SLASH: u64 = 30_000;

    // ========================================================================
    // Reward Distribution Gas Costs
    // ========================================================================

    /// Gas cost for distributeEpochRewards (system-only).
    /// Higher cost due to iteration over validator set and state updates.
    pub const DISTRIBUTE_EPOCH_REWARDS: u64 = 100_000;

    /// Gas cost for getAccumulatedFees.
    pub const GET_ACCUMULATED_FEES: u64 = 2_100;

    /// Gas cost for getTotalDistributed.
    pub const GET_TOTAL_DISTRIBUTED: u64 = 2_100;
}

// Solidity interface using alloy-sol-types
sol! {
    /// Staking precompile interface.
    interface IStaking {
        /// Register as a validator with BLS public key.
        ///
        /// Requires: msg.value >= MIN_VALIDATOR_STAKE (1 CPH)
        /// Gas: 50,000
        function registerValidator(bytes32 blsPubkey) external payable;

        /// Deregister as a validator.
        ///
        /// Marks validator for exit at next epoch boundary.
        /// Gas: 25,000
        function deregisterValidator() external;

        /// Get current validator set.
        ///
        /// Returns parallel arrays of addresses and stakes.
        /// Gas: 2,100 + 100 per validator
        function getValidatorSet() external view returns (address[] memory, uint256[] memory);

        /// Get stake amount for an address.
        ///
        /// Returns 0 if not a validator.
        /// Gas: 2,100
        function getStake(address account) external view returns (uint256);

        /// Slash a validator (system-only).
        ///
        /// Reduces validator stake by specified amount.
        /// Gas: 30,000
        function slash(address validator, uint256 amount) external;

        // ====================================================================
        // Reward Distribution Functions
        // ====================================================================

        /// Distribute epoch rewards to validators (system-only).
        ///
        /// Distributes block rewards + accumulated fees proportionally to stake.
        /// Called at epoch boundaries by the consensus layer.
        /// Gas: 100,000
        /// Returns: Total amount distributed (in wei)
        function distributeEpochRewards(uint256 epochBlockReward) external returns (uint256);

        /// Get accumulated transaction fees for current epoch.
        ///
        /// Gas: 2,100
        function getAccumulatedFees() external view returns (uint256);

        /// Get total rewards distributed since genesis.
        ///
        /// Gas: 2,100
        function getTotalDistributed() external view returns (uint256);
    }
}

/// BLS12-381 public key (48 bytes).
///
/// Used for Data Chain Layer attestations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlsPublicKey([u8; 48]);

impl BlsPublicKey {
    /// Create from bytes (must be 48 bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PrecompileError> {
        if bytes.len() != 48 {
            return Err(PrecompileError::Fatal(
                "BLS public key must be 48 bytes".to_string(),
            ));
        }

        let mut key = [0u8; 48];
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }

    /// Convert to bytes.
    pub fn as_bytes(&self) -> &[u8; 48] {
        &self.0
    }
}

/// Validator registration information.
#[derive(Debug, Clone)]
pub struct ValidatorInfo {
    /// EVM address (derived from Ed25519 pubkey).
    pub address: Address,

    /// BLS12-381 public key for DCL attestations.
    pub bls_pubkey: BlsPublicKey,

    /// Staked amount in wei.
    pub stake: U256,

    /// Registration block height.
    pub registered_at: u64,

    /// Pending deregistration (epoch when it takes effect).
    pub pending_exit: Option<u64>,
}

/// Reward tracking state for epoch-based distribution.
///
/// Tracks accumulated transaction fees and pending block rewards
/// for distribution to validators at epoch boundaries.
#[derive(Debug, Clone, Default)]
pub struct RewardState {
    /// Accumulated transaction fees for current epoch (in wei).
    /// This is collected from all transactions during the epoch.
    pub accumulated_fees: U256,

    /// Block rewards to be distributed at epoch end (in wei).
    /// This is set when distribute_epoch_rewards() is called.
    pub pending_block_rewards: U256,

    /// Last epoch when rewards were distributed.
    pub last_distribution_epoch: u64,

    /// Total rewards distributed since genesis (for metrics/auditing).
    pub total_distributed: U256,
}

/// Staking state managed by the precompile.
#[derive(Debug, Clone)]
pub struct StakingState {
    /// Active validators (address -> ValidatorInfo).
    pub validators: HashMap<Address, ValidatorInfo>,

    /// Total staked amount.
    pub total_stake: U256,

    /// Current epoch number.
    pub epoch: u64,

    /// Reward tracking state for epoch-based distribution.
    pub rewards: RewardState,
}

impl Default for StakingState {
    fn default() -> Self {
        Self {
            validators: HashMap::new(),
            total_stake: U256::ZERO,
            epoch: 0,
            rewards: RewardState::default(),
        }
    }
}

/// Genesis validator data for initializing staking state.
///
/// This struct is used to pass validator information from the genesis file
/// to initialize the staking precompile state on node startup.
#[derive(Debug, Clone)]
pub struct GenesisValidatorData {
    /// Validator's EVM address.
    pub address: Address,
    /// BLS12-381 public key (48 bytes).
    pub bls_pubkey: [u8; 48],
    /// Staked amount in wei.
    pub stake: U256,
}

impl StakingState {
    /// Create staking state from genesis validators.
    ///
    /// This method initializes the staking state with validators from the genesis file,
    /// ensuring the validator set is persisted across node restarts.
    ///
    /// # Arguments
    /// * `validators` - List of genesis validators with their addresses, BLS keys, and stakes
    ///
    /// # Returns
    /// * New StakingState with all genesis validators registered
    pub fn from_genesis_validators(validators: Vec<GenesisValidatorData>) -> Self {
        let mut state = Self::default();

        for validator_data in validators {
            let bls_pubkey = BlsPublicKey(validator_data.bls_pubkey);
            let validator = ValidatorInfo {
                address: validator_data.address,
                bls_pubkey,
                stake: validator_data.stake,
                registered_at: 0, // Genesis block
                pending_exit: None,
            };
            state.add_validator(validator);
        }

        tracing::info!(
            validator_count = state.validators.len(),
            total_stake = %state.total_stake,
            "Initialized staking state from genesis"
        );

        state
    }

    /// Check if an address is a registered validator.
    pub fn is_validator(&self, address: &Address) -> bool {
        self.validators.contains_key(address)
    }

    /// Get stake for an address (returns 0 if not a validator).
    pub fn get_stake(&self, address: &Address) -> U256 {
        self.validators
            .get(address)
            .map(|v| v.stake)
            .unwrap_or(U256::ZERO)
    }

    /// Add a new validator.
    pub fn add_validator(&mut self, validator: ValidatorInfo) {
        self.total_stake += validator.stake;
        self.validators.insert(validator.address, validator);
    }

    /// Remove a validator.
    pub fn remove_validator(&mut self, address: &Address) -> Option<ValidatorInfo> {
        if let Some(validator) = self.validators.remove(address) {
            self.total_stake -= validator.stake;
            Some(validator)
        } else {
            None
        }
    }

    /// Mark a validator for exit.
    pub fn mark_for_exit(&mut self, address: &Address, exit_epoch: u64) -> Result<(), String> {
        if let Some(validator) = self.validators.get_mut(address) {
            validator.pending_exit = Some(exit_epoch);
            Ok(())
        } else {
            Err("Validator not found".to_string())
        }
    }

    /// Slash a validator's stake.
    pub fn slash_validator(&mut self, address: &Address, amount: U256) -> Result<(), String> {
        if let Some(validator) = self.validators.get_mut(address) {
            let new_stake = validator.stake.saturating_sub(amount);
            self.total_stake = self.total_stake.saturating_sub(amount);
            validator.stake = new_stake;

            // Remove validator if stake falls below minimum
            if new_stake < U256::from(MIN_VALIDATOR_STAKE) {
                validator.pending_exit = Some(self.epoch + 1);
            }

            Ok(())
        } else {
            Err("Validator not found".to_string())
        }
    }

    // ========================================================================
    // Reward Distribution Methods
    // ========================================================================

    /// Accumulate transaction fees from a block execution.
    ///
    /// Called after each block is executed to track fees for later distribution.
    ///
    /// # Arguments
    /// * `fees` - Total transaction fees collected from the block (in wei)
    pub fn accumulate_fees(&mut self, fees: U256) {
        self.rewards.accumulated_fees = self.rewards.accumulated_fees.saturating_add(fees);
    }

    /// Distribute rewards at epoch boundary.
    ///
    /// This method calculates and distributes rewards to all active validators
    /// proportionally to their stake. Rewards include:
    /// - Block rewards (minted tokens)
    /// - Accumulated transaction fees
    ///
    /// # Arguments
    /// * `epoch_block_reward` - Block reward for this epoch (in wei)
    /// * `current_epoch` - The current epoch number
    ///
    /// # Returns
    /// * Total amount distributed to all validators (in wei)
    ///
    /// # Distribution Formula
    /// For each validator: `reward = total_rewards * (validator_stake / total_stake)`
    pub fn distribute_epoch_rewards(
        &mut self,
        epoch_block_reward: U256,
        current_epoch: u64,
    ) -> U256 {
        // Skip if no validators or no stake
        if self.validators.is_empty() || self.total_stake.is_zero() {
            // Reset accumulators even if nothing to distribute
            self.rewards.accumulated_fees = U256::ZERO;
            self.rewards.pending_block_rewards = U256::ZERO;
            return U256::ZERO;
        }

        // Total rewards = block rewards + accumulated fees
        let total_rewards = epoch_block_reward.saturating_add(self.rewards.accumulated_fees);

        if total_rewards.is_zero() {
            return U256::ZERO;
        }

        let mut total_distributed = U256::ZERO;

        // Distribute proportionally to stake
        // We iterate over validators and calculate their share
        let original_total_stake = self.total_stake;

        for validator in self.validators.values_mut() {
            // Skip validators marked for exit
            if validator.pending_exit.is_some() {
                continue;
            }

            // Calculate proportional share: (stake / total_stake) * total_rewards
            // Use multiplication first to maintain precision, then divide
            let validator_share = (validator.stake * total_rewards) / original_total_stake;

            // Add to validator's stake (compound rewards)
            validator.stake = validator.stake.saturating_add(validator_share);

            total_distributed = total_distributed.saturating_add(validator_share);
        }

        // Update total stake with distributed rewards
        self.total_stake = self.total_stake.saturating_add(total_distributed);

        // Update reward tracking state
        self.rewards.total_distributed = self
            .rewards
            .total_distributed
            .saturating_add(total_distributed);
        self.rewards.last_distribution_epoch = current_epoch;

        // Reset accumulators for next epoch
        self.rewards.accumulated_fees = U256::ZERO;
        self.rewards.pending_block_rewards = U256::ZERO;

        tracing::info!(
            epoch = current_epoch,
            block_reward = %epoch_block_reward,
            fees = %self.rewards.accumulated_fees,
            total_distributed = %total_distributed,
            new_total_stake = %self.total_stake,
            "Epoch rewards distributed"
        );

        total_distributed
    }

    /// Get accumulated fees for current epoch.
    pub fn get_accumulated_fees(&self) -> U256 {
        self.rewards.accumulated_fees
    }

    /// Get total rewards distributed since genesis.
    pub fn get_total_distributed(&self) -> U256 {
        self.rewards.total_distributed
    }

    /// Get the last epoch when rewards were distributed.
    pub fn get_last_distribution_epoch(&self) -> u64 {
        self.rewards.last_distribution_epoch
    }

    /// Advance to the next epoch.
    ///
    /// Called at epoch boundaries to increment the epoch counter.
    /// This should be called AFTER distribute_epoch_rewards().
    pub fn advance_epoch(&mut self) {
        self.epoch += 1;
    }
}

/// Staking precompile implementation.
///
/// Thread-safe using Arc<RwLock<StakingState>>.
#[derive(Debug, Clone)]
pub struct StakingPrecompile {
    state: Arc<RwLock<StakingState>>,
}

impl StakingPrecompile {
    /// Create a new staking precompile with empty state.
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(StakingState::default())),
        }
    }

    /// Create with existing state (for testing).
    pub fn with_state(state: StakingState) -> Self {
        Self {
            state: Arc::new(RwLock::new(state)),
        }
    }

    /// Create from genesis validators.
    ///
    /// This is the primary constructor for production use. It initializes the
    /// staking precompile with the validator set from the genesis file, ensuring
    /// the validator state is correctly populated on node startup.
    ///
    /// # Arguments
    /// * `validators` - List of genesis validators
    ///
    /// # Example
    /// ```rust,ignore
    /// let validators = vec![
    ///     GenesisValidatorData {
    ///         address: Address::from_slice(&[1u8; 20]),
    ///         bls_pubkey: [0u8; 48],
    ///         stake: U256::from(32_000_000_000_000_000_000u128),
    ///     },
    /// ];
    /// let precompile = StakingPrecompile::from_genesis_validators(validators);
    /// ```
    pub fn from_genesis_validators(validators: Vec<GenesisValidatorData>) -> Self {
        let state = StakingState::from_genesis_validators(validators);
        Self {
            state: Arc::new(RwLock::new(state)),
        }
    }

    /// Get a reference to the current state (for testing/queries).
    pub fn state(&self) -> Arc<RwLock<StakingState>> {
        Arc::clone(&self.state)
    }

    /// Main precompile entry point.
    ///
    /// Decodes function selector and routes to appropriate handler.
    pub fn run(
        &self,
        input: &Bytes,
        gas_limit: u64,
        caller: Address,
        value: U256,
        block_number: u64,
    ) -> PrecompileResult {
        if input.len() < 4 {
            return Err(PrecompileError::Fatal("Input too short".to_string()));
        }

        // Extract function selector (first 4 bytes)
        let selector = &input[0..4];
        let data = &input[4..];

        match selector {
            // registerValidator(bytes32) - selector: 0x607049d8
            [0x60, 0x70, 0x49, 0xd8] => {
                self.register_validator(data, gas_limit, caller, value, block_number)
            }
            // deregisterValidator() - selector: 0x6a911ccf
            [0x6a, 0x91, 0x1c, 0xcf] => self.deregister_validator(gas_limit, caller),
            // getValidatorSet() - selector: 0xcf331250
            [0xcf, 0x33, 0x12, 0x50] => self.get_validator_set(gas_limit),
            // getStake(address) - selector: 0x7a766460
            [0x7a, 0x76, 0x64, 0x60] => self.get_stake(data, gas_limit),
            // slash(address, uint256) - selector: 0x02fb4d85
            [0x02, 0xfb, 0x4d, 0x85] => self.slash(data, gas_limit, caller),

            // ================================================================
            // Reward Distribution Functions
            // ================================================================

            // distributeEpochRewards(uint256) - selector: 0xd5670b95
            // keccak256("distributeEpochRewards(uint256)")[0:4]
            [0xd5, 0x67, 0x0b, 0x95] => self.distribute_epoch_rewards(data, gas_limit, caller),
            // getAccumulatedFees() - selector: 0x5df45a37
            // keccak256("getAccumulatedFees()")[0:4]
            [0x5d, 0xf4, 0x5a, 0x37] => self.get_accumulated_fees_precompile(gas_limit),
            // getTotalDistributed() - selector: 0x5695fa58
            // keccak256("getTotalDistributed()")[0:4]
            [0x56, 0x95, 0xfa, 0x58] => self.get_total_distributed_precompile(gas_limit),

            _ => Err(PrecompileError::Fatal(
                "Unknown function selector".to_string(),
            )),
        }
    }

    /// Register a new validator.
    ///
    /// Function: registerValidator(bytes32 blsPubkey)
    /// Selector: 0x607049d8
    /// Gas: 50,000
    fn register_validator(
        &self,
        data: &[u8],
        gas_limit: u64,
        caller: Address,
        value: U256,
        block_number: u64,
    ) -> PrecompileResult {
        const GAS_COST: u64 = gas::REGISTER_VALIDATOR;

        if gas_limit < GAS_COST {
            return Err(PrecompileError::Fatal("Out of gas".to_string()));
        }

        // Decode BLS public key (bytes32, padded from 48 bytes)
        if data.len() < 32 {
            return Err(PrecompileError::Fatal(
                "Invalid BLS pubkey data".to_string(),
            ));
        }

        // For bytes32, we expect the 48-byte BLS key to be right-padded with zeros
        // In practice, the caller should encode it properly
        // We'll take bytes 0..48 if available, otherwise pad
        let mut bls_bytes = [0u8; 48];
        let copy_len = std::cmp::min(data.len(), 48);
        bls_bytes[..copy_len].copy_from_slice(&data[..copy_len]);

        let bls_pubkey = BlsPublicKey::from_bytes(&bls_bytes)?;

        // Check minimum stake
        if value < U256::from(MIN_VALIDATOR_STAKE) {
            return Err(PrecompileError::Fatal(format!(
                "Insufficient stake: minimum {MIN_VALIDATOR_STAKE} wei required"
            )));
        }

        // Check if already registered
        let mut state = self.state.write();

        if state.is_validator(&caller) {
            return Err(PrecompileError::Fatal(
                "Already registered as validator".to_string(),
            ));
        }

        // Add to validator set
        let validator = ValidatorInfo {
            address: caller,
            bls_pubkey,
            stake: value,
            registered_at: block_number,
            pending_exit: None,
        };

        state.add_validator(validator);

        // Track validator registration metrics
        STAKING_VALIDATORS_REGISTERED.inc();
        // Update total stake delegated gauge (convert U256 to f64 for gauge)
        let total_stake_f64 = state.total_stake.to::<u128>() as f64;
        STAKING_STAKE_DELEGATED.set(total_stake_f64);

        Ok(PrecompileOutput {
            gas_used: GAS_COST,
            gas_refunded: 0,
            bytes: Bytes::new(),
            reverted: false,
        })
    }

    /// Deregister as a validator.
    ///
    /// Function: deregisterValidator()
    /// Selector: 0x6a911ccf
    /// Gas: 25,000
    fn deregister_validator(&self, gas_limit: u64, caller: Address) -> PrecompileResult {
        const GAS_COST: u64 = gas::DEREGISTER_VALIDATOR;

        if gas_limit < GAS_COST {
            return Err(PrecompileError::Fatal("Out of gas".to_string()));
        }

        let mut state = self.state.write();

        if !state.is_validator(&caller) {
            return Err(PrecompileError::Fatal(
                "Not a registered validator".to_string(),
            ));
        }

        // Mark for exit at next epoch
        let exit_epoch = state.epoch + 1;
        state
            .mark_for_exit(&caller, exit_epoch)
            .map_err(|e| PrecompileError::Fatal(e.to_string()))?;

        // Track validator deregistration metrics
        STAKING_VALIDATORS_DEREGISTERED.inc();

        Ok(PrecompileOutput {
            gas_used: GAS_COST,
            gas_refunded: 0,
            bytes: Bytes::new(),
            reverted: false,
        })
    }

    /// Get current validator set.
    ///
    /// Function: getValidatorSet() returns (address[], uint256[])
    /// Selector: 0xe7b5c8a9
    /// Gas: 2,100 + 100 per validator
    fn get_validator_set(&self, gas_limit: u64) -> PrecompileResult {
        let state = self.state.read();

        let validator_count = state.validators.len();
        let gas_cost = gas::GET_VALIDATOR_SET_BASE
            + (gas::GET_VALIDATOR_SET_PER_VALIDATOR * validator_count as u64);

        if gas_limit < gas_cost {
            return Err(PrecompileError::Fatal("Out of gas".to_string()));
        }

        // Collect addresses and stakes
        let mut addresses = Vec::new();
        let mut stakes = Vec::new();

        for validator in state.validators.values() {
            addresses.push(validator.address);
            stakes.push(validator.stake);
        }

        // Encode as ABI: (address[], uint256[])
        let output = encode_validator_set(&addresses, &stakes);

        Ok(PrecompileOutput {
            gas_used: gas_cost,
            gas_refunded: 0,
            bytes: output,
            reverted: false,
        })
    }

    /// Get stake for an address.
    ///
    /// Function: getStake(address) returns uint256
    /// Selector: 0x7a766460
    /// Gas: 2,100
    fn get_stake(&self, data: &[u8], gas_limit: u64) -> PrecompileResult {
        const GAS_COST: u64 = gas::GET_STAKE;

        if gas_limit < GAS_COST {
            return Err(PrecompileError::Fatal("Out of gas".to_string()));
        }

        if data.len() < 32 {
            return Err(PrecompileError::Fatal("Invalid address data".to_string()));
        }

        // Address is right-aligned in 32 bytes (bytes 12..32)
        let address = Address::from_slice(&data[12..32]);

        let state = self.state.read();

        let stake = state.get_stake(&address);

        // Encode uint256 as 32 bytes
        let output = encode_uint256(stake);

        Ok(PrecompileOutput {
            gas_used: GAS_COST,
            gas_refunded: 0,
            bytes: output,
            reverted: false,
        })
    }

    /// Slash a validator (system-only).
    ///
    /// Function: slash(address validator, uint256 amount)
    /// Selector: 0x02fb4d85
    /// Gas: 30,000
    fn slash(&self, data: &[u8], gas_limit: u64, caller: Address) -> PrecompileResult {
        const GAS_COST: u64 = gas::SLASH;

        if gas_limit < GAS_COST {
            return Err(PrecompileError::Fatal("Out of gas".to_string()));
        }

        // Only callable by system
        if caller != SYSTEM_ADDRESS {
            return Err(PrecompileError::Fatal(
                "Unauthorized: system-only function".to_string(),
            ));
        }

        if data.len() < 64 {
            return Err(PrecompileError::Fatal("Invalid slash data".to_string()));
        }

        // Decode address (bytes 12..32)
        let validator = Address::from_slice(&data[12..32]);

        // Decode amount (bytes 32..64)
        let amount = U256::from_be_slice(&data[32..64]);

        let mut state = self.state.write();

        state
            .slash_validator(&validator, amount)
            .map_err(|e| PrecompileError::Fatal(e.to_string()))?;

        Ok(PrecompileOutput {
            gas_used: GAS_COST,
            gas_refunded: 0,
            bytes: Bytes::new(),
            reverted: false,
        })
    }

    // ========================================================================
    // Reward Distribution Precompile Functions
    // ========================================================================

    /// Distribute epoch rewards to validators (system-only).
    ///
    /// Function: distributeEpochRewards(uint256 epochBlockReward)
    /// Selector: 0xd5670b95
    /// Gas: 100,000
    ///
    /// This function is called by the consensus layer at epoch boundaries
    /// to distribute block rewards and accumulated transaction fees to validators.
    fn distribute_epoch_rewards(
        &self,
        data: &[u8],
        gas_limit: u64,
        caller: Address,
    ) -> PrecompileResult {
        const GAS_COST: u64 = gas::DISTRIBUTE_EPOCH_REWARDS;

        if gas_limit < GAS_COST {
            return Err(PrecompileError::Fatal("Out of gas".to_string()));
        }

        // Only callable by system
        if caller != SYSTEM_ADDRESS {
            return Err(PrecompileError::Fatal(
                "Unauthorized: system-only function".to_string(),
            ));
        }

        if data.len() < 32 {
            return Err(PrecompileError::Fatal(
                "Invalid epoch block reward data".to_string(),
            ));
        }

        // Decode epoch block reward (uint256)
        let epoch_block_reward = U256::from_be_slice(&data[0..32]);

        let mut state = self.state.write();

        // Get current epoch
        let current_epoch = state.epoch;

        // Distribute rewards
        let total_distributed = state.distribute_epoch_rewards(epoch_block_reward, current_epoch);

        // Track rewards distribution metric
        if !total_distributed.is_zero() {
            STAKING_REWARDS_DISTRIBUTED.inc();
            // Update total stake gauge after rewards are distributed
            let total_stake_f64 = state.total_stake.to::<u128>() as f64;
            STAKING_STAKE_DELEGATED.set(total_stake_f64);
        }

        // Advance to next epoch
        state.advance_epoch();

        // Encode return value (uint256 total_distributed)
        let output = encode_uint256(total_distributed);

        Ok(PrecompileOutput {
            gas_used: GAS_COST,
            gas_refunded: 0,
            bytes: output,
            reverted: false,
        })
    }

    /// Get accumulated transaction fees for current epoch.
    ///
    /// Function: getAccumulatedFees()
    /// Selector: 0x5df45a37
    /// Gas: 2,100
    fn get_accumulated_fees_precompile(&self, gas_limit: u64) -> PrecompileResult {
        const GAS_COST: u64 = gas::GET_ACCUMULATED_FEES;

        if gas_limit < GAS_COST {
            return Err(PrecompileError::Fatal("Out of gas".to_string()));
        }

        let state = self.state.read();
        let fees = state.get_accumulated_fees();

        let output = encode_uint256(fees);

        Ok(PrecompileOutput {
            gas_used: GAS_COST,
            gas_refunded: 0,
            bytes: output,
            reverted: false,
        })
    }

    /// Get total rewards distributed since genesis.
    ///
    /// Function: getTotalDistributed()
    /// Selector: 0x5695fa58
    /// Gas: 2,100
    fn get_total_distributed_precompile(&self, gas_limit: u64) -> PrecompileResult {
        const GAS_COST: u64 = gas::GET_TOTAL_DISTRIBUTED;

        if gas_limit < GAS_COST {
            return Err(PrecompileError::Fatal("Out of gas".to_string()));
        }

        let state = self.state.read();
        let total = state.get_total_distributed();

        let output = encode_uint256(total);

        Ok(PrecompileOutput {
            gas_used: GAS_COST,
            gas_refunded: 0,
            bytes: output,
            reverted: false,
        })
    }
}

impl Default for StakingPrecompile {
    fn default() -> Self {
        Self::new()
    }
}

/// Encode validator set as ABI (address[], uint256[]).
fn encode_validator_set(addresses: &[Address], stakes: &[U256]) -> Bytes {
    // ABI encoding for two dynamic arrays:
    // offset_addresses (32 bytes) | offset_stakes (32 bytes) | addresses_data | stakes_data

    let mut output = Vec::new();

    // Offset to addresses array (after two offset fields = 64 bytes)
    let addresses_offset = U256::from(64u64);
    output.extend_from_slice(&addresses_offset.to_be_bytes::<32>());

    // Offset to stakes array (after addresses array)
    // Each address is 32 bytes, plus 32 bytes for length
    let stakes_offset = U256::from(64 + 32 + (addresses.len() * 32));
    output.extend_from_slice(&stakes_offset.to_be_bytes::<32>());

    // Encode addresses array
    // Length
    let addr_len = U256::from(addresses.len());
    output.extend_from_slice(&addr_len.to_be_bytes::<32>());
    // Elements (left-padded to 32 bytes)
    for addr in addresses {
        let mut padded = [0u8; 32];
        padded[12..32].copy_from_slice(addr.as_slice());
        output.extend_from_slice(&padded);
    }

    // Encode stakes array
    // Length
    let stakes_len = U256::from(stakes.len());
    output.extend_from_slice(&stakes_len.to_be_bytes::<32>());
    // Elements
    for stake in stakes {
        output.extend_from_slice(&stake.to_be_bytes::<32>());
    }

    Bytes::from(output)
}

/// Encode uint256 as 32 bytes (big-endian).
fn encode_uint256(value: U256) -> Bytes {
    Bytes::from(value.to_be_bytes::<32>().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bls_pubkey_from_bytes() {
        let bytes = [0u8; 48];
        let key = BlsPublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(key.as_bytes(), &bytes);

        // Invalid length
        let short_bytes = [0u8; 32];
        assert!(BlsPublicKey::from_bytes(&short_bytes).is_err());
    }

    #[test]
    fn test_staking_state_add_remove() {
        let mut state = StakingState::default();

        let addr = Address::with_last_byte(1);
        let validator = ValidatorInfo {
            address: addr,
            bls_pubkey: BlsPublicKey([0u8; 48]),
            stake: U256::from(MIN_VALIDATOR_STAKE),
            registered_at: 100,
            pending_exit: None,
        };

        // Add validator
        state.add_validator(validator);
        assert!(state.is_validator(&addr));
        assert_eq!(state.get_stake(&addr), U256::from(MIN_VALIDATOR_STAKE));
        assert_eq!(state.total_stake, U256::from(MIN_VALIDATOR_STAKE));

        // Remove validator
        let removed = state.remove_validator(&addr);
        assert!(removed.is_some());
        assert!(!state.is_validator(&addr));
        assert_eq!(state.total_stake, U256::ZERO);
    }

    #[test]
    fn test_staking_state_slash() {
        let mut state = StakingState::default();

        let addr = Address::with_last_byte(2);
        let validator = ValidatorInfo {
            address: addr,
            bls_pubkey: BlsPublicKey([0u8; 48]),
            stake: U256::from(MIN_VALIDATOR_STAKE * 2),
            registered_at: 100,
            pending_exit: None,
        };

        state.add_validator(validator);

        // Slash half the stake
        let slash_amount = U256::from(MIN_VALIDATOR_STAKE);
        state.slash_validator(&addr, slash_amount).unwrap();

        assert_eq!(state.get_stake(&addr), U256::from(MIN_VALIDATOR_STAKE));
        assert_eq!(state.total_stake, U256::from(MIN_VALIDATOR_STAKE));
    }

    #[test]
    fn test_precompile_register_validator() {
        let precompile = StakingPrecompile::new();

        // Prepare input: registerValidator(bytes32 blsPubkey)
        let mut input = vec![0x60, 0x70, 0x49, 0xd8]; // selector
        input.extend_from_slice(&[1u8; 32]); // BLS pubkey (simplified)

        let caller = Address::with_last_byte(3);
        let value = U256::from(MIN_VALIDATOR_STAKE);

        let result = precompile.run(&Bytes::from(input), 100_000, caller, value, 1);

        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output.gas_used, gas::REGISTER_VALIDATOR);

        // Check state
        let state = precompile.state.read();
        assert!(state.is_validator(&caller));
        assert_eq!(state.get_stake(&caller), value);
    }

    #[test]
    fn test_precompile_register_insufficient_stake() {
        let precompile = StakingPrecompile::new();

        let mut input = vec![0x60, 0x70, 0x49, 0xd8]; // selector
        input.extend_from_slice(&[1u8; 32]); // BLS pubkey

        let caller = Address::with_last_byte(4);
        let value = U256::from(MIN_VALIDATOR_STAKE - 1); // Too low

        let result = precompile.run(&Bytes::from(input), 100_000, caller, value, 1);

        assert!(result.is_err());
    }

    #[test]
    fn test_precompile_deregister_validator() {
        let precompile = StakingPrecompile::new();

        // First register
        let mut input = vec![0x60, 0x70, 0x49, 0xd8];
        input.extend_from_slice(&[1u8; 32]);
        let caller = Address::with_last_byte(5);
        let value = U256::from(MIN_VALIDATOR_STAKE);
        precompile
            .run(&Bytes::from(input), 100_000, caller, value, 1)
            .unwrap();

        // Now deregister
        let dereg_input = vec![0x6a, 0x91, 0x1c, 0xcf]; // selector
        let result = precompile.run(&Bytes::from(dereg_input), 100_000, caller, U256::ZERO, 2);

        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output.gas_used, gas::DEREGISTER_VALIDATOR);

        // Check state - validator should be marked for exit
        let state = precompile.state.read();
        let validator = state.validators.get(&caller).unwrap();
        assert!(validator.pending_exit.is_some());
    }

    #[test]
    fn test_precompile_get_stake() {
        let precompile = StakingPrecompile::new();

        // Register a validator
        let mut reg_input = vec![0x60, 0x70, 0x49, 0xd8];
        reg_input.extend_from_slice(&[1u8; 32]);
        let validator_addr = Address::with_last_byte(6);
        let stake = U256::from(MIN_VALIDATOR_STAKE * 2);
        precompile
            .run(&Bytes::from(reg_input), 100_000, validator_addr, stake, 1)
            .unwrap();

        // Query stake
        let mut input = vec![0x7a, 0x76, 0x64, 0x60]; // selector
        let mut addr_bytes = [0u8; 32];
        addr_bytes[12..32].copy_from_slice(validator_addr.as_slice());
        input.extend_from_slice(&addr_bytes);

        let result = precompile.run(&Bytes::from(input), 100_000, Address::ZERO, U256::ZERO, 2);

        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output.gas_used, gas::GET_STAKE);

        // Decode output
        let returned_stake = U256::from_be_slice(&output.bytes);
        assert_eq!(returned_stake, stake);
    }

    #[test]
    fn test_precompile_get_validator_set() {
        let precompile = StakingPrecompile::new();

        // Register two validators
        let addr1 = Address::with_last_byte(7);
        let stake1 = U256::from(MIN_VALIDATOR_STAKE);
        let mut input1 = vec![0x60, 0x70, 0x49, 0xd8];
        input1.extend_from_slice(&[1u8; 32]);
        precompile
            .run(&Bytes::from(input1), 100_000, addr1, stake1, 1)
            .unwrap();

        let addr2 = Address::with_last_byte(8);
        let stake2 = U256::from(MIN_VALIDATOR_STAKE * 2);
        let mut input2 = vec![0x60, 0x70, 0x49, 0xd8];
        input2.extend_from_slice(&[2u8; 32]);
        precompile
            .run(&Bytes::from(input2), 100_000, addr2, stake2, 2)
            .unwrap();

        // Query validator set
        let input = vec![0xcf, 0x33, 0x12, 0x50]; // selector

        let result = precompile.run(&Bytes::from(input), 100_000, Address::ZERO, U256::ZERO, 3);

        assert!(result.is_ok());
        let output = result.unwrap();

        // Check gas cost (base + 2 validators)
        let expected_gas = gas::GET_VALIDATOR_SET_BASE + (gas::GET_VALIDATOR_SET_PER_VALIDATOR * 2);
        assert_eq!(output.gas_used, expected_gas);

        // Output should contain encoded validator set
        assert!(!output.bytes.is_empty());
    }

    #[test]
    fn test_precompile_slash_unauthorized() {
        let precompile = StakingPrecompile::new();

        // Try to slash as non-system caller
        let mut input = vec![0x02, 0xfb, 0x4d, 0x85]; // selector
        let mut addr_bytes = [0u8; 32];
        let target = Address::with_last_byte(9);
        addr_bytes[12..32].copy_from_slice(target.as_slice());
        input.extend_from_slice(&addr_bytes);
        input.extend_from_slice(&U256::from(1000u64).to_be_bytes::<32>());

        let unauthorized_caller = Address::with_last_byte(10);
        let result = precompile.run(
            &Bytes::from(input),
            100_000,
            unauthorized_caller,
            U256::ZERO,
            1,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_encode_uint256() {
        let value = U256::from(12345u64);
        let encoded = encode_uint256(value);

        assert_eq!(encoded.len(), 32);
        assert_eq!(U256::from_be_slice(&encoded), value);
    }

    // ============================================================================
    // Tests for genesis validator loading (Issue #97 fix)
    // ============================================================================

    #[test]
    fn test_staking_state_from_genesis_validators_empty() {
        // Empty genesis should create empty state
        let state = StakingState::from_genesis_validators(vec![]);

        assert_eq!(state.validators.len(), 0);
        assert_eq!(state.total_stake, U256::ZERO);
        assert_eq!(state.epoch, 0);
    }

    #[test]
    fn test_staking_state_from_genesis_validators_single() {
        // Single validator from genesis
        let addr = Address::with_last_byte(100);
        let stake = U256::from(32_000_000_000_000_000_000u128); // 32 CPH

        let validators = vec![GenesisValidatorData {
            address: addr,
            bls_pubkey: [42u8; 48],
            stake,
        }];

        let state = StakingState::from_genesis_validators(validators);

        assert_eq!(state.validators.len(), 1);
        assert!(state.is_validator(&addr));
        assert_eq!(state.get_stake(&addr), stake);
        assert_eq!(state.total_stake, stake);

        // Check validator details
        let validator = state.validators.get(&addr).unwrap();
        assert_eq!(validator.registered_at, 0); // Genesis block
        assert!(validator.pending_exit.is_none());
        assert_eq!(validator.bls_pubkey.0, [42u8; 48]);
    }

    #[test]
    fn test_staking_state_from_genesis_validators_multiple() {
        // Multiple validators from genesis
        let addr1 = Address::with_last_byte(101);
        let stake1 = U256::from(32_000_000_000_000_000_000u128); // 32 CPH

        let addr2 = Address::with_last_byte(102);
        let stake2 = U256::from(64_000_000_000_000_000_000u128); // 64 CPH

        let addr3 = Address::with_last_byte(103);
        let stake3 = U256::from(100_000_000_000_000_000_000u128); // 100 CPH

        let validators = vec![
            GenesisValidatorData {
                address: addr1,
                bls_pubkey: [1u8; 48],
                stake: stake1,
            },
            GenesisValidatorData {
                address: addr2,
                bls_pubkey: [2u8; 48],
                stake: stake2,
            },
            GenesisValidatorData {
                address: addr3,
                bls_pubkey: [3u8; 48],
                stake: stake3,
            },
        ];

        let state = StakingState::from_genesis_validators(validators);

        assert_eq!(state.validators.len(), 3);
        assert!(state.is_validator(&addr1));
        assert!(state.is_validator(&addr2));
        assert!(state.is_validator(&addr3));

        let expected_total = stake1 + stake2 + stake3;
        assert_eq!(state.total_stake, expected_total);
    }

    #[test]
    fn test_staking_precompile_from_genesis_validators() {
        // Test StakingPrecompile::from_genesis_validators
        let addr = Address::with_last_byte(110);
        let stake = U256::from(50_000_000_000_000_000_000u128); // 50 CPH

        let validators = vec![GenesisValidatorData {
            address: addr,
            bls_pubkey: [99u8; 48],
            stake,
        }];

        let precompile = StakingPrecompile::from_genesis_validators(validators);

        // Verify state is properly initialized
        let state = precompile.state.read();
        assert_eq!(state.validators.len(), 1);
        assert!(state.is_validator(&addr));
        assert_eq!(state.get_stake(&addr), stake);
    }

    #[test]
    fn test_genesis_validators_can_be_queried_via_precompile() {
        // Test that genesis validators can be queried via the precompile interface
        let addr = Address::with_last_byte(120);
        let stake = U256::from(32_000_000_000_000_000_000u128);

        let validators = vec![GenesisValidatorData {
            address: addr,
            bls_pubkey: [77u8; 48],
            stake,
        }];

        let precompile = StakingPrecompile::from_genesis_validators(validators);

        // Query stake via getStake() function
        let mut input = vec![0x7a, 0x76, 0x64, 0x60]; // selector for getStake
        let mut addr_bytes = [0u8; 32];
        addr_bytes[12..32].copy_from_slice(addr.as_slice());
        input.extend_from_slice(&addr_bytes);

        let result = precompile.run(&Bytes::from(input), 100_000, Address::ZERO, U256::ZERO, 1);

        assert!(result.is_ok());
        let output = result.unwrap();
        let returned_stake = U256::from_be_slice(&output.bytes);
        assert_eq!(returned_stake, stake);
    }

    #[test]
    fn test_genesis_validators_appear_in_validator_set() {
        // Test that genesis validators appear in getValidatorSet()
        let addr1 = Address::with_last_byte(130);
        let stake1 = U256::from(32_000_000_000_000_000_000u128);

        let addr2 = Address::with_last_byte(131);
        let stake2 = U256::from(64_000_000_000_000_000_000u128);

        let validators = vec![
            GenesisValidatorData {
                address: addr1,
                bls_pubkey: [1u8; 48],
                stake: stake1,
            },
            GenesisValidatorData {
                address: addr2,
                bls_pubkey: [2u8; 48],
                stake: stake2,
            },
        ];

        let precompile = StakingPrecompile::from_genesis_validators(validators);

        // Query validator set via getValidatorSet() function
        let input = vec![0xcf, 0x33, 0x12, 0x50]; // selector for getValidatorSet

        let result = precompile.run(&Bytes::from(input), 100_000, Address::ZERO, U256::ZERO, 1);

        assert!(result.is_ok());
        let output = result.unwrap();

        // Verify gas cost reflects 2 validators
        let expected_gas = gas::GET_VALIDATOR_SET_BASE + (gas::GET_VALIDATOR_SET_PER_VALIDATOR * 2);
        assert_eq!(output.gas_used, expected_gas);

        // Output should contain encoded validator set
        assert!(!output.bytes.is_empty());
    }

    #[test]
    fn test_genesis_validator_can_register_additional_stake() {
        // Test that a genesis validator can add more stake via registerValidator
        let addr = Address::with_last_byte(140);
        let initial_stake = U256::from(32_000_000_000_000_000_000u128);

        let validators = vec![GenesisValidatorData {
            address: addr,
            bls_pubkey: [88u8; 48],
            stake: initial_stake,
        }];

        let precompile = StakingPrecompile::from_genesis_validators(validators);

        // Verify initial state
        {
            let state = precompile.state.read();
            assert_eq!(state.get_stake(&addr), initial_stake);
        }

        // Try to register again (should fail - already a validator)
        let mut input = vec![0x60, 0x70, 0x49, 0xd8]; // selector for registerValidator
        input.extend_from_slice(&[1u8; 32]); // BLS pubkey
        let additional_stake = U256::from(10_000_000_000_000_000_000u128);

        let result = precompile.run(&Bytes::from(input), 100_000, addr, additional_stake, 1);

        // Should fail because validator is already registered
        assert!(result.is_err());
    }
}
