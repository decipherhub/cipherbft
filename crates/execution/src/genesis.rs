//! EVM genesis state initialization for CipherBFT.
//!
//! This module handles initializing EVM state from genesis alloc entries
//! and bootstrapping the staking precompile storage.
//!
//! # Responsibilities
//!
//! - Initialize account balances from genesis alloc
//! - Deploy contract bytecode from genesis alloc
//! - Set initial storage from genesis alloc
//! - Bootstrap staking precompile (0x100) with validator stake data
//!
//! # Staking Precompile Storage Layout
//!
//! The staking precompile at address 0x100 has a sequential storage layout:
//!
//! ```text
//! Slot 0: version (uint256) = 1
//! Slot 1: validatorCount (uint256)
//! Slot 2: totalStaked (uint256)
//! Slot 3+: Validator entries (3 slots each)
//!   - Slot +0: address (left-padded to 32 bytes)
//!   - Slot +1: stakedAmount (uint256)
//!   - Slot +2: votingPower (uint256)
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use cipherbft_execution::genesis::GenesisInitializer;
//! use cipherbft_execution::InMemoryProvider;
//! use cipherbft_types::genesis::Genesis;
//!
//! let provider = InMemoryProvider::new();
//! let initializer = GenesisInitializer::new(&provider);
//!
//! let genesis = Genesis::load(Path::new("genesis.json"))?;
//! let result = initializer.initialize(&genesis)?;
//!
//! println!("Initialized {} accounts", result.account_count);
//! println!("Registered {} validators", result.validator_count);
//! ```

use crate::database::{Account, Provider};
use crate::error::{DatabaseError, ExecutionError, Result};
use crate::precompiles::STAKING_PRECOMPILE_ADDRESS;
use crate::rlp::KECCAK_EMPTY;
use alloy_primitives::{keccak256, Address, B256, U256};
use cipherbft_types::genesis::{BootstrapResult, Genesis, GenesisValidator};
use revm_state::Bytecode;
use std::sync::Arc;

/// Storage slot indices for the staking precompile.
mod staking_slots {
    use alloy_primitives::U256;

    /// Storage version (always 1)
    pub const VERSION: U256 = U256::ZERO;
    /// Number of validators
    pub const VALIDATOR_COUNT: U256 = U256::from_limbs([1, 0, 0, 0]);
    /// Total staked amount
    pub const TOTAL_STAKED: U256 = U256::from_limbs([2, 0, 0, 0]);
    /// First validator entry starts at slot 3
    pub const VALIDATORS_START: U256 = U256::from_limbs([3, 0, 0, 0]);
    /// Each validator occupies 3 slots
    pub const SLOTS_PER_VALIDATOR: u64 = 3;
}

/// Genesis state initializer for the EVM.
///
/// Handles the one-time initialization of EVM state from a genesis configuration,
/// including account balances, contract deployments, and staking precompile setup.
pub struct GenesisInitializer<P: Provider> {
    provider: Arc<P>,
}

impl<P: Provider> GenesisInitializer<P> {
    /// Create a new genesis initializer with the given provider.
    ///
    /// # Arguments
    ///
    /// * `provider` - The storage provider to write genesis state to
    pub fn new(provider: Arc<P>) -> Self {
        Self { provider }
    }

    /// Initialize EVM state from a genesis configuration.
    ///
    /// This method performs the following steps:
    /// 1. Validates the genesis configuration
    /// 2. Initializes all accounts from the `alloc` section
    /// 3. Deploys any contract bytecode
    /// 4. Sets initial storage values
    /// 5. Initializes treasury account if configured
    /// 6. Bootstraps the staking precompile with validator data
    ///
    /// # Arguments
    ///
    /// * `genesis` - The validated genesis configuration
    ///
    /// # Returns
    ///
    /// Returns a `BootstrapResult` containing initialization statistics.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Genesis validation fails
    /// - Provider operations fail
    pub fn initialize(&self, genesis: &Genesis) -> Result<BootstrapResult> {
        // Validate genesis first
        genesis
            .validate()
            .map_err(|e| ExecutionError::config(format!("Genesis validation failed: {}", e)))?;

        // Initialize accounts from alloc
        let mut account_count = self.initialize_alloc(genesis)?;

        // Initialize treasury account if configured
        if let Some(treasury_account_created) = self.initialize_treasury(genesis)? {
            if treasury_account_created {
                account_count += 1;
            }
        }

        // Bootstrap staking precompile with validator data
        let (validator_count, total_staked) = self.initialize_staking_precompile(genesis)?;

        // Compute genesis hash (simplified - just hash of chain_id for now)
        // In production, this would be the hash of the genesis block header
        let genesis_hash = self.compute_genesis_hash(genesis);

        Ok(BootstrapResult::new(
            validator_count,
            total_staked,
            account_count,
            genesis.chain_id(),
            genesis_hash,
        ))
    }

    /// Initialize accounts from the genesis alloc section.
    ///
    /// For each entry in `alloc`:
    /// - Creates the account with balance and nonce
    /// - Stores contract bytecode if present
    /// - Sets initial storage slots
    fn initialize_alloc(&self, genesis: &Genesis) -> Result<usize> {
        let mut count = 0;

        for (address, entry) in &genesis.alloc {
            // Compute code hash
            let (code_hash, has_code) = if let Some(code) = &entry.code {
                if code.is_empty() {
                    (KECCAK_EMPTY, false)
                } else {
                    let hash = keccak256(code.as_ref());
                    // Store the bytecode
                    let bytecode = Bytecode::new_raw(code.clone());
                    self.provider.set_code(hash, bytecode).map_err(|e| {
                        ExecutionError::Database(DatabaseError::mdbx(format!(
                            "Failed to store code for {}: {}",
                            address, e
                        )))
                    })?;
                    (hash, true)
                }
            } else {
                (KECCAK_EMPTY, false)
            };

            // Create account
            let account = Account {
                nonce: entry.nonce.unwrap_or(if has_code { 1 } else { 0 }),
                balance: entry.balance,
                code_hash,
                storage_root: B256::ZERO, // Will be computed during state root calculation
            };

            self.provider.set_account(*address, account).map_err(|e| {
                ExecutionError::Database(DatabaseError::mdbx(format!(
                    "Failed to set account {}: {}",
                    address, e
                )))
            })?;

            // Set initial storage
            for (slot, value) in &entry.storage {
                let slot_u256 = U256::from_be_bytes(slot.0);
                let value_u256 = U256::from_be_bytes(value.0);

                self.provider
                    .set_storage(*address, slot_u256, value_u256)
                    .map_err(|e| {
                        ExecutionError::Database(DatabaseError::mdbx(format!(
                            "Failed to set storage for {} slot {}: {}",
                            address, slot, e
                        )))
                    })?;
            }

            count += 1;
        }

        Ok(count)
    }

    /// Initialize the treasury account if configured in genesis.
    ///
    /// The treasury provides the initial token supply for the network.
    /// Rewards distributed to validators are minted from the system,
    /// and the treasury serves as a reserve for ecosystem funding.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(true))` - Treasury account was created (not in alloc)
    /// - `Ok(Some(false))` - Treasury was in alloc, balance updated
    /// - `Ok(None)` - No treasury configured
    fn initialize_treasury(&self, genesis: &Genesis) -> Result<Option<bool>> {
        let staking = &genesis.cipherbft.staking;

        // Check if treasury is configured
        let (treasury_addr, supply) = match (
            &staking.treasury_address,
            &staking.initial_treasury_supply_wei,
        ) {
            (Some(addr), Some(supply)) if !supply.is_zero() => (*addr, *supply),
            _ => return Ok(None), // No treasury configured or zero supply
        };

        // Check if treasury address is already in alloc
        let already_in_alloc = genesis.alloc.contains_key(&treasury_addr);

        if already_in_alloc {
            // Treasury address exists in alloc - the alloc balance takes precedence
            // but we log this situation for transparency
            tracing::info!(
                treasury = %treasury_addr,
                alloc_balance = %genesis.alloc[&treasury_addr].balance,
                configured_supply = %supply,
                "Treasury address found in alloc, using alloc balance"
            );
            Ok(Some(false))
        } else {
            // Create new treasury account with the configured supply
            let treasury_account = Account {
                nonce: 0,
                balance: supply,
                code_hash: KECCAK_EMPTY,
                storage_root: B256::ZERO,
            };

            self.provider
                .set_account(treasury_addr, treasury_account)
                .map_err(|e| {
                    ExecutionError::Database(DatabaseError::mdbx(format!(
                        "Failed to create treasury account {}: {}",
                        treasury_addr, e
                    )))
                })?;

            tracing::info!(
                treasury = %treasury_addr,
                supply = %supply,
                "Treasury account initialized at genesis"
            );

            Ok(Some(true))
        }
    }

    /// Initialize the staking precompile with validator data.
    ///
    /// Sets up the storage layout at address 0x100:
    /// - Slot 0: version = 1
    /// - Slot 1: validatorCount
    /// - Slot 2: totalStaked
    /// - Slot 3+: Validator entries (3 slots each)
    fn initialize_staking_precompile(&self, genesis: &Genesis) -> Result<(usize, U256)> {
        let validators = &genesis.cipherbft.validators;
        let validator_count = validators.len();
        let total_staked = genesis.total_staked();

        // Create staking precompile account (no code, just storage)
        let staking_account = Account {
            nonce: 0,
            balance: U256::ZERO, // Precompile doesn't hold funds
            code_hash: KECCAK_EMPTY,
            storage_root: B256::ZERO,
        };

        self.provider
            .set_account(STAKING_PRECOMPILE_ADDRESS, staking_account)
            .map_err(|e| {
                ExecutionError::Database(DatabaseError::mdbx(format!(
                    "Failed to create staking precompile account: {}",
                    e
                )))
            })?;

        // Set version = 1
        self.set_staking_storage(staking_slots::VERSION, U256::from(1))?;

        // Set validator count
        self.set_staking_storage(staking_slots::VALIDATOR_COUNT, U256::from(validator_count))?;

        // Set total staked
        self.set_staking_storage(staking_slots::TOTAL_STAKED, total_staked)?;

        // Set validator entries
        for (i, validator) in validators.iter().enumerate() {
            self.write_validator_entry(i, validator, total_staked)?;
        }

        Ok((validator_count, total_staked))
    }

    /// Write a single validator entry to staking precompile storage.
    ///
    /// Each validator occupies 3 consecutive storage slots:
    /// - Slot base+0: address (left-padded to 32 bytes)
    /// - Slot base+1: stakedAmount
    /// - Slot base+2: votingPower (proportional to stake)
    fn write_validator_entry(
        &self,
        index: usize,
        validator: &GenesisValidator,
        total_staked: U256,
    ) -> Result<()> {
        let base_slot = staking_slots::VALIDATORS_START
            + U256::from(index as u64 * staking_slots::SLOTS_PER_VALIDATOR);

        // Slot +0: Address (left-padded to 32 bytes)
        let address_slot = base_slot;
        let address_value = address_to_u256(validator.address);
        self.set_staking_storage(address_slot, address_value)?;

        // Slot +1: Staked amount
        let stake_slot = base_slot + U256::from(1);
        self.set_staking_storage(stake_slot, validator.staked_amount)?;

        // Slot +2: Voting power (proportional to stake, scaled to basis points 10000)
        let power_slot = base_slot + U256::from(2);
        let voting_power = if total_staked.is_zero() {
            U256::ZERO
        } else {
            // Calculate voting power as percentage * 10000 (basis points)
            // voting_power = (stake * 10000) / total_staked
            validator
                .staked_amount
                .checked_mul(U256::from(10000))
                .and_then(|v| v.checked_div(total_staked))
                .unwrap_or(U256::ZERO)
        };
        self.set_staking_storage(power_slot, voting_power)?;

        Ok(())
    }

    /// Helper to set storage on the staking precompile.
    fn set_staking_storage(&self, slot: U256, value: U256) -> Result<()> {
        self.provider
            .set_storage(STAKING_PRECOMPILE_ADDRESS, slot, value)
            .map_err(|e| {
                ExecutionError::Database(DatabaseError::mdbx(format!(
                    "Failed to set staking precompile storage slot {}: {}",
                    slot, e
                )))
            })
    }

    /// Compute a genesis hash from the configuration.
    ///
    /// This is a simplified implementation that hashes key genesis parameters.
    /// In production, this would be the proper genesis block header hash.
    fn compute_genesis_hash(&self, genesis: &Genesis) -> B256 {
        // Hash chain_id + network_id + total_staked + validator_count
        let mut data = Vec::new();
        data.extend_from_slice(&genesis.chain_id().to_be_bytes());
        data.extend_from_slice(genesis.cipherbft.network_id.as_bytes());
        data.extend_from_slice(&genesis.total_staked().to_be_bytes::<32>());
        data.extend_from_slice(&(genesis.validator_count() as u64).to_be_bytes());
        keccak256(&data)
    }
}

/// Convert an address to a U256 (left-padded).
fn address_to_u256(address: Address) -> U256 {
    let mut bytes = [0u8; 32];
    bytes[12..32].copy_from_slice(address.as_slice());
    U256::from_be_bytes(bytes)
}

/// Read the number of validators from staking precompile storage.
///
/// Useful for validation and testing.
pub fn read_validator_count<P: Provider>(provider: &P) -> Result<usize> {
    let value = provider
        .get_storage(STAKING_PRECOMPILE_ADDRESS, staking_slots::VALIDATOR_COUNT)
        .map_err(|e| {
            ExecutionError::Database(DatabaseError::mdbx(format!(
                "Failed to read validator count: {}",
                e
            )))
        })?;

    Ok(value.to::<usize>())
}

/// Read the total staked amount from staking precompile storage.
///
/// Useful for validation and testing.
pub fn read_total_staked<P: Provider>(provider: &P) -> Result<U256> {
    provider
        .get_storage(STAKING_PRECOMPILE_ADDRESS, staking_slots::TOTAL_STAKED)
        .map_err(|e| {
            ExecutionError::Database(DatabaseError::mdbx(format!(
                "Failed to read total staked: {}",
                e
            )))
        })
}

/// Read a validator's staked amount from staking precompile storage.
///
/// # Arguments
///
/// * `provider` - The storage provider
/// * `index` - The validator index (0-based)
pub fn read_validator_stake<P: Provider>(provider: &P, index: usize) -> Result<U256> {
    let base_slot = staking_slots::VALIDATORS_START
        + U256::from(index as u64 * staking_slots::SLOTS_PER_VALIDATOR);
    let stake_slot = base_slot + U256::from(1);

    provider
        .get_storage(STAKING_PRECOMPILE_ADDRESS, stake_slot)
        .map_err(|e| {
            ExecutionError::Database(DatabaseError::mdbx(format!(
                "Failed to read validator {} stake: {}",
                index, e
            )))
        })
}

/// Read a validator's address from staking precompile storage.
///
/// # Arguments
///
/// * `provider` - The storage provider
/// * `index` - The validator index (0-based)
pub fn read_validator_address<P: Provider>(provider: &P, index: usize) -> Result<Address> {
    let base_slot = staking_slots::VALIDATORS_START
        + U256::from(index as u64 * staking_slots::SLOTS_PER_VALIDATOR);

    let value = provider
        .get_storage(STAKING_PRECOMPILE_ADDRESS, base_slot)
        .map_err(|e| {
            ExecutionError::Database(DatabaseError::mdbx(format!(
                "Failed to read validator {} address: {}",
                index, e
            )))
        })?;

    // Extract address from right 20 bytes
    let bytes = value.to_be_bytes::<32>();
    Ok(Address::from_slice(&bytes[12..32]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::InMemoryProvider;
    use cipherbft_types::genesis::{
        CipherBftConfig, ConsensusParams, DclParams, Genesis, GenesisValidator, NativeTokenConfig,
        StakingParams,
    };
    use cipherbft_types::geth::{AllocEntry, GethConfig};
    use std::collections::HashMap;
    use std::str::FromStr;

    fn sample_validator(addr: &str, stake_cph: u128) -> GenesisValidator {
        GenesisValidator {
            address: Address::from_str(addr).unwrap(),
            name: Some("test-validator".to_string()),
            ed25519_pubkey: "0x".to_owned() + &"a".repeat(64),
            bls_pubkey: "0x".to_owned() + &"b".repeat(96),
            staked_amount: U256::from(stake_cph * 1_000_000_000_000_000_000u128),
            commission_rate_percent: 10,
        }
    }

    fn sample_genesis(validators: Vec<GenesisValidator>) -> Genesis {
        let mut alloc = HashMap::new();

        // Add validator accounts to alloc
        for validator in &validators {
            alloc.insert(
                validator.address,
                AllocEntry::new(validator.staked_amount * U256::from(2)), // 2x stake as balance
            );
        }

        // Add a test EOA account
        let test_account = Address::from_str("0x1111111111111111111111111111111111111111").unwrap();
        alloc.insert(
            test_account,
            AllocEntry::new(U256::from(100_000_000_000_000_000_000u128)), // 100 CPH
        );

        Genesis {
            config: GethConfig::new(85300),
            alloc,
            gas_limit: U256::from(30_000_000u64),
            difficulty: U256::from(1u64),
            nonce: Some(U256::ZERO),
            timestamp: Some(U256::ZERO),
            extra_data: None,
            mix_hash: None,
            coinbase: None,
            cipherbft: CipherBftConfig {
                genesis_time: "2024-01-15T00:00:00Z".to_string(),
                network_id: "cipherbft-testnet-1".to_string(),
                native_token: NativeTokenConfig::default(),
                consensus: ConsensusParams::default(),
                dcl: DclParams::default(),
                staking: StakingParams::default(),
                validators,
            },
        }
    }

    #[test]
    fn test_genesis_initialization_single_validator() {
        let provider = Arc::new(InMemoryProvider::new());
        let initializer = GenesisInitializer::new(provider.clone());

        let validator = sample_validator("0x742d35Cc6634C0532925a3b844Bc9e7595f0bC01", 32);
        let genesis = sample_genesis(vec![validator.clone()]);

        let result = initializer.initialize(&genesis).unwrap();

        // Check bootstrap result
        assert_eq!(result.validator_count, 1);
        assert_eq!(result.account_count, 2); // validator + test account
        assert_eq!(result.chain_id, 85300);
        assert_eq!(
            result.total_staked,
            U256::from(32_000_000_000_000_000_000u128)
        );

        // Verify staking precompile storage
        assert_eq!(read_validator_count(&*provider).unwrap(), 1);
        assert_eq!(
            read_total_staked(&*provider).unwrap(),
            U256::from(32_000_000_000_000_000_000u128)
        );
        assert_eq!(
            read_validator_address(&*provider, 0).unwrap(),
            validator.address
        );
        assert_eq!(
            read_validator_stake(&*provider, 0).unwrap(),
            U256::from(32_000_000_000_000_000_000u128)
        );

        // Verify validator account was created
        let account = provider.get_account(validator.address).unwrap().unwrap();
        assert_eq!(account.balance, U256::from(64_000_000_000_000_000_000u128));
        // 2x stake
    }

    #[test]
    fn test_genesis_initialization_multiple_validators() {
        let provider = Arc::new(InMemoryProvider::new());
        let initializer = GenesisInitializer::new(provider.clone());

        let validators = vec![
            sample_validator("0x742d35Cc6634C0532925a3b844Bc9e7595f0bC01", 32), // 32 CPH
            sample_validator("0x853d35Cc6634C0532925a3b844Bc9e7595f0bC02", 48), // 48 CPH
            sample_validator("0x964d35Cc6634C0532925a3b844Bc9e7595f0bC03", 20), // 20 CPH
        ];

        let genesis = sample_genesis(validators.clone());
        let result = initializer.initialize(&genesis).unwrap();

        assert_eq!(result.validator_count, 3);
        assert_eq!(result.account_count, 4); // 3 validators + test account

        // Total staked = 32 + 48 + 20 = 100 CPH
        let expected_total = U256::from(100_000_000_000_000_000_000u128);
        assert_eq!(result.total_staked, expected_total);
        assert_eq!(read_total_staked(&*provider).unwrap(), expected_total);

        // Verify each validator
        for (i, validator) in validators.iter().enumerate() {
            assert_eq!(
                read_validator_address(&*provider, i).unwrap(),
                validator.address
            );
            assert_eq!(
                read_validator_stake(&*provider, i).unwrap(),
                validator.staked_amount
            );
        }
    }

    #[test]
    fn test_genesis_initialization_with_contract() {
        let provider = Arc::new(InMemoryProvider::new());
        let initializer = GenesisInitializer::new(provider.clone());

        let validator = sample_validator("0x742d35Cc6634C0532925a3b844Bc9e7595f0bC01", 32);
        let mut genesis = sample_genesis(vec![validator]);

        // Add a contract with bytecode and storage
        let contract_addr =
            Address::from_str("0x2222222222222222222222222222222222222222").unwrap();
        let code = alloy_primitives::Bytes::from(vec![0x60, 0x80, 0x60, 0x40, 0x52]); // Simple bytecode
        let mut storage = HashMap::new();
        storage.insert(B256::ZERO, B256::from(U256::from(42).to_be_bytes::<32>()));

        genesis.alloc.insert(
            contract_addr,
            AllocEntry::contract(U256::ZERO, code.clone()).with_storage(storage),
        );

        let result = initializer.initialize(&genesis).unwrap();
        assert_eq!(result.account_count, 3); // validator + test account + contract

        // Verify contract was deployed
        let account = provider.get_account(contract_addr).unwrap().unwrap();
        assert_ne!(account.code_hash, KECCAK_EMPTY);
        assert_eq!(account.nonce, 1); // Contracts start with nonce 1

        // Verify code was stored
        let stored_code = provider.get_code(account.code_hash).unwrap();
        assert!(stored_code.is_some());

        // Verify storage was set
        let storage_value = provider.get_storage(contract_addr, U256::ZERO).unwrap();
        assert_eq!(storage_value, U256::from(42));
    }

    #[test]
    fn test_address_to_u256() {
        let addr = Address::from_str("0x742d35Cc6634C0532925a3b844Bc9e7595f0bC01").unwrap();
        let value = address_to_u256(addr);

        // Extract address back from U256
        let bytes = value.to_be_bytes::<32>();
        let recovered = Address::from_slice(&bytes[12..32]);
        assert_eq!(recovered, addr);
    }

    #[test]
    fn test_voting_power_calculation() {
        let provider = Arc::new(InMemoryProvider::new());
        let initializer = GenesisInitializer::new(provider.clone());

        // Create validators with known stakes: 25%, 50%, 25%
        let validators = vec![
            sample_validator("0x742d35Cc6634C0532925a3b844Bc9e7595f0bC01", 25),
            sample_validator("0x853d35Cc6634C0532925a3b844Bc9e7595f0bC02", 50),
            sample_validator("0x964d35Cc6634C0532925a3b844Bc9e7595f0bC03", 25),
        ];

        let genesis = sample_genesis(validators);
        initializer.initialize(&genesis).unwrap();

        // Read voting powers (should be in basis points: 2500, 5000, 2500)
        let power_0 = provider
            .get_storage(
                STAKING_PRECOMPILE_ADDRESS,
                staking_slots::VALIDATORS_START + U256::from(2),
            )
            .unwrap();
        let power_1 = provider
            .get_storage(
                STAKING_PRECOMPILE_ADDRESS,
                staking_slots::VALIDATORS_START + U256::from(5),
            )
            .unwrap();
        let power_2 = provider
            .get_storage(
                STAKING_PRECOMPILE_ADDRESS,
                staking_slots::VALIDATORS_START + U256::from(8),
            )
            .unwrap();

        assert_eq!(power_0, U256::from(2500)); // 25%
        assert_eq!(power_1, U256::from(5000)); // 50%
        assert_eq!(power_2, U256::from(2500)); // 25%
    }

    #[test]
    fn test_staking_precompile_account_created() {
        let provider = Arc::new(InMemoryProvider::new());
        let initializer = GenesisInitializer::new(provider.clone());

        let validator = sample_validator("0x742d35Cc6634C0532925a3b844Bc9e7595f0bC01", 32);
        let genesis = sample_genesis(vec![validator]);

        initializer.initialize(&genesis).unwrap();

        // Verify staking precompile account exists
        let account = provider
            .get_account(STAKING_PRECOMPILE_ADDRESS)
            .unwrap()
            .unwrap();

        assert_eq!(account.balance, U256::ZERO);
        assert_eq!(account.nonce, 0);
        assert_eq!(account.code_hash, KECCAK_EMPTY);
    }

    #[test]
    fn test_staking_precompile_version() {
        let provider = Arc::new(InMemoryProvider::new());
        let initializer = GenesisInitializer::new(provider.clone());

        let validator = sample_validator("0x742d35Cc6634C0532925a3b844Bc9e7595f0bC01", 32);
        let genesis = sample_genesis(vec![validator]);

        initializer.initialize(&genesis).unwrap();

        // Verify version is set to 1
        let version = provider
            .get_storage(STAKING_PRECOMPILE_ADDRESS, staking_slots::VERSION)
            .unwrap();
        assert_eq!(version, U256::from(1));
    }

    #[test]
    fn test_genesis_hash_deterministic() {
        let provider1 = Arc::new(InMemoryProvider::new());
        let provider2 = Arc::new(InMemoryProvider::new());

        let initializer1 = GenesisInitializer::new(provider1);
        let initializer2 = GenesisInitializer::new(provider2);

        let validator = sample_validator("0x742d35Cc6634C0532925a3b844Bc9e7595f0bC01", 32);
        let genesis = sample_genesis(vec![validator]);

        let result1 = initializer1.initialize(&genesis).unwrap();
        let result2 = initializer2.initialize(&genesis).unwrap();

        // Genesis hash should be deterministic
        assert_eq!(result1.genesis_hash, result2.genesis_hash);
    }

    #[test]
    fn test_treasury_initialization() {
        let provider = Arc::new(InMemoryProvider::new());
        let initializer = GenesisInitializer::new(provider.clone());

        let validator = sample_validator("0x742d35Cc6634C0532925a3b844Bc9e7595f0bC01", 32);
        let mut genesis = sample_genesis(vec![validator]);

        // Configure treasury
        let treasury_addr =
            Address::from_str("0x000000000000000000000000000000000000CAFE").unwrap();
        let treasury_supply = U256::from(100_000_000_000_000_000_000_000u128); // 100,000 tokens

        genesis.cipherbft.staking.treasury_address = Some(treasury_addr);
        genesis.cipherbft.staking.initial_treasury_supply_wei = Some(treasury_supply);

        let result = initializer.initialize(&genesis).unwrap();

        // Treasury should be counted in account_count
        // 1 validator + 1 test account + 1 treasury = 3
        assert_eq!(result.account_count, 3);

        // Verify treasury account was created with correct balance
        let account = provider.get_account(treasury_addr).unwrap().unwrap();
        assert_eq!(account.balance, treasury_supply);
        assert_eq!(account.nonce, 0);
        assert_eq!(account.code_hash, KECCAK_EMPTY);
    }

    #[test]
    fn test_treasury_already_in_alloc() {
        let provider = Arc::new(InMemoryProvider::new());
        let initializer = GenesisInitializer::new(provider.clone());

        let validator = sample_validator("0x742d35Cc6634C0532925a3b844Bc9e7595f0bC01", 32);
        let mut genesis = sample_genesis(vec![validator]);

        // Configure treasury at an address that's already in alloc
        let treasury_addr =
            Address::from_str("0x000000000000000000000000000000000000CAFE").unwrap();
        let treasury_supply = U256::from(100_000_000_000_000_000_000_000u128);
        let alloc_balance = U256::from(50_000_000_000_000_000_000_000u128); // Different balance

        // Add treasury to alloc with different balance
        genesis
            .alloc
            .insert(treasury_addr, AllocEntry::new(alloc_balance));

        genesis.cipherbft.staking.treasury_address = Some(treasury_addr);
        genesis.cipherbft.staking.initial_treasury_supply_wei = Some(treasury_supply);

        let result = initializer.initialize(&genesis).unwrap();

        // Treasury already in alloc, so account_count should be:
        // 1 validator + 1 test account + 1 treasury (in alloc) = 3
        assert_eq!(result.account_count, 3);

        // Alloc balance should take precedence
        let account = provider.get_account(treasury_addr).unwrap().unwrap();
        assert_eq!(account.balance, alloc_balance);
    }

    #[test]
    fn test_no_treasury_configured() {
        let provider = Arc::new(InMemoryProvider::new());
        let initializer = GenesisInitializer::new(provider.clone());

        let validator = sample_validator("0x742d35Cc6634C0532925a3b844Bc9e7595f0bC01", 32);
        let genesis = sample_genesis(vec![validator]);

        // No treasury configured (default)
        assert!(genesis.cipherbft.staking.treasury_address.is_none());

        let result = initializer.initialize(&genesis).unwrap();

        // Only validator + test account = 2
        assert_eq!(result.account_count, 2);
    }
}
