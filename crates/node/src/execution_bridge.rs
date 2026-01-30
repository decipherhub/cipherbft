//! Execution layer integration bridge
//!
//! This module provides the bridge between the consensus layer (data-chain)
//! and the execution layer, enabling transaction validation and Cut execution.

use cipherbft_data_chain::worker::TransactionValidator;
use cipherbft_execution::{
    keccak256, Address, BlockInput, Bytes, Car as ExecutionCar, ChainConfig, Cut as ExecutionCut,
    ExecutionEngine, ExecutionLayerTrait, ExecutionResult, GenesisInitializer,
    GenesisValidatorData, MdbxProvider, StakingPrecompile, B256, U256,
};
use cipherbft_storage::{Database, DatabaseConfig, DclStore, EvmStore, MdbxEvmStore};
use cipherbft_types::genesis::Genesis;
use std::path::Path;
use std::sync::Arc;
use std::sync::RwLock as StdRwLock;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Result of block execution with computed block hash and parent hash.
///
/// This extends `ExecutionResult` with the properly computed block hash
/// and parent hash needed for RPC responses and chain connectivity.
#[derive(Debug, Clone)]
pub struct BlockExecutionResult {
    /// The underlying execution result
    pub execution_result: ExecutionResult,
    /// The computed block hash (keccak256 of block header fields)
    pub block_hash: B256,
    /// The parent block hash (hash of the previous block)
    pub parent_hash: B256,
    /// The block timestamp
    pub timestamp: u64,
    /// Raw executed transactions (RLP-encoded bytes) for storage.
    ///
    /// These are the transactions that were included in the block,
    /// in execution order. Used by the node to store transactions
    /// for `eth_getTransactionByHash` RPC queries.
    pub executed_transactions: Vec<Bytes>,
}

/// Bridge between consensus and execution layers
///
/// Maintains the connection between the consensus layer and the execution layer,
/// tracking block hashes to ensure proper chain connectivity.
///
/// Uses `MdbxProvider` for persistent EVM state storage, ensuring state
/// survives node restarts.
pub struct ExecutionBridge {
    /// Execution layer instance with persistent MDBX storage
    execution: Arc<RwLock<ExecutionEngine<MdbxProvider>>>,
    /// DCL storage for batch lookups
    dcl_store: Arc<dyn DclStore>,
    /// Hash of the last executed block (used as parent hash for the next block)
    ///
    /// Initialized to B256::ZERO for the genesis block.
    /// Updated after each successful block execution.
    last_block_hash: StdRwLock<B256>,
    /// Block gas limit from genesis configuration.
    /// Used when creating Cuts and blocks.
    gas_limit: u64,
}

impl ExecutionBridge {
    /// Create a new execution bridge with persistent MDBX storage.
    ///
    /// # Arguments
    ///
    /// * `config` - Chain configuration for the execution layer
    /// * `dcl_store` - DCL storage for batch lookups
    /// * `data_dir` - Directory for persistent EVM state storage
    ///
    /// # Note
    /// This creates an execution bridge with an empty staking state.
    /// For production use, prefer `from_genesis` to initialize the staking
    /// state from the genesis file.
    pub fn new(
        config: ChainConfig,
        dcl_store: Arc<dyn DclStore>,
        data_dir: &Path,
    ) -> anyhow::Result<Self> {
        let gas_limit = config.block_gas_limit;

        // Create MDBX database for EVM state persistence
        let evm_db_path = data_dir.join("evm_storage");
        std::fs::create_dir_all(&evm_db_path)?;
        let evm_db_config = DatabaseConfig::new(&evm_db_path);
        let evm_database = Database::open(evm_db_config)
            .map_err(|e| anyhow::anyhow!("Failed to open EVM storage database: {}", e))?;
        let evm_store = MdbxEvmStore::new(Arc::clone(evm_database.env()));
        let provider = MdbxProvider::new(evm_store);

        info!("Created persistent EVM store at {}", evm_db_path.display());

        let execution = ExecutionEngine::new(config, provider);

        Ok(Self {
            execution: Arc::new(RwLock::new(execution)),
            dcl_store,
            // Genesis block has no parent, so initialize to zero
            last_block_hash: StdRwLock::new(B256::ZERO),
            gas_limit,
        })
    }

    /// Create a new execution bridge initialized from genesis with persistent MDBX storage.
    ///
    /// This is the primary constructor for production use. It initializes the
    /// staking precompile with the validator set from the genesis file, ensuring
    /// the validator state is correctly populated on node startup.
    ///
    /// The EVM state is persisted to MDBX, ensuring state survives node restarts.
    ///
    /// # Arguments
    ///
    /// * `config` - Chain configuration for the execution layer
    /// * `dcl_store` - DCL storage for batch lookups
    /// * `genesis` - Genesis configuration containing validator set
    /// * `data_dir` - Directory for persistent EVM state storage
    ///
    /// # Returns
    ///
    /// A new `ExecutionBridge` with staking state initialized from genesis validators
    /// and persistent EVM storage.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let genesis = GenesisLoader::load_and_validate(path)?;
    /// let bridge = ExecutionBridge::from_genesis(config, dcl_store, &genesis, &data_dir)?;
    /// ```
    pub fn from_genesis(
        config: ChainConfig,
        dcl_store: Arc<dyn DclStore>,
        genesis: &Genesis,
        data_dir: &Path,
    ) -> anyhow::Result<Self> {
        // Convert genesis validators to execution layer format
        let genesis_validators: Vec<GenesisValidatorData> = genesis
            .cipherbft
            .validators
            .iter()
            .filter_map(|v| {
                // Parse BLS public key (strip 0x prefix if present)
                let bls_hex = v.bls_pubkey.trim_start_matches("0x");
                let bls_bytes = match hex::decode(bls_hex) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        warn!(
                            address = %v.address,
                            error = %e,
                            "Failed to parse BLS public key, skipping validator"
                        );
                        return None;
                    }
                };

                if bls_bytes.len() != 48 {
                    warn!(
                        address = %v.address,
                        expected = 48,
                        actual = bls_bytes.len(),
                        "Invalid BLS public key length, skipping validator"
                    );
                    return None;
                }

                let mut bls_pubkey = [0u8; 48];
                bls_pubkey.copy_from_slice(&bls_bytes);

                Some(GenesisValidatorData {
                    address: v.address,
                    bls_pubkey,
                    stake: v.staked_amount,
                })
            })
            .collect();

        // Extract gas_limit from genesis (convert U256 to u64 safely)
        let gas_limit: u64 = genesis.gas_limit.try_into().unwrap_or(30_000_000);

        info!(
            validator_count = genesis_validators.len(),
            total_stake = %genesis.total_staked(),
            gas_limit = gas_limit,
            "Initializing execution layer from genesis with persistent storage"
        );

        // Create MDBX database for EVM state persistence
        let evm_db_path = data_dir.join("evm_storage");
        std::fs::create_dir_all(&evm_db_path)?;
        let evm_db_config = DatabaseConfig::new(&evm_db_path);
        let evm_database = Database::open(evm_db_config)
            .map_err(|e| anyhow::anyhow!("Failed to open EVM storage database: {}", e))?;
        let evm_store = MdbxEvmStore::new(Arc::clone(evm_database.env()));

        // Check if this is a fresh database or a restart by checking for existing state.
        // If current_block is already set, the database has state from previous execution
        // and we should NOT re-initialize genesis (which would overwrite all state).
        let needs_genesis_init = evm_store
            .get_current_block()
            .map(|opt| opt.is_none())
            .unwrap_or(true);

        let provider = MdbxProvider::new(evm_store);

        info!("Created persistent EVM store at {}", evm_db_path.display());

        // Create Arc wrapper for provider (needed for GenesisInitializer)
        let provider_arc = Arc::new(provider);

        if needs_genesis_init {
            // Initialize genesis allocations (balances, contracts, storage)
            // This must be done BEFORE creating the ExecutionEngine so that
            // eth_getBalance and other RPC queries can see the initial state.
            let initializer = GenesisInitializer::new(Arc::clone(&provider_arc));
            let bootstrap_result = initializer
                .initialize(genesis)
                .map_err(|e| anyhow::anyhow!("Failed to initialize genesis state: {}", e))?;

            info!(
                accounts = bootstrap_result.account_count,
                validators = bootstrap_result.validator_count,
                total_staked = %bootstrap_result.total_staked,
                genesis_hash = %bootstrap_result.genesis_hash,
                "Genesis state initialized to persistent storage"
            );
        } else {
            // Database already has state - this is a node restart
            info!("Existing EVM state found, skipping genesis initialization (node restart)");
        }

        // Unwrap the Arc to get ownership of the provider for ExecutionEngine
        // This is safe because we just created the Arc and initializer is done
        let provider = Arc::try_unwrap(provider_arc)
            .map_err(|_| anyhow::anyhow!("Failed to unwrap provider Arc - unexpected reference"))?;

        let execution =
            ExecutionEngine::with_genesis_validators(config, provider, genesis_validators);

        Ok(Self {
            execution: Arc::new(RwLock::new(execution)),
            dcl_store,
            // Genesis block has no parent, so initialize to zero
            last_block_hash: StdRwLock::new(B256::ZERO),
            gas_limit,
        })
    }

    /// Get the configured block gas limit.
    pub fn gas_limit(&self) -> u64 {
        self.gas_limit
    }

    /// Validate a transaction for mempool CheckTx
    ///
    /// This is called by workers before accepting transactions into batches.
    ///
    /// # Arguments
    ///
    /// * `tx` - Transaction bytes to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if valid, or an error describing the validation failure.
    pub async fn check_tx(&self, tx: &[u8]) -> anyhow::Result<()> {
        let execution = self.execution.read().await;
        let tx_bytes = Bytes::copy_from_slice(tx);

        execution
            .validate_transaction(&tx_bytes)
            .map_err(|e| anyhow::anyhow!("Transaction validation failed: {}", e))
    }

    /// Execute a finalized Cut from consensus
    ///
    /// This is called when the Primary produces a CutReady event.
    /// After successful execution, updates the `last_block_hash` for chain connectivity.
    ///
    /// # Arguments
    ///
    /// * `consensus_cut` - Finalized Cut with ordered transactions from consensus layer
    ///
    /// # Returns
    ///
    /// Returns `BlockExecutionResult` containing execution result with properly computed
    /// block hash and parent hash for RPC responses.
    pub async fn execute_cut(
        &self,
        consensus_cut: cipherbft_data_chain::Cut,
    ) -> anyhow::Result<BlockExecutionResult> {
        // Count total batch digests across all cars
        let total_batches: usize = consensus_cut
            .cars
            .values()
            .map(|car| car.batch_digests.len())
            .sum();

        info!(
            height = consensus_cut.height,
            cars = consensus_cut.cars.len(),
            total_batches,
            "Executing Cut"
        );

        // Extract beneficiary from consensus cut BEFORE conversion (which consumes the Cut)
        // TODO: Add proposer address verification against validator set to prevent
        // malicious proposers from setting arbitrary beneficiary addresses.
        let beneficiary = match consensus_cut.proposer_address {
            Some(addr) => addr,
            None => {
                warn!(
                    height = consensus_cut.height,
                    "Cut has no proposer_address, using Address::ZERO as beneficiary. \
                     Block rewards will be unclaimable."
                );
                Address::ZERO
            }
        };

        // Convert consensus Cut to execution Cut (fetches batches from storage)
        let execution_cut = self.convert_cut(consensus_cut).await?;

        // Store block metadata for hash computation after execution
        let block_number = execution_cut.block_number;
        let timestamp = execution_cut.timestamp;
        let parent_hash = execution_cut.parent_hash;

        // Capture all transactions BEFORE they're consumed by execution.
        // These will be stored by the node for eth_getTransactionByHash queries.
        let executed_transactions: Vec<Bytes> = execution_cut
            .cars
            .iter()
            .flat_map(|car| car.transactions.iter().cloned())
            .collect();

        // Convert Cut to BlockInput by flattening transactions from all Cars
        let block_input = BlockInput {
            block_number: execution_cut.block_number,
            timestamp: execution_cut.timestamp,
            transactions: executed_transactions.clone(),
            parent_hash: execution_cut.parent_hash,
            gas_limit: execution_cut.gas_limit,
            base_fee_per_gas: execution_cut.base_fee_per_gas,
            beneficiary,
        };

        let mut execution = self.execution.write().await;

        let result = execution
            .execute_block(block_input)
            .map_err(|e| anyhow::anyhow!("Block execution failed: {}", e))?;

        // Compute and store the new block hash for the next block's parent_hash
        let new_block_hash = compute_block_hash(
            block_number,
            timestamp,
            parent_hash,
            result.state_root,
            result.transactions_root,
            result.receipts_root,
        );

        // Update the last block hash for the next execution
        if let Ok(mut guard) = self.last_block_hash.write() {
            *guard = new_block_hash;
        }

        debug!(
            height = block_number,
            block_hash = %new_block_hash,
            parent_hash = %parent_hash,
            "Block hash updated"
        );

        Ok(BlockExecutionResult {
            execution_result: result,
            block_hash: new_block_hash,
            parent_hash,
            timestamp,
            executed_transactions,
        })
    }

    /// Convert a consensus Cut to an execution Cut
    ///
    /// This converts the data-chain Cut format to the execution layer format.
    /// Fetches actual batches from storage to extract transactions.
    /// Uses the tracked `last_block_hash` as the parent hash to maintain chain connectivity.
    async fn convert_cut(
        &self,
        consensus_cut: cipherbft_data_chain::Cut,
    ) -> anyhow::Result<ExecutionCut> {
        // Convert Cars from HashMap to sorted Vec
        let mut execution_cars = Vec::new();

        // Track batch fetch statistics for diagnostics
        let mut batches_expected = 0usize;
        let mut batches_found = 0usize;
        let mut total_txs = 0usize;

        for (validator_id, car) in consensus_cut.ordered_cars() {
            // Extract transactions from batches by fetching from storage
            let mut transactions = Vec::new();
            for batch_digest in &car.batch_digests {
                batches_expected += 1;
                // Fetch the actual batch from storage using its digest
                match self.dcl_store.get_batch(&batch_digest.digest).await {
                    Ok(Some(batch)) => {
                        batches_found += 1;
                        let tx_count = batch.transactions.len();
                        total_txs += tx_count;
                        debug!(
                            digest = %batch_digest.digest,
                            worker_id = batch_digest.worker_id,
                            tx_count,
                            "Batch found in storage"
                        );
                        // Convert each transaction (Vec<u8>) to Bytes
                        for tx in batch.transactions {
                            transactions.push(Bytes::from(tx));
                        }
                    }
                    Ok(None) => {
                        warn!(
                            digest = %batch_digest.digest,
                            worker_id = batch_digest.worker_id,
                            "Batch not found in storage, skipping - TRANSACTIONS WILL BE LOST"
                        );
                    }
                    Err(e) => {
                        warn!(
                            digest = %batch_digest.digest,
                            error = %e,
                            "Failed to fetch batch from storage - TRANSACTIONS WILL BE LOST"
                        );
                    }
                }
            }

            let execution_car = ExecutionCar {
                validator_id: U256::from_be_slice(validator_id.as_bytes()),
                transactions,
            };

            execution_cars.push(execution_car);
        }

        // Log summary at INFO level for easy diagnosis
        if batches_expected > 0 {
            info!(
                height = consensus_cut.height,
                batches_expected,
                batches_found,
                batches_missing = batches_expected - batches_found,
                total_txs,
                "convert_cut batch fetch summary"
            );
        }

        // Read the parent hash from the last executed block
        let parent_hash = self
            .last_block_hash
            .read()
            .map(|guard| *guard)
            .unwrap_or(B256::ZERO);

        Ok(ExecutionCut {
            block_number: consensus_cut.height,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            parent_hash,
            cars: execution_cars,
            gas_limit: self.gas_limit,             // Use genesis gas limit
            base_fee_per_gas: Some(1_000_000_000), // Default base fee
        })
    }

    /// Get a shared reference to the execution bridge for use across workers
    pub fn shared(self) -> Arc<Self> {
        Arc::new(self)
    }

    /// Distribute epoch rewards to validators.
    ///
    /// This method should be called at epoch boundaries (e.g., every 100 blocks)
    /// to distribute accumulated transaction fees and block rewards to validators
    /// proportionally to their stake.
    ///
    /// # Arguments
    ///
    /// * `epoch_block_reward` - Fixed block reward for the epoch (in wei)
    /// * `current_epoch` - The epoch number being finalized
    ///
    /// # Returns
    ///
    /// Total amount of rewards distributed to validators (in wei)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // At epoch boundary (e.g., block 100, 200, 300...)
    /// let epoch_reward = genesis.cipherbft.staking.epoch_block_reward_wei;
    /// let distributed = bridge.distribute_epoch_rewards(epoch_reward, current_epoch).await?;
    /// info!(epoch = current_epoch, distributed = %distributed, "Epoch rewards distributed");
    /// ```
    pub async fn distribute_epoch_rewards(
        &self,
        epoch_block_reward: U256,
        current_epoch: u64,
    ) -> anyhow::Result<U256> {
        let execution = self.execution.read().await;
        let distributed = execution.distribute_epoch_rewards(epoch_block_reward, current_epoch);

        info!(
            epoch = current_epoch,
            epoch_block_reward = %epoch_block_reward,
            total_distributed = %distributed,
            "Epoch rewards distributed to validators"
        );

        Ok(distributed)
    }

    /// Get accumulated fees pending distribution.
    ///
    /// Returns the total transaction fees accumulated since the last
    /// epoch reward distribution.
    pub async fn get_accumulated_fees(&self) -> U256 {
        let execution = self.execution.read().await;
        execution.get_accumulated_fees()
    }

    /// Get total rewards distributed to validators across all epochs.
    pub async fn get_total_distributed(&self) -> U256 {
        let execution = self.execution.read().await;
        execution.get_total_distributed()
    }

    /// Get a reference to the underlying storage provider.
    ///
    /// This allows sharing the provider with the RPC layer so that queries
    /// like `eth_getBalance` can see the same state as the execution layer.
    /// The provider uses MDBX for persistent storage, ensuring state survives
    /// node restarts.
    pub async fn provider(&self) -> Arc<MdbxProvider> {
        let execution = self.execution.read().await;
        execution.provider()
    }

    /// Get a reference to the staking precompile.
    ///
    /// This allows sharing the staking precompile with the RPC layer so that
    /// `eth_call` to address 0x100 can query the same validator state as the
    /// execution layer. This is essential for RPC queries about validators,
    /// stakes, and rewards.
    pub async fn staking_precompile(&self) -> Arc<StakingPrecompile> {
        let execution = self.execution.read().await;
        Arc::clone(execution.staking_precompile())
    }
}

/// Compute a deterministic block hash from block components.
///
/// This hash is used to link blocks together, ensuring chain connectivity.
/// The hash is computed by concatenating key block fields and hashing with keccak256.
///
/// # Arguments
///
/// * `block_number` - The block height
/// * `timestamp` - Block timestamp in seconds
/// * `parent_hash` - Hash of the parent block
/// * `state_root` - State root after execution
/// * `transactions_root` - Merkle root of transactions
/// * `receipts_root` - Merkle root of receipts
///
/// # Returns
///
/// A 32-byte block hash
fn compute_block_hash(
    block_number: u64,
    timestamp: u64,
    parent_hash: B256,
    state_root: B256,
    transactions_root: B256,
    receipts_root: B256,
) -> B256 {
    // Concatenate block fields into a single buffer for hashing
    // Layout: block_number (8) + timestamp (8) + parent_hash (32) + state_root (32)
    //         + transactions_root (32) + receipts_root (32) = 144 bytes
    let mut data = Vec::with_capacity(144);
    data.extend_from_slice(&block_number.to_be_bytes());
    data.extend_from_slice(&timestamp.to_be_bytes());
    data.extend_from_slice(parent_hash.as_slice());
    data.extend_from_slice(state_root.as_slice());
    data.extend_from_slice(transactions_root.as_slice());
    data.extend_from_slice(receipts_root.as_slice());

    keccak256(&data)
}

/// Create a default execution bridge for testing/development
///
/// Uses default chain configuration and persistent MDBX storage in a temporary directory.
/// The temporary directory is returned alongside the bridge so it persists for the
/// lifetime of the test.
#[cfg(test)]
fn create_default_bridge() -> anyhow::Result<(ExecutionBridge, tempfile::TempDir)> {
    let config = ChainConfig::default();
    let dcl_store: Arc<dyn DclStore> = Arc::new(cipherbft_storage::InMemoryStore::new());
    let temp_dir = tempfile::tempdir()?;
    let bridge = ExecutionBridge::new(config, dcl_store, temp_dir.path())?;
    Ok((bridge, temp_dir))
}

/// Implement TransactionValidator trait for ExecutionBridge
#[async_trait::async_trait]
impl TransactionValidator for ExecutionBridge {
    async fn validate_transaction(&self, tx: &[u8]) -> Result<(), String> {
        self.check_tx(tx)
            .await
            .map_err(|e| format!("Validation failed: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_bridge() {
        let result = create_default_bridge();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_check_tx_placeholder() {
        let (bridge, _temp_dir) = create_default_bridge().unwrap();

        // Currently returns error since validate_transaction is not implemented
        let result = bridge.check_tx(&[0x01, 0x02, 0x03]).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_transaction_validator_trait() {
        use cipherbft_data_chain::worker::TransactionValidator;

        let (bridge, _temp_dir) = create_default_bridge().unwrap();

        // Test TransactionValidator trait implementation
        let result = bridge.validate_transaction(&[0x01, 0x02, 0x03]).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_compute_block_hash_deterministic() {
        // Same inputs should produce the same hash
        let block_number = 1u64;
        let timestamp = 1234567890u64;
        let parent_hash = B256::ZERO;
        let state_root = B256::from([1u8; 32]);
        let transactions_root = B256::from([2u8; 32]);
        let receipts_root = B256::from([3u8; 32]);

        let hash1 = compute_block_hash(
            block_number,
            timestamp,
            parent_hash,
            state_root,
            transactions_root,
            receipts_root,
        );

        let hash2 = compute_block_hash(
            block_number,
            timestamp,
            parent_hash,
            state_root,
            transactions_root,
            receipts_root,
        );

        assert_eq!(hash1, hash2, "Block hash should be deterministic");
    }

    #[test]
    fn test_compute_block_hash_different_inputs() {
        // Different inputs should produce different hashes
        let hash1 = compute_block_hash(
            1,
            1234567890,
            B256::ZERO,
            B256::from([1u8; 32]),
            B256::from([2u8; 32]),
            B256::from([3u8; 32]),
        );

        let hash2 = compute_block_hash(
            2, // Different block number
            1234567890,
            B256::ZERO,
            B256::from([1u8; 32]),
            B256::from([2u8; 32]),
            B256::from([3u8; 32]),
        );

        assert_ne!(
            hash1, hash2,
            "Different inputs should produce different hashes"
        );
    }

    #[test]
    fn test_compute_block_hash_parent_hash_matters() {
        // Changing parent hash should change the block hash
        let hash1 = compute_block_hash(
            1,
            1234567890,
            B256::ZERO,
            B256::from([1u8; 32]),
            B256::from([2u8; 32]),
            B256::from([3u8; 32]),
        );

        let hash2 = compute_block_hash(
            1,
            1234567890,
            B256::from([99u8; 32]), // Different parent hash
            B256::from([1u8; 32]),
            B256::from([2u8; 32]),
            B256::from([3u8; 32]),
        );

        assert_ne!(
            hash1, hash2,
            "Different parent hash should produce different block hash"
        );
    }

    #[tokio::test]
    async fn test_last_block_hash_initialized_to_zero() {
        let (bridge, _temp_dir) = create_default_bridge().unwrap();

        // The last_block_hash should be initialized to B256::ZERO
        let last_hash = bridge
            .last_block_hash
            .read()
            .map(|guard| *guard)
            .unwrap_or(B256::from([0xffu8; 32])); // Use non-zero as fallback to detect errors

        assert_eq!(
            last_hash,
            B256::ZERO,
            "Initial last_block_hash should be B256::ZERO"
        );
    }

    #[tokio::test]
    async fn test_gas_limit_from_config() {
        let (bridge, _temp_dir) = create_default_bridge().unwrap();

        // Default gas limit from ChainConfig should be 30_000_000
        assert_eq!(bridge.gas_limit(), 30_000_000);
    }

    #[tokio::test]
    async fn test_gas_limit_custom() {
        use cipherbft_storage::{DclStore, InMemoryStore};

        let config = ChainConfig {
            block_gas_limit: 50_000_000,
            ..Default::default()
        };
        let dcl_store: Arc<dyn DclStore> = Arc::new(InMemoryStore::new());
        let temp_dir = tempfile::tempdir().unwrap();
        let bridge = ExecutionBridge::new(config, dcl_store, temp_dir.path()).unwrap();

        assert_eq!(bridge.gas_limit(), 50_000_000);
    }
}
