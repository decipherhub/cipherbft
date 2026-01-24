//! Execution layer integration bridge
//!
//! This module provides the bridge between the consensus layer (data-chain)
//! and the execution layer, enabling transaction validation and Cut execution.

use cipherbft_data_chain::worker::TransactionValidator;
use cipherbft_execution::{
    keccak256, BlockInput, Bytes, Car as ExecutionCar, ChainConfig, Cut as ExecutionCut,
    ExecutionEngine, ExecutionLayerTrait, ExecutionResult, GenesisValidatorData, InMemoryProvider,
    B256, U256,
};
use cipherbft_storage::DclStore;
use cipherbft_types::genesis::Genesis;
use std::sync::Arc;
use std::sync::RwLock as StdRwLock;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Bridge between consensus and execution layers
///
/// Maintains the connection between the consensus layer and the execution layer,
/// tracking block hashes to ensure proper chain connectivity.
pub struct ExecutionBridge {
    /// Execution layer instance
    execution: Arc<RwLock<ExecutionEngine<InMemoryProvider>>>,
    /// DCL storage for batch lookups
    dcl_store: Arc<dyn DclStore>,
    /// Hash of the last executed block (used as parent hash for the next block)
    ///
    /// Initialized to B256::ZERO for the genesis block.
    /// Updated after each successful block execution.
    last_block_hash: StdRwLock<B256>,
}

impl ExecutionBridge {
    /// Create a new execution bridge
    ///
    /// # Arguments
    ///
    /// * `config` - Chain configuration for the execution layer
    /// * `dcl_store` - DCL storage for batch lookups
    ///
    /// # Note
    /// This creates an execution bridge with an empty staking state.
    /// For production use, prefer `from_genesis` to initialize the staking
    /// state from the genesis file.
    pub fn new(config: ChainConfig, dcl_store: Arc<dyn DclStore>) -> anyhow::Result<Self> {
        let provider = InMemoryProvider::new();
        let execution = ExecutionEngine::new(config, provider);

        Ok(Self {
            execution: Arc::new(RwLock::new(execution)),
            dcl_store,
            // Genesis block has no parent, so initialize to zero
            last_block_hash: StdRwLock::new(B256::ZERO),
        })
    }

    /// Create a new execution bridge initialized from genesis.
    ///
    /// This is the primary constructor for production use. It initializes the
    /// staking precompile with the validator set from the genesis file, ensuring
    /// the validator state is correctly populated on node startup.
    ///
    /// # Arguments
    ///
    /// * `config` - Chain configuration for the execution layer
    /// * `dcl_store` - DCL storage for batch lookups
    /// * `genesis` - Genesis configuration containing validator set
    ///
    /// # Returns
    ///
    /// A new `ExecutionBridge` with staking state initialized from genesis validators.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let genesis = GenesisLoader::load_and_validate(path)?;
    /// let bridge = ExecutionBridge::from_genesis(config, dcl_store, &genesis)?;
    /// ```
    pub fn from_genesis(
        config: ChainConfig,
        dcl_store: Arc<dyn DclStore>,
        genesis: &Genesis,
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

        info!(
            validator_count = genesis_validators.len(),
            total_stake = %genesis.total_staked(),
            "Initializing execution layer from genesis"
        );

        let provider = InMemoryProvider::new();
        let execution =
            ExecutionEngine::with_genesis_validators(config, provider, genesis_validators);

        Ok(Self {
            execution: Arc::new(RwLock::new(execution)),
            dcl_store,
            // Genesis block has no parent, so initialize to zero
            last_block_hash: StdRwLock::new(B256::ZERO),
        })
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
    /// Returns execution result with state root and receipts.
    pub async fn execute_cut(
        &self,
        consensus_cut: cipherbft_data_chain::Cut,
    ) -> anyhow::Result<ExecutionResult> {
        debug!(
            height = consensus_cut.height,
            cars = consensus_cut.cars.len(),
            "Executing Cut"
        );

        // Convert consensus Cut to execution Cut (fetches batches from storage)
        let execution_cut = self.convert_cut(consensus_cut).await?;

        // Store block metadata for hash computation after execution
        let block_number = execution_cut.block_number;
        let timestamp = execution_cut.timestamp;
        let parent_hash = execution_cut.parent_hash;

        // Convert Cut to BlockInput by flattening transactions from all Cars
        let block_input = BlockInput {
            block_number: execution_cut.block_number,
            timestamp: execution_cut.timestamp,
            transactions: execution_cut
                .cars
                .iter()
                .flat_map(|car| car.transactions.iter().cloned())
                .collect(),
            parent_hash: execution_cut.parent_hash,
            gas_limit: execution_cut.gas_limit,
            base_fee_per_gas: execution_cut.base_fee_per_gas,
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

        Ok(result)
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

        for (validator_id, car) in consensus_cut.ordered_cars() {
            // Extract transactions from batches by fetching from storage
            let mut transactions = Vec::new();
            for batch_digest in &car.batch_digests {
                // Fetch the actual batch from storage using its digest
                match self.dcl_store.get_batch(&batch_digest.digest).await {
                    Ok(Some(batch)) => {
                        // Convert each transaction (Vec<u8>) to Bytes
                        for tx in batch.transactions {
                            transactions.push(Bytes::from(tx));
                        }
                    }
                    Ok(None) => {
                        warn!(
                            digest = %batch_digest.digest,
                            worker_id = batch_digest.worker_id,
                            "Batch not found in storage, skipping"
                        );
                    }
                    Err(e) => {
                        warn!(
                            digest = %batch_digest.digest,
                            error = %e,
                            "Failed to fetch batch from storage"
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
            gas_limit: 30_000_000,                 // Default gas limit
            base_fee_per_gas: Some(1_000_000_000), // Default base fee
        })
    }

    /// Get a shared reference to the execution bridge for use across workers
    pub fn shared(self) -> Arc<Self> {
        Arc::new(self)
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
/// Uses default chain configuration and in-memory storage.
pub fn create_default_bridge() -> anyhow::Result<ExecutionBridge> {
    let config = ChainConfig::default();
    let dcl_store: Arc<dyn DclStore> = Arc::new(cipherbft_storage::InMemoryStore::new());
    ExecutionBridge::new(config, dcl_store)
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
        let bridge = create_default_bridge();
        assert!(bridge.is_ok());
    }

    #[tokio::test]
    async fn test_check_tx_placeholder() {
        let bridge = create_default_bridge().unwrap();

        // Currently returns error since validate_transaction is not implemented
        let result = bridge.check_tx(&[0x01, 0x02, 0x03]).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_transaction_validator_trait() {
        use cipherbft_data_chain::worker::TransactionValidator;

        let bridge = create_default_bridge().unwrap();

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
        let bridge = create_default_bridge().unwrap();

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
}
