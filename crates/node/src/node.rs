//! Node runner - ties Primary, Workers, and Network together
//!
//! # Task Supervision
//!
//! The node uses a [`NodeSupervisor`] for structured task management:
//! - All background tasks are tracked and can be cancelled gracefully
//! - Shutdown follows a specific order to ensure clean state
//! - Critical task failures trigger coordinated shutdown
//!
//! # Shutdown Order
//!
//! 1. Stop accepting new network connections
//! 2. Drain in-flight consensus rounds (via cancellation signal)
//! 3. Flush pending storage writes
//! 4. Close database connections
//! 5. Exit

use crate::config::NodeConfig;
use crate::execution_bridge::{BlockExecutionResult, ExecutionBridge};
use crate::execution_sync::{ExecutionSyncConfig, ExecutionSyncTracker, SyncAction};
use crate::network::{TcpPrimaryNetwork, TcpWorkerNetwork};
use crate::supervisor::NodeSupervisor;
use alloy_primitives::{Address, B256};
use anyhow::{Context, Result};
use cipherbft_consensus::{
    create_context, default_consensus_params, default_engine_config_single_part, spawn_host,
    spawn_network, spawn_sync, spawn_wal, ConsensusHeight, ConsensusSigner,
    ConsensusSigningProvider, ConsensusValidator, EpochConfig, MalachiteEngineBuilder, SyncConfig,
};
use cipherbft_crypto::{BlsKeyPair, BlsPublicKey, Ed25519KeyPair, Ed25519PublicKey};
use cipherbft_data_chain::{
    error::DclError,
    primary::{Primary, PrimaryConfig, PrimaryEvent},
    storage::BatchStore as DclBatchStore,
    worker::{Worker, WorkerConfig},
    Batch, Cut, DclMessage, WorkerMessage,
};
use cipherbft_execution::{
    keccak256, Bytes as ExecutionBytes, ChainConfig, Log as ExecutionLog,
    TransactionReceipt as ExecutionReceipt, U256,
};
use cipherbft_storage::{
    Block, BlockStore, Database, DatabaseConfig, DclStore, Log as StorageLog, LogStore,
    MdbxBlockStore, MdbxDclStore, MdbxLogStore, MdbxReceiptStore, MdbxTransactionStore,
    Receipt as StorageReceipt, ReceiptStore, StoredLog, Transaction as StorageTransaction,
    TransactionStore,
};
use cipherbft_types::genesis::{AttestationQuorum, Genesis};
use cipherbft_types::Hash;
use cipherbft_types::ValidatorId;
use informalsystems_malachitebft_metrics::SharedRegistry;
use informalsystems_malachitebft_network::{
    Config as NetworkConfig, DiscoveryConfig, GossipSubConfig, Keypair, Multiaddr, PubSubProtocol,
    TransportProtocol,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use cipherbft_metrics;

/// Adapter to bridge DclStore (storage crate) to BatchStore (data-chain crate)
///
/// Workers require `BatchStore` from data-chain, but the node uses `DclStore` from storage.
/// This adapter wraps `DclStore` and implements the `BatchStore` trait, allowing Workers
/// to persist batches to the same storage used by `ExecutionBridge` for fetching transactions.
///
/// Without this adapter, batches created by Workers would only exist in memory and would
/// not be retrievable when executing Cuts (causing transactions to be skipped).
struct DclStoreBatchAdapter {
    inner: Arc<dyn DclStore>,
}

impl DclStoreBatchAdapter {
    fn new(store: Arc<dyn DclStore>) -> Self {
        Self { inner: store }
    }
}

#[async_trait::async_trait]
impl DclBatchStore for DclStoreBatchAdapter {
    async fn put_batch(&self, batch: Batch) -> Result<Hash, DclError> {
        let hash = batch.hash();
        self.inner
            .put_batch(batch)
            .await
            .map_err(|e| DclError::Storage(e.to_string()))?;
        Ok(hash)
    }

    async fn get_batch(&self, hash: &Hash) -> Result<Option<Batch>, DclError> {
        self.inner
            .get_batch(hash)
            .await
            .map_err(|e| DclError::Storage(e.to_string()))
    }

    async fn has_batch(&self, hash: &Hash) -> Result<bool, DclError> {
        self.inner
            .has_batch(hash)
            .await
            .map_err(|e| DclError::Storage(e.to_string()))
    }
}

/// Validator public key information for both DCL and Consensus layers
#[derive(Clone, Debug)]
pub struct ValidatorInfo {
    /// BLS public key for DCL layer (threshold signatures)
    pub bls_public_key: BlsPublicKey,
    /// Ed25519 public key for Consensus layer (Malachite signing)
    pub ed25519_public_key: Ed25519PublicKey,
    /// Voting power for consensus
    pub voting_power: u64,
    /// Ethereum address (secp256k1) for block beneficiary
    pub ethereum_address: Address,
}

impl ValidatorInfo {
    /// Create a new validator info with default voting power
    pub fn new(bls_public_key: BlsPublicKey, ed25519_public_key: Ed25519PublicKey) -> Self {
        Self {
            bls_public_key,
            ed25519_public_key,
            voting_power: 100, // Default voting power
            ethereum_address: Address::ZERO,
        }
    }

    /// Create with custom voting power
    pub fn with_voting_power(
        bls_public_key: BlsPublicKey,
        ed25519_public_key: Ed25519PublicKey,
        voting_power: u64,
    ) -> Self {
        Self {
            bls_public_key,
            ed25519_public_key,
            voting_power,
            ethereum_address: Address::ZERO,
        }
    }

    /// Create validator info with voting power and ethereum address
    pub fn with_ethereum_address(
        bls_public_key: BlsPublicKey,
        ed25519_public_key: Ed25519PublicKey,
        voting_power: u64,
        ethereum_address: Address,
    ) -> Self {
        Self {
            bls_public_key,
            ed25519_public_key,
            voting_power,
            ethereum_address,
        }
    }
}

/// Default gas limit for blocks (30 million)
const DEFAULT_GAS_LIMIT: u64 = 30_000_000;

/// A running CipherBFT node
pub struct Node {
    /// Configuration
    config: NodeConfig,
    /// BLS keypair for DCL layer
    bls_keypair: BlsKeyPair,
    /// Ed25519 keypair for consensus layer
    ed25519_keypair: Ed25519KeyPair,
    /// Our validator ID
    validator_id: ValidatorId,
    /// Known validators with both BLS and Ed25519 public keys
    validators: HashMap<ValidatorId, ValidatorInfo>,
    /// Execution layer bridge
    execution_bridge: Option<Arc<ExecutionBridge>>,
    /// Shared DCL store for consensus sync and execution bridge.
    /// When set to MdbxDclStore, enables persistent certificate storage for sync support.
    dcl_store: Option<Arc<dyn DclStore>>,
    /// Whether DCL (Data Chain Layer) is enabled.
    /// When disabled, consensus proceeds without data availability attestations.
    dcl_enabled: bool,
    /// Epoch block reward in wei (from genesis staking params).
    /// Used for validator reward distribution at epoch boundaries.
    epoch_block_reward: U256,
    /// Block beneficiary address (coinbase) from genesis.
    /// This is the address that receives block rewards.
    beneficiary: [u8; 20],
    /// Block gas limit from genesis configuration.
    gas_limit: u64,
    /// Attestation quorum for DCL Cars (from genesis).
    /// Determines how many validators must attest before a Car can be included.
    attestation_quorum: AttestationQuorum,
}

impl Node {
    /// Create a new node with provided keypairs
    ///
    /// # Arguments
    ///
    /// * `config` - Node configuration
    /// * `bls_keypair` - BLS keypair for DCL layer (threshold signatures)
    /// * `ed25519_keypair` - Ed25519 keypair for consensus layer (Malachite signing)
    pub fn new(
        config: NodeConfig,
        bls_keypair: BlsKeyPair,
        ed25519_keypair: Ed25519KeyPair,
    ) -> Result<Self> {
        // Derive validator ID from Ed25519 public key (matches genesis)
        let validator_id = ed25519_keypair.public_key.validator_id();

        // Verify validator ID matches if configured
        if let Some(config_vid) = config.validator_id {
            if validator_id != config_vid {
                anyhow::bail!(
                    "Validator ID mismatch: config has {:?}, derived {:?}",
                    config_vid,
                    validator_id
                );
            }
        }

        Ok(Self {
            config,
            bls_keypair,
            ed25519_keypair,
            validator_id,
            validators: HashMap::new(),
            execution_bridge: None,
            dcl_store: None,
            dcl_enabled: true, // Default to enabled, overridden by genesis
            epoch_block_reward: U256::from(2_000_000_000_000_000_000u128), // Default: 2 CPH
            gas_limit: DEFAULT_GAS_LIMIT, // Default, overridden by genesis
            beneficiary: [0u8; 20], // Default zero, overridden by genesis
            attestation_quorum: AttestationQuorum::default(), // Default 2f+1, overridden by genesis
        })
    }

    /// Add a known validator with both BLS and Ed25519 public keys
    pub fn add_validator(
        &mut self,
        id: ValidatorId,
        bls_pubkey: BlsPublicKey,
        ed25519_pubkey: Ed25519PublicKey,
    ) {
        self.validators
            .insert(id, ValidatorInfo::new(bls_pubkey, ed25519_pubkey));
    }

    /// Add a known validator with custom voting power
    pub fn add_validator_with_power(
        &mut self,
        id: ValidatorId,
        bls_pubkey: BlsPublicKey,
        ed25519_pubkey: Ed25519PublicKey,
        voting_power: u64,
    ) {
        self.validators.insert(
            id,
            ValidatorInfo::with_voting_power(bls_pubkey, ed25519_pubkey, voting_power),
        );
    }

    /// Bootstrap validators from genesis file (T029).
    ///
    /// Parses validator public keys from genesis and adds them to the node's
    /// validator set with voting power derived from staked amounts.
    ///
    /// # Arguments
    ///
    /// * `genesis` - Validated genesis configuration
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Ed25519 public key parsing fails (invalid hex or length)
    /// - BLS public key parsing fails (invalid hex or length)
    pub fn bootstrap_validators_from_genesis(&mut self, genesis: &Genesis) -> Result<()> {
        let total_stake = genesis.total_staked();

        info!(
            "Bootstrapping {} validators from genesis (total stake: {} wei)",
            genesis.validator_count(),
            total_stake
        );

        for validator in &genesis.cipherbft.validators {
            // Parse Ed25519 public key (strip 0x prefix if present)
            let ed25519_hex = validator.ed25519_pubkey.trim_start_matches("0x");
            let ed25519_bytes = hex::decode(ed25519_hex).map_err(|e| {
                anyhow::anyhow!(
                    "Invalid Ed25519 public key hex for {}: {}",
                    validator.address,
                    e
                )
            })?;

            if ed25519_bytes.len() != 32 {
                anyhow::bail!(
                    "Ed25519 public key for {} must be 32 bytes, got {}",
                    validator.address,
                    ed25519_bytes.len()
                );
            }

            let mut ed25519_arr = [0u8; 32];
            ed25519_arr.copy_from_slice(&ed25519_bytes);
            let ed25519_pubkey = Ed25519PublicKey::from_bytes(&ed25519_arr).map_err(|e| {
                anyhow::anyhow!(
                    "Invalid Ed25519 public key for {}: {:?}",
                    validator.address,
                    e
                )
            })?;

            // Parse BLS public key (strip 0x prefix if present)
            let bls_hex = validator.bls_pubkey.trim_start_matches("0x");
            let bls_bytes = hex::decode(bls_hex).map_err(|e| {
                anyhow::anyhow!(
                    "Invalid BLS public key hex for {}: {}",
                    validator.address,
                    e
                )
            })?;

            if bls_bytes.len() != 48 {
                anyhow::bail!(
                    "BLS public key for {} must be 48 bytes, got {}",
                    validator.address,
                    bls_bytes.len()
                );
            }

            let mut bls_arr = [0u8; 48];
            bls_arr.copy_from_slice(&bls_bytes);
            let bls_pubkey = BlsPublicKey::from_bytes(&bls_arr).map_err(|e| {
                anyhow::anyhow!("Invalid BLS public key for {}: {:?}", validator.address, e)
            })?;

            // Derive validator ID from Ed25519 public key (matches genesis)
            let validator_id = ed25519_pubkey.validator_id();

            // Calculate voting power from stake (proportional to total stake)
            // Scale to reasonable voting power values (avoid overflow)
            let voting_power = if total_stake.is_zero() {
                100u64 // Default if no stake
            } else {
                // voting_power = (stake * 10000) / total_stake
                // This gives voting power proportional to stake share
                // with 10000 as the scaling factor for precision
                let stake_u128: u128 = validator.staked_amount.try_into().unwrap_or(u128::MAX);
                let total_u128: u128 = total_stake.try_into().unwrap_or(u128::MAX);
                let power = (stake_u128.saturating_mul(10000)) / total_u128.max(1);
                power.max(1) as u64 // Ensure at least 1 voting power
            };

            info!(
                "Adding validator: genesis_address={}, derived_validator_id={}, ed25519_pubkey={}, voting_power={}",
                validator.address, validator_id, validator.ed25519_pubkey, voting_power
            );

            self.validators.insert(
                validator_id,
                ValidatorInfo::with_ethereum_address(
                    bls_pubkey,
                    ed25519_pubkey,
                    voting_power,
                    validator.address, // This is the secp256k1 Ethereum address from genesis
                ),
            );
        }

        info!(
            "Bootstrapped {} validators from genesis",
            self.validators.len()
        );

        // Set DCL enabled flag from genesis configuration
        self.dcl_enabled = genesis.cipherbft.dcl.enabled;
        if !self.dcl_enabled {
            info!("DCL (Data Chain Layer) is DISABLED - consensus will proceed without data availability attestations");
        }

        // Set attestation quorum from genesis DCL params
        self.attestation_quorum = genesis.cipherbft.dcl.attestation_quorum;
        info!(
            "Attestation quorum set from genesis: {:?}",
            self.attestation_quorum
        );

        // Set beneficiary address from genesis coinbase (if specified)
        if let Some(coinbase) = genesis.coinbase {
            self.beneficiary = coinbase.0 .0;
            info!("Block beneficiary set from genesis: {}", coinbase);
        }

        // Set gas limit from genesis
        self.gas_limit = genesis.gas_limit.try_into().unwrap_or(DEFAULT_GAS_LIMIT);
        info!("Block gas limit set from genesis: {}", self.gas_limit);

        Ok(())
    }

    /// Enable execution layer integration
    ///
    /// Must be called before `run()` to enable Cut execution.
    ///
    /// # Note
    /// This creates an execution layer with an in-memory DCL store (for testing),
    /// but uses persistent MDBX storage for EVM state in the node's data directory.
    /// For production use, prefer `with_execution_layer_from_genesis` to
    /// initialize the staking state from the genesis file and enable
    /// persistent storage for consensus sync support.
    pub fn with_execution_layer(mut self) -> Result<Self> {
        use cipherbft_storage::InMemoryStore;
        let chain_config = ChainConfig::default();
        let dcl_store: Arc<dyn DclStore> = Arc::new(InMemoryStore::new());
        self.dcl_store = Some(dcl_store.clone());
        // Ensure data directory exists for EVM storage
        std::fs::create_dir_all(&self.config.data_dir)?;
        let bridge = ExecutionBridge::new(chain_config, dcl_store, &self.config.data_dir)?;
        self.execution_bridge = Some(Arc::new(bridge));
        Ok(self)
    }

    /// Enable execution layer integration with genesis validators.
    ///
    /// This is the preferred method for production use. It initializes the
    /// staking precompile with the validator set from the genesis file,
    /// ensuring validators are correctly registered on node startup.
    ///
    /// Creates a persistent MdbxDclStore for DCL data and consensus certificates.
    /// The same store is shared between the ExecutionBridge and the consensus sync
    /// mechanism, enabling validators to sync from height 1.
    ///
    /// # Arguments
    ///
    /// * `genesis` - Validated genesis configuration
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let genesis = GenesisLoader::load_and_validate(path)?;
    /// let node = Node::new(config, bls_keypair, ed25519_keypair)?
    ///     .with_execution_layer_from_genesis(&genesis)?;
    /// ```
    pub fn with_execution_layer_from_genesis(mut self, genesis: &Genesis) -> Result<Self> {
        let chain_config = ChainConfig::default();

        // Create persistent DCL store using MDBX for production use.
        // This enables consensus sync support by persisting Cut + CommitCertificate pairs.
        std::fs::create_dir_all(&self.config.data_dir)?;
        let dcl_db_path = self.config.data_dir.join("dcl_storage");
        let dcl_db_config = DatabaseConfig::new(&dcl_db_path);
        let dcl_database =
            Database::open(dcl_db_config).context("Failed to open DCL storage database")?;
        let dcl_store: Arc<dyn DclStore> = Arc::new(MdbxDclStore::new(Arc::new(dcl_database)));

        info!("Created persistent DCL store at {}", dcl_db_path.display());

        // Store the dcl_store for later use in spawn_host (consensus sync)
        self.dcl_store = Some(dcl_store.clone());

        let bridge =
            ExecutionBridge::from_genesis(chain_config, dcl_store, genesis, &self.config.data_dir)?;
        self.execution_bridge = Some(Arc::new(bridge));

        // Store epoch block reward from genesis for reward distribution at epoch boundaries
        self.epoch_block_reward = genesis.cipherbft.staking.epoch_block_reward_wei;

        info!(
            "Execution layer initialized with {} validators from genesis (epoch reward: {} wei)",
            genesis.validator_count(),
            self.epoch_block_reward
        );
        Ok(self)
    }

    /// Run the node with a default supervisor.
    ///
    /// Creates a new [`NodeSupervisor`] and runs the node until shutdown is triggered
    /// (e.g., via Ctrl+C signal).
    pub async fn run(self) -> Result<()> {
        let supervisor = NodeSupervisor::new();
        self.run_with_supervisor(supervisor).await
    }

    /// Run the node with a provided supervisor.
    ///
    /// This allows external control over task supervision, useful for:
    /// - Testing with custom shutdown timing
    /// - Coordinating multiple nodes in a single process
    /// - Custom shutdown ordering
    ///
    /// # Arguments
    ///
    /// * `supervisor` - The supervisor that manages task lifecycle
    pub async fn run_with_supervisor(self, supervisor: NodeSupervisor) -> Result<()> {
        info!("Starting node with validator ID: {:?}", self.validator_id);

        // Initialize and start metrics server
        cipherbft_metrics::init();
        let metrics_addr: std::net::SocketAddr = format!("0.0.0.0:{}", self.config.metrics_port)
            .parse()
            .expect("valid metrics address");
        let _metrics_handle = cipherbft_metrics::spawn_metrics_server(metrics_addr);
        tracing::info!(
            "Metrics server started on port {}",
            self.config.metrics_port
        );

        // Create data directory if needed
        std::fs::create_dir_all(&self.config.data_dir)?;

        // Get cancellation token for graceful shutdown
        let cancel_token = supervisor.cancellation_token();

        // Create channel for CutReady events to Consensus Host
        let (cut_tx, cut_rx) = mpsc::channel::<Cut>(100);

        // Create channels for Primary (only used when DCL enabled)
        let (primary_incoming_tx, mut primary_incoming_rx) =
            mpsc::channel::<(ValidatorId, DclMessage)>(1000);

        // Create channel to signal empty cut sender to advance (used when DCL disabled)
        // This creates a lockstep between consensus decisions and cut generation
        let (cut_advance_tx, mut cut_advance_rx) = mpsc::channel::<()>(1);

        // Conditionally spawn DCL (Data Chain Layer) based on genesis config
        // When disabled, we bypass DCL and send empty cuts directly to consensus
        let mut primary_handle_opt: Option<cipherbft_data_chain::primary::PrimaryHandle> = None;
        // Store reference to primary network for RPC NetworkApi
        let mut primary_network_opt: Option<Arc<TcpPrimaryNetwork>> = None;
        // Transaction channel sender for RPC -> Worker forwarding (created when DCL enabled)
        let mut mempool_tx_sender_opt: Option<mpsc::Sender<Vec<u8>>> = None;

        if self.dcl_enabled {
            // Create primary network
            let primary_network = Arc::new(TcpPrimaryNetwork::new(
                self.validator_id,
                &self.config.peers,
                primary_incoming_tx.clone(),
            ));

            // Store reference for RPC NetworkApi before moving into adapter
            primary_network_opt = Some(Arc::clone(&primary_network));

            // Start primary listener
            Arc::clone(&primary_network)
                .start_listener(self.config.primary_listen)
                .await
                .with_context(|| {
                    format!(
                        "Failed to start primary network listener on {}",
                        self.config.primary_listen
                    )
                })?;

            // Connect to peers (with retry) - supervised task
            supervisor.spawn_cancellable("peer-connector", {
                let network = Arc::clone(&primary_network);
                move |token| async move {
                    // Initial delay to let other nodes start
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    loop {
                        tokio::select! {
                            biased;
                            _ = token.cancelled() => {
                                info!("Peer connector shutting down");
                                break;
                            }
                            _ = tokio::time::sleep(Duration::from_secs(5)) => {
                                network.connect_to_all_peers().await;
                            }
                        }
                    }
                    Ok(())
                }
            });

            // Create Primary configuration
            // For devnet, allow unlimited empty cars so consensus can make progress without real transactions
            let primary_config =
                PrimaryConfig::new(self.validator_id, self.bls_keypair.secret_key.clone())
                    .with_car_interval(Duration::from_millis(self.config.car_interval_ms))
                    .with_max_empty_cars(u32::MAX)
                    .with_attestation_quorum(self.attestation_quorum);

            // Extract BLS public keys for DCL layer (Primary uses BLS for threshold signatures)
            let bls_pubkeys: HashMap<ValidatorId, BlsPublicKey> = self
                .validators
                .iter()
                .map(|(id, info)| (*id, info.bls_public_key.clone()))
                .collect();

            // Log all known validators for debugging
            info!(
                "Primary will know {} validators: {:?}",
                bls_pubkeys.len(),
                bls_pubkeys.keys().collect::<Vec<_>>()
            );

            // Load the last finalized cut for Primary state restoration on restart
            // This is CRITICAL for validator restart: without it, a restarted validator
            // would create CARs at position 0, but other validators expect continuity
            // from the last finalized position, causing PositionGap errors.
            let initial_cut = if let Some(ref store) = self.dcl_store {
                match store.get_latest_finalized_cut().await {
                    Ok(Some(cut)) => {
                        info!(
                            "Restoring Primary state from finalized cut at height {} with {} validators",
                            cut.height,
                            cut.cars.len()
                        );
                        Some(cut)
                    }
                    Ok(None) => {
                        info!("No finalized cut in storage, Primary starting fresh");
                        None
                    }
                    Err(e) => {
                        warn!(
                            "Failed to load finalized cut for Primary restart: {}, starting fresh",
                            e
                        );
                        None
                    }
                }
            } else {
                debug!("No DCL store available, Primary starting without state restoration");
                None
            };

            // Spawn Primary task with optional initial cut for restart recovery
            let (primary_handle, worker_rxs) = Primary::spawn_with_initial_cut(
                primary_config,
                bls_pubkeys,
                Box::new(TcpPrimaryNetworkAdapter {
                    network: primary_network,
                }),
                self.config.num_workers as u8,
                None, // storage - not used for now
                initial_cut,
            );

            // Create transaction channel for RPC -> Worker forwarding
            // This channel is used by ChannelMempoolApi to send transactions to workers
            let (mempool_tx_sender, mempool_tx_receiver) = mpsc::channel::<Vec<u8>>(4096);
            mempool_tx_sender_opt = Some(mempool_tx_sender);
            // Wrap receiver in Option so we can move it into worker 0's bridge
            let mut mempool_tx_receiver_opt = Some(mempool_tx_receiver);

            // Create batch storage adapter for Workers to persist batches
            // This is CRITICAL: Workers must use the same storage as ExecutionBridge
            // so that batches can be retrieved when executing Cuts.
            let worker_batch_storage: Option<Arc<dyn DclBatchStore>> = self
                .dcl_store
                .clone()
                .map(|store| Arc::new(DclStoreBatchAdapter::new(store)) as Arc<dyn DclBatchStore>);

            // Spawn Workers and wire up channels
            // Workers receive batches from peers and notify Primary when batches are ready
            for (worker_idx, mut from_primary_rx) in worker_rxs.into_iter().enumerate() {
                let worker_id = worker_idx as u8;

                // Create Worker network with incoming message channel
                let (worker_incoming_tx, mut worker_incoming_rx) =
                    mpsc::channel::<(ValidatorId, WorkerMessage)>(1024);

                let worker_network = TcpWorkerNetwork::new(
                    self.validator_id,
                    worker_id,
                    &self.config.peers,
                    worker_incoming_tx,
                );

                // Start Worker network listener
                if let Some(listen_addr) = self.config.worker_listens.get(worker_id as usize) {
                    let network_for_listener = Arc::new(worker_network.clone());
                    let listen_addr = *listen_addr;
                    tokio::spawn(async move {
                        if let Err(e) = network_for_listener.start_listener(listen_addr).await {
                            error!("Failed to start worker {} listener: {}", worker_id, e);
                        }
                    });

                    // Connect to peers after a brief delay to allow listeners to start
                    let network_for_connect = worker_network.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        network_for_connect.connect_to_all_peers().await;
                    });
                }

                // Create Worker config and spawn with batch storage
                // Passing the storage adapter ensures batches are persisted and retrievable
                // during Cut execution (for transaction inclusion in blocks)
                //
                // IMPORTANT: flush_interval (50ms) must be shorter than Primary's car_interval (100ms)
                // to ensure batches are flushed before Cars are created. Without this, there's a race
                // condition where Primary creates empty Cars before Worker flushes pending batches.
                let worker_config = WorkerConfig::new(self.validator_id, worker_id)
                    .with_flush_interval(std::time::Duration::from_millis(50));
                let mut worker_handle = Worker::spawn_with_storage(
                    worker_config,
                    Box::new(worker_network),
                    worker_batch_storage.clone(),
                );

                // Combined bridge task: handles all communication with Worker
                // - Primary -> Worker: forward batch requests
                // - Worker -> Primary: forward batch digests
                // - Network -> Worker: forward peer messages
                // - RPC -> Worker: forward mempool transactions (worker 0 only)
                let token = cancel_token.clone();
                let primary_worker_sender = primary_handle.worker_sender();
                // Worker 0 handles RPC transactions from the mempool channel
                let mempool_rx = if worker_id == 0 {
                    mempool_tx_receiver_opt.take()
                } else {
                    None
                };
                tokio::spawn(async move {
                    // Move mempool_rx into the async block
                    let mut mempool_rx = mempool_rx;
                    info!(
                        "Worker {} bridge started (mempool_rx: {})",
                        worker_id,
                        if mempool_rx.is_some() {
                            "enabled"
                        } else {
                            "disabled"
                        }
                    );
                    loop {
                        // Use a macro-like pattern to handle optional mempool receiver
                        // Worker 0 has mempool_rx, others don't
                        tokio::select! {
                            biased;

                            _ = token.cancelled() => {
                                debug!("Worker {} bridge shutting down", worker_id);
                                break;
                            }

                            // RPC -> Worker: forward mempool transactions (worker 0 only)
                            tx = async {
                                match &mut mempool_rx {
                                    Some(rx) => rx.recv().await,
                                    None => std::future::pending().await,
                                }
                            } => {
                                if let Some(tx_bytes) = tx {
                                    info!("Worker {} received transaction from RPC mempool ({} bytes)", worker_id, tx_bytes.len());
                                    if worker_handle.submit_transaction(tx_bytes).await.is_err() {
                                        warn!("Worker {} submit_transaction failed", worker_id);
                                        // Don't break - continue processing other messages
                                    } else {
                                        info!("Worker {} forwarded transaction to batch maker", worker_id);
                                    }
                                }
                            }

                            // Primary -> Worker: forward batch requests and digests
                            msg = from_primary_rx.recv() => {
                                match msg {
                                    Some(m) => {
                                        if worker_handle.send_from_primary(m).await.is_err() {
                                            warn!("Worker {} send_from_primary failed", worker_id);
                                            break;
                                        }
                                    }
                                    None => {
                                        debug!("Worker {} primary channel closed", worker_id);
                                        break;
                                    }
                                }
                            }

                            // Worker -> Primary: forward batch availability notifications
                            msg = worker_handle.recv_from_worker() => {
                                match msg {
                                    Some(m) => {
                                        info!("Worker {} bridge forwarding {:?} to Primary", worker_id, m);
                                        if primary_worker_sender.send(m).await.is_err() {
                                            warn!("Worker {} send to primary failed", worker_id);
                                            break;
                                        }
                                    }
                                    None => {
                                        debug!("Worker {} receiver closed", worker_id);
                                        break;
                                    }
                                }
                            }

                            // Network -> Worker: forward peer messages (batches, sync requests)
                            msg = worker_incoming_rx.recv() => {
                                match msg {
                                    Some((peer, worker_msg)) => {
                                        if worker_handle.send_from_peer(peer, worker_msg).await.is_err() {
                                            warn!("Worker {} send_from_peer failed", worker_id);
                                            break;
                                        }
                                    }
                                    None => {
                                        debug!("Worker {} network channel closed", worker_id);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                });

                info!("Worker {} spawned and wired", worker_id);
            }

            primary_handle_opt = Some(primary_handle);
            info!(
                "DCL layer spawned with Primary and {} workers",
                self.config.num_workers
            );

            // Drop the cut_advance_rx receiver since it's only used when DCL is disabled.
            // This ensures cut_advance_tx.send() fails immediately instead of blocking,
            // preventing deadlock in the event loop.
            drop(cut_advance_rx);
        } else {
            // DCL disabled: spawn a task that sends empty cuts directly to consensus
            // This allows consensus to proceed without data availability attestations
            // IMPORTANT: Cuts are sent in lockstep with consensus decisions to avoid
            // the cut buffer filling up before consensus can use them
            info!("DCL DISABLED - spawning empty cut sender for consensus bypass");
            let cut_tx_bypass = cut_tx.clone();
            supervisor.spawn_cancellable("empty-cut-sender", move |token| async move {
                let mut height = 1u64;

                // Send the first cut immediately at height 1
                let empty_cut = Cut::new(height);
                info!("Sending initial empty cut for height {}", height);
                if let Err(e) = cut_tx_bypass.send(empty_cut).await {
                    warn!("Failed to send initial empty cut: {}", e);
                    return Ok(());
                }
                height += 1;

                // After the first cut, wait for consensus to decide before sending the next
                // This creates a lockstep: cut -> propose -> decide -> next cut
                loop {
                    tokio::select! {
                        biased;
                        _ = token.cancelled() => {
                            info!("Empty cut sender shutting down");
                            break;
                        }
                        // Wait for signal that consensus decided, then send next cut
                        result = cut_advance_rx.recv() => {
                            match result {
                                Some(()) => {
                                    let empty_cut = Cut::new(height);
                                    info!("Sending empty cut for height {} (after consensus decision)", height);
                                    if let Err(e) = cut_tx_bypass.send(empty_cut).await {
                                        warn!("Failed to send empty cut: {}", e);
                                        break;
                                    }
                                    height += 1;
                                }
                                None => {
                                    info!("Cut advance channel closed, stopping empty cut sender");
                                    break;
                                }
                            }
                        }
                    }
                }
                Ok(())
            });
        }

        let (decided_tx, mut decided_rx) = mpsc::channel::<(ConsensusHeight, Cut)>(100);

        // Get Ed25519 keypair for Consensus
        let ed25519_pubkey = self.ed25519_keypair.public_key.clone();
        // Extract secret key bytes before moving keypair (needed for libp2p Keypair)
        let ed25519_secret_bytes = self.ed25519_keypair.secret_key.to_bytes();
        let consensus_signer = ConsensusSigner::new(self.ed25519_keypair.clone());
        let signing_provider = ConsensusSigningProvider::new(consensus_signer);

        // Create Consensus context and validators
        // Build validator set from all known validators using their Ed25519 public keys
        // Chain ID: cipherbft-testnet-1 (Cosmos-style for consensus layer)
        // Note: For EVM execution layer, use numeric chain ID 84530001
        let chain_id = "cipherbft-testnet-1";

        // Look up our own voting power from the validator set (set during bootstrap_validators_from_genesis)
        // Fall back to 100 if not found (e.g., if bootstrap wasn't called)
        let our_voting_power = self
            .validators
            .get(&self.validator_id)
            .map(|info| info.voting_power)
            .unwrap_or(100);

        // Get our own ethereum address from the validator set (or use ZERO if not found)
        let our_ethereum_address = self
            .validators
            .get(&self.validator_id)
            .map(|info| info.ethereum_address)
            .unwrap_or(Address::ZERO);

        // Start with ourselves
        let mut consensus_validators = vec![ConsensusValidator::new_with_ethereum_address(
            self.validator_id,
            ed25519_pubkey,
            our_voting_power,
            our_ethereum_address,
        )];

        // Add all other validators from the known validator set
        for (validator_id, info) in &self.validators {
            if *validator_id != self.validator_id {
                consensus_validators.push(ConsensusValidator::new_with_ethereum_address(
                    *validator_id,
                    info.ed25519_public_key.clone(),
                    info.voting_power,
                    info.ethereum_address,
                ));
            }
        }
        // Determine initial height from storage (for restart recovery)
        // If we have persistent storage and there's a finalized cut, resume from that height + 1
        let initial_height = if let Some(store) = &self.dcl_store {
            match store.get_latest_finalized_cut().await {
                Ok(Some(cut)) => {
                    let resume_height = cut.height + 1;
                    info!(
                        "Resuming consensus from height {} (latest finalized: {})",
                        resume_height, cut.height
                    );
                    Some(ConsensusHeight(resume_height))
                }
                Ok(None) => {
                    info!("No finalized cuts in storage, starting from height 1");
                    None
                }
                Err(e) => {
                    warn!(
                        "Failed to read latest finalized cut: {}, starting from height 1",
                        e
                    );
                    None
                }
            }
        } else {
            info!("No persistent DCL storage, starting consensus from height 1");
            None
        };

        let ctx = create_context(chain_id, consensus_validators, initial_height)?;
        // Find our own address in the sorted validator set by matching our validator ID.
        // Note: The validator set is sorted by voting power (desc), then address (asc),
        // so we cannot assume our position - we must search for ourselves.
        let our_address = ctx
            .validator_set()
            .as_slice()
            .iter()
            .find(|v| v.address.0 == self.validator_id)
            .expect("our validator must be in the validator set")
            .address;
        let params = default_consensus_params(&ctx, our_address);
        let consensus_config = default_engine_config_single_part();

        // Create metrics registry for consensus actors
        let metrics = SharedRegistry::global().with_moniker("cipherbft-consensus");

        // Create libp2p keypair from Ed25519 secret key for consensus network
        // This ensures deterministic PeerId across node restarts
        let consensus_keypair = Keypair::ed25519_from_bytes(ed25519_secret_bytes).map_err(|e| {
            anyhow::anyhow!("Failed to create libp2p keypair from Ed25519 key: {}", e)
        })?;
        info!(
            "Consensus network PeerId: {}",
            consensus_keypair.public().to_peer_id()
        );

        // Create network config for consensus p2p layer
        // Convert SocketAddr to Multiaddr format
        let listen_addr: Multiaddr = format!(
            "/ip4/{}/tcp/{}",
            self.config.consensus_listen.ip(),
            self.config.consensus_listen.port()
        )
        .parse()
        .expect("valid multiaddr from config");

        // Convert peer consensus addresses to Multiaddr format for libp2p
        let persistent_peers: Vec<Multiaddr> = self
            .config
            .peers
            .iter()
            .filter_map(|peer| {
                let addr = &peer.consensus_addr;
                let multiaddr_str = format!("/ip4/{}/tcp/{}", addr.ip(), addr.port());
                match multiaddr_str.parse::<Multiaddr>() {
                    Ok(multiaddr) => Some(multiaddr),
                    Err(e) => {
                        warn!(
                            "Failed to parse peer consensus address {} as Multiaddr: {}",
                            addr, e
                        );
                        None
                    }
                }
            })
            .collect();
        info!(
            "Configured {} persistent peers for consensus network",
            persistent_peers.len()
        );

        let network_config = NetworkConfig {
            listen_addr: listen_addr.clone(),
            persistent_peers,
            discovery: DiscoveryConfig::default(),
            idle_connection_timeout: Duration::from_secs(15 * 60),
            transport: TransportProtocol::Tcp,
            gossipsub: GossipSubConfig::default(),
            pubsub_protocol: PubSubProtocol::default(),
            rpc_max_size: 10 * 1024 * 1024,    // 10 MiB
            pubsub_max_size: 10 * 1024 * 1024, // 10 MiB
            enable_sync: true,
        };

        // Spawn Consensus actors
        let network = spawn_network(consensus_keypair, network_config, metrics.clone())
            .await
            .with_context(|| {
                format!(
                    "Failed to start consensus network on {}. \
                     Port {} may already be in use. \
                     Check with: lsof -i :{}",
                    listen_addr,
                    self.config.consensus_listen.port(),
                    self.config.consensus_listen.port()
                )
            })?;

        let wal_path = self.config.data_dir.join("wal");
        let wal = spawn_wal(&ctx, wal_path, metrics.clone()).await?;

        // Pass network to host for ProposalAndParts mode (enables non-proposers to receive proposal parts)
        // Pass the shared DCL store for persistent certificate storage (enables sync from height 1)
        let host = spawn_host(
            self.validator_id,
            ctx.clone(),
            cut_rx,
            Some(decided_tx),
            Some(network.clone()),
            self.dcl_store.clone(),
            self.config.wait_for_cut_timeout_ms,
        )
        .await?;

        // Spawn Sync actor for state synchronization
        // Use higher parallelism to catch up faster when significantly behind
        let sync_config = SyncConfig::new(true)
            .with_parallel_requests(20) // Increased from default 5 for faster catch-up
            .with_request_timeout(Duration::from_secs(30)); // Longer timeout for slower networks
        let sync = spawn_sync(ctx.clone(), network.clone(), host.clone(), sync_config).await?;

        // Build and spawn Consensus engine with sync support
        let _engine_handles = MalachiteEngineBuilder::new(
            ctx.clone(),
            params,
            consensus_config,
            Box::new(signing_provider),
            network,
            host,
            wal,
        )
        .with_sync(sync)
        .spawn()
        .await?;

        info!("Consensus engine started");

        // RPC storage reference - used to update block number when consensus decides
        // Moved outside the `if` block so it can be passed to run_event_loop
        use cipherbft_execution::MdbxProvider;
        use cipherbft_rpc::{MdbxRpcStorage, StubDebugExecutionApi};
        let rpc_storage: Option<Arc<MdbxRpcStorage<MdbxProvider>>> = if self.config.rpc_enabled {
            // Create MDBX database for block/receipt storage
            let db_path = self.config.data_dir.join("rpc_storage");
            let db_config = DatabaseConfig::new(&db_path);
            let database =
                Database::open(db_config).context("Failed to open RPC storage database")?;
            let db_env = database.env().clone();

            // Create block, receipt, transaction, and log stores
            let block_store = Arc::new(MdbxBlockStore::new(db_env.clone()));
            let receipt_store = Arc::new(MdbxReceiptStore::new(db_env.clone()));
            let transaction_store = Arc::new(MdbxTransactionStore::new(db_env.clone()));
            let log_store = Arc::new(MdbxLogStore::new(db_env));

            // Get provider from ExecutionBridge to share state with execution layer.
            // This ensures eth_getBalance and other RPC queries see the same state
            // as the execution layer, including genesis allocations.
            let provider = if let Some(ref bridge) = self.execution_bridge {
                bridge.provider().await
            } else {
                // Execution bridge is required for RPC to function properly.
                // The MdbxProvider is needed to share EVM state with the RPC layer.
                anyhow::bail!(
                    "RPC enabled but no execution bridge configured. \
                     Call with_execution_layer() or with_execution_layer_from_genesis() \
                     before enabling RPC."
                );
            };

            // Create MdbxRpcStorage with chain ID and transaction store.
            // The transaction store enables eth_getTransactionByHash and
            // full_transactions=true support in eth_getBlockByNumber/Hash.
            let chain_id = 85300u64; // CipherBFT testnet chain ID
            let storage = Arc::new(MdbxRpcStorage::with_transaction_store(
                provider,
                block_store,
                receipt_store,
                transaction_store,
                Some(log_store), // Enable eth_getLogs queries
                chain_id,
            ));

            // Ensure genesis block (block 0) exists for Ethereum RPC compatibility
            // Block explorers like Blockscout expect block 0 to exist
            let genesis_hash: Option<[u8; 32]> =
                match storage.block_store().get_block_by_number(0).await {
                    Ok(Some(existing_block)) => {
                        debug!("Genesis block (block 0) already exists in storage");
                        Some(existing_block.hash)
                    }
                    Ok(None) => {
                        // Create and store genesis block
                        let genesis_timestamp = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        let genesis_block =
                            Self::create_genesis_block(genesis_timestamp, self.gas_limit);
                        let hash = genesis_block.hash;
                        if let Err(e) = storage.block_store().put_block(&genesis_block).await {
                            error!("Failed to store genesis block: {}", e);
                            None
                        } else {
                            info!(
                                "Created genesis block (block 0) with hash 0x{}",
                                hex::encode(&genesis_block.hash[..8])
                            );
                            Some(hash)
                        }
                    }
                    Err(e) => {
                        warn!("Failed to check for genesis block: {}", e);
                        None
                    }
                };

            // Synchronize genesis block hash with execution bridge for correct parent_hash in block 1
            if let (Some(hash), Some(ref bridge)) = (genesis_hash, &self.execution_bridge) {
                bridge.set_genesis_block_hash(B256::from(hash));
            }

            // Initialize latest_block from storage (important for restart scenarios)
            // Note: We check for the latest block AFTER ensuring genesis exists
            if let Ok(Some(latest)) = storage.block_store().get_latest_block_number().await {
                storage.set_latest_block(latest);
                info!("Initialized RPC latest_block from storage: {}", latest);

                // CRITICAL: Restore last_block_hash for correct parent_hash in next block
                // On node restart, the ExecutionBridge's in-memory last_block_hash is lost.
                // We must restore it from the latest block in storage to ensure the next
                // block's parent_hash correctly references the latest block's hash.
                if latest > 0 {
                    if let Some(ref bridge) = self.execution_bridge {
                        match storage.block_store().get_block_by_number(latest).await {
                            Ok(Some(latest_block)) => {
                                bridge.restore_last_block_hash(B256::from(latest_block.hash));
                            }
                            Ok(None) => {
                                warn!(
                                    "Latest block {} not found in storage despite get_latest_block_number returning it",
                                    latest
                                );
                            }
                            Err(e) => {
                                warn!(
                                    "Failed to retrieve latest block {} for hash recovery: {}",
                                    latest, e
                                );
                            }
                        }
                    }
                }
            }

            Some(storage)
        } else {
            None
        };

        // Create debug executor for debug_* RPC methods
        let rpc_debug_executor: Option<Arc<StubDebugExecutionApi>> = if self.config.rpc_enabled {
            Some(Arc::new(StubDebugExecutionApi::new()))
        } else {
            None
        };

        // Create subscription manager for WebSocket subscriptions (eth_subscribe)
        // This needs to be shared between the RPC server and the event loop
        // so that new blocks can be broadcast to subscribers
        let subscription_manager = if rpc_storage.is_some() {
            use cipherbft_rpc::SubscriptionManager;
            Some(Arc::new(SubscriptionManager::default()))
        } else {
            None
        };

        // Create RPC executor before the RPC setup block so it can be shared
        // with the event loop for updating latest_block on consensus decisions
        use cipherbft_rpc::EvmExecutionApi;
        let rpc_executor: Option<Arc<EvmExecutionApi<MdbxProvider>>> = if self.config.rpc_enabled {
            let (exec_provider, staking_precompile) =
                if let Some(ref bridge) = self.execution_bridge {
                    // Get the provider and staking precompile from the execution bridge
                    // to ensure RPC queries see the same state as the execution layer
                    (bridge.provider().await, bridge.staking_precompile().await)
                } else {
                    // Execution bridge is required for RPC to function properly
                    anyhow::bail!(
                        "RPC enabled but no execution bridge configured. \
                         Call with_execution_layer() or with_execution_layer_from_genesis() \
                         before enabling RPC."
                    );
                };
            let chain_id = 85300u64;
            Some(Arc::new(EvmExecutionApi::new(
                exec_provider,
                chain_id,
                staking_precompile,
            )))
        } else {
            None
        };

        // Mempool handle for cleaning up pending transactions after block execution
        // This is set when RPC is enabled and DCL is enabled (ChannelMempoolApi)
        let mut rpc_mempool: Option<Arc<cipherbft_rpc::MempoolWrapper>> = None;

        // Start RPC server if enabled
        if let (Some(ref storage), Some(ref debug_executor), Some(ref sub_mgr)) =
            (&rpc_storage, &rpc_debug_executor, &subscription_manager)
        {
            use crate::NodeNetworkApi;
            use cipherbft_rpc::{MempoolWrapper, RpcConfig, RpcServer};

            let chain_id = 85300u64; // CipherBFT testnet chain ID
            let mut rpc_config = RpcConfig::with_chain_id(chain_id);
            rpc_config.http_port = self.config.rpc_http_port;
            rpc_config.ws_port = self.config.rpc_ws_port;

            // Use the shared executor created above
            let executor = rpc_executor
                .clone()
                .expect("rpc_executor should be Some when RPC enabled");

            // Use MempoolWrapper::channel when DCL is enabled (transactions forwarded to workers),
            // otherwise fall back to MempoolWrapper::stub
            let mempool = Arc::new(if let Some(tx_sender) = mempool_tx_sender_opt.take() {
                info!("RPC using ChannelMempoolApi - transactions will be forwarded to workers");
                MempoolWrapper::channel(tx_sender, chain_id)
            } else {
                warn!(
                    "RPC using StubMempoolApi - transactions will NOT be processed (DCL disabled)"
                );
                MempoolWrapper::stub()
            });
            // Use real NetworkApi when DCL enabled, stub otherwise
            let network = Arc::new(if let Some(ref pn) = primary_network_opt {
                NodeNetworkApi::tcp(Arc::clone(pn))
            } else {
                NodeNetworkApi::stub()
            });

            // Clone mempool for use in event loop to clean up pending txs after block execution
            rpc_mempool = Some(mempool.clone());

            // Use with_subscription_manager to share the subscription manager
            // between the RPC server and the event loop for broadcasting blocks
            let rpc_server = RpcServer::with_subscription_manager(
                rpc_config,
                storage.clone(),
                mempool,
                executor,
                network,
                debug_executor.clone(),
                sub_mgr.clone(),
            );

            let http_port = self.config.rpc_http_port;
            let ws_port = self.config.rpc_ws_port;
            let rpc_cancel_token = cancel_token.clone();
            supervisor.spawn_cancellable("rpc-server", move |_token| async move {
                info!(
                    "Starting JSON-RPC server (HTTP: {}, WS: {})",
                    http_port, ws_port
                );
                // Start the server
                if let Err(e) = rpc_server.start().await {
                    if !rpc_cancel_token.is_cancelled() {
                        error!("RPC server error: {}", e);
                    }
                    return Ok(());
                }
                info!("RPC server running");

                // Keep the server alive until shutdown is requested
                // The RpcServer holds the ServerHandles which keep the servers running
                rpc_cancel_token.cancelled().await;

                info!("RPC server stopping...");
                if let Err(e) = rpc_server.stop().await {
                    warn!("Error stopping RPC server: {}", e);
                }
                info!("RPC server stopped");
                Ok(())
            });
        }

        info!("Node started, entering main loop");

        // Clone execution bridge for use in event loop
        let execution_bridge = self.execution_bridge.clone();

        // Create epoch configuration for reward distribution timing
        // Default: 100 blocks per epoch
        let epoch_config = EpochConfig::default();

        // Block configuration from genesis
        let gas_limit = self.gas_limit;

        // Run the main event loop with graceful shutdown support
        let result = Self::run_event_loop(
            cancel_token,
            &mut primary_incoming_rx,
            primary_handle_opt.as_mut(),
            &cut_tx,
            &mut decided_rx,
            cut_advance_tx,
            execution_bridge,
            rpc_storage,
            subscription_manager,
            rpc_debug_executor,
            rpc_executor,
            rpc_mempool,
            epoch_config,
            self.epoch_block_reward,
            gas_limit,
        )
        .await;

        // Graceful shutdown sequence
        info!("Shutting down node components...");

        // Step 1: Signal Primary to stop (if DCL is enabled)
        if let Some(primary_handle) = primary_handle_opt {
            info!("Stopping Primary...");
            primary_handle.shutdown().await;
        } else {
            info!("DCL disabled, skipping Primary shutdown");
        }

        // Step 2: Wait for supervisor to complete all tracked tasks
        info!("Waiting for supervised tasks to complete...");
        if let Err(e) = supervisor.shutdown().await {
            warn!("Some tasks did not complete cleanly: {}", e);
        }

        info!("Node shutdown complete");
        result
    }

    /// Internal event loop that handles messages and can be cancelled.
    ///
    /// When `primary_handle` is `Some`, DCL is enabled and we handle Primary events.
    /// When `primary_handle` is `None`, DCL is disabled and we only handle consensus decisions.
    ///
    /// The `cut_advance_tx` channel is used to signal the empty cut sender (when DCL disabled)
    /// to advance to the next height after consensus decides on a block.
    ///
    /// At epoch boundaries, distributes accumulated transaction fees and block rewards
    /// to validators proportionally to their stake.
    #[allow(clippy::too_many_arguments)]
    async fn run_event_loop(
        cancel_token: CancellationToken,
        primary_incoming_rx: &mut mpsc::Receiver<(ValidatorId, DclMessage)>,
        mut primary_handle: Option<&mut cipherbft_data_chain::primary::PrimaryHandle>,
        cut_tx: &mpsc::Sender<Cut>,
        decided_rx: &mut mpsc::Receiver<(ConsensusHeight, Cut)>,
        cut_advance_tx: mpsc::Sender<()>,
        execution_bridge: Option<Arc<ExecutionBridge>>,
        rpc_storage: Option<Arc<cipherbft_rpc::MdbxRpcStorage<cipherbft_execution::MdbxProvider>>>,
        subscription_manager: Option<Arc<cipherbft_rpc::SubscriptionManager>>,
        rpc_debug_executor: Option<Arc<cipherbft_rpc::StubDebugExecutionApi>>,
        rpc_executor: Option<
            Arc<cipherbft_rpc::EvmExecutionApi<cipherbft_execution::MdbxProvider>>,
        >,
        rpc_mempool: Option<Arc<cipherbft_rpc::MempoolWrapper>>,
        epoch_config: EpochConfig,
        epoch_block_reward: U256,
        gas_limit: u64,
    ) -> Result<()> {
        // Initialize execution-consensus sync tracker
        // This detects when execution falls behind and halts before unrecoverable divergence
        let sync_tracker = ExecutionSyncTracker::new(ExecutionSyncConfig::default());

        loop {
            tokio::select! {
                biased;

                // Check for shutdown signal first (highest priority)
                _ = cancel_token.cancelled() => {
                    info!("Received shutdown signal, exiting event loop");
                    return Ok(());
                }

                // Consensus Decided events - execute the decided Cut
                // CRITICAL: This must have HIGH PRIORITY in the biased select!
                // If Primary events (CutReady, CarCreated, etc.) starve this branch:
                // 1. Consensus decisions are not processed by the node
                // 2. notify_decision() is never called
                // 3. Primary can't form the next cut
                // 4. wait_for_cut() times out in consensus host
                // 5. All validators vote NIL → liveness failure
                Some((height, cut)) = decided_rx.recv() => {
                    debug!(
                        "Consensus decided at height {} with {} cars",
                        height,
                        cut.cars.len()
                    );

                    // Notify Primary that consensus has decided on this height (only when DCL enabled)
                    // This allows Primary to advance its state and produce cuts for the next height
                    // CRITICAL: We pass the cut so Primary can sync position tracking from decided CARs
                    if let Some(ref mut handle) = primary_handle {
                        if let Err(e) = handle.notify_decision(height.0, cut.clone()).await {
                            warn!("Failed to notify Primary of consensus decision: {:?}", e);
                        }

                        // CRITICAL FIX: Wait for and drain CutReady events after notify_decision.
                        //
                        // notify_decision() is non-blocking - it sends a command to Primary's command channel
                        // and returns immediately. The Primary task processes this command asynchronously:
                        // 1. Primary receives ConsensusDecided command
                        // 2. Primary calls finalize_height() and try_form_cut()
                        // 3. Primary sends CutReady event to the event channel
                        //
                        // We MUST forward this CutReady to consensus BEFORE doing execution work, otherwise:
                        // 1. Consensus starts the next height and requests a value
                        // 2. ChannelValueBuilder doesn't have the cut (it's stuck in this channel)
                        // 3. Consensus times out on Propose step, all validators vote NIL
                        // 4. System gets stuck in a liveness failure
                        //
                        // Solution: Yield to let Primary process the command, then poll for events
                        // with a short timeout to ensure we catch the CutReady event.
                        let drain_deadline = tokio::time::Instant::now() + Duration::from_millis(100);
                        let mut got_cut_ready = false;

                        loop {
                            // First yield to allow the Primary task to run and process the command
                            tokio::task::yield_now().await;

                            // Try to receive any pending events
                            match handle.try_recv_event() {
                                Ok(event) => {
                                    match event {
                                        PrimaryEvent::CutReady(new_cut) => {
                                            debug!(
                                                "Cut ready at height {} with {} validators (drained after decision)",
                                                new_cut.height,
                                                new_cut.validator_count()
                                            );
                                            if let Err(e) = cut_tx.send(new_cut).await {
                                                warn!("Failed to send Cut to Consensus Host: {}", e);
                                            }
                                            got_cut_ready = true;
                                        }
                                        PrimaryEvent::CarCreated(car) => {
                                            debug!(
                                                "Car created at position {} with {} batches (drained after decision)",
                                                car.position,
                                                car.batch_digests.len()
                                            );
                                        }
                                        PrimaryEvent::AttestationGenerated { car_proposer, .. } => {
                                            debug!("Generated attestation for Car from {:?} (drained after decision)", car_proposer);
                                        }
                                        PrimaryEvent::SyncBatches { digests, target } => {
                                            debug!(
                                                "Need to sync {} batches from {:?} (drained after decision)",
                                                digests.len(),
                                                target
                                            );
                                        }
                                    }
                                    // Continue draining other events even after getting CutReady
                                }
                                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                                    // No events pending - check if we should continue waiting
                                    if got_cut_ready || tokio::time::Instant::now() >= drain_deadline {
                                        // Either got the CutReady or timed out, proceed with execution
                                        break;
                                    }
                                    // Keep yielding and polling until we get the CutReady or timeout
                                }
                                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                                    warn!("Primary event channel disconnected");
                                    break;
                                }
                            }
                        }
                    }

                    // Execute Cut if execution layer is enabled
                    // Then store the block to MDBX for RPC queries
                    if let Some(ref bridge) = execution_bridge {
                        // Extract beneficiary from Cut BEFORE execute_cut consumes it
                        // The proposer_address is the Ethereum address of the validator who built this Cut
                        let block_beneficiary: [u8; 20] = cut
                            .proposer_address
                            .map(|addr| addr.into_array())
                            .unwrap_or([0u8; 20]);

                        match bridge.execute_cut(cut).await {
                            Ok(block_result) => {
                                // Track successful execution for divergence detection
                                sync_tracker.on_success(height.0);

                                info!(
                                    "Cut executed successfully - state_root: {}, gas_used: {}, block_hash: {}",
                                    block_result.execution_result.state_root,
                                    block_result.execution_result.gas_used,
                                    block_result.block_hash
                                );

                                // Store the block to MDBX for eth_getBlockByNumber queries
                                // IMPORTANT: Store all data BEFORE updating latest_block to avoid race conditions
                                // where clients see a block number they can't actually query yet.
                                // All storage operations (block, receipts, txs, logs) are gated on block storage success
                                // to prevent orphaned records referencing non-existent blocks.
                                if let Some(ref storage) = rpc_storage {
                                    // Create and store the block FIRST
                                    let block = Self::execution_result_to_block(height.0, &block_result, block_beneficiary, gas_limit);
                                    if let Err(e) = storage.block_store().put_block(&block).await {
                                        error!("Failed to store block {} (hash: {}) to MDBX: {}", height.0, block_result.block_hash, e);
                                        // Skip all related storage operations - don't create orphaned receipts/txs/logs
                                    } else {
                                        debug!("Stored block {} to MDBX with hash {}", height.0, block_result.block_hash);

                                        // Store receipts for eth_getBlockReceipts queries
                                        if !block_result.execution_result.receipts.is_empty() {
                                            let block_hash_bytes = block_result.block_hash.0;
                                            let storage_receipts: Vec<StorageReceipt> = block_result
                                                .execution_result
                                                .receipts
                                                .iter()
                                                .map(|r| Self::execution_receipt_to_storage(r, block_hash_bytes))
                                                .collect();
                                            if let Err(e) = storage.receipt_store().put_receipts(&storage_receipts).await {
                                                error!("Failed to store {} receipts for block {}: {}", storage_receipts.len(), height.0, e);
                                            } else {
                                                debug!("Stored {} receipts for block {}", storage_receipts.len(), height.0);
                                            }
                                        }

                                        // Store transactions for eth_getTransactionByHash queries
                                        if let Some(tx_store) = storage.transaction_store() {
                                            if !block_result.executed_transactions.is_empty() {
                                                let block_hash_bytes = block_result.block_hash.0;
                                                let storage_txs: Vec<StorageTransaction> = block_result
                                                    .executed_transactions
                                                    .iter()
                                                    .enumerate()
                                                    .filter_map(|(idx, tx_bytes)| {
                                                        Self::raw_tx_to_storage_transaction(
                                                            tx_bytes,
                                                            height.0,
                                                            block_hash_bytes,
                                                            idx as u32,
                                                        )
                                                    })
                                                    .collect();

                                                if !storage_txs.is_empty() {
                                                    if let Err(e) = tx_store.put_transactions(&storage_txs).await {
                                                        error!(
                                                            "Failed to store {} transactions for block {}: {}",
                                                            storage_txs.len(),
                                                            height.0,
                                                            e
                                                        );
                                                    } else {
                                                        debug!(
                                                            "Stored {} transactions for block {}",
                                                            storage_txs.len(),
                                                            height.0
                                                        );
                                                    }
                                                }
                                            }
                                        }

                                        // Store logs for eth_getLogs queries
                                        if let Some(log_store) = storage.log_store() {
                                            let mut all_logs: Vec<StoredLog> = Vec::new();
                                            let block_hash = block_result.block_hash.0;

                                            for (receipt_idx, receipt) in block_result.execution_result.receipts.iter().enumerate() {
                                                for log in receipt.logs.iter() {
                                                    all_logs.push(StoredLog {
                                                        address: log.address.0 .0,
                                                        topics: log.topics.iter().map(|t| t.0).collect(),
                                                        data: log.data.to_vec(),
                                                        block_number: height.0,
                                                        block_hash,
                                                        transaction_hash: receipt.transaction_hash.0,
                                                        transaction_index: receipt_idx as u32,
                                                        log_index: all_logs.len() as u32,
                                                        removed: false,
                                                    });
                                                }
                                            }

                                            if !all_logs.is_empty() {
                                                if let Err(e) = log_store.put_logs(&all_logs).await {
                                                    error!("Failed to store {} logs for block {}: {}", all_logs.len(), height.0, e);
                                                } else {
                                                    debug!("Stored {} logs for block {}", all_logs.len(), height.0);
                                                }
                                            }
                                        }

                                        // NOW update latest block number AFTER all data is stored
                                        // This ensures clients never see a block number they can't query
                                        storage.set_latest_block(height.0);
                                        debug!("Updated RPC storage block number to {}", height.0);

                                        // Also update executor's latest block for eth_call context
                                        if let Some(ref executor) = rpc_executor {
                                            executor.set_latest_block(height.0);
                                            debug!("Updated RPC executor block number to {}", height.0);
                                        }

                                        // Also update debug executor's latest block for debug trace methods
                                        if let Some(ref debug_executor) = rpc_debug_executor {
                                            debug_executor.set_latest_block(height.0);
                                            debug!("Updated RPC debug executor block number to {}", height.0);
                                        }

                                        // Broadcast to WebSocket subscribers (eth_subscribe("newHeads"))
                                        // Only broadcast AFTER block is queryable
                                        if let Some(ref sub_mgr) = subscription_manager {
                                            use cipherbft_rpc::storage_block_to_rpc_block;
                                            let rpc_block = storage_block_to_rpc_block(block.clone(), false);
                                            sub_mgr.broadcast_block(rpc_block);
                                            debug!("Broadcast block {} to WebSocket subscribers", height.0);
                                        }

                                        // Clean up executed transactions and retry pending ones
                                        // This prevents stale transactions from accumulating and
                                        // ensures skipped transactions (e.g., NonceTooLow) are retried
                                        if let Some(ref mempool) = rpc_mempool {
                                            use alloy_rlp::Decodable;
                                            use reth_primitives::TransactionSigned;

                                            let tx_hashes: Vec<B256> = block_result
                                                .executed_transactions
                                                .iter()
                                                .filter_map(|tx_bytes| {
                                                    TransactionSigned::decode(&mut tx_bytes.as_ref())
                                                        .ok()
                                                        .map(|tx| *tx.tx_hash())
                                                })
                                                .collect();

                                            // Remove executed transactions from pending map
                                            if !tx_hashes.is_empty() {
                                                mempool.remove_included(&tx_hashes);
                                                debug!(
                                                    "Removed {} executed transactions from mempool pending map",
                                                    tx_hashes.len()
                                                );
                                            }

                                            // ALWAYS retry pending transactions after every block
                                            // Previously this was inside the if block, causing pending
                                            // transactions to only retry when a block had executed txs.
                                            // This led to multi-minute delays when the chain had empty blocks.
                                            let retried = mempool.retry_pending(&tx_hashes).await;
                                            if retried > 0 {
                                                debug!(
                                                    "Re-queued {} pending transactions for retry",
                                                    retried
                                                );
                                            }
                                        }
                                    }
                                }

                                // Check for epoch boundary and distribute rewards
                                // Epoch rewards (block rewards + accumulated fees) are distributed
                                // to validators proportionally to their stake at epoch boundaries
                                if epoch_config.is_epoch_boundary(height) {
                                    let current_epoch = epoch_config.epoch_for_height(height);
                                    match bridge.distribute_epoch_rewards(epoch_block_reward, current_epoch).await {
                                        Ok(distributed) => {
                                            if !distributed.is_zero() {
                                                info!(
                                                    "Epoch {} rewards distributed: {} wei to validators",
                                                    current_epoch, distributed
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            error!("Failed to distribute epoch {} rewards: {}", current_epoch, e);
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                // Check sync tracker for divergence-based halt decision
                                let action = sync_tracker.on_failure(height.0, &e.to_string());
                                match action {
                                    SyncAction::Continue => {
                                        // Log error but continue processing
                                        error!("Cut execution failed at height {}: {}", height.0, e);
                                    }
                                    SyncAction::Halt { reason } => {
                                        // Critical divergence detected - halt node
                                        error!(
                                            "CRITICAL: Execution-consensus divergence detected. {}. \
                                             Halting node to prevent unrecoverable state.",
                                            reason
                                        );
                                        return Err(anyhow::anyhow!(
                                            "Execution halted due to divergence: {}", reason
                                        ));
                                    }
                                }
                            }
                        }
                    } else {
                        // No execution bridge, just update the block number
                        if let Some(ref storage) = rpc_storage {
                            storage.set_latest_block(height.0);
                            debug!("Updated RPC block number to {}", height.0);
                        }
                    }

                    // Signal empty cut sender to advance (when DCL disabled)
                    // This creates lockstep: cut -> propose -> decide -> next cut
                    // Using send().await ensures strict synchronization - consensus waits until
                    // the empty cut sender has processed the previous signal before continuing.
                    // Note: When DCL is enabled, the receiver is dropped, so this send will fail silently.
                    let _ = cut_advance_tx.send(()).await;
                }

                // Incoming network messages -> forward to Primary (only when DCL enabled)
                Some((from, msg)) = primary_incoming_rx.recv(), if primary_handle.is_some() => {
                    debug!("Received message from {:?}: {:?}", from, msg.type_name());
                    if let Some(ref mut handle) = primary_handle {
                        if let Err(e) = handle.send_from_peer(from, msg).await {
                            warn!("Failed to forward message to Primary: {:?}", e);
                        }
                    }
                }

                // Primary events (only when DCL enabled)
                Some(event) = async {
                    if let Some(ref mut handle) = primary_handle {
                        handle.recv_event().await
                    } else {
                        // When DCL disabled, this branch never yields
                        std::future::pending::<Option<PrimaryEvent>>().await
                    }
                } => {
                    match event {
                        PrimaryEvent::CutReady(cut) => {
                            debug!(
                                "Cut ready at height {} with {} validators",
                                cut.height,
                                cut.validator_count()
                            );
                            // Send Cut to Consensus Host for ordering
                            // Consensus will decide on the cut and send it back via decided_rx
                            if let Err(e) = cut_tx.send(cut.clone()).await {
                                warn!("Failed to send Cut to Consensus Host: {}", e);
                            }
                        }
                        PrimaryEvent::CarCreated(car) => {
                            debug!(
                                "Car created at position {} with {} batches",
                                car.position,
                                car.batch_digests.len()
                            );
                        }
                        PrimaryEvent::AttestationGenerated { car_proposer, .. } => {
                            debug!("Generated attestation for Car from {:?}", car_proposer);
                        }
                        PrimaryEvent::SyncBatches { digests, target } => {
                            debug!(
                                "Need to sync {} batches from {:?}",
                                digests.len(),
                                target
                            );
                        }
                    }
                }
            }
        }
    }

    /// Get the validator ID
    pub fn validator_id(&self) -> ValidatorId {
        self.validator_id
    }

    /// Convert a BlockExecutionResult to a storage Block for MDBX persistence.
    ///
    /// This creates a Block struct suitable for storage from the execution result.
    /// The block hash and parent hash are properly computed by the ExecutionBridge.
    ///
    /// # Arguments
    ///
    /// * `block_number` - The block height
    /// * `result` - Execution result containing state roots and receipts
    /// * `beneficiary` - Block beneficiary address (coinbase) from genesis
    /// * `gas_limit` - Block gas limit from genesis configuration
    fn execution_result_to_block(
        block_number: u64,
        result: &BlockExecutionResult,
        beneficiary: [u8; 20],
        gas_limit: u64,
    ) -> Block {
        let exec = &result.execution_result;

        // Extract transaction hashes from receipts
        let transaction_hashes: Vec<[u8; 32]> =
            exec.receipts.iter().map(|r| r.transaction_hash.0).collect();
        let transaction_count = transaction_hashes.len() as u32;

        // Create the block with execution results (size will be calculated below)
        // Use the properly computed block_hash and parent_hash from BlockExecutionResult
        let mut block = Block {
            hash: result.block_hash.0,
            number: block_number,
            parent_hash: result.parent_hash.0,
            ommers_hash: [0u8; 32], // Always empty in PoS
            beneficiary,            // From genesis coinbase
            state_root: exec.state_root.0,
            transactions_root: exec.transactions_root.0,
            receipts_root: exec.receipts_root.0,
            logs_bloom: exec.logs_bloom.0.to_vec(),
            difficulty: [0u8; 32], // Always zero in PoS
            gas_limit,
            gas_used: exec.gas_used,
            timestamp: result.timestamp,
            extra_data: Vec::new(),
            mix_hash: [0u8; 32],                   // prevrandao in PoS
            nonce: [0u8; 8],                       // Always zero in PoS
            base_fee_per_gas: Some(1_000_000_000), // 1 gwei default
            transaction_hashes,
            transaction_count,
            total_difficulty: [0u8; 32], // Not used in PoS
            size: 0,                     // Placeholder, calculated below
        };

        // Calculate exact RLP-encoded block header size
        block.size = block.calculate_size();
        block
    }

    /// Convert an execution TransactionReceipt to a storage Receipt for MDBX persistence.
    ///
    /// This bridges the execution layer receipt format to the storage layer format.
    /// The block_hash parameter is passed explicitly because the execution receipt
    /// is created before the block hash is computed, so it contains a placeholder value.
    fn execution_receipt_to_storage(
        receipt: &ExecutionReceipt,
        block_hash: [u8; 32],
    ) -> StorageReceipt {
        // Convert logs
        let logs: Vec<StorageLog> = receipt
            .logs
            .iter()
            .enumerate()
            .map(|(i, log)| {
                Self::execution_log_to_storage(log, i as u32, receipt.transaction_index as u32)
            })
            .collect();

        StorageReceipt {
            transaction_hash: receipt.transaction_hash.0,
            block_number: receipt.block_number,
            block_hash,
            transaction_index: receipt.transaction_index as u32,
            from: receipt.from.0 .0,
            to: receipt.to.map(|a| a.0 .0),
            contract_address: receipt.contract_address.map(|a| a.0 .0),
            gas_used: receipt.gas_used,
            cumulative_gas_used: receipt.cumulative_gas_used,
            status: receipt.status == 1,
            logs,
            logs_bloom: receipt.logs_bloom.0.to_vec(),
            effective_gas_price: receipt.effective_gas_price,
            transaction_type: receipt.transaction_type,
        }
    }

    /// Convert an execution Log to a storage Log.
    fn execution_log_to_storage(
        log: &ExecutionLog,
        log_index: u32,
        transaction_index: u32,
    ) -> StorageLog {
        StorageLog {
            address: log.address.0 .0,
            topics: log.topics.iter().map(|t| t.0).collect(),
            data: log.data.to_vec(),
            log_index,
            transaction_index,
        }
    }

    /// Convert raw transaction bytes to StorageTransaction for MDBX persistence.
    ///
    /// Parses RLP-encoded transaction bytes and extracts all fields needed for
    /// `eth_getTransactionByHash` and `full_transactions=true` responses.
    ///
    /// # Arguments
    /// * `tx_bytes` - RLP-encoded transaction bytes
    /// * `block_number` - Block number containing this transaction
    /// * `block_hash` - Block hash containing this transaction
    /// * `transaction_index` - Index of this transaction within the block
    ///
    /// # Returns
    /// * `Some(StorageTransaction)` if parsing succeeds
    /// * `None` if the transaction cannot be decoded
    fn raw_tx_to_storage_transaction(
        tx_bytes: &ExecutionBytes,
        block_number: u64,
        block_hash: [u8; 32],
        transaction_index: u32,
    ) -> Option<StorageTransaction> {
        use alloy_consensus::Transaction as ConsensusTx;
        use alloy_rlp::Decodable;
        use reth_primitives::TransactionSigned;
        use reth_primitives_traits::SignedTransaction;

        // Decode the RLP-encoded transaction
        let tx = TransactionSigned::decode(&mut tx_bytes.as_ref()).ok()?;

        // Get the transaction hash
        let tx_hash = *tx.tx_hash();

        // Recover the sender address using try_recover (SignedTransaction trait)
        let sender = tx.try_recover().ok()?;

        // Get signature components
        let signature = *tx.signature();

        // Determine transaction type
        let tx_type = tx.tx_type() as u8;

        // Get gas price fields based on transaction type
        // Use the Transaction trait methods directly on TransactionSigned
        // Note: alloy returns u128 for gas prices, but storage uses u64 (sufficient for real values)
        let (gas_price, max_fee_per_gas, max_priority_fee_per_gas): (
            Option<u64>,
            Option<u64>,
            Option<u64>,
        ) = match tx_type {
            0 | 1 => {
                // Legacy (0) or EIP-2930 (1): use gas_price
                (Some(tx.max_fee_per_gas() as u64), None, None)
            }
            2 => {
                // EIP-1559: use max_fee_per_gas and max_priority_fee_per_gas
                (
                    None,
                    Some(tx.max_fee_per_gas() as u64),
                    tx.max_priority_fee_per_gas().map(|v| v as u64),
                )
            }
            _ => (None, None, None),
        };

        // Convert value to big-endian bytes
        let value_bytes: [u8; 32] = tx.value().to_be_bytes();

        // Convert signature v from bool (odd_y_parity) to u64
        // EIP-155: v = chain_id * 2 + 35 + parity (0 or 1)
        // For typed transactions (EIP-2930, EIP-1559): v is just parity (0 or 1)
        let v: u64 = if tx_type == 0 {
            // Legacy: use EIP-155 encoding if chain_id present
            match tx.chain_id() {
                Some(chain_id) => chain_id * 2 + 35 + (signature.v() as u64),
                None => 27 + (signature.v() as u64),
            }
        } else {
            // Typed transactions: parity is 0 or 1
            signature.v() as u64
        };

        // Convert r and s from U256 to [u8; 32]
        let r_bytes: [u8; 32] = signature.r().to_be_bytes();
        let s_bytes: [u8; 32] = signature.s().to_be_bytes();

        Some(StorageTransaction {
            hash: tx_hash.0,
            block_number,
            block_hash,
            transaction_index,
            from: sender.0 .0,
            to: tx.to().map(|a| a.0 .0),
            value: value_bytes,
            input: tx.input().to_vec(),
            nonce: tx.nonce(),
            gas: tx.gas_limit(),
            gas_price,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            chain_id: tx.chain_id(),
            v,
            r: r_bytes,
            s: s_bytes,
            transaction_type: tx_type,
        })
    }

    /// Create a genesis block (block 0) for RPC compatibility.
    ///
    /// Ethereum block explorers like Blockscout expect a genesis block to exist.
    /// This creates a minimal genesis block with empty transactions and standard values.
    ///
    /// # Arguments
    /// * `timestamp` - Genesis block timestamp (Unix seconds)
    ///
    /// # Returns
    /// A Block struct representing the genesis block (block 0).
    fn create_genesis_block(timestamp: u64, gas_limit: u64) -> Block {
        // Empty trie root: keccak256(RLP([]))
        // This is the standard Ethereum empty trie root
        let empty_trie_root: [u8; 32] = [
            0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0,
            0xf8, 0x6e, 0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5,
            0xe3, 0x63, 0xb4, 0x21,
        ];

        // Ommers hash for empty list: keccak256(RLP([]))
        // In Ethereum, this is the hash of an empty list
        let empty_ommers_hash: [u8; 32] = [
            0x1d, 0xcc, 0x4d, 0xe8, 0xde, 0xc7, 0x5d, 0x7a, 0xab, 0x85, 0xb5, 0x67, 0xb6, 0xcc,
            0xd4, 0x1a, 0xd3, 0x12, 0x45, 0x1b, 0x94, 0x8a, 0x74, 0x13, 0xf0, 0xa1, 0x42, 0xfd,
            0x40, 0xd4, 0x93, 0x47,
        ];

        // Create a deterministic genesis block hash based on timestamp
        // This ensures the same genesis always produces the same hash
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(b"cipherbft-genesis-");
        hash_input.extend_from_slice(&timestamp.to_be_bytes());
        let genesis_hash: [u8; 32] = keccak256(&hash_input).0;

        // Create genesis block (size will be calculated below)
        let mut block = Block {
            hash: genesis_hash,
            number: 0,
            parent_hash: [0u8; 32], // Genesis has no parent
            ommers_hash: empty_ommers_hash,
            beneficiary: [0u8; 20], // No validator for genesis
            state_root: empty_trie_root,
            transactions_root: empty_trie_root,
            receipts_root: empty_trie_root,
            logs_bloom: vec![0u8; 256], // Empty bloom filter
            difficulty: [0u8; 32],      // Zero in PoS
            gas_limit,
            gas_used: 0, // No transactions in genesis
            timestamp,
            extra_data: b"CipherBFT Genesis".to_vec(),
            mix_hash: [0u8; 32],                   // Zero in PoS
            nonce: [0u8; 8],                       // Zero in PoS
            base_fee_per_gas: Some(1_000_000_000), // 1 gwei
            transaction_hashes: Vec::new(),        // No transactions
            transaction_count: 0,
            total_difficulty: [0u8; 32], // Zero in PoS
            size: 0,                     // Placeholder, calculated below
        };

        // Calculate exact RLP-encoded block header size
        block.size = block.calculate_size();
        block
    }
}

/// Adapter to make TcpPrimaryNetwork work with PrimaryNetwork trait
struct TcpPrimaryNetworkAdapter {
    network: Arc<TcpPrimaryNetwork>,
}

#[async_trait::async_trait]
impl cipherbft_data_chain::primary::PrimaryNetwork for TcpPrimaryNetworkAdapter {
    async fn broadcast_car(&self, car: &cipherbft_data_chain::Car) {
        self.network.broadcast_car(car).await;
    }

    async fn send_attestation(
        &self,
        proposer: ValidatorId,
        attestation: &cipherbft_data_chain::Attestation,
    ) {
        self.network.send_attestation(proposer, attestation).await;
    }

    async fn broadcast(&self, message: &DclMessage) {
        self.network.broadcast(message).await;
    }

    async fn send_to(&self, peer: ValidatorId, message: &DclMessage) {
        self.network.send_to(peer, message).await;
    }
}
