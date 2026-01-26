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
use crate::network::{TcpPrimaryNetwork, TcpWorkerNetwork};
use crate::supervisor::NodeSupervisor;
use anyhow::{Context, Result};
use cipherbft_consensus::{
    create_context, default_consensus_params, default_engine_config_single_part, spawn_host,
    spawn_network, spawn_wal, ConsensusHeight, ConsensusSigner, ConsensusSigningProvider,
    ConsensusValidator, MalachiteEngineBuilder,
};
use cipherbft_crypto::{BlsKeyPair, BlsPublicKey, Ed25519KeyPair, Ed25519PublicKey};
use cipherbft_data_chain::{
    primary::{Primary, PrimaryConfig, PrimaryEvent},
    worker::{Worker, WorkerConfig},
    Cut, DclMessage, WorkerMessage,
};
use cipherbft_execution::{
    keccak256, ChainConfig, InMemoryProvider, Log as ExecutionLog,
    TransactionReceipt as ExecutionReceipt,
};
use cipherbft_storage::{
    Block, BlockStore, Database, DatabaseConfig, Log as StorageLog, MdbxBlockStore,
    MdbxReceiptStore, Receipt as StorageReceipt, ReceiptStore,
};
use cipherbft_types::genesis::Genesis;
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

/// Validator public key information for both DCL and Consensus layers
#[derive(Clone, Debug)]
pub struct ValidatorInfo {
    /// BLS public key for DCL layer (threshold signatures)
    pub bls_public_key: BlsPublicKey,
    /// Ed25519 public key for Consensus layer (Malachite signing)
    pub ed25519_public_key: Ed25519PublicKey,
    /// Voting power for consensus
    pub voting_power: u64,
}

impl ValidatorInfo {
    /// Create a new validator info with default voting power
    pub fn new(bls_public_key: BlsPublicKey, ed25519_public_key: Ed25519PublicKey) -> Self {
        Self {
            bls_public_key,
            ed25519_public_key,
            voting_power: 100, // Default voting power
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
        }
    }
}

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
    /// Whether DCL (Data Chain Layer) is enabled.
    /// When disabled, consensus proceeds without data availability attestations.
    dcl_enabled: bool,
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
            dcl_enabled: true, // Default to enabled, overridden by genesis
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

            debug!(
                "Adding validator {} (stake: {}, voting_power: {})",
                validator.address, validator.staked_amount, voting_power
            );

            self.validators.insert(
                validator_id,
                ValidatorInfo::with_voting_power(bls_pubkey, ed25519_pubkey, voting_power),
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

        Ok(())
    }

    /// Enable execution layer integration
    ///
    /// Must be called before `run()` to enable Cut execution.
    ///
    /// # Note
    /// This creates an execution layer with an empty staking state.
    /// For production use, prefer `with_execution_layer_from_genesis` to
    /// initialize the staking state from the genesis file.
    pub fn with_execution_layer(mut self) -> Result<Self> {
        use cipherbft_storage::{DclStore, InMemoryStore};
        let chain_config = ChainConfig::default();
        let dcl_store: std::sync::Arc<dyn DclStore> = std::sync::Arc::new(InMemoryStore::new());
        let bridge = ExecutionBridge::new(chain_config, dcl_store)?;
        self.execution_bridge = Some(Arc::new(bridge));
        Ok(self)
    }

    /// Enable execution layer integration with genesis validators.
    ///
    /// This is the preferred method for production use. It initializes the
    /// staking precompile with the validator set from the genesis file,
    /// ensuring validators are correctly registered on node startup.
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
        use cipherbft_storage::{DclStore, InMemoryStore};
        let chain_config = ChainConfig::default();
        let dcl_store: std::sync::Arc<dyn DclStore> = std::sync::Arc::new(InMemoryStore::new());
        let bridge = ExecutionBridge::from_genesis(chain_config, dcl_store, genesis)?;
        self.execution_bridge = Some(Arc::new(bridge));
        info!(
            "Execution layer initialized with {} validators from genesis",
            genesis.validator_count()
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

        if self.dcl_enabled {
            // Create primary network
            let primary_network = Arc::new(TcpPrimaryNetwork::new(
                self.validator_id,
                &self.config.peers,
                primary_incoming_tx.clone(),
            ));

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
                    .with_max_empty_cars(u32::MAX);

            // Extract BLS public keys for DCL layer (Primary uses BLS for threshold signatures)
            let bls_pubkeys: HashMap<ValidatorId, BlsPublicKey> = self
                .validators
                .iter()
                .map(|(id, info)| (*id, info.bls_public_key.clone()))
                .collect();

            // Spawn Primary task
            let (primary_handle, worker_rxs) = Primary::spawn(
                primary_config,
                bls_pubkeys,
                Box::new(TcpPrimaryNetworkAdapter {
                    network: primary_network,
                }),
                self.config.num_workers as u8,
            );

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

                // Create Worker config and spawn
                let worker_config = WorkerConfig::new(self.validator_id, worker_id);
                let mut worker_handle = Worker::spawn(worker_config, Box::new(worker_network));

                // Combined bridge task: handles all communication with Worker
                // - Primary -> Worker: forward batch requests
                // - Worker -> Primary: forward batch digests
                // - Network -> Worker: forward peer messages
                let token = cancel_token.clone();
                let primary_worker_sender = primary_handle.worker_sender();
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            biased;

                            _ = token.cancelled() => {
                                debug!("Worker {} bridge shutting down", worker_id);
                                break;
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

        // Start with ourselves
        let mut consensus_validators = vec![ConsensusValidator::new(
            self.validator_id,
            ed25519_pubkey,
            our_voting_power,
        )];

        // Add all other validators from the known validator set
        for (validator_id, info) in &self.validators {
            if *validator_id != self.validator_id {
                consensus_validators.push(ConsensusValidator::new(
                    *validator_id,
                    info.ed25519_public_key.clone(),
                    info.voting_power,
                ));
            }
        }
        let ctx = create_context(chain_id, consensus_validators, None)?;
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
        let host = spawn_host(
            self.validator_id,
            ctx.clone(),
            cut_rx,
            Some(decided_tx),
            Some(network.clone()),
        )
        .await?;

        // Build and spawn Consensus engine
        let _engine_handles = MalachiteEngineBuilder::new(
            ctx.clone(),
            params,
            consensus_config,
            Box::new(signing_provider),
            network,
            host,
            wal,
        )
        .spawn()
        .await?;

        info!("Consensus engine started");

        // RPC storage reference - used to update block number when consensus decides
        // Moved outside the `if` block so it can be passed to run_event_loop
        use cipherbft_rpc::MdbxRpcStorage;
        let rpc_storage: Option<Arc<MdbxRpcStorage<InMemoryProvider>>> = if self.config.rpc_enabled
        {
            // Create MDBX database for block/receipt storage
            let db_path = self.config.data_dir.join("rpc_storage");
            let db_config = DatabaseConfig::new(&db_path);
            let database =
                Database::open(db_config).context("Failed to open RPC storage database")?;
            let db_env = database.env().clone();

            // Create block and receipt stores
            let block_store = Arc::new(MdbxBlockStore::new(db_env.clone()));
            let receipt_store = Arc::new(MdbxReceiptStore::new(db_env));

            // Create a provider for state queries (shared with execution layer)
            let provider = Arc::new(InMemoryProvider::new());

            // Create MdbxRpcStorage with chain ID
            let chain_id = 85300u64; // CipherBFT testnet chain ID
            let storage = Arc::new(MdbxRpcStorage::new(
                provider,
                block_store,
                receipt_store,
                chain_id,
            ));

            // Ensure genesis block (block 0) exists for Ethereum RPC compatibility
            // Block explorers like Blockscout expect block 0 to exist
            match storage.block_store().get_block_by_number(0).await {
                Ok(Some(_)) => {
                    debug!("Genesis block (block 0) already exists in storage");
                }
                Ok(None) => {
                    // Create and store genesis block
                    let genesis_timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let genesis_block = Self::create_genesis_block(genesis_timestamp);
                    if let Err(e) = storage.block_store().put_block(&genesis_block).await {
                        error!("Failed to store genesis block: {}", e);
                    } else {
                        info!(
                            "Created genesis block (block 0) with hash 0x{}",
                            hex::encode(&genesis_block.hash[..8])
                        );
                    }
                }
                Err(e) => {
                    warn!("Failed to check for genesis block: {}", e);
                }
            }

            // Initialize latest_block from storage (important for restart scenarios)
            // Note: We check for the latest block AFTER ensuring genesis exists
            if let Ok(Some(latest)) = storage.block_store().get_latest_block_number().await {
                storage.set_latest_block(latest);
                info!("Initialized RPC latest_block from storage: {}", latest);
            }

            Some(storage)
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

        // Start RPC server if enabled
        if let Some(ref storage) = rpc_storage {
            use cipherbft_rpc::{
                RpcConfig, RpcServer, StubExecutionApi, StubMempoolApi, StubNetworkApi,
            };

            let mut rpc_config = RpcConfig::with_chain_id(85300); // CipherBFT testnet chain ID
            rpc_config.http_port = self.config.rpc_http_port;
            rpc_config.ws_port = self.config.rpc_ws_port;

            // For now, use stub implementations for mempool, execution, and network
            // Block storage is now backed by MDBX
            let mempool = Arc::new(StubMempoolApi::new());
            let executor = Arc::new(StubExecutionApi::new());
            let network = Arc::new(StubNetworkApi::new());

            // Use with_subscription_manager to share the subscription manager
            // between the RPC server and the event loop for broadcasting blocks
            let rpc_server = RpcServer::with_subscription_manager(
                rpc_config,
                storage.clone(),
                mempool,
                executor,
                network,
                subscription_manager.clone().unwrap(),
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
    #[allow(clippy::too_many_arguments)]
    async fn run_event_loop(
        cancel_token: CancellationToken,
        primary_incoming_rx: &mut mpsc::Receiver<(ValidatorId, DclMessage)>,
        mut primary_handle: Option<&mut cipherbft_data_chain::primary::PrimaryHandle>,
        cut_tx: &mpsc::Sender<Cut>,
        decided_rx: &mut mpsc::Receiver<(ConsensusHeight, Cut)>,
        cut_advance_tx: mpsc::Sender<()>,
        execution_bridge: Option<Arc<ExecutionBridge>>,
        rpc_storage: Option<Arc<cipherbft_rpc::MdbxRpcStorage<InMemoryProvider>>>,
        subscription_manager: Option<Arc<cipherbft_rpc::SubscriptionManager>>,
    ) -> Result<()> {
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
                        match bridge.execute_cut(cut).await {
                            Ok(block_result) => {
                                info!(
                                    "Cut executed successfully - state_root: {}, gas_used: {}, block_hash: {}",
                                    block_result.execution_result.state_root,
                                    block_result.execution_result.gas_used,
                                    block_result.block_hash
                                );

                                // Store the block to MDBX for eth_getBlockByNumber queries
                                if let Some(ref storage) = rpc_storage {
                                    // Update latest block number
                                    storage.set_latest_block(height.0);
                                    debug!("Updated RPC block number to {}", height.0);

                                    // Create and store the block
                                    let block = Self::execution_result_to_block(height.0, &block_result);
                                    if let Err(e) = storage.block_store().put_block(&block).await {
                                        error!("Failed to store block {} to MDBX: {}", height.0, e);
                                    } else {
                                        debug!("Stored block {} to MDBX with hash {}", height.0, block_result.block_hash);

                                        // Broadcast to WebSocket subscribers (eth_subscribe("newHeads"))
                                        if let Some(ref sub_mgr) = subscription_manager {
                                            use cipherbft_rpc::storage_block_to_rpc_block;
                                            let rpc_block = storage_block_to_rpc_block(block.clone(), false);
                                            sub_mgr.broadcast_block(rpc_block);
                                            debug!("Broadcast block {} to WebSocket subscribers", height.0);
                                        }
                                    }

                                    // Store receipts for eth_getBlockReceipts queries
                                    if !block_result.execution_result.receipts.is_empty() {
                                        let storage_receipts: Vec<StorageReceipt> = block_result
                                            .execution_result
                                            .receipts
                                            .iter()
                                            .map(Self::execution_receipt_to_storage)
                                            .collect();
                                        if let Err(e) = storage.receipt_store().put_receipts(&storage_receipts).await {
                                            error!("Failed to store {} receipts for block {}: {}", storage_receipts.len(), height.0, e);
                                        } else {
                                            debug!("Stored {} receipts for block {}", storage_receipts.len(), height.0);
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Cut execution failed: {}", e);
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
    fn execution_result_to_block(block_number: u64, result: &BlockExecutionResult) -> Block {
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
            beneficiary: [0u8; 20], // TODO: Set to validator address
            state_root: exec.state_root.0,
            transactions_root: exec.transactions_root.0,
            receipts_root: exec.receipts_root.0,
            logs_bloom: exec.logs_bloom.0.to_vec(),
            difficulty: [0u8; 32], // Always zero in PoS
            gas_limit: 30_000_000, // TODO: Get from config
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
    fn execution_receipt_to_storage(receipt: &ExecutionReceipt) -> StorageReceipt {
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
            block_hash: receipt.block_hash.0,
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
    fn create_genesis_block(timestamp: u64) -> Block {
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
            gas_limit: 30_000_000,      // Standard gas limit
            gas_used: 0,                // No transactions in genesis
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
