//! Node runner - ties Primary, Workers, and Network together

use crate::config::NodeConfig;
use crate::execution_bridge::ExecutionBridge;
use crate::network::TcpPrimaryNetwork;
use crate::util::validator_id_from_bls;
use anyhow::Result;
use cipherbft_consensus::{
    create_context, default_consensus_params, default_engine_config_single_part, spawn_host,
    spawn_network, spawn_wal, ConsensusHeight, ConsensusSigner, ConsensusSigningProvider,
    ConsensusValidator, MalachiteEngineBuilder,
};
use cipherbft_crypto::{BlsKeyPair, BlsPublicKey};
use cipherbft_data_chain::{
    primary::{Primary, PrimaryConfig, PrimaryEvent},
    Cut, DclMessage,
};
use cipherbft_execution::ChainConfig;
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
use tracing::{debug, error, info, warn};

/// A running CipherBFT node
pub struct Node {
    /// Configuration
    config: NodeConfig,
    /// BLS keypair
    keypair: BlsKeyPair,
    /// Our validator ID
    validator_id: ValidatorId,
    /// Known validators and their public keys
    validators: HashMap<ValidatorId, BlsPublicKey>,
    /// Execution layer bridge
    execution_bridge: Option<Arc<ExecutionBridge>>,
}

impl Node {
    /// Create a new node from configuration
    pub fn new(config: NodeConfig) -> Result<Self> {
        let keypair = config.keypair()?;
        let validator_id = validator_id_from_bls(&keypair.public_key);

        // Verify validator ID matches
        if validator_id != config.validator_id {
            anyhow::bail!(
                "Validator ID mismatch: config has {:?}, derived {:?}",
                config.validator_id,
                validator_id
            );
        }

        Ok(Self {
            config,
            keypair,
            validator_id,
            validators: HashMap::new(),
            execution_bridge: None,
        })
    }

    /// Add a known validator
    pub fn add_validator(&mut self, id: ValidatorId, pubkey: BlsPublicKey) {
        self.validators.insert(id, pubkey);
    }

    /// Enable execution layer integration
    ///
    /// Must be called before `run()` to enable Cut execution.
    pub fn with_execution_layer(mut self) -> Result<Self> {
        let chain_config = ChainConfig::default();
        let bridge = ExecutionBridge::new(chain_config)?;
        self.execution_bridge = Some(Arc::new(bridge));
        Ok(self)
    }

    /// Run the node
    pub async fn run(self) -> Result<()> {
        info!("Starting node with validator ID: {:?}", self.validator_id);

        // Create data directory if needed
        std::fs::create_dir_all(&self.config.data_dir)?;

        // Create channels for Primary
        let (primary_incoming_tx, mut primary_incoming_rx) =
            mpsc::channel::<(ValidatorId, DclMessage)>(1000);

        // Create primary network
        let primary_network = Arc::new(TcpPrimaryNetwork::new(
            self.validator_id,
            &self.config.peers,
            primary_incoming_tx.clone(),
        ));

        // Start primary listener
        Arc::clone(&primary_network)
            .start_listener(self.config.primary_listen)
            .await?;

        // Connect to peers (with retry)
        tokio::spawn({
            let network = Arc::clone(&primary_network);
            async move {
                // Initial delay to let other nodes start
                tokio::time::sleep(Duration::from_secs(1)).await;
                loop {
                    network.connect_to_all_peers().await;
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        });

        // Create Primary configuration
        let primary_config = PrimaryConfig::new(self.validator_id, self.keypair.secret_key.clone())
            .with_car_interval(Duration::from_millis(self.config.car_interval_ms))
            .with_max_empty_cars(3);

        // Create channel for CutReady events to Consensus Host
        let (cut_tx, cut_rx) = mpsc::channel::<Cut>(100);

        // Spawn Primary task
        let (mut primary_handle, _worker_rxs) = Primary::spawn(
            primary_config,
            self.validators.clone(),
            Box::new(TcpPrimaryNetworkAdapter {
                network: primary_network,
            }),
            self.config.num_workers as u8,
        );
        let (decided_tx, mut decided_rx) = mpsc::channel::<(ConsensusHeight, Cut)>(100);

        // Get Ed25519 keypair for Consensus
        let ed25519_keypair = self.config.ed25519_keypair()?;
        let ed25519_pubkey = ed25519_keypair.public_key.clone();
        let consensus_signer = ConsensusSigner::new(ed25519_keypair);
        let signing_provider = ConsensusSigningProvider::new(consensus_signer);

        // Create Consensus context and validators
        // TODO: Currently we only have BLS public keys in validators map
        // Need to add Ed25519 public keys to validator set
        // For now, create a minimal validator set with just ourselves
        let chain_id = "cipherbft-test";
        let consensus_validators = vec![ConsensusValidator::new(
            self.validator_id,
            ed25519_pubkey,
            100, // voting power
        )];
        let ctx = create_context(chain_id, consensus_validators, None)?;
        let our_address = ctx.validator_set().as_slice()[0].address;
        let params = default_consensus_params(&ctx, our_address);
        let consensus_config = default_engine_config_single_part();

        // Create metrics registry for consensus actors
        let metrics = SharedRegistry::global().with_moniker("cipherbft-consensus");

        // Generate libp2p keypair from Ed25519 key for consensus network
        // TODO: Use the actual Ed25519 key from config when available
        let consensus_keypair = Keypair::generate_ed25519();

        // Create network config for consensus p2p layer
        // Convert SocketAddr to Multiaddr format
        let listen_addr: Multiaddr = format!(
            "/ip4/{}/tcp/{}",
            self.config.consensus_listen.ip(),
            self.config.consensus_listen.port()
        )
        .parse()
        .expect("valid multiaddr from config");
        let network_config = NetworkConfig {
            listen_addr: listen_addr.clone(),
            persistent_peers: vec![], // TODO: Configure persistent_peers from NodeConfig.peers
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
        let network = spawn_network(consensus_keypair, network_config, metrics.clone()).await?;

        let wal_path = self.config.data_dir.join("consensus_wal");
        let wal = spawn_wal(&ctx, wal_path, metrics.clone()).await?;

        let host = spawn_host(self.validator_id, ctx.clone(), cut_rx, Some(decided_tx)).await?;

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
        info!("Node started, entering main loop");

        // Clone execution bridge for use in event loop
        let execution_bridge = self.execution_bridge.clone();

        // Main event loop
        loop {
            tokio::select! {
                // Incoming network messages -> forward to Primary
                Some((from, msg)) = primary_incoming_rx.recv() => {
                    debug!("Received message from {:?}: {:?}", from, msg.type_name());
                    if let Err(e) = primary_handle.send_from_peer(from, msg).await {
                        warn!("Failed to forward message to Primary: {:?}", e);
                    }
                }

                // Primary events
                Some(event) = primary_handle.recv_event() => {
                    match event {
                        PrimaryEvent::CutReady(cut) => {
                            info!(
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

                // Consensus Decided events - execute the decided Cut
                Some((height, cut)) = decided_rx.recv() => {
                    info!(
                        "Consensus decided at height {} with {} cars",
                        height,
                        cut.cars.len()
                    );

                    // Execute Cut if execution layer is enabled
                    if let Some(ref bridge) = execution_bridge {
                        match bridge.execute_cut(cut).await {
                            Ok(result) => {
                                info!(
                                    "Cut executed successfully - state_root: {}, gas_used: {}",
                                    result.state_root,
                                    result.gas_used
                                );
                            }
                            Err(e) => {
                                error!("Cut execution failed: {}", e);
                            }
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
}
