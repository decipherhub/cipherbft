//! Node runner - ties Primary, Workers, and Network together

use crate::config::NodeConfig;
use crate::network::TcpPrimaryNetwork;
use crate::util::validator_id_from_bls;
use anyhow::Result;
use cipherbft_crypto::{BlsKeyPair, BlsPublicKey};
use cipherbft_data_chain::{
    primary::{Primary, PrimaryConfig, PrimaryEvent},
    DclMessage,
};
use cipherbft_types::ValidatorId;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

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
        })
    }

    /// Add a known validator
    pub fn add_validator(&mut self, id: ValidatorId, pubkey: BlsPublicKey) {
        self.validators.insert(id, pubkey);
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

        // Spawn Primary task
        let (mut primary_handle, _worker_rxs) = Primary::spawn(
            primary_config,
            self.validators.clone(),
            Box::new(TcpPrimaryNetworkAdapter {
                network: primary_network,
            }),
            self.config.num_workers as u8,
        );

        info!("Node started, entering main loop");

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
