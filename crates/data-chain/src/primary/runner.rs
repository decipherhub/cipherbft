//! Primary process runner
//!
//! The Primary main loop orchestrates:
//! - Car creation from batch digests
//! - Broadcasting Cars to peers
//! - Processing received Cars and generating attestations
//! - Collecting and aggregating attestations
//! - Forming Cuts for consensus

use crate::attestation::{AggregatedAttestation, Attestation};
use crate::batch::BatchDigest;
use crate::car::Car;
use crate::cut::Cut;
use crate::error::DclError;
use crate::messages::{DclMessage, PrimaryToWorker, WorkerToPrimary};
use crate::primary::attestation_collector::AttestationCollector;
use crate::primary::config::PrimaryConfig;
use crate::primary::core::Core;
use crate::primary::cut_former::CutFormer;
use crate::primary::proposer::Proposer;
use crate::primary::state::{PipelineStage, PrimaryState};
use crate::storage::CarStore;
use cipherbft_crypto::BlsPublicKey;
use cipherbft_metrics::dcl::{
    DCL_ATTESTATIONS_RECEIVED, DCL_ATTESTATIONS_SENT, DCL_DAG_CERTIFICATES, DCL_DAG_DEPTH,
    DCL_DAG_PENDING_BATCHES, DCL_PRIMARY_CARS_CREATED, DCL_PRIMARY_CUTS_CREATED,
    DCL_PRIMARY_CUT_LATENCY, DCL_QUORUM_REACHED, DCL_SYNC_LAG_BLOCKS, DCL_SYNC_REQUESTS,
};
use cipherbft_types::{Hash, ValidatorId};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::{debug, error, info, trace, warn};

/// Events emitted by the Primary
#[derive(Debug)]
pub enum PrimaryEvent {
    /// Cut is ready for consensus
    CutReady(Cut),
    /// Car created and needs to be broadcast
    CarCreated(Car),
    /// Attestation generated and needs to be sent
    AttestationGenerated {
        car_proposer: ValidatorId,
        attestation: Attestation,
    },
    /// Request Workers to sync missing batches
    SyncBatches {
        digests: Vec<Hash>,
        target: ValidatorId,
    },
}

/// Commands sent to the Primary from external sources
#[derive(Debug)]
pub enum PrimaryCommand {
    /// Notify that consensus has decided on a height
    ConsensusDecided {
        /// The height that was decided
        height: u64,
        /// The Cut that was decided (used to sync positions)
        cut: Cut,
    },
}

/// Network interface for Primary-to-Primary communication
#[async_trait::async_trait]
pub trait PrimaryNetwork: Send + Sync {
    /// Broadcast Car to all peer Primaries
    async fn broadcast_car(&self, car: &Car);

    /// Send attestation to Car proposer
    async fn send_attestation(&self, proposer: ValidatorId, attestation: &Attestation);

    /// Broadcast message to all peers
    async fn broadcast(&self, message: &DclMessage);

    /// Send a message to a specific peer
    ///
    /// Used for point-to-point communication, such as responding to CarRequest.
    async fn send_to(&self, peer: ValidatorId, message: &DclMessage);
}

/// Handle for a spawned Primary task
pub struct PrimaryHandle {
    /// Join handle for the primary task
    handle: tokio::task::JoinHandle<()>,
    /// Sender for Worker-to-Primary messages
    worker_sender: mpsc::Sender<WorkerToPrimary>,
    /// Sender for network messages (from peer Primaries)
    network_sender: mpsc::Sender<(ValidatorId, DclMessage)>,
    /// Sender for commands to the Primary
    command_sender: mpsc::Sender<PrimaryCommand>,
    /// Receiver for Primary events
    event_receiver: mpsc::Receiver<PrimaryEvent>,
}

impl PrimaryHandle {
    /// Get a clone of the worker sender for bridging
    ///
    /// This is used when spawning Workers in a separate task that needs
    /// to forward messages to Primary.
    pub fn worker_sender(&self) -> mpsc::Sender<WorkerToPrimary> {
        self.worker_sender.clone()
    }

    /// Send a message from Worker
    pub async fn send_from_worker(
        &self,
        msg: WorkerToPrimary,
    ) -> Result<(), mpsc::error::SendError<WorkerToPrimary>> {
        self.worker_sender.send(msg).await
    }

    /// Send a message from peer Primary
    pub async fn send_from_peer(
        &self,
        peer: ValidatorId,
        msg: DclMessage,
    ) -> Result<(), mpsc::error::SendError<(ValidatorId, DclMessage)>> {
        self.network_sender.send((peer, msg)).await
    }

    /// Receive an event from Primary
    pub async fn recv_event(&mut self) -> Option<PrimaryEvent> {
        self.event_receiver.recv().await
    }

    /// Try to receive an event without blocking
    pub fn try_recv_event(&mut self) -> Result<PrimaryEvent, mpsc::error::TryRecvError> {
        self.event_receiver.try_recv()
    }

    /// Request shutdown and wait for primary to finish
    pub async fn shutdown(self) {
        self.handle.abort();
        let _ = self.handle.await;
    }

    /// Check if the primary task is finished
    pub fn is_finished(&self) -> bool {
        self.handle.is_finished()
    }

    /// Notify the Primary that consensus has decided on a height
    ///
    /// This triggers the Primary to advance its state and continue producing cuts.
    /// The Cut is passed so that the Primary can sync its position tracking with
    /// the authoritative decided state - this ensures validators that missed some
    /// CARs during collection still have consistent position tracking.
    pub async fn notify_decision(
        &self,
        height: u64,
        cut: Cut,
    ) -> Result<(), mpsc::error::SendError<PrimaryCommand>> {
        self.command_sender
            .send(PrimaryCommand::ConsensusDecided { height, cut })
            .await
    }
}

/// Primary process - handles Car creation, attestation collection, and Cut formation
pub struct Primary {
    /// Configuration
    config: PrimaryConfig,
    /// Internal state
    state: PrimaryState,
    /// Car proposer
    proposer: Proposer,
    /// Core message processor
    core: Core,
    /// Attestation collector
    attestation_collector: AttestationCollector,
    /// Cut former
    cut_former: CutFormer,
    /// Channel to receive messages from Workers
    from_workers: mpsc::Receiver<WorkerToPrimary>,
    /// Channels to send messages to Workers (used for sync requests)
    #[allow(dead_code)]
    to_workers: Vec<mpsc::Sender<PrimaryToWorker>>,
    /// Channel to receive messages from peer Primaries
    from_network: mpsc::Receiver<(ValidatorId, DclMessage)>,
    /// Channel to receive commands (e.g., consensus decisions)
    from_commands: mpsc::Receiver<PrimaryCommand>,
    /// Network interface
    network: Box<dyn PrimaryNetwork>,
    /// Optional persistent storage for Cars and attestations
    storage: Option<Arc<dyn CarStore>>,
    /// Channel to send events
    event_sender: mpsc::Sender<PrimaryEvent>,
    /// Last Cut (for monotonicity)
    last_cut: Option<Cut>,
    /// Shutdown flag
    shutdown: bool,
    /// Time when cut formation started (for latency tracking)
    cut_start_time: Option<Instant>,
}

impl Primary {
    /// Spawn a new Primary task
    pub fn spawn(
        config: PrimaryConfig,
        validator_pubkeys: HashMap<ValidatorId, BlsPublicKey>,
        network: Box<dyn PrimaryNetwork>,
        worker_count: u8,
    ) -> (PrimaryHandle, Vec<mpsc::Receiver<PrimaryToWorker>>) {
        Self::spawn_with_storage(config, validator_pubkeys, network, worker_count, None)
    }

    /// Spawn a new Primary task with optional persistent storage
    pub fn spawn_with_storage(
        config: PrimaryConfig,
        validator_pubkeys: HashMap<ValidatorId, BlsPublicKey>,
        network: Box<dyn PrimaryNetwork>,
        worker_count: u8,
        storage: Option<Arc<dyn CarStore>>,
    ) -> (PrimaryHandle, Vec<mpsc::Receiver<PrimaryToWorker>>) {
        Self::spawn_with_initial_cut(
            config,
            validator_pubkeys,
            network,
            worker_count,
            storage,
            None,
        )
    }

    /// Spawn a new Primary task with optional initial cut for restart recovery
    ///
    /// When `initial_cut` is provided, Primary state is initialized from the cut:
    /// - Position tracking (our_position, last_seen_positions) is restored
    /// - Height tracking (current_height, last_finalized_height) is restored
    ///
    /// This enables seamless validator restart: other validators will accept
    /// our CARs because positions are continuous from the last finalized state.
    ///
    /// # Arguments
    /// * `config` - Primary configuration
    /// * `validator_pubkeys` - BLS public keys for all validators
    /// * `network` - Network interface for peer communication
    /// * `worker_count` - Number of worker processes
    /// * `storage` - Optional persistent storage for CARs
    /// * `initial_cut` - Optional cut to initialize state from (for restart recovery)
    pub fn spawn_with_initial_cut(
        config: PrimaryConfig,
        validator_pubkeys: HashMap<ValidatorId, BlsPublicKey>,
        network: Box<dyn PrimaryNetwork>,
        worker_count: u8,
        storage: Option<Arc<dyn CarStore>>,
        initial_cut: Option<Cut>,
    ) -> (PrimaryHandle, Vec<mpsc::Receiver<PrimaryToWorker>>) {
        let (from_workers_tx, from_workers_rx) = mpsc::channel(1024);
        let (from_network_tx, from_network_rx) = mpsc::channel(1024);
        let (command_tx, command_rx) = mpsc::channel(64);
        let (event_tx, event_rx) = mpsc::channel(256);

        // Create worker channels
        let mut to_workers = Vec::with_capacity(worker_count as usize);
        let mut worker_receivers = Vec::with_capacity(worker_count as usize);
        for _ in 0..worker_count {
            let (tx, rx) = mpsc::channel(256);
            to_workers.push(tx);
            worker_receivers.push(rx);
        }

        let config_clone = config.clone();
        let handle = tokio::spawn(async move {
            let mut primary = Primary::new_with_initial_cut(
                config_clone,
                validator_pubkeys,
                from_workers_rx,
                to_workers,
                from_network_rx,
                command_rx,
                network,
                event_tx,
                storage,
                initial_cut,
            );
            primary.run().await;
        });

        let primary_handle = PrimaryHandle {
            handle,
            worker_sender: from_workers_tx,
            network_sender: from_network_tx,
            command_sender: command_tx,
            event_receiver: event_rx,
        };

        (primary_handle, worker_receivers)
    }

    /// Create a new Primary
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: PrimaryConfig,
        validator_pubkeys: HashMap<ValidatorId, BlsPublicKey>,
        from_workers: mpsc::Receiver<WorkerToPrimary>,
        to_workers: Vec<mpsc::Sender<PrimaryToWorker>>,
        from_network: mpsc::Receiver<(ValidatorId, DclMessage)>,
        from_commands: mpsc::Receiver<PrimaryCommand>,
        network: Box<dyn PrimaryNetwork>,
        event_sender: mpsc::Sender<PrimaryEvent>,
    ) -> Self {
        Self::new_with_storage(
            config,
            validator_pubkeys,
            from_workers,
            to_workers,
            from_network,
            from_commands,
            network,
            event_sender,
            None,
        )
    }

    /// Create a new Primary with optional persistent storage
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_storage(
        config: PrimaryConfig,
        validator_pubkeys: HashMap<ValidatorId, BlsPublicKey>,
        from_workers: mpsc::Receiver<WorkerToPrimary>,
        to_workers: Vec<mpsc::Sender<PrimaryToWorker>>,
        from_network: mpsc::Receiver<(ValidatorId, DclMessage)>,
        from_commands: mpsc::Receiver<PrimaryCommand>,
        network: Box<dyn PrimaryNetwork>,
        event_sender: mpsc::Sender<PrimaryEvent>,
        storage: Option<Arc<dyn CarStore>>,
    ) -> Self {
        Self::new_with_initial_cut(
            config,
            validator_pubkeys,
            from_workers,
            to_workers,
            from_network,
            from_commands,
            network,
            event_sender,
            storage,
            None,
        )
    }

    /// Create a new Primary with optional initial cut for restart recovery
    ///
    /// When `initial_cut` is provided, Primary state is initialized from the cut,
    /// restoring position tracking for seamless validator restart.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_initial_cut(
        config: PrimaryConfig,
        validator_pubkeys: HashMap<ValidatorId, BlsPublicKey>,
        from_workers: mpsc::Receiver<WorkerToPrimary>,
        to_workers: Vec<mpsc::Sender<PrimaryToWorker>>,
        from_network: mpsc::Receiver<(ValidatorId, DclMessage)>,
        from_commands: mpsc::Receiver<PrimaryCommand>,
        network: Box<dyn PrimaryNetwork>,
        event_sender: mpsc::Sender<PrimaryEvent>,
        storage: Option<Arc<dyn CarStore>>,
        initial_cut: Option<Cut>,
    ) -> Self {
        // Initialize state from cut if available, otherwise start fresh
        let state = match initial_cut.as_ref() {
            Some(cut) => {
                info!(
                    validator = %config.validator_id,
                    cut_height = cut.height,
                    cut_validators = cut.cars.len(),
                    "Initializing Primary state from finalized cut"
                );
                PrimaryState::from_cut(config.validator_id, config.equivocation_retention, cut)
            }
            None => {
                info!(
                    validator = %config.validator_id,
                    "Initializing Primary state from scratch (no finalized cut)"
                );
                PrimaryState::new(config.validator_id, config.equivocation_retention)
            }
        };

        let proposer = Proposer::new(
            config.validator_id,
            config.bls_secret_key.clone(),
            config.max_empty_cars,
        );

        // Build validator indices
        let mut validators: Vec<ValidatorId> = validator_pubkeys.keys().cloned().collect();
        validators.sort();
        let validator_indices: HashMap<_, _> = validators
            .iter()
            .enumerate()
            .map(|(i, v)| (*v, i))
            .collect();

        let our_keypair =
            cipherbft_crypto::BlsKeyPair::from_secret_key(config.bls_secret_key.clone());
        let core = Core::new(
            config.validator_id,
            our_keypair,
            validator_pubkeys.clone(),
            config.attestation_quorum,
        );

        let attestation_collector = AttestationCollector::new(
            config.validator_id,
            core.attestation_threshold(),
            core.validator_count(),
            validator_indices,
            config.attestation_timeout_base,
            config.attestation_timeout_max,
        );

        let cut_former = CutFormer::new(validators, config.attestation_quorum);

        Self {
            config,
            state,
            proposer,
            core,
            attestation_collector,
            cut_former,
            from_workers,
            to_workers,
            from_network,
            from_commands,
            network,
            storage,
            event_sender,
            last_cut: initial_cut,
            shutdown: false,
            cut_start_time: None,
        }
    }

    /// Run the Primary main loop
    pub async fn run(&mut self) {
        info!(
            validator = %self.config.validator_id,
            startup_delay = ?self.config.startup_delay,
            "Primary starting, waiting for network to establish connections"
        );

        // Wait for network connections to be established before starting CAR creation.
        // This prevents position 0 CARs from being broadcast when no peers are connected,
        // which would cause PositionGap errors when later CARs arrive at other validators.
        tokio::time::sleep(self.config.startup_delay).await;

        info!(
            validator = %self.config.validator_id,
            "Primary startup delay complete, beginning CAR creation"
        );

        // Set up Car creation interval
        let mut car_interval = interval(self.config.car_interval);
        car_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Set up attestation timeout check interval
        let mut timeout_interval = interval(Duration::from_millis(100));
        timeout_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        while !self.shutdown {
            tokio::select! {
                // Handle messages from Workers
                Some(msg) = self.from_workers.recv() => {
                    self.handle_worker_message(msg).await;
                }

                // Handle messages from peer Primaries
                Some((peer, msg)) = self.from_network.recv() => {
                    self.handle_network_message(peer, msg).await;
                }

                // Handle commands (e.g., consensus decisions)
                Some(cmd) = self.from_commands.recv() => {
                    self.handle_command(cmd).await;
                }

                // Periodic Car creation
                _ = car_interval.tick() => {
                    let pending_count = self.state.pending_digests.len();
                    if pending_count > 0 {
                        info!(pending_count, "car_interval tick - has pending digests");
                    }
                    self.try_create_car().await;
                }

                // Check attestation timeouts
                _ = timeout_interval.tick() => {
                    self.check_attestation_timeouts().await;
                }
            }
        }

        info!(
            validator = %self.config.validator_id,
            "Primary shutting down"
        );
    }

    /// Handle message from Worker
    async fn handle_worker_message(&mut self, msg: WorkerToPrimary) {
        match msg {
            WorkerToPrimary::BatchDigest {
                worker_id,
                digest,
                tx_count,
                byte_size,
            } => {
                info!(
                    worker_id,
                    tx_count,
                    byte_size,
                    digest = %digest,
                    "Primary received batch digest from Worker"
                );
                self.state
                    .add_batch_digest(BatchDigest::new(worker_id, digest, tx_count, byte_size));

                // Track pending batches count
                DCL_DAG_PENDING_BATCHES.set(self.state.pending_digests.len() as f64);
            }

            WorkerToPrimary::BatchSynced { digest, success } => {
                // DIAGNOSTIC: Log at INFO level to debug batch sync flow
                info!(
                    digest = %digest,
                    success,
                    awaiting_cars_count = self.state.cars_awaiting_batches.len(),
                    "BatchSynced received at Primary"
                );

                if success {
                    // Mark batch as available
                    self.state.mark_batch_available(digest);

                    // Check if any waiting Cars are now ready
                    let ready_cars = self.state.get_ready_cars();

                    // DIAGNOSTIC: Log ready cars count
                    info!(
                        digest = %digest,
                        ready_count = ready_cars.len(),
                        remaining_awaiting = self.state.cars_awaiting_batches.len(),
                        "Checked for ready Cars after batch sync"
                    );
                    for car in ready_cars {
                        // IMPORTANT: The Car was already validated when first received
                        // (position check, signature, parent_ref all passed). We queued
                        // it only because batches were missing. Now that batches are
                        // available, we directly create the attestation without re-running
                        // validation (which would fail position check since subsequent
                        // Cars have already advanced the position counter).
                        info!(
                            proposer = %car.proposer,
                            position = car.position,
                            batch_count = car.batch_digests.len(),
                            "Creating attestation after batch sync completed"
                        );

                        // Create attestation directly (skip position re-validation)
                        let attestation = self.core.create_attestation(&car);

                        // Track attestation sent metric
                        DCL_ATTESTATIONS_SENT.inc();

                        // Send attestation to proposer
                        self.network
                            .send_attestation(car.proposer, &attestation)
                            .await;

                        // Emit event
                        let _ = self
                            .event_sender
                            .send(PrimaryEvent::AttestationGenerated {
                                car_proposer: car.proposer,
                                attestation,
                            })
                            .await;
                    }
                }
            }

            WorkerToPrimary::Ready { worker_id } => {
                info!(worker_id, "Worker ready");
            }
        }
    }

    /// Handle commands from external sources (e.g., node)
    async fn handle_command(&mut self, cmd: PrimaryCommand) {
        match cmd {
            PrimaryCommand::ConsensusDecided { height, cut } => {
                debug!(
                    height,
                    validator = %self.config.validator_id,
                    cut_cars = cut.cars.len(),
                    "Received consensus decision notification"
                );

                // CRITICAL: Sync position tracking from the decided Cut BEFORE advancing state
                // This ensures validators that missed some CARs during collection still have
                // consistent position tracking for subsequent heights
                self.state.sync_positions_from_cut(&cut);

                // CRITICAL: Process any queued CARs that are now ready after position sync.
                // When CARs arrive before the consensus decision is processed, they get queued
                // due to PositionGap errors. After sync_positions_from_cut() updates positions,
                // these queued CARs may now be at the expected position and should be processed.
                //
                // IMPORTANT: We must process in a LOOP because:
                // 1. Processing CAR at position N advances expected_position to N+1
                // 2. This may make another queued CAR at position N+1 become ready
                // 3. We need to continue until no more CARs become ready
                //
                // We also check ALL validators with queued CARs, not just those in the cut.
                loop {
                    let validators_to_check = self.state.get_validators_with_queued_cars();
                    if validators_to_check.is_empty() {
                        break;
                    }

                    let mut processed_any = false;
                    for validator in validators_to_check {
                        let ready_cars = self.state.get_cars_ready_after_gap_filled(&validator);
                        for ready_car in ready_cars {
                            debug!(
                                proposer = %ready_car.proposer,
                                position = ready_car.position,
                                "Processing queued Car after consensus decision synced positions"
                            );
                            self.handle_received_car(ready_car.proposer, ready_car)
                                .await;
                            processed_any = true;
                        }
                    }

                    if !processed_any {
                        break; // No more CARs became ready, exit loop
                    }
                }

                // Advance state to allow producing cuts for the next height
                self.state.finalize_height(height);

                // CRITICAL: Try to form a cut now that we're in Collecting stage.
                // This handles the case where queued CARs were processed above and reached
                // attestation threshold BEFORE finalize_height() was called. At that point,
                // try_form_cut() would have returned early because pipeline_stage was still
                // Proposing. Now that we're in Collecting stage, we can form the cut.
                self.try_form_cut().await;

                // Update DAG depth metric (current finalized height)
                DCL_DAG_DEPTH.set(self.state.last_finalized_height as f64);

                // Track total DAG certificates (attested CARs)
                DCL_DAG_CERTIFICATES.set(self.state.attested_cars.len() as f64);

                // Reset sync lag (we're caught up if consensus decided)
                DCL_SYNC_LAG_BLOCKS.set(0.0);

                debug!(
                    new_height = self.state.current_height,
                    last_finalized = self.state.last_finalized_height,
                    "Primary state advanced after consensus decision"
                );
            }
        }
    }

    /// Handle message from peer Primary
    async fn handle_network_message(&mut self, peer: ValidatorId, msg: DclMessage) {
        match msg {
            DclMessage::Car(car) => {
                self.handle_received_car(peer, car).await;
            }

            DclMessage::Attestation(attestation) => {
                self.handle_received_attestation(attestation).await;
            }

            DclMessage::CarRequest {
                validator,
                position,
            } => {
                debug!(
                    from = %peer,
                    validator = %validator,
                    position,
                    "Car request received"
                );

                // Lookup the CAR in storage and respond
                let car_opt = if let Some(ref storage) = self.storage {
                    match storage.get_car(&validator, position).await {
                        Ok(car) => car,
                        Err(e) => {
                            warn!(
                                validator = %validator,
                                position,
                                error = %e,
                                "Failed to lookup Car from storage"
                            );
                            None
                        }
                    }
                } else {
                    // No storage configured - cannot respond with CAR data
                    debug!(
                        validator = %validator,
                        position,
                        "No storage configured, cannot lookup Car"
                    );
                    None
                };

                // Send CarResponse back to the requester
                let response = DclMessage::CarResponse(car_opt.clone());
                self.network.send_to(peer, &response).await;

                debug!(
                    to = %peer,
                    validator = %validator,
                    position,
                    has_car = car_opt.is_some(),
                    "Car response sent"
                );
            }

            DclMessage::CarResponse(car_opt) => {
                if let Some(car) = car_opt {
                    debug!(
                        from = %peer,
                        proposer = %car.proposer,
                        position = car.position,
                        "Received CarResponse for gap recovery"
                    );

                    // Clear the pending request tracker
                    self.state.clear_car_request(&car.proposer, car.position);

                    // Process the missing Car first
                    self.handle_received_car(peer, car.clone()).await;

                    // After processing, check if any queued Cars are now ready
                    // This handles the case where we had position 2 queued and just received position 1
                    let ready_cars = self.state.get_cars_ready_after_gap_filled(&car.proposer);
                    for ready_car in ready_cars {
                        debug!(
                            proposer = %ready_car.proposer,
                            position = ready_car.position,
                            "Processing queued Car after gap filled"
                        );
                        // Process recursively - might trigger more attestations or gap recoveries
                        self.handle_received_car(ready_car.proposer, ready_car)
                            .await;
                    }
                } else {
                    debug!(
                        from = %peer,
                        "Received empty CarResponse - peer doesn't have the requested Car"
                    );
                }
            }

            DclMessage::BatchRequest { digest } => {
                // Forward to appropriate Worker
                debug!(
                    from = %peer,
                    digest = %digest,
                    "Batch request received"
                );
            }

            DclMessage::BatchResponse { digest, data } => {
                debug!(
                    from = %peer,
                    digest = %digest,
                    has_data = data.is_some(),
                    "Batch response received"
                );
            }

            DclMessage::CarWithAttestation { car, attestation } => {
                self.handle_received_car_with_attestation(peer, car, *attestation)
                    .await;
            }
        }
    }

    /// Handle a received Car
    async fn handle_received_car(&mut self, from: ValidatorId, car: Car) {
        // DIAGNOSTIC: Log at INFO level for batched Cars to trace attestation flow
        let batch_count = car.batch_digests.len();
        if batch_count > 0 {
            info!(
                from = %from,
                proposer = %car.proposer,
                position = car.position,
                batch_count,
                "Received BATCHED Car from peer"
            );
        } else {
            debug!(
                from = %from,
                proposer = %car.proposer,
                position = car.position,
                "Received Car"
            );
        }

        // Check batch availability (T097)
        let (has_all_batches, missing_digests) = self.state.check_batch_availability(&car);

        if !has_all_batches {
            // DIAGNOSTIC: Log at INFO to trace batch sync trigger
            info!(
                proposer = %car.proposer,
                position = car.position,
                batch_count,
                missing_count = missing_digests.len(),
                "Car missing batches, triggering sync"
            );

            // Check if we're already waiting for this Car
            let car_hash = car.hash();
            if !self.state.is_awaiting_batches(&car_hash) {
                // Add to awaiting queue (T098)
                self.state
                    .add_car_awaiting_batches(car.clone(), missing_digests.clone());

                // DIAGNOSTIC: Confirm Car added to awaiting queue
                info!(
                    proposer = %car.proposer,
                    position = car.position,
                    car_hash = %car_hash,
                    awaiting_count = self.state.cars_awaiting_batches.len(),
                    "Car added to awaiting queue"
                );

                // Track sync request metric
                DCL_SYNC_REQUESTS.inc();

                // Trigger batch sync via Workers (T098)
                // Send sync request to first Worker (in production, would choose appropriate Worker)
                if !self.to_workers.is_empty() {
                    let _ = self.to_workers[0]
                        .send(PrimaryToWorker::Synchronize {
                            digests: missing_digests.clone(),
                            target_validator: car.proposer,
                        })
                        .await;
                }

                // Emit sync event
                let _ = self
                    .event_sender
                    .send(PrimaryEvent::SyncBatches {
                        digests: missing_digests,
                        target: car.proposer,
                    })
                    .await;
            }
            return;
        }

        match self.core.handle_car(&car, &mut self.state, has_all_batches) {
            Ok(Some(attestation)) => {
                debug!(
                    proposer = %car.proposer,
                    position = car.position,
                    "Generated attestation (T099)"
                );

                // Track attestation sent metric
                DCL_ATTESTATIONS_SENT.inc();

                // Send attestation to proposer (T100)
                self.network
                    .send_attestation(car.proposer, &attestation)
                    .await;

                // Emit event
                let _ = self
                    .event_sender
                    .send(PrimaryEvent::AttestationGenerated {
                        car_proposer: car.proposer,
                        attestation,
                    })
                    .await;
            }

            Ok(None) => {
                // Shouldn't happen since we checked batch availability above
                debug!(
                    proposer = %car.proposer,
                    position = car.position,
                    "Car valid but no attestation generated"
                );
            }

            Err(DclError::PositionGap {
                validator,
                expected,
                actual,
            }) => {
                // Position gap detected - the Car arrived out of order
                // We need to request the missing predecessor(s) and queue this Car
                debug!(
                    from = %from,
                    proposer = %validator,
                    expected,
                    actual,
                    "Position gap detected, initiating gap recovery"
                );

                // Queue the out-of-order Car for later processing
                if !self.state.is_awaiting_gap_sync(&validator, actual) {
                    self.state.queue_car_awaiting_gap(car.clone(), expected);
                }

                // Request missing Cars (all positions from expected to actual-1)
                let missing_positions = self.state.get_missing_positions(&validator, actual);
                for pos in missing_positions {
                    if !self.state.is_car_request_pending(&validator, pos) {
                        debug!(
                            validator = %validator,
                            position = pos,
                            "Sending CarRequest for missing position"
                        );

                        // Track the pending request
                        self.state.track_car_request(validator, pos);

                        // Send CarRequest to all peers (one of them should have it)
                        let request = DclMessage::CarRequest {
                            validator,
                            position: pos,
                        };
                        self.network.broadcast(&request).await;
                    }
                }
            }

            Err(e) => {
                warn!(
                    from = %from,
                    proposer = %car.proposer,
                    error = %e,
                    "Invalid Car"
                );
            }
        }
    }

    /// Handle a received attestation
    async fn handle_received_attestation(&mut self, attestation: Attestation) {
        info!(
            attester = %attestation.attester,
            car_hash = %attestation.car_hash,
            "Received attestation from peer"
        );

        // Track attestation received metric
        DCL_ATTESTATIONS_RECEIVED.inc();

        // Verify attestation
        if let Err(e) = self.core.verify_attestation(&attestation) {
            warn!(
                attester = %attestation.attester,
                error = %e,
                "Invalid attestation"
            );
            return;
        }

        // Add to collector
        match self.attestation_collector.add_attestation(attestation) {
            Ok(Some(aggregated)) => {
                // Threshold reached - Car is ready for Cut
                info!(
                    car_hash = %aggregated.car_hash,
                    count = aggregated.count(),
                    "Attestation threshold reached - Car ready for Cut"
                );

                // Track quorum reached metric
                DCL_QUORUM_REACHED.inc();

                self.handle_aggregated_attestation(aggregated).await;
            }

            Ok(None) => {
                // Need more attestations
                trace!("Attestation added, waiting for more");
            }

            Err(e) => {
                debug!(error = %e, "Failed to add attestation");
            }
        }
    }

    /// Handle aggregated attestation (threshold reached)
    async fn handle_aggregated_attestation(&mut self, aggregated: AggregatedAttestation) {
        // Persist attestation to storage if available
        if let Some(ref storage) = self.storage {
            if let Err(e) = storage.put_attestation(aggregated.clone()).await {
                error!(
                    car_hash = %aggregated.car_hash,
                    error = %e,
                    "Failed to persist attestation to storage"
                );
            }
        }

        // Get the Car from pending state
        if let Some(pending) = self.state.remove_pending_car(&aggregated.car_hash) {
            let car = pending.car;

            info!(
                position = car.position,
                batch_count = car.batch_digests.len(),
                car_hash = %aggregated.car_hash,
                attestation_count = aggregated.count(),
                "Car marked as attested - broadcasting to peers"
            );

            // CRITICAL FIX: Broadcast CarWithAttestation to all peers
            //
            // This ensures that ALL validators know about this attested Car, not just
            // the proposer who collected attestations. Without this broadcast, when
            // another validator is the consensus proposer, their Cut would not include
            // this Car because it's not in their attested_cars.
            //
            // Flow:
            // 1. This validator (Car proposer) collects 2f+1 attestations
            // 2. Broadcast (Car, AggregatedAttestation) to all peers
            // 3. Peers receive and verify, then add to their attested_cars
            // 4. Now ALL validators can include this Car in their Cut
            let broadcast_msg = DclMessage::CarWithAttestation {
                car: car.clone(),
                attestation: Box::new(aggregated.clone()),
            };
            self.network.broadcast(&broadcast_msg).await;

            // Mark as attested with the aggregated attestation (contains BLS aggregate signature)
            self.state.mark_attested(car.clone(), aggregated);

            // Track total attested CARs (DAG certificates)
            DCL_DAG_CERTIFICATES.set(self.state.attested_cars.len() as f64);

            // Try to form a Cut
            self.try_form_cut().await;
        } else {
            warn!(
                car_hash = %aggregated.car_hash,
                "Threshold reached but Car not found in pending state"
            );
        }
    }

    /// Handle a received CarWithAttestation broadcast
    ///
    /// This is called when another validator broadcasts that their Car has reached
    /// the attestation threshold. We verify the attestation and add the Car to our
    /// attested_cars so it can be included in our Cut.
    async fn handle_received_car_with_attestation(
        &mut self,
        from: ValidatorId,
        car: Car,
        attestation: AggregatedAttestation,
    ) {
        let car_hash = car.hash();

        // DIAGNOSTIC: Log at entry to confirm message was received
        info!(
            from = %from,
            proposer = %car.proposer,
            position = car.position,
            batch_count = car.batch_digests.len(),
            attestation_count = attestation.count(),
            "Received CarWithAttestation broadcast"
        );

        // Skip if this is our own Car (we already have it from attestation collection)
        if car.proposer == self.config.validator_id {
            trace!(
                car_hash = %car_hash,
                "Ignoring CarWithAttestation for our own Car"
            );
            return;
        }

        // Check if we should skip this Car
        // IMPORTANT: Don't skip if the incoming Car has batches and existing is empty!
        // This ensures batched Cars are always preferred over empty Cars.
        if self.state.attested_cars.contains_key(&car.proposer) {
            let existing = &self.state.attested_cars[&car.proposer];
            let existing_has_batches = !existing.0.batch_digests.is_empty();
            let incoming_has_batches = !car.batch_digests.is_empty();

            // Only skip if:
            // 1. We already have a batched Car (preserve batched Cars)
            // 2. OR both are empty/batched and existing has higher/equal position
            let should_skip = existing_has_batches
                || (!incoming_has_batches && existing.0.position >= car.position);

            if should_skip {
                trace!(
                    proposer = %car.proposer,
                    position = car.position,
                    existing_position = existing.0.position,
                    existing_has_batches,
                    incoming_has_batches,
                    "Skipping CarWithAttestation (existing preferred)"
                );
                return;
            }

            // Incoming has batches but existing is empty - will replace!
            info!(
                proposer = %car.proposer,
                incoming_position = car.position,
                incoming_batches = car.batch_digests.len(),
                existing_position = existing.0.position,
                "Replacing empty Car with batched Car from peer"
            );
        }

        // Verify the attestation using Core's pubkey lookup
        let core = &self.core;
        if !attestation.verify(|idx| core.get_pubkey_by_index(idx)) {
            warn!(
                from = %from,
                car_hash = %car_hash,
                "Invalid aggregated attestation signature"
            );
            return;
        }

        // Verify the attestation count meets threshold
        if attestation.count() < self.core.attestation_threshold() {
            warn!(
                from = %from,
                car_hash = %car_hash,
                count = attestation.count(),
                threshold = self.core.attestation_threshold(),
                "Attestation count below threshold"
            );
            return;
        }

        info!(
            from = %from,
            proposer = %car.proposer,
            position = car.position,
            batch_count = car.batch_digests.len(),
            attestation_count = attestation.count(),
            "Received valid CarWithAttestation from peer"
        );

        // Persist attestation to storage if available
        if let Some(ref storage) = self.storage {
            if let Err(e) = storage.put_attestation(attestation.clone()).await {
                error!(
                    car_hash = %car_hash,
                    error = %e,
                    "Failed to persist received attestation to storage"
                );
            }
        }

        // Add to attested_cars (this enables Cut formation)
        self.state.mark_attested(car.clone(), attestation);

        // Track total attested CARs (DAG certificates)
        DCL_DAG_CERTIFICATES.set(self.state.attested_cars.len() as f64);

        // Try to form a Cut with this newly attested Car
        self.try_form_cut().await;
    }

    /// Try to create a new Car
    async fn try_create_car(&mut self) {
        let pending_digests = self.state.take_pending_digests();
        let is_empty = pending_digests.is_empty();
        let digest_count = pending_digests.len();

        // Check empty car policy
        if is_empty && !self.state.can_create_empty_car(self.config.max_empty_cars) {
            // Skip this round - no digests to restore since is_empty
            return;
        }

        let position = self.state.our_position;
        let parent_ref = self.state.last_car_hash;

        // Log state before Car creation attempt for debugging
        info!(
            position,
            has_parent_ref = parent_ref.is_some(),
            digest_count,
            "Attempting to create Car"
        );

        match self.proposer.create_car(
            position,
            pending_digests.clone(),
            parent_ref,
            self.state.empty_car_count,
        ) {
            Ok(Some(car)) => {
                let car_hash = car.hash();

                // Track CAR creation metric
                DCL_PRIMARY_CARS_CREATED.inc();

                // Update pending batches gauge (cleared after forming a Car)
                DCL_DAG_PENDING_BATCHES.set(0.0);

                // Start cut formation timer if not already started
                if self.cut_start_time.is_none() {
                    self.cut_start_time = Some(Instant::now());
                }

                info!(
                    position = car.position,
                    batch_count = car.batch_digests.len(),
                    hash = %car_hash,
                    "Created Car successfully"
                );

                // Persist to storage if available (T091)
                if let Some(ref storage) = self.storage {
                    if let Err(e) = storage.put_car(car.clone()).await {
                        error!(
                            position = car.position,
                            hash = %car_hash,
                            error = %e,
                            "Failed to persist Car to storage"
                        );
                        // Continue anyway - in-memory state will still have it
                    }
                }

                // Update our state
                self.state.update_our_position(position, car_hash, is_empty);
                self.state.our_position += 1;

                // Create self-attestation for attestation collector
                let self_attestation = self.core.create_attestation(&car);

                // Start collecting attestations
                self.attestation_collector
                    .start_collection(car.clone(), self_attestation);

                // Add to pending
                self.state.add_pending_car(car.clone());

                // Broadcast to peers
                self.network.broadcast_car(&car).await;

                // Emit event
                let _ = self.event_sender.send(PrimaryEvent::CarCreated(car)).await;
            }

            Ok(None) => {
                // Cannot create empty Car (policy)
                // Restore digests so they aren't lost
                for digest in pending_digests {
                    self.state.add_batch_digest(digest);
                }
                trace!("Skipping Car creation (empty car policy)");
            }

            Err(e) => {
                // CRITICAL FIX: Restore pending digests on error
                // Without this, transactions would be lost when Car creation fails
                // (e.g., due to missing parent_ref when position > 0)
                for digest in pending_digests {
                    self.state.add_batch_digest(digest);
                }
                error!(
                    error = %e,
                    position,
                    has_parent_ref = parent_ref.is_some(),
                    digest_count,
                    "Failed to create Car - digests restored"
                );
            }
        }
    }

    /// Check for attestation timeouts
    async fn check_attestation_timeouts(&mut self) {
        let timed_out = self.attestation_collector.check_timeouts();

        for (hash, car) in timed_out {
            let has_batches = !car.batch_digests.is_empty();

            // Apply backoff
            if self.attestation_collector.apply_backoff(&hash) {
                debug!(
                    hash = %hash,
                    position = car.position,
                    has_batches,
                    "Applying attestation timeout backoff"
                );
                // Could re-broadcast Car here
            } else {
                // IMPORTANT: Don't timeout Cars with batches!
                // Peers need extra time to sync batch data before they can attest.
                // Without this, batched Cars timeout before peers finish syncing,
                // causing attestations to be rejected with UnknownCar error.
                if has_batches {
                    // Reset the timeout without losing existing attestations
                    info!(
                        hash = %hash,
                        position = car.position,
                        batch_count = car.batch_digests.len(),
                        attestation_count = self.attestation_collector.attestation_count(&hash).unwrap_or(0),
                        "Extending timeout for batched Car - peers may still be syncing"
                    );
                    self.attestation_collector.reset_timeout(&hash);
                } else {
                    warn!(
                        hash = %hash,
                        position = car.position,
                        "Car attestation failed after max retries"
                    );
                    self.attestation_collector.remove(&hash);
                    self.state.remove_pending_car(&hash);
                }
            }
        }
    }

    /// Try to form a Cut from attested Cars
    ///
    /// Uses pipeline stage to ensure we only produce one cut per consensus height.
    /// We only form a new cut when in Collecting stage. After forming a cut,
    /// we transition to Proposing stage and wait for consensus to decide before
    /// producing the next cut (via finalize_height).
    async fn try_form_cut(&mut self) {
        // Only form cuts when in Collecting stage (waiting for attestations)
        // This prevents producing multiple cuts before consensus decides
        if self.state.pipeline_stage != PipelineStage::Collecting {
            trace!(
                stage = ?self.state.pipeline_stage,
                "Skipping cut formation - not in Collecting stage"
            );
            return;
        }

        // Get attested cars from state (properly populated by mark_attested)
        let attested_cars = self.state.get_attested_cars();

        // Get validators with attested cars
        let validators = self.state.validators_with_attested_cars();

        if validators.is_empty() {
            return;
        }

        // Form Cut at current_height (which is already the next height to produce)
        // current_height is set to last_finalized_height + 1 by finalize_height()
        let height = self.state.current_height;

        match self
            .cut_former
            .form_cut(height, attested_cars, self.last_cut.as_ref())
        {
            Ok(cut) => {
                if cut.validator_count() > 0 {
                    // Track cut creation metric
                    DCL_PRIMARY_CUTS_CREATED.inc();

                    // Track cut formation latency
                    if let Some(start) = self.cut_start_time.take() {
                        DCL_PRIMARY_CUT_LATENCY
                            .with_label_values(&[])
                            .observe(start.elapsed().as_secs_f64());
                    }

                    // Calculate total batches in this Cut for diagnostics
                    let total_batches: usize =
                        cut.cars.values().map(|c| c.batch_digests.len()).sum();
                    info!(
                        height = cut.height,
                        validators = cut.validator_count(),
                        total_batches,
                        "Formed Cut"
                    );

                    // Emit event
                    let _ = self
                        .event_sender
                        .send(PrimaryEvent::CutReady(cut.clone()))
                        .await;

                    // Update last cut and transition to Proposing stage
                    // current_height is NOT updated here - it will be updated
                    // by finalize_height when consensus decides on this cut
                    self.last_cut = Some(cut);
                    self.state.pipeline_stage = PipelineStage::Proposing;

                    debug!(
                        height,
                        "Transitioned to Proposing stage, awaiting consensus decision"
                    );
                }
            }

            Err(e) => {
                warn!(error = %e, "Failed to form Cut");
            }
        }
    }

    /// Get attestation count for a pending Car
    pub fn attestation_count(&self, car_hash: &Hash) -> Option<usize> {
        self.attestation_collector.attestation_count(car_hash)
    }

    /// Check if shutdown was requested
    pub fn is_shutdown(&self) -> bool {
        self.shutdown
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbft_crypto::BlsKeyPair;
    use cipherbft_types::VALIDATOR_ID_SIZE;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    /// Helper to derive ValidatorId from BLS public key (for tests only)
    fn validator_id_from_bls_pubkey(pubkey: &cipherbft_crypto::BlsPublicKey) -> ValidatorId {
        let hash = pubkey.hash();
        let mut bytes = [0u8; VALIDATOR_ID_SIZE];
        bytes.copy_from_slice(&hash[12..32]); // last 20 bytes
        ValidatorId::from_bytes(bytes)
    }

    struct MockNetwork {
        car_broadcasts: Arc<Mutex<Vec<Car>>>,
        attestation_sends: Arc<Mutex<Vec<(ValidatorId, Attestation)>>>,
    }

    impl MockNetwork {
        fn new() -> Self {
            Self {
                car_broadcasts: Arc::new(Mutex::new(Vec::new())),
                attestation_sends: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    #[async_trait::async_trait]
    impl PrimaryNetwork for MockNetwork {
        async fn broadcast_car(&self, car: &Car) {
            self.car_broadcasts.lock().await.push(car.clone());
        }

        async fn send_attestation(&self, proposer: ValidatorId, attestation: &Attestation) {
            self.attestation_sends
                .lock()
                .await
                .push((proposer, attestation.clone()));
        }

        async fn broadcast(&self, _message: &DclMessage) {}

        async fn send_to(&self, _peer: ValidatorId, _message: &DclMessage) {
            // MockNetwork doesn't track direct sends in current tests
        }
    }

    fn make_test_setup(
        n: usize,
    ) -> (
        PrimaryConfig,
        HashMap<ValidatorId, BlsPublicKey>,
        Vec<BlsKeyPair>,
    ) {
        let keypairs: Vec<BlsKeyPair> = (0..n)
            .map(|_| BlsKeyPair::generate(&mut rand::thread_rng()))
            .collect();

        let validator_pubkeys: HashMap<_, _> = keypairs
            .iter()
            .map(|kp| {
                let id = validator_id_from_bls_pubkey(&kp.public_key);
                (id, kp.public_key.clone())
            })
            .collect();

        let our_id = validator_id_from_bls_pubkey(&keypairs[0].public_key);
        let config = PrimaryConfig::new(our_id, keypairs[0].secret_key.clone())
            .with_car_interval(Duration::from_millis(50))
            .with_attestation_timeout(Duration::from_millis(100), Duration::from_millis(500))
            .with_startup_delay(Duration::ZERO); // No delay for tests

        (config, validator_pubkeys, keypairs)
    }

    #[tokio::test]
    async fn test_primary_car_creation() {
        let (config, validator_pubkeys, _keypairs) = make_test_setup(4);

        let (_from_workers_tx, from_workers_rx) = mpsc::channel(100);
        let (_from_network_tx, from_network_rx) = mpsc::channel(100);
        let (_command_tx, command_rx) = mpsc::channel(64);
        let (event_tx, mut event_rx) = mpsc::channel(100);

        let network = MockNetwork::new();
        let car_broadcasts = network.car_broadcasts.clone();

        let mut primary = Primary::new(
            config,
            validator_pubkeys,
            from_workers_rx,
            vec![],
            from_network_rx,
            command_rx,
            Box::new(network),
            event_tx,
        );

        // Add batch digest
        primary
            .handle_worker_message(WorkerToPrimary::BatchDigest {
                worker_id: 0,
                digest: Hash::compute(b"batch1"),
                tx_count: 10,
                byte_size: 100,
            })
            .await;

        // Trigger Car creation
        primary.try_create_car().await;

        // Should have broadcast a Car
        assert_eq!(car_broadcasts.lock().await.len(), 1);

        // Should have emitted CarCreated event
        let event = event_rx.try_recv().unwrap();
        assert!(matches!(event, PrimaryEvent::CarCreated(_)));
    }

    #[tokio::test]
    async fn test_primary_spawn() {
        let (config, validator_pubkeys, _keypairs) = make_test_setup(4);

        let network = MockNetwork::new();
        let car_broadcasts = network.car_broadcasts.clone();

        let (mut handle, _worker_rxs) =
            Primary::spawn(config, validator_pubkeys, Box::new(network), 1);

        // Send batch digest
        handle
            .send_from_worker(WorkerToPrimary::BatchDigest {
                worker_id: 0,
                digest: Hash::compute(b"batch1"),
                tx_count: 10,
                byte_size: 100,
            })
            .await
            .unwrap();

        // Wait for Car creation
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Should have received CarCreated event
        let event = handle.try_recv_event();
        assert!(event.is_ok() || !car_broadcasts.lock().await.is_empty());

        handle.shutdown().await;
    }

    // T101: Test attestation flow
    #[tokio::test]
    async fn test_attestation_flow() {
        let (config, validator_pubkeys, keypairs) = make_test_setup(4);

        let (_from_workers_tx, from_workers_rx) = mpsc::channel(100);
        let (_from_network_tx, from_network_rx) = mpsc::channel(100);
        let (_command_tx, command_rx) = mpsc::channel(64);
        let (event_tx, mut event_rx) = mpsc::channel(100);

        let network = MockNetwork::new();
        let attestation_sends = network.attestation_sends.clone();

        let mut primary = Primary::new(
            config.clone(),
            validator_pubkeys.clone(),
            from_workers_rx,
            vec![],
            from_network_rx,
            command_rx,
            Box::new(network),
            event_tx,
        );

        // Create a Car from another validator
        let other_id = validator_id_from_bls_pubkey(&keypairs[1].public_key);
        let batch_digest = crate::batch::BatchDigest::new(0, Hash::compute(b"batch"), 10, 100);

        // First, we need to register the batch as available
        primary.state.mark_batch_available(batch_digest.digest);

        let mut car = Car::new(other_id, 0, vec![batch_digest], None);
        let signing_bytes = car.signing_bytes();
        car.signature = keypairs[1].sign_car(&signing_bytes);

        // Handle the received Car - should generate attestation
        primary.handle_received_car(other_id, car.clone()).await;

        // Should have sent attestation to proposer
        let sends = attestation_sends.lock().await;
        assert_eq!(sends.len(), 1);
        assert_eq!(sends[0].0, other_id);
        assert_eq!(sends[0].1.car_hash, car.hash());

        // Should have emitted AttestationGenerated event
        let event = event_rx.try_recv().unwrap();
        match event {
            PrimaryEvent::AttestationGenerated {
                car_proposer,
                attestation,
            } => {
                assert_eq!(car_proposer, other_id);
                assert_eq!(attestation.car_hash, car.hash());
            }
            _ => panic!("Expected AttestationGenerated event"),
        }
    }

    // T101: Test batch sync trigger when Car has missing batches
    #[tokio::test]
    async fn test_missing_batch_triggers_sync() {
        let (config, validator_pubkeys, keypairs) = make_test_setup(4);

        let (_from_workers_tx, from_workers_rx) = mpsc::channel(100);
        let (_from_network_tx, from_network_rx) = mpsc::channel(100);
        let (_command_tx, command_rx) = mpsc::channel(64);
        let (event_tx, mut event_rx) = mpsc::channel(100);
        let (to_worker_tx, mut to_worker_rx) = mpsc::channel::<PrimaryToWorker>(100);

        let network = MockNetwork::new();
        let attestation_sends = network.attestation_sends.clone();

        let mut primary = Primary::new_with_storage(
            config.clone(),
            validator_pubkeys.clone(),
            from_workers_rx,
            vec![to_worker_tx],
            from_network_rx,
            command_rx,
            Box::new(network),
            event_tx,
            None,
        );

        // Create a Car with a batch we don't have
        let other_id = validator_id_from_bls_pubkey(&keypairs[1].public_key);
        let missing_batch = Hash::compute(b"missing_batch");
        let batch_digest = crate::batch::BatchDigest::new(0, missing_batch, 10, 100);

        let mut car = Car::new(other_id, 0, vec![batch_digest], None);
        let signing_bytes = car.signing_bytes();
        car.signature = keypairs[1].sign_car(&signing_bytes);

        // Handle the received Car - should trigger sync, not attestation
        primary.handle_received_car(other_id, car.clone()).await;

        // Should NOT have sent attestation (missing batches)
        assert_eq!(attestation_sends.lock().await.len(), 0);

        // Should have emitted SyncBatches event
        let event = event_rx.try_recv().unwrap();
        match event {
            PrimaryEvent::SyncBatches { digests, target } => {
                assert_eq!(digests.len(), 1);
                assert_eq!(digests[0], missing_batch);
                assert_eq!(target, other_id);
            }
            _ => panic!("Expected SyncBatches event"),
        }

        // Should have sent sync request to worker
        let worker_msg = to_worker_rx.try_recv().unwrap();
        match worker_msg {
            PrimaryToWorker::Synchronize {
                digests,
                target_validator,
            } => {
                assert_eq!(digests.len(), 1);
                assert_eq!(digests[0], missing_batch);
                assert_eq!(target_validator, other_id);
            }
            _ => panic!("Expected Synchronize message"),
        }

        // Car should be in awaiting queue
        assert!(primary.state.is_awaiting_batches(&car.hash()));
    }
}
