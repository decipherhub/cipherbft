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
use crate::messages::{DclMessage, PrimaryToWorker, WorkerToPrimary};
use crate::primary::attestation_collector::AttestationCollector;
use crate::primary::config::PrimaryConfig;
use crate::primary::core::Core;
use crate::primary::cut_former::CutFormer;
use crate::primary::proposer::Proposer;
use crate::primary::state::PrimaryState;
use crate::storage::CarStore;
use cipherbft_crypto::BlsPublicKey;
use cipherbft_types::{Hash, ValidatorId};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
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
    /// Receiver for Primary events
    event_receiver: mpsc::Receiver<PrimaryEvent>,
}

impl PrimaryHandle {
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
        let (from_workers_tx, from_workers_rx) = mpsc::channel(1024);
        let (from_network_tx, from_network_rx) = mpsc::channel(1024);
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
            let mut primary = Primary::new_with_storage(
                config_clone,
                validator_pubkeys,
                from_workers_rx,
                to_workers,
                from_network_rx,
                network,
                event_tx,
                storage,
            );
            primary.run().await;
        });

        let primary_handle = PrimaryHandle {
            handle,
            worker_sender: from_workers_tx,
            network_sender: from_network_tx,
            event_receiver: event_rx,
        };

        (primary_handle, worker_receivers)
    }

    /// Create a new Primary
    pub fn new(
        config: PrimaryConfig,
        validator_pubkeys: HashMap<ValidatorId, BlsPublicKey>,
        from_workers: mpsc::Receiver<WorkerToPrimary>,
        to_workers: Vec<mpsc::Sender<PrimaryToWorker>>,
        from_network: mpsc::Receiver<(ValidatorId, DclMessage)>,
        network: Box<dyn PrimaryNetwork>,
        event_sender: mpsc::Sender<PrimaryEvent>,
    ) -> Self {
        Self::new_with_storage(
            config,
            validator_pubkeys,
            from_workers,
            to_workers,
            from_network,
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
        network: Box<dyn PrimaryNetwork>,
        event_sender: mpsc::Sender<PrimaryEvent>,
        storage: Option<Arc<dyn CarStore>>,
    ) -> Self {
        let state = PrimaryState::new(config.validator_id);

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
        let core = Core::new(config.validator_id, our_keypair, validator_pubkeys.clone());

        let attestation_collector = AttestationCollector::new(
            config.validator_id,
            core.attestation_threshold(),
            core.validator_count(),
            validator_indices,
            config.attestation_timeout_base,
            config.attestation_timeout_max,
        );

        let cut_former = CutFormer::new(validators);

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
            network,
            storage,
            event_sender,
            last_cut: None,
            shutdown: false,
        }
    }

    /// Run the Primary main loop
    pub async fn run(&mut self) {
        info!(
            validator = %self.config.validator_id,
            "Primary starting"
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

                // Periodic Car creation
                _ = car_interval.tick() => {
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
                trace!(
                    worker_id,
                    tx_count,
                    byte_size,
                    "Received batch digest from Worker"
                );
                self.state
                    .add_batch_digest(BatchDigest::new(worker_id, digest, tx_count, byte_size));
            }

            WorkerToPrimary::BatchSynced { digest, success } => {
                debug!(
                    digest = %digest,
                    success,
                    "Batch sync result"
                );

                if success {
                    // Mark batch as available
                    self.state.mark_batch_available(digest);

                    // Check if any waiting Cars are now ready
                    let ready_cars = self.state.get_ready_cars();
                    for car in ready_cars {
                        debug!(
                            proposer = %car.proposer,
                            position = car.position,
                            "Processing Car that was waiting for batches"
                        );
                        // Re-process the Car now that batches are available
                        // Use a dummy validator since we already have the Car
                        self.handle_received_car(car.proposer, car).await;
                    }
                }
            }

            WorkerToPrimary::Ready { worker_id } => {
                info!(worker_id, "Worker ready");
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
                    self.handle_received_car(peer, car).await;
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
        }
    }

    /// Handle a received Car
    async fn handle_received_car(&mut self, from: ValidatorId, car: Car) {
        debug!(
            from = %from,
            proposer = %car.proposer,
            position = car.position,
            "Received Car"
        );

        // Check batch availability (T097)
        let (has_all_batches, missing_digests) = self.state.check_batch_availability(&car);

        if !has_all_batches {
            debug!(
                proposer = %car.proposer,
                position = car.position,
                missing_count = missing_digests.len(),
                "Car missing batches, triggering sync"
            );

            // Check if we're already waiting for this Car
            let car_hash = car.hash();
            if !self.state.is_awaiting_batches(&car_hash) {
                // Add to awaiting queue (T098)
                self.state
                    .add_car_awaiting_batches(car.clone(), missing_digests.clone());

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
        debug!(
            attester = %attestation.attester,
            car_hash = %attestation.car_hash,
            "Received attestation"
        );

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
                debug!(
                    car_hash = %aggregated.car_hash,
                    count = aggregated.count(),
                    "Attestation threshold reached"
                );
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

            // Mark as attested with the aggregated attestation (contains BLS aggregate signature)
            self.state.mark_attested(car.clone(), aggregated);

            // Try to form a Cut
            self.try_form_cut().await;
        }
    }

    /// Try to create a new Car
    async fn try_create_car(&mut self) {
        let pending_digests = self.state.take_pending_digests();
        let is_empty = pending_digests.is_empty();

        // Check empty car policy
        if is_empty && !self.state.can_create_empty_car(self.config.max_empty_cars) {
            // Skip this round
            return;
        }

        let position = self.state.our_position;
        let parent_ref = self.state.last_car_hash;

        match self.proposer.create_car(
            position,
            pending_digests,
            parent_ref,
            self.state.empty_car_count,
        ) {
            Ok(Some(car)) => {
                let car_hash = car.hash();
                debug!(
                    position = car.position,
                    batch_count = car.batch_digests.len(),
                    hash = %car_hash,
                    "Created Car"
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
                trace!("Skipping Car creation (empty car policy)");
            }

            Err(e) => {
                error!(error = %e, "Failed to create Car");
            }
        }
    }

    /// Check for attestation timeouts
    async fn check_attestation_timeouts(&mut self) {
        let timed_out = self.attestation_collector.check_timeouts();

        for (hash, car) in timed_out {
            // Apply backoff
            if self.attestation_collector.apply_backoff(&hash) {
                debug!(
                    hash = %hash,
                    position = car.position,
                    "Applying attestation timeout backoff"
                );
                // Could re-broadcast Car here
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

    /// Try to form a Cut from attested Cars
    async fn try_form_cut(&mut self) {
        // Get attested cars from state (properly populated by mark_attested)
        let attested_cars = self.state.get_attested_cars();

        // Get validators with attested cars
        let validators = self.state.validators_with_attested_cars();

        if validators.is_empty() {
            return;
        }

        // Form Cut
        let height = self.state.current_height + 1;

        match self
            .cut_former
            .form_cut(height, attested_cars, self.last_cut.as_ref())
        {
            Ok(cut) => {
                if cut.validator_count() > 0 {
                    debug!(
                        height = cut.height,
                        validators = cut.validator_count(),
                        "Formed Cut"
                    );

                    // Emit event
                    let _ = self
                        .event_sender
                        .send(PrimaryEvent::CutReady(cut.clone()))
                        .await;

                    // Update last cut
                    self.last_cut = Some(cut);
                    self.state.current_height = height;
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
            .with_attestation_timeout(Duration::from_millis(100), Duration::from_millis(500));

        (config, validator_pubkeys, keypairs)
    }

    #[tokio::test]
    async fn test_primary_car_creation() {
        let (config, validator_pubkeys, _keypairs) = make_test_setup(4);

        let (_from_workers_tx, from_workers_rx) = mpsc::channel(100);
        let (_from_network_tx, from_network_rx) = mpsc::channel(100);
        let (event_tx, mut event_rx) = mpsc::channel(100);

        let network = MockNetwork::new();
        let car_broadcasts = network.car_broadcasts.clone();

        let mut primary = Primary::new(
            config,
            validator_pubkeys,
            from_workers_rx,
            vec![],
            from_network_rx,
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
        let (event_tx, mut event_rx) = mpsc::channel(100);

        let network = MockNetwork::new();
        let attestation_sends = network.attestation_sends.clone();

        let mut primary = Primary::new(
            config.clone(),
            validator_pubkeys.clone(),
            from_workers_rx,
            vec![],
            from_network_rx,
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
