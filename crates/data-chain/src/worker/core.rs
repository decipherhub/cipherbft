//! Worker process core implementation
//!
//! The Worker main loop handles:
//! - Receiving transactions from mempool
//! - Batching transactions by size/time threshold
//! - Broadcasting batches to peer Workers
//! - Reporting batch digests to Primary
//! - Handling sync requests from Primary

use crate::batch::{Batch, Transaction};
use crate::messages::{PrimaryToWorker, WorkerMessage, WorkerToPrimary};
use crate::worker::batch_maker::BatchMaker;
use crate::worker::config::WorkerConfig;
use crate::worker::state::WorkerState;
use crate::worker::synchronizer::Synchronizer;
use cipherbft_types::{Hash, ValidatorId};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::{debug, error, info, trace, warn};

/// Commands that can be sent to the Worker
#[derive(Debug)]
pub enum WorkerCommand {
    /// Submit a transaction
    Transaction(Transaction),
    /// Message from Primary
    FromPrimary(PrimaryToWorker),
    /// Message from peer Worker (over network)
    FromPeer {
        peer: ValidatorId,
        message: WorkerMessage,
    },
    /// Force flush pending batch
    FlushBatch,
}

/// Events emitted by the Worker
#[derive(Debug)]
pub enum WorkerEvent {
    /// Batch created and ready to broadcast
    BatchCreated(Batch),
    /// Message to send to Primary
    ToPrimary(WorkerToPrimary),
    /// Message to send to peer Worker
    ToPeer {
        peer: ValidatorId,
        message: WorkerMessage,
    },
    /// Worker is shutting down
    Shutdown,
}

/// Network interface for Worker-to-Worker communication
#[async_trait::async_trait]
pub trait WorkerNetwork: Send + Sync {
    /// Broadcast batch to all peer Workers with same worker_id
    async fn broadcast_batch(&self, batch: &Batch);

    /// Send message to specific peer Worker
    async fn send_to_peer(&self, peer: ValidatorId, message: WorkerMessage);

    /// Request batches from peer
    async fn request_batches(&self, peer: ValidatorId, digests: Vec<Hash>);
}

/// Handle for a spawned Worker task
pub struct WorkerHandle {
    /// Join handle for the worker task
    handle: tokio::task::JoinHandle<()>,
    /// Sender for transactions
    tx_sender: mpsc::Sender<Transaction>,
    /// Sender for Primary-to-Worker messages
    primary_sender: mpsc::Sender<PrimaryToWorker>,
    /// Receiver for Worker-to-Primary messages
    worker_receiver: mpsc::Receiver<WorkerToPrimary>,
    /// Worker ID
    worker_id: u8,
}

impl WorkerHandle {
    /// Get the worker ID
    pub fn worker_id(&self) -> u8 {
        self.worker_id
    }

    /// Submit a transaction to the worker
    pub async fn submit_transaction(&self, tx: Transaction) -> Result<(), mpsc::error::SendError<Transaction>> {
        self.tx_sender.send(tx).await
    }

    /// Send a message to the worker from Primary
    pub async fn send_from_primary(&self, msg: PrimaryToWorker) -> Result<(), mpsc::error::SendError<PrimaryToWorker>> {
        self.primary_sender.send(msg).await
    }

    /// Receive a message from the worker (for Primary)
    pub async fn recv_from_worker(&mut self) -> Option<WorkerToPrimary> {
        self.worker_receiver.recv().await
    }

    /// Try to receive a message without blocking
    pub fn try_recv_from_worker(&mut self) -> Result<WorkerToPrimary, mpsc::error::TryRecvError> {
        self.worker_receiver.try_recv()
    }

    /// Request shutdown and wait for worker to finish
    pub async fn shutdown(self) {
        let _ = self.primary_sender.send(PrimaryToWorker::Shutdown).await;
        let _ = self.handle.await;
    }

    /// Check if the worker task is finished
    pub fn is_finished(&self) -> bool {
        self.handle.is_finished()
    }
}

/// Worker process - handles transaction batching and dissemination
pub struct Worker {
    /// Configuration
    config: WorkerConfig,
    /// Internal state
    state: WorkerState,
    /// Batch maker for assembling transactions
    batch_maker: BatchMaker,
    /// Synchronizer for batch recovery
    synchronizer: Synchronizer,
    /// Channel to send messages to Primary
    to_primary: mpsc::Sender<WorkerToPrimary>,
    /// Channel to receive commands from Primary
    from_primary: mpsc::Receiver<PrimaryToWorker>,
    /// Channel to receive transactions from mempool
    tx_receiver: mpsc::Receiver<Transaction>,
    /// Network interface for peer communication
    network: Box<dyn WorkerNetwork>,
    /// Shutdown flag
    shutdown: bool,
}

impl Worker {
    /// Spawn a new Worker task
    ///
    /// Returns a handle that can be used to interact with the worker
    pub fn spawn(config: WorkerConfig, network: Box<dyn WorkerNetwork>) -> WorkerHandle {
        let (to_primary_tx, to_primary_rx) = mpsc::channel(1024);
        let (from_primary_tx, from_primary_rx) = mpsc::channel(256);
        let (tx_sender, tx_receiver) = mpsc::channel(4096);

        let worker_id = config.worker_id;

        let handle = tokio::spawn(async move {
            let mut worker = Worker::new(
                config,
                to_primary_tx,
                from_primary_rx,
                tx_receiver,
                network,
            );
            worker.run().await;
        });

        WorkerHandle {
            handle,
            tx_sender,
            primary_sender: from_primary_tx,
            worker_receiver: to_primary_rx,
            worker_id,
        }
    }

    /// Create a new Worker
    pub fn new(
        config: WorkerConfig,
        to_primary: mpsc::Sender<WorkerToPrimary>,
        from_primary: mpsc::Receiver<PrimaryToWorker>,
        tx_receiver: mpsc::Receiver<Transaction>,
        network: Box<dyn WorkerNetwork>,
    ) -> Self {
        let state = WorkerState::new(config.validator_id, config.worker_id);
        let batch_maker = BatchMaker::new(
            config.worker_id,
            config.max_batch_bytes,
            config.max_batch_txs,
        );
        let synchronizer = Synchronizer::new(
            Duration::from_secs(5), // sync timeout
            3,                      // max retries
        );

        Self {
            config,
            state,
            batch_maker,
            synchronizer,
            to_primary,
            from_primary,
            tx_receiver,
            network,
            shutdown: false,
        }
    }

    /// Run the Worker main loop
    pub async fn run(&mut self) {
        info!(
            worker_id = self.config.worker_id,
            validator = %self.config.validator_id,
            "Worker starting"
        );

        // Send ready signal to Primary
        if let Err(e) = self
            .to_primary
            .send(WorkerToPrimary::Ready {
                worker_id: self.config.worker_id,
            })
            .await
        {
            error!("Failed to send ready signal to Primary: {}", e);
            return;
        }

        // Set up flush timer
        let mut flush_interval = interval(self.config.flush_interval);
        flush_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Set up sync timeout check interval
        let mut sync_check_interval = interval(Duration::from_millis(500));
        sync_check_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        while !self.shutdown {
            tokio::select! {
                // Handle incoming transactions
                Some(tx) = self.tx_receiver.recv() => {
                    self.handle_transaction(tx).await;
                }

                // Handle messages from Primary
                Some(msg) = self.from_primary.recv() => {
                    self.handle_primary_message(msg).await;
                }

                // Time-based flush
                _ = flush_interval.tick() => {
                    self.check_time_flush().await;
                }

                // Check sync timeouts
                _ = sync_check_interval.tick() => {
                    self.check_sync_timeouts().await;
                }
            }
        }

        info!(
            worker_id = self.config.worker_id,
            "Worker shutting down"
        );
    }

    /// Handle incoming transaction
    async fn handle_transaction(&mut self, tx: Transaction) {
        trace!(
            worker_id = self.config.worker_id,
            tx_size = tx.len(),
            "Received transaction"
        );

        // Add to batch maker
        if let Some(batch) = self.batch_maker.add_transaction(tx) {
            self.process_batch(batch).await;
        }
    }

    /// Handle message from Primary
    async fn handle_primary_message(&mut self, msg: PrimaryToWorker) {
        match msg {
            PrimaryToWorker::Synchronize {
                digests,
                target_validator,
            } => {
                debug!(
                    worker_id = self.config.worker_id,
                    digests_count = digests.len(),
                    target = %target_validator,
                    "Sync request from Primary"
                );

                // Check which digests we already have
                let missing: Vec<Hash> = digests
                    .into_iter()
                    .filter(|d| !self.state.has_batch(d))
                    .collect();

                if missing.is_empty() {
                    // All batches already available
                    return;
                }

                // Start sync for missing batches
                let _request_id = self.synchronizer.start_sync(missing.clone(), target_validator);

                // Request from peer
                self.network.request_batches(target_validator, missing).await;
            }

            PrimaryToWorker::Cleanup { finalized_height } => {
                debug!(
                    worker_id = self.config.worker_id,
                    finalized_height,
                    "Cleanup request from Primary"
                );
                self.state.cleanup(finalized_height);
            }

            PrimaryToWorker::Shutdown => {
                info!(
                    worker_id = self.config.worker_id,
                    "Received shutdown signal from Primary"
                );
                self.shutdown = true;
            }
        }
    }

    /// Handle message from peer Worker
    pub async fn handle_peer_message(&mut self, peer: ValidatorId, msg: WorkerMessage) {
        match msg {
            WorkerMessage::Batch(batch) => {
                debug!(
                    worker_id = self.config.worker_id,
                    from = %peer,
                    batch_txs = batch.transactions.len(),
                    "Received batch from peer"
                );

                // Store the batch
                let hash = self.state.store_batch(batch);

                // Mark as synced if we were waiting for it
                if self.synchronizer.is_syncing(&hash) {
                    self.synchronizer.mark_synced(&hash);

                    // Notify Primary
                    let _ = self
                        .to_primary
                        .send(WorkerToPrimary::BatchSynced {
                            digest: hash,
                            success: true,
                        })
                        .await;
                }
            }

            WorkerMessage::BatchRequest { digests, requestor } => {
                debug!(
                    worker_id = self.config.worker_id,
                    from = %requestor,
                    count = digests.len(),
                    "Batch request from peer"
                );

                // Respond with each requested batch
                for digest in digests {
                    let batch_data = self.state.get_batch(&digest).cloned();
                    self.network
                        .send_to_peer(
                            requestor,
                            WorkerMessage::BatchResponse {
                                digest,
                                data: batch_data,
                            },
                        )
                        .await;
                }
            }

            WorkerMessage::BatchResponse { digest, data } => {
                if let Some(batch) = data {
                    debug!(
                        worker_id = self.config.worker_id,
                        from = %peer,
                        "Received batch response"
                    );

                    // Verify digest matches
                    let computed_digest = batch.digest();
                    if computed_digest.digest != digest {
                        warn!(
                            worker_id = self.config.worker_id,
                            expected = %digest,
                            got = %computed_digest.digest,
                            "Batch digest mismatch"
                        );
                        return;
                    }

                    // Store the batch
                    self.state.store_batch(batch);

                    // Mark as synced
                    if self.synchronizer.is_syncing(&digest) {
                        self.synchronizer.mark_synced(&digest);

                        // Notify Primary
                        let _ = self
                            .to_primary
                            .send(WorkerToPrimary::BatchSynced {
                                digest,
                                success: true,
                            })
                            .await;
                    }
                } else {
                    warn!(
                        worker_id = self.config.worker_id,
                        digest = %digest,
                        from = %peer,
                        "Peer does not have requested batch"
                    );
                }
            }
        }
    }

    /// Check if we should flush due to time threshold
    async fn check_time_flush(&mut self) {
        if self.batch_maker.should_flush_by_time(self.config.flush_interval)
            && self.batch_maker.has_pending()
        {
            if let Some(batch) = self.batch_maker.flush() {
                self.process_batch(batch).await;
            }
        }
    }

    /// Check for sync timeouts
    async fn check_sync_timeouts(&mut self) {
        let timeouts = self.synchronizer.check_timeouts();

        for (request_id, digests, target, should_retry) in timeouts {
            if should_retry {
                debug!(
                    worker_id = self.config.worker_id,
                    request_id,
                    "Retrying batch sync"
                );
                self.network.request_batches(target, digests).await;
            } else {
                warn!(
                    worker_id = self.config.worker_id,
                    request_id,
                    "Batch sync failed after max retries"
                );

                // Notify Primary of failure
                for digest in digests {
                    let _ = self
                        .to_primary
                        .send(WorkerToPrimary::BatchSynced {
                            digest,
                            success: false,
                        })
                        .await;
                }
            }
        }
    }

    /// Process a completed batch
    async fn process_batch(&mut self, batch: Batch) {
        let digest = batch.digest();

        debug!(
            worker_id = self.config.worker_id,
            tx_count = batch.transactions.len(),
            byte_size = digest.byte_size,
            digest = %digest.digest,
            "Created batch"
        );

        // Store locally
        self.state.store_batch(batch.clone());

        // Broadcast to peer Workers
        self.network.broadcast_batch(&batch).await;

        // Report to Primary
        let _ = self
            .to_primary
            .send(WorkerToPrimary::BatchDigest {
                worker_id: self.config.worker_id,
                digest: digest.digest,
                tx_count: digest.tx_count,
                byte_size: digest.byte_size,
            })
            .await;
    }

    /// Force flush any pending transactions
    pub async fn flush(&mut self) {
        if let Some(batch) = self.batch_maker.flush() {
            self.process_batch(batch).await;
        }
    }

    /// Get the number of stored batches
    pub fn batch_count(&self) -> usize {
        self.state.batch_count()
    }

    /// Get a stored batch by digest
    pub fn get_batch(&self, digest: &Hash) -> Option<&Batch> {
        self.state.get_batch(digest)
    }

    /// Check if shutdown was requested
    pub fn is_shutdown(&self) -> bool {
        self.shutdown
    }

    /// Get worker ID
    pub fn worker_id(&self) -> u8 {
        self.config.worker_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    /// Mock network for testing
    struct MockNetwork {
        broadcasts: Arc<Mutex<Vec<Batch>>>,
        peer_messages: Arc<Mutex<Vec<(ValidatorId, WorkerMessage)>>>,
    }

    impl MockNetwork {
        fn new() -> Self {
            Self {
                broadcasts: Arc::new(Mutex::new(Vec::new())),
                peer_messages: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    #[async_trait::async_trait]
    impl WorkerNetwork for MockNetwork {
        async fn broadcast_batch(&self, batch: &Batch) {
            self.broadcasts.lock().await.push(batch.clone());
        }

        async fn send_to_peer(&self, peer: ValidatorId, message: WorkerMessage) {
            self.peer_messages.lock().await.push((peer, message));
        }

        async fn request_batches(&self, peer: ValidatorId, digests: Vec<Hash>) {
            self.peer_messages.lock().await.push((
                peer,
                WorkerMessage::BatchRequest {
                    digests,
                    requestor: ValidatorId::ZERO,
                },
            ));
        }
    }

    fn make_test_worker() -> (
        Worker,
        mpsc::Receiver<WorkerToPrimary>,
        mpsc::Sender<PrimaryToWorker>,
        mpsc::Sender<Transaction>,
        Arc<Mutex<Vec<Batch>>>,
    ) {
        let (to_primary_tx, to_primary_rx) = mpsc::channel(100);
        let (from_primary_tx, from_primary_rx) = mpsc::channel(100);
        let (tx_sender, tx_receiver) = mpsc::channel(100);

        let config = WorkerConfig::new(ValidatorId::ZERO, 0)
            .with_max_batch_bytes(100)
            .with_max_batch_txs(5)
            .with_flush_interval(Duration::from_millis(50));

        let network = MockNetwork::new();
        let broadcasts = network.broadcasts.clone();

        let worker = Worker::new(
            config,
            to_primary_tx,
            from_primary_rx,
            tx_receiver,
            Box::new(network),
        );

        (worker, to_primary_rx, from_primary_tx, tx_sender, broadcasts)
    }

    #[tokio::test]
    async fn test_worker_transaction_batching() {
        let (mut worker, mut to_primary_rx, _, tx_sender, broadcasts) = make_test_worker();

        // Send 5 transactions (triggers batch at count threshold)
        for i in 0..5 {
            worker.handle_transaction(vec![i; 10]).await;
        }

        // Should have created one batch
        assert_eq!(worker.batch_count(), 1);
        assert_eq!(broadcasts.lock().await.len(), 1);

        // Should have sent digest to Primary
        let msg = to_primary_rx.try_recv().unwrap();
        match msg {
            WorkerToPrimary::BatchDigest {
                worker_id,
                tx_count,
                ..
            } => {
                assert_eq!(worker_id, 0);
                assert_eq!(tx_count, 5);
            }
            _ => panic!("unexpected message"),
        }
    }

    #[tokio::test]
    async fn test_worker_size_threshold() {
        let (mut worker, _, _, _, broadcasts) = make_test_worker();

        // Send transactions totaling > 100 bytes
        for _ in 0..3 {
            worker.handle_transaction(vec![0u8; 40]).await;
        }

        // Should have created a batch at 120 bytes (> 100 threshold)
        assert_eq!(worker.batch_count(), 1);
        assert_eq!(broadcasts.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn test_worker_flush() {
        let (mut worker, _, _, _, broadcasts) = make_test_worker();

        // Send 2 transactions (below threshold)
        worker.handle_transaction(vec![1, 2, 3]).await;
        worker.handle_transaction(vec![4, 5, 6]).await;

        assert_eq!(worker.batch_count(), 0);

        // Force flush
        worker.flush().await;

        assert_eq!(worker.batch_count(), 1);
        assert_eq!(broadcasts.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn test_worker_peer_batch_receive() {
        let (mut worker, mut to_primary_rx, _, _, _) = make_test_worker();

        // Receive batch from peer
        let batch = Batch::new(0, vec![vec![1, 2, 3]], 12345);
        let digest = batch.digest().digest;

        worker
            .handle_peer_message(ValidatorId::from_bytes([1u8; 32]), WorkerMessage::Batch(batch))
            .await;

        // Should have stored the batch
        assert!(worker.get_batch(&digest).is_some());
    }

    #[tokio::test]
    async fn test_worker_shutdown() {
        let (mut worker, _, _from_primary_tx, _, _) = make_test_worker();

        assert!(!worker.is_shutdown());

        worker
            .handle_primary_message(PrimaryToWorker::Shutdown)
            .await;

        assert!(worker.is_shutdown());
    }

    #[tokio::test]
    async fn test_worker_spawn() {
        let config = WorkerConfig::new(ValidatorId::ZERO, 0)
            .with_max_batch_bytes(100)
            .with_max_batch_txs(5)
            .with_flush_interval(Duration::from_millis(50));

        let network = MockNetwork::new();
        let broadcasts = network.broadcasts.clone();

        let mut handle = Worker::spawn(config, Box::new(network));

        // Wait for ready signal
        let msg = handle.recv_from_worker().await.unwrap();
        assert!(matches!(msg, WorkerToPrimary::Ready { worker_id: 0 }));

        // Submit transactions to trigger batch
        for i in 0..5 {
            handle.submit_transaction(vec![i; 10]).await.unwrap();
        }

        // Give worker time to process
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Should have received batch digest
        let msg = handle.recv_from_worker().await.unwrap();
        match msg {
            WorkerToPrimary::BatchDigest {
                worker_id,
                tx_count,
                ..
            } => {
                assert_eq!(worker_id, 0);
                assert_eq!(tx_count, 5);
            }
            _ => panic!("unexpected message: {:?}", msg),
        }

        // Verify broadcast
        assert_eq!(broadcasts.lock().await.len(), 1);

        // Shutdown
        handle.shutdown().await;
    }
}
