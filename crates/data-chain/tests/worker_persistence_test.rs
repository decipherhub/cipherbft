//! Integration test for Worker batch persistence (Task 1.3)
//!
//! Tests that Workers properly persist batches to storage when configured.

#![cfg(feature = "mdbx")]

use cipherbft_data_chain::batch::Batch;
use cipherbft_data_chain::error::DclError;
use cipherbft_data_chain::messages::{WorkerMessage, WorkerToPrimary};
use cipherbft_data_chain::storage::BatchStore as DclBatchStore;
use cipherbft_data_chain::worker::{Worker, WorkerConfig, WorkerNetwork};
use cipherbft_storage::mdbx::{DatabaseConfig, Database, MdbxBatchStore};
use cipherbft_storage::BatchStore as StorageBatchStore;
use cipherbft_types::{Hash, ValidatorId, VALIDATOR_ID_SIZE};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

fn make_validator_id(id: u8) -> ValidatorId {
    let mut bytes = [0u8; VALIDATOR_ID_SIZE];
    bytes[0] = id;
    ValidatorId::from_bytes(bytes)
}

/// Adapter to bridge cipherbft-storage BatchStore to data-chain BatchStore
///
/// The cipherbft-storage crate has a different BatchStore trait signature:
/// - put_batch(&self, batch: &Batch) -> BatchStoreResult<()>
///
/// The data-chain crate expects:
/// - put_batch(&self, batch: Batch) -> Result<Hash, DclError>
struct MdbxBatchStoreAdapter {
    inner: MdbxBatchStore,
}

impl MdbxBatchStoreAdapter {
    fn new(inner: MdbxBatchStore) -> Self {
        Self { inner }
    }
}

#[async_trait::async_trait]
impl DclBatchStore for MdbxBatchStoreAdapter {
    async fn put_batch(&self, batch: Batch) -> Result<Hash, DclError> {
        let hash = batch.hash();
        StorageBatchStore::put_batch(&self.inner, &batch)
            .await
            .map_err(|e| DclError::Storage(e.to_string()))?;
        Ok(hash)
    }

    async fn get_batch(&self, hash: &Hash) -> Result<Option<Batch>, DclError> {
        StorageBatchStore::get_batch(&self.inner, hash)
            .await
            .map_err(|e| DclError::Storage(e.to_string()))
    }

    async fn has_batch(&self, hash: &Hash) -> Result<bool, DclError> {
        StorageBatchStore::has_batch(&self.inner, hash)
            .await
            .map_err(|e| DclError::Storage(e.to_string()))
    }
}

/// Mock network for testing
struct MockNetwork {
    broadcasts: Arc<Mutex<Vec<Batch>>>,
}

impl MockNetwork {
    fn new() -> Self {
        Self {
            broadcasts: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[async_trait::async_trait]
impl WorkerNetwork for MockNetwork {
    async fn broadcast_batch(&self, batch: &Batch) {
        self.broadcasts.lock().await.push(batch.clone());
    }

    async fn send_to_peer(&self, _peer: ValidatorId, _message: WorkerMessage) {}

    async fn request_batches(&self, _peer: ValidatorId, _digests: Vec<Hash>) {}
}

/// Helper to create a temporary MDBX database
fn create_temp_db() -> (Database, tempfile::TempDir) {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let config = DatabaseConfig::new(temp_dir.path());
    let db = Database::open(config).expect("Failed to open database");
    (db, temp_dir)
}

/// Test that batches are persisted to MDBX storage when created
#[tokio::test]
async fn test_worker_persists_batches_to_mdbx() {
    // Create temporary MDBX database
    let (db, _temp_dir) = create_temp_db();
    let mdbx_store = MdbxBatchStore::new(Arc::clone(db.env()));
    let adapter = Arc::new(MdbxBatchStoreAdapter::new(mdbx_store));

    // Create worker config
    let config = WorkerConfig::new(make_validator_id(0), 0)
        .with_max_batch_bytes(100)
        .with_max_batch_txs(5)
        .with_flush_interval(Duration::from_millis(50));

    let network = MockNetwork::new();
    let broadcasts = network.broadcasts.clone();

    // Spawn worker with storage
    let mut handle = Worker::spawn_with_storage(config, Box::new(network), Some(adapter.clone()));

    // Wait for ready signal
    let msg = handle.recv_from_worker().await.expect("Worker should send ready");
    assert!(matches!(msg, WorkerToPrimary::Ready { worker_id: 0 }));

    // Submit 5 transactions to trigger batch creation
    for i in 0..5u8 {
        handle
            .submit_transaction(vec![i; 10])
            .await
            .expect("Failed to submit transaction");
    }

    // Give worker time to process and persist
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify batch was broadcast
    let broadcast_batches = broadcasts.lock().await;
    assert_eq!(broadcast_batches.len(), 1, "Should have broadcast one batch");

    let batch = &broadcast_batches[0];
    let batch_hash = batch.hash();

    // Verify batch is in storage
    assert!(
        adapter.has_batch(&batch_hash).await.expect("has_batch failed"),
        "Batch should be persisted in MDBX storage"
    );

    // Verify we can retrieve the full batch
    let retrieved = adapter
        .get_batch(&batch_hash)
        .await
        .expect("get_batch failed")
        .expect("Batch should exist in storage");

    assert_eq!(retrieved.transactions.len(), 5);
    assert_eq!(retrieved.worker_id, 0);

    // Shutdown worker
    handle.shutdown().await;
}

/// Test that batches received from peers are also persisted
#[tokio::test]
async fn test_worker_persists_peer_batches_to_mdbx() {
    // Create temporary MDBX database
    let (db, _temp_dir) = create_temp_db();
    let mdbx_store = MdbxBatchStore::new(Arc::clone(db.env()));
    let adapter = Arc::new(MdbxBatchStoreAdapter::new(mdbx_store));

    // Create worker config
    let config = WorkerConfig::new(make_validator_id(0), 0)
        .with_max_batch_bytes(1000)
        .with_max_batch_txs(100)
        .with_flush_interval(Duration::from_secs(60)); // Long interval to avoid auto-flush

    let network = MockNetwork::new();

    // Spawn worker with storage
    let mut handle = Worker::spawn_with_storage(config, Box::new(network), Some(adapter.clone()));

    // Wait for ready signal
    let msg = handle.recv_from_worker().await.expect("Worker should send ready");
    assert!(matches!(msg, WorkerToPrimary::Ready { worker_id: 0 }));

    // Create a batch from a "peer"
    let peer_batch = Batch::new(1, vec![vec![1, 2, 3], vec![4, 5, 6]], 12345);
    let batch_hash = peer_batch.hash();

    // Send batch as if from peer
    let peer = make_validator_id(1);
    handle
        .send_from_peer(peer, WorkerMessage::Batch(peer_batch))
        .await
        .expect("Failed to send peer message");

    // Give worker time to process and persist
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify batch is in storage
    assert!(
        adapter.has_batch(&batch_hash).await.expect("has_batch failed"),
        "Peer batch should be persisted in MDBX storage"
    );

    // Verify we can retrieve the full batch
    let retrieved = adapter
        .get_batch(&batch_hash)
        .await
        .expect("get_batch failed")
        .expect("Batch should exist in storage");

    assert_eq!(retrieved.transactions.len(), 2);
    assert_eq!(retrieved.worker_id, 1);

    // Shutdown worker
    handle.shutdown().await;
}

/// Test that worker functions correctly without storage (backward compatibility)
#[tokio::test]
async fn test_worker_without_storage() {
    // Create worker config
    let config = WorkerConfig::new(make_validator_id(0), 0)
        .with_max_batch_bytes(100)
        .with_max_batch_txs(5)
        .with_flush_interval(Duration::from_millis(50));

    let network = MockNetwork::new();
    let broadcasts = network.broadcasts.clone();

    // Spawn worker WITHOUT storage
    let mut handle = Worker::spawn(config, Box::new(network));

    // Wait for ready signal
    let msg = handle.recv_from_worker().await.expect("Worker should send ready");
    assert!(matches!(msg, WorkerToPrimary::Ready { worker_id: 0 }));

    // Submit 5 transactions to trigger batch creation
    for i in 0..5u8 {
        handle
            .submit_transaction(vec![i; 10])
            .await
            .expect("Failed to submit transaction");
    }

    // Give worker time to process
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify batch was still broadcast (worker works without storage)
    let broadcast_batches = broadcasts.lock().await;
    assert_eq!(broadcast_batches.len(), 1, "Should have broadcast one batch");

    // Shutdown worker
    handle.shutdown().await;
}
