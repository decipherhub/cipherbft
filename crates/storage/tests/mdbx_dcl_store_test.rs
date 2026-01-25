//! Integration tests for MdbxDclStore
//!
//! These tests verify that the MDBX-backed DCL storage implementation
//! correctly implements the DclStore trait with persistence.

#![cfg(feature = "mdbx")]

use cipherbft_crypto::BlsKeyPair;
use cipherbft_data_chain::{AggregatedAttestation, Batch, BatchDigest, Car, Cut};
use cipherbft_storage::dcl::{DclStore, DclStoreExt, DclStoreTx};
use cipherbft_storage::mdbx::{Database, DatabaseConfig, MdbxDclStore};
use cipherbft_storage::tables::{CarRange, CutRange};
use cipherbft_types::{Hash, ValidatorId};
use std::sync::Arc;
use tempfile::tempdir;

/// Helper to create a test database
fn create_test_db() -> Arc<Database> {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let config = DatabaseConfig::new(temp_dir.path());
    Arc::new(Database::open(config).expect("Failed to open database"))
}

/// Helper to create a test batch
fn create_test_batch(worker_id: u8, tx_count: usize) -> Batch {
    let transactions: Vec<Vec<u8>> = (0..tx_count)
        .map(|i| format!("tx_{worker_id}_{i}").into_bytes())
        .collect();

    Batch {
        worker_id,
        transactions,
        timestamp: 1000 + worker_id as u64,
    }
}

/// Helper to create a test validator ID
fn create_validator_id(seed: u8) -> ValidatorId {
    let mut bytes = [0u8; 20];
    bytes[0] = seed;
    bytes[19] = seed;
    ValidatorId::from_bytes(bytes)
}

/// Helper to create a test Car with proper signature
fn create_test_car(proposer: ValidatorId, position: u64, batch_hashes: &[Hash]) -> Car {
    let batch_digests: Vec<BatchDigest> = batch_hashes
        .iter()
        .enumerate()
        .map(|(i, hash)| BatchDigest {
            worker_id: i as u8,
            digest: *hash,
            tx_count: 1,
            byte_size: 100,
        })
        .collect();

    // Create Car and sign it properly
    let mut car = Car::new(proposer, position, batch_digests, None);
    let keypair = BlsKeyPair::generate(&mut rand::thread_rng());
    let signing_bytes = car.signing_bytes();
    car.signature = keypair.sign_car(&signing_bytes);
    car
}

/// Helper to create a test attestation with proper signatures
fn create_test_attestation(car: &Car) -> AggregatedAttestation {
    use cipherbft_data_chain::Attestation;

    // Create attestations at indices 0, 1, 3 (matching the original bitmap pattern)
    let attester_indices = [0usize, 1, 3];
    let attestations_with_indices: Vec<(Attestation, usize)> = attester_indices
        .iter()
        .map(|&idx| {
            let keypair = BlsKeyPair::generate(&mut rand::thread_rng());
            let attester_id = create_validator_id(idx as u8);
            let mut att = Attestation::from_car(car, attester_id);
            att.signature = keypair.sign_attestation(&att.get_signing_bytes());
            (att, idx)
        })
        .collect();

    AggregatedAttestation::aggregate_with_indices(&attestations_with_indices, 4)
        .expect("aggregation should succeed")
}

// ============================================================
// Batch Operation Tests
// ============================================================

#[tokio::test]
async fn test_batch_put_and_get() {
    let db = create_test_db();
    let store = MdbxDclStore::new(db);

    let batch = create_test_batch(1, 3);
    let hash = batch.hash();

    // Store the batch
    store.put_batch(batch.clone()).await.unwrap();

    // Retrieve and verify
    let retrieved = store.get_batch(&hash).await.unwrap();
    assert!(retrieved.is_some());

    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.worker_id, batch.worker_id);
    assert_eq!(retrieved.transactions.len(), batch.transactions.len());
    assert_eq!(retrieved.timestamp, batch.timestamp);
}

#[tokio::test]
async fn test_batch_has() {
    let db = create_test_db();
    let store = MdbxDclStore::new(db);

    let batch = create_test_batch(1, 2);
    let hash = batch.hash();

    // Before storing
    assert!(!store.has_batch(&hash).await.unwrap());

    // After storing
    store.put_batch(batch).await.unwrap();
    assert!(store.has_batch(&hash).await.unwrap());
}

#[tokio::test]
async fn test_batch_delete() {
    let db = create_test_db();
    let store = MdbxDclStore::new(db);

    let batch = create_test_batch(1, 2);
    let hash = batch.hash();

    store.put_batch(batch).await.unwrap();
    assert!(store.has_batch(&hash).await.unwrap());

    // Delete
    let deleted = store.delete_batch(&hash).await.unwrap();
    assert!(deleted);

    // Verify deleted
    assert!(!store.has_batch(&hash).await.unwrap());

    // Delete non-existent returns false
    let deleted_again = store.delete_batch(&hash).await.unwrap();
    assert!(!deleted_again);
}

// ============================================================
// Car Operation Tests
// ============================================================

#[tokio::test]
async fn test_car_put_and_get() {
    let db = create_test_db();
    let store = MdbxDclStore::new(db);

    let validator = create_validator_id(1);
    let batch = create_test_batch(1, 2);
    let car = create_test_car(validator, 0, &[batch.hash()]);

    // Store the car
    store.put_car(car.clone()).await.unwrap();

    // Retrieve by validator and position
    let retrieved = store.get_car(&validator, 0).await.unwrap();
    assert!(retrieved.is_some());

    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.proposer, validator);
    assert_eq!(retrieved.position, 0);
    assert_eq!(retrieved.batch_digests.len(), 1);
}

#[tokio::test]
async fn test_car_get_by_hash() {
    let db = create_test_db();
    let store = MdbxDclStore::new(db);

    let validator = create_validator_id(2);
    let batch = create_test_batch(2, 3);
    let car = create_test_car(validator, 5, &[batch.hash()]);
    let car_hash = car.hash();

    store.put_car(car.clone()).await.unwrap();

    // Retrieve by hash
    let retrieved = store.get_car_by_hash(&car_hash).await.unwrap();
    assert!(retrieved.is_some());

    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.hash(), car_hash);
}

#[tokio::test]
async fn test_car_highest_position() {
    let db = create_test_db();
    let store = MdbxDclStore::new(db);

    let validator = create_validator_id(3);

    // No cars yet
    let highest = store.get_highest_car_position(&validator).await.unwrap();
    assert!(highest.is_none());

    // Add cars at positions 0, 5, 10
    for pos in [0u64, 5, 10] {
        let batch = create_test_batch(pos as u8, 1);
        let car = create_test_car(validator, pos, &[batch.hash()]);
        store.put_car(car).await.unwrap();
    }

    // Highest should be 10
    let highest = store.get_highest_car_position(&validator).await.unwrap();
    assert_eq!(highest, Some(10));
}

#[tokio::test]
async fn test_car_range() {
    let db = create_test_db();
    let store = MdbxDclStore::new(db);

    let validator = create_validator_id(4);

    // Add cars at positions 0, 1, 2, 3, 4
    for pos in 0..5u8 {
        let batch = create_test_batch(pos, 1);
        let car = create_test_car(validator, pos as u64, &[batch.hash()]);
        store.put_car(car).await.unwrap();
    }

    // Get range 1..=3
    let range = CarRange {
        validator_id: validator,
        start: 1,
        end: Some(3),
    };
    let cars = store.get_cars_range(range).await.unwrap();
    assert_eq!(cars.len(), 3);
    assert_eq!(cars[0].position, 1);
    assert_eq!(cars[1].position, 2);
    assert_eq!(cars[2].position, 3);
}

#[tokio::test]
async fn test_car_delete() {
    let db = create_test_db();
    let store = MdbxDclStore::new(db);

    let validator = create_validator_id(5);
    let batch = create_test_batch(5, 1);
    let car = create_test_car(validator, 0, &[batch.hash()]);
    let car_hash = car.hash();

    store.put_car(car).await.unwrap();
    assert!(store.has_car(&validator, 0).await.unwrap());

    // Delete
    let deleted = store.delete_car(&validator, 0).await.unwrap();
    assert!(deleted);

    // Verify deleted from both indices
    assert!(!store.has_car(&validator, 0).await.unwrap());
    assert!(store.get_car_by_hash(&car_hash).await.unwrap().is_none());
}

// ============================================================
// Attestation Operation Tests
// ============================================================

#[tokio::test]
async fn test_attestation_put_and_get() {
    let db = create_test_db();
    let store = MdbxDclStore::new(db);

    let validator = create_validator_id(6);
    let batch = create_test_batch(6, 1);
    let car = create_test_car(validator, 0, &[batch.hash()]);
    let attestation = create_test_attestation(&car);
    let car_hash = car.hash();

    store.put_attestation(attestation.clone()).await.unwrap();

    let retrieved = store.get_attestation(&car_hash).await.unwrap();
    assert!(retrieved.is_some());

    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.car_hash, car_hash);
    assert_eq!(retrieved.car_position, 0);
}

#[tokio::test]
async fn test_attestation_delete() {
    let db = create_test_db();
    let store = MdbxDclStore::new(db);

    let validator = create_validator_id(7);
    let batch = create_test_batch(7, 1);
    let car = create_test_car(validator, 0, &[batch.hash()]);
    let attestation = create_test_attestation(&car);
    let car_hash = car.hash();

    store.put_attestation(attestation).await.unwrap();
    assert!(store.has_attestation(&car_hash).await.unwrap());

    let deleted = store.delete_attestation(&car_hash).await.unwrap();
    assert!(deleted);
    assert!(!store.has_attestation(&car_hash).await.unwrap());
}

// ============================================================
// Cut Operation Tests
// ============================================================

#[tokio::test]
async fn test_pending_cut_operations() {
    let db = create_test_db();
    let store = MdbxDclStore::new(db);

    let cut = Cut::new(100);

    // Store pending cut
    store.put_pending_cut(cut.clone()).await.unwrap();

    // Retrieve
    let retrieved = store.get_pending_cut(100).await.unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().height, 100);

    // Get all pending cuts
    let all = store.get_all_pending_cuts().await.unwrap();
    assert_eq!(all.len(), 1);

    // Delete
    let deleted = store.delete_pending_cut(100).await.unwrap();
    assert!(deleted);
    assert!(store.get_pending_cut(100).await.unwrap().is_none());
}

#[tokio::test]
async fn test_finalize_cut() {
    let db = create_test_db();
    let store = MdbxDclStore::new(db);

    let cut = Cut::new(50);

    // Store as pending
    store.put_pending_cut(cut).await.unwrap();
    assert!(store.get_pending_cut(50).await.unwrap().is_some());
    assert!(store.get_finalized_cut(50).await.unwrap().is_none());

    // Finalize
    let finalized = store.finalize_cut(50).await.unwrap();
    assert!(finalized.is_some());
    assert_eq!(finalized.unwrap().height, 50);

    // Verify moved from pending to finalized
    assert!(store.get_pending_cut(50).await.unwrap().is_none());
    assert!(store.get_finalized_cut(50).await.unwrap().is_some());
}

#[tokio::test]
async fn test_latest_finalized_cut() {
    let db = create_test_db();
    let store = MdbxDclStore::new(db);

    // No cuts yet
    assert!(store.get_latest_finalized_cut().await.unwrap().is_none());

    // Add finalized cuts at heights 10, 20, 30
    for height in [10u64, 20, 30] {
        let cut = Cut::new(height);
        store.put_finalized_cut(cut).await.unwrap();
    }

    // Latest should be 30
    let latest = store.get_latest_finalized_cut().await.unwrap();
    assert!(latest.is_some());
    assert_eq!(latest.unwrap().height, 30);
}

#[tokio::test]
async fn test_finalized_cuts_range() {
    let db = create_test_db();
    let store = MdbxDclStore::new(db);

    // Add finalized cuts at heights 0, 10, 20, 30, 40
    for height in [0u64, 10, 20, 30, 40] {
        let cut = Cut::new(height);
        store.put_finalized_cut(cut).await.unwrap();
    }

    // Get range 10..=30
    let range = CutRange {
        start: 10,
        end: Some(30),
    };
    let cuts = store.get_finalized_cuts_range(range).await.unwrap();
    assert_eq!(cuts.len(), 3);
    assert_eq!(cuts[0].height, 10);
    assert_eq!(cuts[1].height, 20);
    assert_eq!(cuts[2].height, 30);
}

// ============================================================
// Statistics Tests
// ============================================================

#[tokio::test]
async fn test_storage_stats() {
    let db = create_test_db();
    let store = MdbxDclStore::new(db);

    // Initially empty
    let stats = store.stats().await.unwrap();
    assert_eq!(stats.batch_count, 0);
    assert_eq!(stats.car_count, 0);
    assert_eq!(stats.attestation_count, 0);
    assert_eq!(stats.pending_cut_count, 0);
    assert_eq!(stats.finalized_cut_count, 0);

    // Add some data
    let batch = create_test_batch(1, 2);
    store.put_batch(batch.clone()).await.unwrap();

    let validator = create_validator_id(1);
    let car = create_test_car(validator, 0, &[batch.hash()]);
    store.put_car(car.clone()).await.unwrap();

    let attestation = create_test_attestation(&car);
    store.put_attestation(attestation).await.unwrap();

    store.put_pending_cut(Cut::new(1)).await.unwrap();
    store.put_finalized_cut(Cut::new(0)).await.unwrap();

    // Check counts
    let stats = store.stats().await.unwrap();
    assert_eq!(stats.batch_count, 1);
    assert_eq!(stats.car_count, 1);
    assert_eq!(stats.attestation_count, 1);
    assert_eq!(stats.pending_cut_count, 1);
    assert_eq!(stats.finalized_cut_count, 1);
    assert!(stats.storage_bytes > 0);
}

// ============================================================
// Transaction Tests
// ============================================================

#[tokio::test]
async fn test_transaction_commit() {
    let db = create_test_db();
    let store = MdbxDclStore::new(db);

    // Start transaction
    let mut tx = store.begin_tx().await.unwrap();

    let batch = create_test_batch(10, 2);
    let hash = batch.hash();
    tx.put_batch(batch).await.unwrap();

    // Before commit, not visible in main store
    assert!(!store.has_batch(&hash).await.unwrap());

    // Commit
    tx.commit().await.unwrap();

    // After commit, visible
    assert!(store.has_batch(&hash).await.unwrap());
}

#[tokio::test]
async fn test_transaction_abort() {
    let db = create_test_db();
    let store = MdbxDclStore::new(db);

    let batch = create_test_batch(11, 2);
    let hash = batch.hash();

    // Start transaction
    let mut tx = store.begin_tx().await.unwrap();
    tx.put_batch(batch).await.unwrap();

    // Abort
    tx.abort().await.unwrap();

    // After abort, not visible
    assert!(!store.has_batch(&hash).await.unwrap());
}

#[tokio::test]
async fn test_transaction_finalize_cut() {
    let db = create_test_db();
    let store = MdbxDclStore::new(db);

    // First put a pending cut
    store.put_pending_cut(Cut::new(100)).await.unwrap();

    // Finalize in a transaction
    let mut tx = store.begin_tx().await.unwrap();
    let finalized = tx.finalize_cut(100).await.unwrap();
    assert!(finalized.is_some());
    tx.commit().await.unwrap();

    // Verify state after commit
    assert!(store.get_pending_cut(100).await.unwrap().is_none());
    assert!(store.get_finalized_cut(100).await.unwrap().is_some());
}

// ============================================================
// Pruning Tests
// ============================================================

#[tokio::test]
async fn test_prune_before() {
    let db = create_test_db();
    let store = MdbxDclStore::new(db);

    // Add finalized cuts at heights 0, 10, 20, 30
    for height in [0u64, 10, 20, 30] {
        let cut = Cut::new(height);
        store.put_finalized_cut(cut).await.unwrap();
    }

    // Prune before height 20
    let pruned = store.prune_before(20).await.unwrap();
    assert!(pruned > 0);

    // Heights 0 and 10 should be gone
    assert!(store.get_finalized_cut(0).await.unwrap().is_none());
    assert!(store.get_finalized_cut(10).await.unwrap().is_none());

    // Heights 20 and 30 should remain
    assert!(store.get_finalized_cut(20).await.unwrap().is_some());
    assert!(store.get_finalized_cut(30).await.unwrap().is_some());
}

// ============================================================
// Persistence Tests
// ============================================================

#[tokio::test]
async fn test_persistence_across_reopens() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let db_path = temp_dir.path().to_path_buf();

    let batch_hash;
    let car_hash;

    // First session: write data
    {
        let config = DatabaseConfig::new(&db_path);
        let db = Arc::new(Database::open(config).unwrap());
        let store = MdbxDclStore::new(db);

        let batch = create_test_batch(100, 5);
        batch_hash = batch.hash();
        store.put_batch(batch.clone()).await.unwrap();

        let validator = create_validator_id(100);
        let car = create_test_car(validator, 0, &[batch_hash]);
        car_hash = car.hash();
        store.put_car(car).await.unwrap();

        store.put_finalized_cut(Cut::new(1)).await.unwrap();
    }

    // Second session: verify data persisted
    {
        let config = DatabaseConfig::new(&db_path);
        let db = Arc::new(Database::open(config).unwrap());
        let store = MdbxDclStore::new(db);

        // Batch should still exist
        assert!(store.has_batch(&batch_hash).await.unwrap());

        // Car should still exist
        assert!(store.get_car_by_hash(&car_hash).await.unwrap().is_some());

        // Finalized cut should still exist
        assert!(store.get_finalized_cut(1).await.unwrap().is_some());
    }
}
