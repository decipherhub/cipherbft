//! Integration test for crash recovery (T118)
//!
//! Tests that pipeline state can be recovered after a crash using the WAL.

use cipherbft_crypto::BlsKeyPair;
use cipherbft_data_chain::{
    primary::state::{PipelineStage, PrimaryState},
    Attestation, Car,
};
use cipherbft_storage::wal::{
    InMemoryWal, PipelineStage as WalPipelineStage, Wal, WalEntry, WalRecovery,
};
use cipherbft_types::{ValidatorId, VALIDATOR_ID_SIZE};

fn make_validator_id(id: u8) -> ValidatorId {
    let mut bytes = [0u8; VALIDATOR_ID_SIZE];
    bytes[0] = id;
    ValidatorId::from_bytes(bytes)
}

fn make_test_car(validator_id: ValidatorId, position: u64) -> Car {
    Car::new(validator_id, position, vec![], None)
}

fn make_test_attestation(car: &Car, attester: ValidatorId) -> Attestation {
    let kp = BlsKeyPair::generate(&mut rand::thread_rng());
    let mut att = Attestation::from_car(car, attester);
    att.signature = kp.sign_attestation(&att.get_signing_bytes());
    att
}

/// Test basic WAL recovery for pipeline state
#[tokio::test]
async fn test_pipeline_state_wal_recovery() {
    let wal = InMemoryWal::new();

    let validator1 = make_validator_id(1);
    let validator2 = make_validator_id(2);

    // Simulate pipeline operations before crash:
    // 1. Stage changed to Proposing
    wal.append(WalEntry::PipelineStageChanged {
        stage: WalPipelineStage::Proposing,
        height: 5,
    })
    .await
    .unwrap();

    // 2. Received attestation for next height
    let car = make_test_car(validator1, 10);
    let attestation = make_test_attestation(&car, validator2);
    wal.append(WalEntry::NextHeightAttestation {
        height: 6,
        attestation: attestation.clone(),
    })
    .await
    .unwrap();

    // 3. "Crash" - now recover
    let recovery = WalRecovery::new(wal);
    let state = recovery.recover().await.unwrap();

    // Verify recovered state
    assert_eq!(state.pipeline_stage, Some(WalPipelineStage::Proposing));
    assert_eq!(state.pipeline_height, Some(5));
    assert_eq!(state.next_height_attestations.len(), 1);
    assert!(state.next_height_attestations.contains_key(&6));
    assert_eq!(state.next_height_attestations.get(&6).unwrap().len(), 1);
}

/// Test recovery with checkpoint
#[tokio::test]
async fn test_pipeline_recovery_after_checkpoint() {
    let wal = InMemoryWal::new();

    let validator1 = make_validator_id(1);
    let validator2 = make_validator_id(2);

    // Before checkpoint (should be ignored after recovery)
    wal.append(WalEntry::PipelineStageChanged {
        stage: WalPipelineStage::Collecting,
        height: 1,
    })
    .await
    .unwrap();

    // Checkpoint at height 3
    wal.checkpoint(3).await.unwrap();

    // After checkpoint (should be recovered)
    wal.append(WalEntry::PipelineStageChanged {
        stage: WalPipelineStage::TimedOut,
        height: 4,
    })
    .await
    .unwrap();

    let car = make_test_car(validator1, 5);
    let attestation = make_test_attestation(&car, validator2);
    wal.append(WalEntry::NextHeightAttestation {
        height: 5,
        attestation: attestation.clone(),
    })
    .await
    .unwrap();

    // Recover
    let recovery = WalRecovery::new(wal);
    let state = recovery.recover().await.unwrap();

    // Should only see state after checkpoint
    assert_eq!(state.pipeline_stage, Some(WalPipelineStage::TimedOut));
    assert_eq!(state.pipeline_height, Some(4));
    assert_eq!(state.next_height_attestations.len(), 1);
}

/// Test that PrimaryState can be restored from recovered WAL state
#[tokio::test]
async fn test_primary_state_restoration() {
    let our_id = make_validator_id(0);
    let validator1 = make_validator_id(1);
    let validator2 = make_validator_id(2);

    let wal = InMemoryWal::new();

    // Simulate: received attestations for height 5 while at height 4
    let car = make_test_car(validator1, 10);
    let attestation = make_test_attestation(&car, validator2);

    wal.append(WalEntry::NextHeightAttestation {
        height: 5,
        attestation: attestation.clone(),
    })
    .await
    .unwrap();

    wal.append(WalEntry::PipelineStageChanged {
        stage: WalPipelineStage::Proposing,
        height: 4,
    })
    .await
    .unwrap();

    // Recover
    let recovery = WalRecovery::new(wal);
    let recovered = recovery.recover().await.unwrap();

    // Restore to PrimaryState
    let mut state = PrimaryState::new(our_id, 1000);
    state.current_height = recovered.pipeline_height.unwrap_or(0);

    // Convert WAL pipeline stage to state pipeline stage
    if let Some(stage) = recovered.pipeline_stage {
        match stage {
            WalPipelineStage::Collecting => state.pipeline_stage = PipelineStage::Collecting,
            WalPipelineStage::Proposing => state.pipeline_stage = PipelineStage::Proposing,
            WalPipelineStage::TimedOut => state.pipeline_stage = PipelineStage::TimedOut,
        }
    }

    // Restore next-height attestations
    for (height, attestations) in recovered.next_height_attestations {
        for att in attestations {
            state.store_next_height_attestation(height, att);
        }
    }

    // Verify state is restored
    assert_eq!(state.current_height, 4);
    assert_eq!(state.pipeline_stage, PipelineStage::Proposing);
    assert!(state.has_pending_next_height_attestations());

    // When we advance to height 5, we should be able to get the pre-received attestation
    let next_atts = state.take_next_height_attestations(5);
    assert_eq!(next_atts.len(), 1);
}

/// Test timeout preservation and recovery
#[tokio::test]
async fn test_timeout_preservation_recovery() {
    use cipherbft_data_chain::AggregatedAttestation;

    let our_id = make_validator_id(0);
    let validator1 = make_validator_id(1);

    let wal = InMemoryWal::new();

    // Create preserved attested car with properly signed aggregated attestation
    let car = make_test_car(validator1, 5);

    // Create properly signed attestations from two validators (indices 0 and 1)
    let attestations_with_indices: Vec<(cipherbft_data_chain::Attestation, usize)> = [0, 1]
        .iter()
        .map(|&idx| {
            let kp = BlsKeyPair::generate(&mut rand::thread_rng());
            let attester_id = make_validator_id(idx as u8);
            let mut att = cipherbft_data_chain::Attestation::from_car(&car, attester_id);
            att.signature = kp.sign_attestation(&att.get_signing_bytes());
            (att, idx)
        })
        .collect();

    let agg = AggregatedAttestation::aggregate_with_indices(&attestations_with_indices, 4)
        .expect("aggregation should succeed");

    // Write preserved cars to WAL
    wal.append(WalEntry::PreservedAttestedCars {
        cars: vec![(validator1, car.clone(), agg.clone())],
    })
    .await
    .unwrap();

    wal.append(WalEntry::PipelineStageChanged {
        stage: WalPipelineStage::TimedOut,
        height: 3,
    })
    .await
    .unwrap();

    // Recover
    let recovery = WalRecovery::new(wal);
    let recovered = recovery.recover().await.unwrap();

    assert_eq!(recovered.preserved_attested_cars.len(), 1);
    let (vid, recovered_car, _) = &recovered.preserved_attested_cars[0];
    assert_eq!(*vid, validator1);
    assert_eq!(recovered_car.position, 5);

    // Restore to PrimaryState
    let mut state = PrimaryState::new(our_id, 1000);

    for (vid, car, att) in recovered.preserved_attested_cars {
        state.preserved_attested_cars.insert(vid, (car, att));
    }

    // Verify preserved cars are in state
    assert_eq!(state.preserved_attested_cars.len(), 1);

    // Restore should move them to attested_cars
    state.restore_preserved_attested_cars();
    assert_eq!(state.attested_cars.len(), 1);
    assert_eq!(state.preserved_attested_cars.len(), 0);
}
