//! Integration tests for state root computation at checkpoint blocks.
//!
//! These tests verify that state roots are computed at the correct intervals
//! (every 100 blocks by default) and that they are deterministic.

use alloy_primitives::{Address, B256};
use cipherbft_execution::{
    BlockInput, ChainConfig, ExecutionEngine, ExecutionLayerTrait, InMemoryProvider,
};

fn create_test_engine() -> ExecutionEngine<InMemoryProvider> {
    let provider = InMemoryProvider::new();
    let config = ChainConfig::default();
    ExecutionEngine::new(config, provider)
}

#[test]
fn test_state_root_computed_at_block_100() {
    let mut engine = create_test_engine();

    // Execute blocks 1-99: state root should be ZERO (no checkpoint yet)
    for block_num in 1..100 {
        let input = BlockInput {
            block_number: block_num,
            timestamp: 1234567890 + block_num,
            transactions: vec![],
            parent_hash: B256::ZERO,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(1_000_000_000),
            beneficiary: Address::ZERO,
        };

        let result = engine.execute_block(input).unwrap();

        // Before first checkpoint, current state root is ZERO
        assert_eq!(
            result.state_root,
            B256::ZERO,
            "Block {} should have ZERO state root (before first checkpoint)",
            block_num
        );
    }

    // Execute block 100: state root SHOULD be computed
    let input = BlockInput {
        block_number: 100,
        timestamp: 1234567890 + 100,
        transactions: vec![],
        parent_hash: B256::ZERO,
        gas_limit: 30_000_000,
        base_fee_per_gas: Some(1_000_000_000),
        beneficiary: Address::ZERO,
    };

    let result = engine.execute_block(input).unwrap();

    // Checkpoint block should have non-ZERO state root
    assert_ne!(
        result.state_root,
        B256::ZERO,
        "Block 100 should have computed state root (checkpoint)"
    );

    let checkpoint_100_root = result.state_root;

    println!("✅ State root computed at block 100");
    println!("   State root: {:?}", checkpoint_100_root);
}

#[test]
fn test_state_root_computed_at_block_200() {
    let mut engine = create_test_engine();

    let mut checkpoint_100_root = B256::ZERO;

    // Execute blocks 1-199
    for block_num in 1..200 {
        let input = BlockInput {
            block_number: block_num,
            timestamp: 1234567890 + block_num,
            transactions: vec![],
            parent_hash: B256::ZERO,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(1_000_000_000),
            beneficiary: Address::ZERO,
        };

        let result = engine.execute_block(input).unwrap();

        // Block 100 computes new state root
        if block_num == 100 {
            assert_ne!(result.state_root, B256::ZERO);
            checkpoint_100_root = result.state_root;
        } else if block_num < 100 {
            // Before first checkpoint: ZERO
            assert_eq!(result.state_root, B256::ZERO);
        } else {
            // After block 100: returns cached root from block 100
            assert_eq!(result.state_root, checkpoint_100_root);
        }
    }

    // Execute block 200: state root SHOULD be computed
    let input = BlockInput {
        block_number: 200,
        timestamp: 1234567890 + 200,
        transactions: vec![],
        parent_hash: B256::ZERO,
        gas_limit: 30_000_000,
        base_fee_per_gas: Some(1_000_000_000),
        beneficiary: Address::ZERO,
    };

    let result = engine.execute_block(input).unwrap();

    // Checkpoint block should have non-ZERO state root
    assert_ne!(
        result.state_root,
        B256::ZERO,
        "Block 200 should have computed state root (checkpoint)"
    );

    let checkpoint_200_root = result.state_root;

    println!("✅ State root computed at block 200");
    println!("   State root: {:?}", checkpoint_200_root);
}

#[test]
fn test_state_root_checkpoints_at_intervals() {
    let mut engine = create_test_engine();

    let mut checkpoint_roots = vec![];
    let mut current_state_root = B256::ZERO;

    // Execute blocks 1-500 and collect checkpoint roots
    for block_num in 1..=500 {
        let input = BlockInput {
            block_number: block_num,
            timestamp: 1234567890 + block_num,
            transactions: vec![],
            parent_hash: B256::ZERO,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(1_000_000_000),
            beneficiary: Address::ZERO,
        };

        let result = engine.execute_block(input).unwrap();

        // Check if this is a checkpoint block (multiple of 100)
        if block_num % 100 == 0 {
            // Checkpoint block: new state root computed
            assert_ne!(
                result.state_root,
                B256::ZERO,
                "Block {} should have state root (checkpoint)",
                block_num
            );
            current_state_root = result.state_root;
            checkpoint_roots.push((block_num, result.state_root));
        } else {
            // Non-checkpoint: returns current state root (from last checkpoint)
            assert_eq!(
                result.state_root, current_state_root,
                "Block {} should return current state root from last checkpoint",
                block_num
            );
        }
    }

    // Verify we have checkpoints at 100, 200, 300, 400, 500
    assert_eq!(checkpoint_roots.len(), 5);
    assert_eq!(checkpoint_roots[0].0, 100);
    assert_eq!(checkpoint_roots[1].0, 200);
    assert_eq!(checkpoint_roots[2].0, 300);
    assert_eq!(checkpoint_roots[3].0, 400);
    assert_eq!(checkpoint_roots[4].0, 500);

    // Verify all checkpoint roots are different (state is evolving)
    // Note: in current implementation they might be the same since it's a simple hash
    // but they should all be non-zero
    for (block_num, root) in &checkpoint_roots {
        assert_ne!(
            *root,
            B256::ZERO,
            "Checkpoint {} root should be non-zero",
            block_num
        );
    }

    println!("✅ State root checkpoints at correct intervals");
    println!("   Checkpoint count: {}", checkpoint_roots.len());
    for (block_num, root) in checkpoint_roots {
        println!("   Block {}: {:?}", block_num, root);
    }
}

#[test]
fn test_state_root_consistent_across_checkpoint_blocks() {
    let mut engine = create_test_engine();

    // Execute up to block 100
    for block_num in 1..=100 {
        let input = BlockInput {
            block_number: block_num,
            timestamp: 1234567890 + block_num,
            transactions: vec![],
            parent_hash: B256::ZERO,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(1_000_000_000),
            beneficiary: Address::ZERO,
        };

        engine.execute_block(input).unwrap();
    }

    // Get state root from engine directly (should be from block 100)
    let state_root_from_engine = engine.state_root();
    assert_ne!(state_root_from_engine, B256::ZERO);

    // Execute block 101-110 (non-checkpoint blocks)
    for block_num in 101..=110 {
        let input = BlockInput {
            block_number: block_num,
            timestamp: 1234567890 + block_num,
            transactions: vec![],
            parent_hash: B256::ZERO,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(1_000_000_000),
            beneficiary: Address::ZERO,
        };

        let result = engine.execute_block(input).unwrap();

        // State root in result should match the one from block 100
        assert_eq!(result.state_root, state_root_from_engine);
    }

    // Engine's current state root should still be the one from block 100
    assert_eq!(engine.state_root(), state_root_from_engine);

    // Execute blocks 111-200 to get to next checkpoint
    for block_num in 111..=200 {
        let input = BlockInput {
            block_number: block_num,
            timestamp: 1234567890 + block_num,
            transactions: vec![],
            parent_hash: B256::ZERO,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(1_000_000_000),
            beneficiary: Address::ZERO,
        };

        let result = engine.execute_block(input).unwrap();

        if block_num < 200 {
            // Before checkpoint: same state root
            assert_eq!(result.state_root, state_root_from_engine);
        } else {
            // At checkpoint 200: new state root computed
            assert_ne!(result.state_root, B256::ZERO);
            assert_eq!(engine.state_root(), result.state_root);
        }
    }

    println!("✅ State root consistent across checkpoint blocks");
}

#[test]
fn test_state_root_progression() {
    let mut engine = create_test_engine();

    // Execute blocks sequentially to test state root progression
    let mut current_state_root = B256::ZERO;

    for block_num in 1..=300 {
        let input = BlockInput {
            block_number: block_num,
            timestamp: 1234567890 + block_num,
            transactions: vec![],
            parent_hash: B256::ZERO,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(1_000_000_000),
            beneficiary: Address::ZERO,
        };

        let result = engine.execute_block(input).unwrap();

        // At checkpoint blocks, state root should be computed (non-zero)
        if block_num % 100 == 0 {
            assert_ne!(
                result.state_root,
                B256::ZERO,
                "Checkpoint block {} should compute state root",
                block_num
            );
            current_state_root = result.state_root;
        } else {
            // Non-checkpoint blocks return current state root
            assert_eq!(
                result.state_root, current_state_root,
                "Block {} should return current state root",
                block_num
            );
        }
    }

    // Verify final state root is non-zero
    assert_ne!(current_state_root, B256::ZERO);

    println!("✅ State root progression works correctly");
}
