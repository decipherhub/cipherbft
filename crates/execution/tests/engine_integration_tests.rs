//! Integration tests for the execution engine.
//!
//! These tests verify the complete execution flow including:
//! - Block execution
//! - State root computation
//! - Transaction processing
//! - Block sealing
//! - Delayed commitment

use cipherbft_execution::{
    BlockInput, ChainConfig, ConsensusBlock, ExecutionEngine, ExecutionLayerTrait,
    InMemoryProvider,
};
use alloy_primitives::{Bloom, Bytes, B256};

fn create_test_engine() -> ExecutionEngine<InMemoryProvider> {
    let provider = InMemoryProvider::new();
    let config = ChainConfig::default();
    ExecutionEngine::new(config, provider)
}

#[test]
fn test_execute_empty_block() {
    let mut engine = create_test_engine();

    let input = BlockInput {
        block_number: 1,
        timestamp: 1234567890,
        transactions: vec![],
        parent_hash: B256::ZERO,
        gas_limit: 30_000_000,
        base_fee_per_gas: Some(1_000_000_000),
    };

    let result = engine.execute_block(input).unwrap();

    assert_eq!(result.block_number, 1);
    assert_eq!(result.gas_used, 0);
    assert_eq!(result.receipts.len(), 0);
    assert_eq!(result.logs_bloom, Bloom::ZERO);
}

#[test]
fn test_execute_multiple_empty_blocks() {
    let mut engine = create_test_engine();

    for block_num in 1..=10 {
        let input = BlockInput {
            block_number: block_num,
            timestamp: 1234567890 + block_num,
            transactions: vec![],
            parent_hash: B256::ZERO,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(1_000_000_000),
        };

        let result = engine.execute_block(input).unwrap();
        assert_eq!(result.block_number, block_num);
    }
}

#[test]
fn test_state_root_computation_at_checkpoint() {
    let mut engine = create_test_engine();

    // Execute blocks up to checkpoint (block 100)
    for block_num in 1..=100 {
        let input = BlockInput {
            block_number: block_num,
            timestamp: 1234567890 + block_num,
            transactions: vec![],
            parent_hash: B256::ZERO,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(1_000_000_000),
        };

        let result = engine.execute_block(input).unwrap();

        // State root should be computed at block 100 (checkpoint)
        if block_num == 100 {
            assert_ne!(result.state_root, B256::ZERO);
        }
    }
}

#[test]
fn test_seal_block() {
    let mut engine = create_test_engine();

    // Execute a block first
    let input = BlockInput {
        block_number: 1,
        timestamp: 1234567890,
        transactions: vec![],
        parent_hash: B256::ZERO,
        gas_limit: 30_000_000,
        base_fee_per_gas: Some(1_000_000_000),
    };

    let execution_result = engine.execute_block(input).unwrap();

    // Seal the block
    let consensus_block = ConsensusBlock {
        number: 1,
        timestamp: 1234567890,
        parent_hash: B256::ZERO,
        transactions: vec![],
        gas_limit: 30_000_000,
        base_fee_per_gas: Some(1_000_000_000),
    };

    let sealed = engine.seal_block(consensus_block, execution_result).unwrap();

    assert_eq!(sealed.header.number, 1);
    assert_ne!(sealed.hash, B256::ZERO);
    assert_eq!(sealed.header.gas_used, 0);
}

#[test]
fn test_delayed_commitment() {
    let mut engine = create_test_engine();

    // Execute blocks to test delayed commitment
    let mut block_hashes = vec![];

    for block_num in 1..=5 {
        let input = BlockInput {
            block_number: block_num,
            timestamp: 1234567890 + block_num,
            transactions: vec![],
            parent_hash: if block_num == 1 {
                B256::ZERO
            } else {
                block_hashes[block_num as usize - 2]
            },
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(1_000_000_000),
        };

        let execution_result = engine.execute_block(input.clone()).unwrap();

        // Seal the block to get its hash
        let consensus_block = ConsensusBlock {
            number: block_num,
            timestamp: input.timestamp,
            parent_hash: input.parent_hash,
            transactions: vec![],
            gas_limit: input.gas_limit,
            base_fee_per_gas: input.base_fee_per_gas,
        };

        let sealed = engine.seal_block(consensus_block, execution_result).unwrap();
        block_hashes.push(sealed.hash);
    }

    // Block 3 should have block 1's hash (N-2)
    // Verify we can retrieve block hashes
    let block_1_hash = engine.get_delayed_block_hash(1).unwrap();
    assert_eq!(block_1_hash, block_hashes[0]);
}

#[test]
fn test_validate_block_sequential() {
    let mut engine = create_test_engine();

    // First block
    let input1 = BlockInput {
        block_number: 1,
        timestamp: 1234567890,
        transactions: vec![],
        parent_hash: B256::ZERO,
        gas_limit: 30_000_000,
        base_fee_per_gas: Some(1_000_000_000),
    };

    assert!(engine.validate_block(&input1).is_ok());
    engine.execute_block(input1).unwrap();

    // Second block (sequential)
    let input2 = BlockInput {
        block_number: 2,
        timestamp: 1234567891,
        transactions: vec![],
        parent_hash: B256::ZERO,
        gas_limit: 30_000_000,
        base_fee_per_gas: Some(1_000_000_000),
    };

    assert!(engine.validate_block(&input2).is_ok());
}

#[test]
fn test_validate_block_non_sequential() {
    let mut engine = create_test_engine();

    // First block
    let input1 = BlockInput {
        block_number: 1,
        timestamp: 1234567890,
        transactions: vec![],
        parent_hash: B256::ZERO,
        gas_limit: 30_000_000,
        base_fee_per_gas: Some(1_000_000_000),
    };

    engine.execute_block(input1).unwrap();

    // Skip to block 5 (non-sequential)
    let input_invalid = BlockInput {
        block_number: 5,
        timestamp: 1234567891,
        transactions: vec![],
        parent_hash: B256::ZERO,
        gas_limit: 30_000_000,
        base_fee_per_gas: Some(1_000_000_000),
    };

    assert!(engine.validate_block(&input_invalid).is_err());
}

#[test]
fn test_validate_block_zero_gas_limit() {
    let engine = create_test_engine();

    let input = BlockInput {
        block_number: 1,
        timestamp: 1234567890,
        transactions: vec![],
        parent_hash: B256::ZERO,
        gas_limit: 0, // Invalid
        base_fee_per_gas: Some(1_000_000_000),
    };

    assert!(engine.validate_block(&input).is_err());
}

#[test]
fn test_state_root_retrieval() {
    let mut engine = create_test_engine();

    // Initial state root should be zero
    assert_eq!(engine.state_root(), B256::ZERO);

    // Execute blocks up to checkpoint
    for block_num in 1..=100 {
        let input = BlockInput {
            block_number: block_num,
            timestamp: 1234567890 + block_num,
            transactions: vec![],
            parent_hash: B256::ZERO,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(1_000_000_000),
        };

        engine.execute_block(input).unwrap();
    }

    // State root should be non-zero after checkpoint
    assert_ne!(engine.state_root(), B256::ZERO);
}

#[test]
fn test_validate_transaction_invalid_rlp() {
    let engine = create_test_engine();

    // Invalid RLP data
    let invalid_tx = Bytes::from(vec![0xff, 0xff, 0xff]);

    assert!(engine.validate_transaction(&invalid_tx).is_err());
}

#[test]
fn test_complete_block_lifecycle() {
    let mut engine = create_test_engine();

    // 1. Create block input
    let input = BlockInput {
        block_number: 1,
        timestamp: 1234567890,
        transactions: vec![],
        parent_hash: B256::ZERO,
        gas_limit: 30_000_000,
        base_fee_per_gas: Some(1_000_000_000),
    };

    // 2. Validate block
    assert!(engine.validate_block(&input).is_ok());

    // 3. Execute block
    let execution_result = engine.execute_block(input.clone()).unwrap();

    assert_eq!(execution_result.block_number, 1);
    assert_eq!(execution_result.gas_used, 0);

    // 4. Seal block
    let consensus_block = ConsensusBlock {
        number: 1,
        timestamp: input.timestamp,
        parent_hash: input.parent_hash,
        transactions: input.transactions,
        gas_limit: input.gas_limit,
        base_fee_per_gas: input.base_fee_per_gas,
    };

    let sealed = engine.seal_block(consensus_block, execution_result).unwrap();

    // 5. Verify sealed block
    assert_eq!(sealed.header.number, 1);
    assert_ne!(sealed.hash, B256::ZERO);
    assert_eq!(sealed.transactions.len(), 0);
}

#[test]
fn test_receipts_root_computation() {
    let mut engine = create_test_engine();

    let input = BlockInput {
        block_number: 1,
        timestamp: 1234567890,
        transactions: vec![],
        parent_hash: B256::ZERO,
        gas_limit: 30_000_000,
        base_fee_per_gas: Some(1_000_000_000),
    };

    let result = engine.execute_block(input).unwrap();

    // Empty block should have empty trie root
    assert_eq!(result.receipts_root, alloy_trie::EMPTY_ROOT_HASH);
}

#[test]
fn test_transactions_root_computation() {
    let mut engine = create_test_engine();

    let input = BlockInput {
        block_number: 1,
        timestamp: 1234567890,
        transactions: vec![],
        parent_hash: B256::ZERO,
        gas_limit: 30_000_000,
        base_fee_per_gas: Some(1_000_000_000),
    };

    let result = engine.execute_block(input).unwrap();

    // Empty block should have empty trie root
    assert_eq!(result.transactions_root, alloy_trie::EMPTY_ROOT_HASH);
}
