//! Integration tests for ExecutionResult completeness.
//!
//! These tests verify that ExecutionResult contains all required fields
//! that the consensus layer needs for block construction.

use alloy_primitives::{Address, Bytes, TxKind, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_consensus::{SignableTransaction, TxEip1559};
use cipherbft_execution::{
    Account, BlockInput, ChainConfig, ExecutionEngine, ExecutionLayerTrait, InMemoryProvider,
    Provider,
};

/// Parameters for creating an EIP-1559 transaction
struct Eip1559TxParams {
    to: Address,
    value: U256,
    nonce: u64,
    gas_limit: u64,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
    data: Bytes,
}

/// Create and sign an EIP-1559 transaction
fn create_eip1559_transaction(signer: &PrivateKeySigner, params: Eip1559TxParams) -> Bytes {
    let tx = TxEip1559 {
        chain_id: 31337,
        nonce: params.nonce,
        gas_limit: params.gas_limit,
        max_fee_per_gas: params.max_fee_per_gas,
        max_priority_fee_per_gas: params.max_priority_fee_per_gas,
        to: TxKind::Call(params.to),
        value: params.value,
        access_list: Default::default(),
        input: params.data,
    };

    let signature = signer.sign_hash_sync(&tx.signature_hash()).unwrap();
    let signed = tx.into_signed(signature);

    // Encode the transaction - EIP-1559 uses type prefix
    let mut encoded = Vec::new();
    encoded.push(0x02); // EIP-1559 type
    signed.rlp_encode(&mut encoded);
    Bytes::from(encoded)
}

/// Create a test engine with funded accounts
fn create_test_engine_with_accounts(
    num_accounts: usize,
) -> (ExecutionEngine<InMemoryProvider>, Vec<PrivateKeySigner>) {
    let provider = InMemoryProvider::new();
    let config = ChainConfig::default();

    // Create signers and fund accounts
    let mut signers = Vec::new();
    let initial_balance = U256::from(1000u128) * U256::from(1_000_000_000_000_000_000u64); // 1000 ETH

    for i in 0..num_accounts {
        // Generate unique private keys
        let pk_bytes = format!("{:064x}", i + 1);
        let signer = pk_bytes.parse::<PrivateKeySigner>().unwrap();
        let addr = signer.address();

        let account = Account {
            nonce: 0,
            balance: initial_balance,
            code_hash: alloy_primitives::keccak256([]),
            storage_root: alloy_primitives::B256::ZERO,
        };

        provider.set_account(addr, account).unwrap();
        signers.push(signer);
    }

    let engine = ExecutionEngine::new(config, provider);
    (engine, signers)
}

#[test]
fn test_execution_result_completeness_50_transactions() {
    // Create engine with 50 funded accounts
    let (mut engine, signers) = create_test_engine_with_accounts(50);

    // Create 50 transactions (each account sends to the next one)
    let mut transactions = Vec::new();
    let transfer_amount = U256::from(1_000_000_000_000_000_000u64); // 1 ETH

    for (i, signer) in signers.iter().enumerate() {
        let recipient = signers[(i + 1) % signers.len()].address();

        let tx = create_eip1559_transaction(
            signer,
            Eip1559TxParams {
                to: recipient,
                value: transfer_amount,
                nonce: 0,
                gas_limit: 21_000,
                max_fee_per_gas: 2_000_000_000,
                max_priority_fee_per_gas: 1_000_000_000,
                data: Bytes::new(),
            },
        );

        transactions.push(tx);
    }

    // Execute block with 50 transactions
    let input = BlockInput {
        block_number: 1,
        timestamp: 1234567890,
        transactions,
        parent_hash: alloy_primitives::B256::ZERO,
        gas_limit: 30_000_000,
        base_fee_per_gas: Some(1_000_000_000),
    };

    let result = engine.execute_block(input).unwrap();

    // Verify ExecutionResult completeness

    // 1. Block metadata
    assert_eq!(result.block_number, 1, "Block number should match input");

    // 2. Receipts
    assert_eq!(result.receipts.len(), 50, "Should have 50 receipts");

    // Verify each receipt has complete data
    for (i, receipt) in result.receipts.iter().enumerate() {
        assert_eq!(receipt.status, 1, "Receipt {} should succeed", i);
        assert_ne!(
            receipt.transaction_hash,
            alloy_primitives::B256::ZERO,
            "Receipt {} should have transaction hash",
            i
        );
        assert_ne!(
            receipt.from,
            Address::ZERO,
            "Receipt {} should have from address",
            i
        );
        assert!(
            receipt.to.is_some(),
            "Receipt {} should have to address",
            i
        );
        assert_eq!(
            receipt.gas_used, 21_000,
            "Receipt {} should have gas used",
            i
        );
        assert_eq!(
            receipt.cumulative_gas_used,
            21_000 * (i as u64 + 1),
            "Receipt {} should have cumulative gas",
            i
        );
        assert!(
            receipt.logs.is_empty(),
            "Receipt {} should have logs field (even if empty)",
            i
        );
        assert_eq!(
            receipt.transaction_index, i as u64,
            "Receipt {} should have correct transaction index",
            i
        );
        assert_eq!(
            receipt.block_number, 1,
            "Receipt {} should have block number",
            i
        );
        // Note: block_hash is set to ZERO until block is sealed
        assert_eq!(
            receipt.block_hash,
            alloy_primitives::B256::ZERO,
            "Receipt {} block_hash should be ZERO (set during sealing)",
            i
        );
    }

    // 3. Gas usage
    assert_eq!(
        result.gas_used,
        21_000 * 50,
        "Total gas used should be 50 * 21000"
    );

    // 4. Merkle roots
    assert_ne!(
        result.receipts_root,
        alloy_primitives::B256::ZERO,
        "Receipts root should be computed"
    );
    assert_ne!(
        result.receipts_root,
        alloy_trie::EMPTY_ROOT_HASH,
        "Receipts root should not be empty"
    );

    assert_ne!(
        result.transactions_root,
        alloy_primitives::B256::ZERO,
        "Transactions root should be computed"
    );
    assert_ne!(
        result.transactions_root,
        alloy_trie::EMPTY_ROOT_HASH,
        "Transactions root should not be empty"
    );

    // 5. State root (should be zero for non-checkpoint blocks)
    assert_eq!(
        result.state_root,
        alloy_primitives::B256::ZERO,
        "State root should be zero for non-checkpoint block"
    );

    // 6. Logs bloom
    assert_eq!(
        result.logs_bloom,
        alloy_primitives::Bloom::ZERO,
        "Logs bloom should be zero (no logs in these transfers)"
    );

    // 7. Block hash (delayed commitment - block N-2 for early blocks this is ZERO)
    // Block 1 doesn't have a block at position -1, so block_hash is ZERO
    assert_eq!(
        result.block_hash,
        alloy_primitives::B256::ZERO,
        "Block hash should be ZERO for block 1 (delayed commitment N-2)"
    );

    println!("✅ ExecutionResult completeness test passed");
    println!("   Transactions: {}", result.receipts.len());
    println!("   Total gas used: {}", result.gas_used);
    println!("   Receipts root: {:?}", result.receipts_root);
    println!("   Transactions root: {:?}", result.transactions_root);
    println!("   Block hash: {:?}", result.block_hash);
}

#[test]
fn test_execution_result_with_mixed_transaction_types() {
    // Create engine with funded accounts
    let (mut engine, signers) = create_test_engine_with_accounts(10);

    let mut transactions = Vec::new();
    let transfer_amount = U256::from(500_000_000_000_000_000u64); // 0.5 ETH

    // Mix of different transaction values and gas limits
    for (i, signer) in signers.iter().enumerate() {
        let recipient = signers[(i + 1) % signers.len()].address();

        let tx = create_eip1559_transaction(
            signer,
            Eip1559TxParams {
                to: recipient,
                value: transfer_amount * U256::from(i + 1), // Varying amounts
                nonce: 0,
                gas_limit: 21_000 + (i as u64 * 1000), // Varying gas limits
                max_fee_per_gas: 2_000_000_000 + (i as u128 * 100_000_000),
                max_priority_fee_per_gas: 1_000_000_000,
                data: Bytes::new(),
            },
        );

        transactions.push(tx);
    }

    let input = BlockInput {
        block_number: 5,
        timestamp: 1234567895,
        transactions,
        parent_hash: alloy_primitives::B256::ZERO,
        gas_limit: 30_000_000,
        base_fee_per_gas: Some(1_000_000_000),
    };

    let result = engine.execute_block(input).unwrap();

    // Verify all receipts are present and valid
    assert_eq!(result.receipts.len(), 10);

    // Verify cumulative gas is strictly increasing
    let mut prev_cumulative = 0u64;
    for receipt in &result.receipts {
        assert!(
            receipt.cumulative_gas_used > prev_cumulative,
            "Cumulative gas should be strictly increasing"
        );
        prev_cumulative = receipt.cumulative_gas_used;
    }

    // Verify total gas matches last cumulative gas
    assert_eq!(
        result.gas_used,
        result.receipts.last().unwrap().cumulative_gas_used,
        "Total gas should match last cumulative gas"
    );

    // Verify all receipts have correct block metadata
    for receipt in &result.receipts {
        assert_eq!(receipt.block_number, 5);
        // Note: block_hash on receipts is set during sealing, not during execution
        assert_eq!(receipt.block_hash, alloy_primitives::B256::ZERO);
    }

    println!("✅ Mixed transaction types test passed");
}

#[test]
fn test_execution_result_determinism() {
    // Same input should produce same output
    let (mut engine1, signers1) = create_test_engine_with_accounts(20);
    let (mut engine2, signers2) = create_test_engine_with_accounts(20);

    // Create identical transactions for both engines
    let mut transactions1 = Vec::new();
    let mut transactions2 = Vec::new();
    let transfer_amount = U256::from(1_000_000_000_000_000_000u64);

    for i in 0..20 {
        let tx1 = create_eip1559_transaction(
            &signers1[i],
            Eip1559TxParams {
                to: signers1[(i + 1) % 20].address(),
                value: transfer_amount,
                nonce: 0,
                gas_limit: 21_000,
                max_fee_per_gas: 2_000_000_000,
                max_priority_fee_per_gas: 1_000_000_000,
                data: Bytes::new(),
            },
        );

        let tx2 = create_eip1559_transaction(
            &signers2[i],
            Eip1559TxParams {
                to: signers2[(i + 1) % 20].address(),
                value: transfer_amount,
                nonce: 0,
                gas_limit: 21_000,
                max_fee_per_gas: 2_000_000_000,
                max_priority_fee_per_gas: 1_000_000_000,
                data: Bytes::new(),
            },
        );

        transactions1.push(tx1);
        transactions2.push(tx2);
    }

    let input1 = BlockInput {
        block_number: 1,
        timestamp: 1234567890,
        transactions: transactions1,
        parent_hash: alloy_primitives::B256::ZERO,
        gas_limit: 30_000_000,
        base_fee_per_gas: Some(1_000_000_000),
    };

    let input2 = BlockInput {
        block_number: 1,
        timestamp: 1234567890,
        transactions: transactions2,
        parent_hash: alloy_primitives::B256::ZERO,
        gas_limit: 30_000_000,
        base_fee_per_gas: Some(1_000_000_000),
    };

    let result1 = engine1.execute_block(input1).unwrap();
    let result2 = engine2.execute_block(input2).unwrap();

    // Verify determinism
    assert_eq!(result1.block_number, result2.block_number);
    assert_eq!(result1.gas_used, result2.gas_used);
    assert_eq!(result1.receipts_root, result2.receipts_root);
    assert_eq!(result1.transactions_root, result2.transactions_root);
    assert_eq!(result1.logs_bloom, result2.logs_bloom);

    // Verify receipt count and gas usage match
    assert_eq!(result1.receipts.len(), result2.receipts.len());

    println!("✅ Execution result determinism test passed");
}
