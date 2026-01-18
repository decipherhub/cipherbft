//! Integration tests with real Ethereum transactions.
//!
//! These tests verify the execution engine works correctly with:
//! - ETH transfers between accounts
//! - Contract deployment
//! - Contract function calls
//! - Multiple transactions in a single block

use alloy_consensus::{SignableTransaction, TxEip1559, TxLegacy};
use alloy_primitives::{Address, Bytes, TxKind, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use cipherbft_execution::{
    Account, BlockInput, ChainConfig, ExecutionEngine, ExecutionLayerTrait, InMemoryProvider,
    Provider,
};

/// Test account 1 with known private key
const TEST_PRIVATE_KEY_1: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// Test account 2 with known private key
const TEST_PRIVATE_KEY_2: &str = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

/// Create a test engine with funded accounts
fn create_test_engine_with_accounts() -> (
    ExecutionEngine<InMemoryProvider>,
    PrivateKeySigner,
    PrivateKeySigner,
) {
    let provider = InMemoryProvider::new();
    let config = ChainConfig::default();

    // Create signers
    let signer1 = TEST_PRIVATE_KEY_1.parse::<PrivateKeySigner>().unwrap();
    let signer2 = TEST_PRIVATE_KEY_2.parse::<PrivateKeySigner>().unwrap();

    let addr1 = signer1.address();
    let addr2 = signer2.address();

    // Fund accounts with 100 ETH each
    let initial_balance = U256::from(100u128) * U256::from(1_000_000_000_000_000_000u64); // 100 ETH in wei

    let account1 = Account {
        nonce: 0,
        balance: initial_balance,
        code_hash: alloy_primitives::keccak256([]),
        storage_root: alloy_primitives::B256::ZERO,
    };

    let account2 = Account {
        nonce: 0,
        balance: initial_balance,
        code_hash: alloy_primitives::keccak256([]),
        storage_root: alloy_primitives::B256::ZERO,
    };

    provider.set_account(addr1, account1).unwrap();
    provider.set_account(addr2, account2).unwrap();

    let engine = ExecutionEngine::new(config, provider);

    (engine, signer1, signer2)
}

/// Create and sign a legacy transaction
fn create_legacy_transaction(
    signer: &PrivateKeySigner,
    to: Address,
    value: U256,
    nonce: u64,
    gas_limit: u64,
    gas_price: u128,
    data: Bytes,
) -> Bytes {
    let tx = TxLegacy {
        chain_id: Some(85300), // CipherBFT Testnet chain ID
        nonce,
        gas_price,
        gas_limit,
        to: TxKind::Call(to),
        value,
        input: data,
    };

    let signature = signer.sign_hash_sync(&tx.signature_hash()).unwrap();
    let signed = tx.into_signed(signature);

    // Encode the transaction
    let mut encoded = Vec::new();
    signed.rlp_encode(&mut encoded);
    Bytes::from(encoded)
}

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
        chain_id: 85300, // CipherBFT Testnet chain ID
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

/// Create a contract creation transaction
fn create_contract_creation_transaction(
    signer: &PrivateKeySigner,
    nonce: u64,
    gas_limit: u64,
    max_fee_per_gas: u128,
    bytecode: Bytes,
) -> Bytes {
    let tx = TxEip1559 {
        chain_id: 85300, // CipherBFT Testnet chain ID
        nonce,
        gas_limit,
        max_fee_per_gas,
        max_priority_fee_per_gas: 1_000_000_000, // 1 gwei
        to: TxKind::Create,
        value: U256::ZERO,
        access_list: Default::default(),
        input: bytecode,
    };

    let signature = signer.sign_hash_sync(&tx.signature_hash()).unwrap();
    let signed = tx.into_signed(signature);

    // Encode the transaction - EIP-1559 uses type prefix
    let mut encoded = Vec::new();
    encoded.push(0x02); // EIP-1559 type
    signed.rlp_encode(&mut encoded);
    Bytes::from(encoded)
}

#[test]
fn test_simple_eth_transfer() {
    let (mut engine, signer1, signer2) = create_test_engine_with_accounts();

    let addr1 = signer1.address();
    let addr2 = signer2.address();

    // Create a transfer transaction: 1 ETH from account1 to account2
    let transfer_amount = U256::from(1_000_000_000_000_000_000u64); // 1 ETH
    let tx = create_eip1559_transaction(
        &signer1,
        Eip1559TxParams {
            to: addr2,
            value: transfer_amount,
            nonce: 0,
            gas_limit: 21_000,
            max_fee_per_gas: 2_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            data: Bytes::new(),
        },
    );

    // Execute block with transaction
    let input = BlockInput {
        block_number: 1,
        timestamp: 1234567890,
        transactions: vec![tx],
        parent_hash: alloy_primitives::B256::ZERO,
        gas_limit: 30_000_000,
        base_fee_per_gas: Some(1_000_000_000),
    };

    let result = engine.execute_block(input).unwrap();

    // Verify execution results
    assert_eq!(result.block_number, 1);
    assert_eq!(result.receipts.len(), 1);
    assert_eq!(result.gas_used, 21_000);

    // Verify receipt
    let receipt = &result.receipts[0];
    assert_eq!(receipt.status, 1); // Success
    assert_eq!(receipt.from, addr1);
    assert_eq!(receipt.to, Some(addr2));
    assert_eq!(receipt.gas_used, 21_000);

    println!("✅ Simple ETH transfer test passed");
    println!("   Gas used: {}", result.gas_used);
    println!("   Transaction succeeded: {}", receipt.status == 1);
}

#[test]
fn test_multiple_transfers_in_block() {
    let (mut engine, signer1, signer2) = create_test_engine_with_accounts();

    let addr1 = signer1.address();
    let addr2 = signer2.address();

    // Create multiple transactions
    let transfer_amount = U256::from(1_000_000_000_000_000_000u64); // 1 ETH

    let tx1 = create_eip1559_transaction(
        &signer1,
        Eip1559TxParams {
            to: addr2,
            value: transfer_amount,
            nonce: 0,
            gas_limit: 21_000,
            max_fee_per_gas: 2_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            data: Bytes::new(),
        },
    );

    let tx2 = create_eip1559_transaction(
        &signer1,
        Eip1559TxParams {
            to: addr2,
            value: transfer_amount,
            nonce: 1,
            gas_limit: 21_000,
            max_fee_per_gas: 2_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            data: Bytes::new(),
        },
    );

    let tx3 = create_eip1559_transaction(
        &signer2,
        Eip1559TxParams {
            to: addr1,
            value: transfer_amount,
            nonce: 0,
            gas_limit: 21_000,
            max_fee_per_gas: 2_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            data: Bytes::new(),
        },
    );

    // Execute block with multiple transactions
    let input = BlockInput {
        block_number: 1,
        timestamp: 1234567890,
        transactions: vec![tx1, tx2, tx3],
        parent_hash: alloy_primitives::B256::ZERO,
        gas_limit: 30_000_000,
        base_fee_per_gas: Some(1_000_000_000),
    };

    let result = engine.execute_block(input).unwrap();

    // Verify execution results
    assert_eq!(result.block_number, 1);
    assert_eq!(result.receipts.len(), 3);
    assert_eq!(result.gas_used, 21_000 * 3); // 3 transfers

    // Verify all receipts succeeded
    for receipt in &result.receipts {
        assert_eq!(receipt.status, 1); // Success
        assert_eq!(receipt.gas_used, 21_000);
    }

    // Verify cumulative gas
    assert_eq!(result.receipts[0].cumulative_gas_used, 21_000);
    assert_eq!(result.receipts[1].cumulative_gas_used, 42_000);
    assert_eq!(result.receipts[2].cumulative_gas_used, 63_000);

    println!("✅ Multiple transfers test passed");
    println!("   Total gas used: {}", result.gas_used);
    println!("   Transactions: {}", result.receipts.len());
}

#[test]
fn test_legacy_transaction() {
    let (mut engine, signer1, signer2) = create_test_engine_with_accounts();

    let addr2 = signer2.address();

    // Create a legacy transaction
    let transfer_amount = U256::from(500_000_000_000_000_000u64); // 0.5 ETH
    let tx = create_legacy_transaction(
        &signer1,
        addr2,
        transfer_amount,
        0,             // nonce
        21_000,        // gas limit
        2_000_000_000, // 2 gwei gas price
        Bytes::new(),
    );

    // Execute block
    let input = BlockInput {
        block_number: 1,
        timestamp: 1234567890,
        transactions: vec![tx],
        parent_hash: alloy_primitives::B256::ZERO,
        gas_limit: 30_000_000,
        base_fee_per_gas: Some(1_000_000_000),
    };

    let result = engine.execute_block(input).unwrap();

    // Verify execution
    assert_eq!(result.receipts.len(), 1);
    assert_eq!(result.receipts[0].status, 1); // Success

    println!("✅ Legacy transaction test passed");
}

#[test]
fn test_contract_deployment() {
    let (mut engine, signer1, _) = create_test_engine_with_accounts();

    // Simple contract bytecode that returns 42 (0x2a)
    // PUSH1 0x2a PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN
    let bytecode = Bytes::from(hex::decode("602a60005260206000f3").unwrap());

    let tx = create_contract_creation_transaction(
        &signer1,
        0,             // nonce
        100_000,       // gas limit
        2_000_000_000, // 2 gwei
        bytecode,
    );

    // Execute block
    let input = BlockInput {
        block_number: 1,
        timestamp: 1234567890,
        transactions: vec![tx],
        parent_hash: alloy_primitives::B256::ZERO,
        gas_limit: 30_000_000,
        base_fee_per_gas: Some(1_000_000_000),
    };

    let result = engine.execute_block(input).unwrap();

    // Verify contract deployment
    assert_eq!(result.receipts.len(), 1);
    let receipt = &result.receipts[0];

    assert_eq!(receipt.status, 1); // Success
    assert!(receipt.contract_address.is_some()); // Contract was created
    assert!(receipt.gas_used > 0);

    println!("✅ Contract deployment test passed");
    println!("   Contract deployed at: {:?}", receipt.contract_address);
    println!("   Gas used: {}", receipt.gas_used);
}

#[test]
fn test_transaction_with_data() {
    let (mut engine, signer1, signer2) = create_test_engine_with_accounts();

    let addr2 = signer2.address();

    // Transaction with calldata (simulating contract call)
    let calldata = Bytes::from(hex::decode("a9059cbb").unwrap()); // ERC20 transfer selector

    let tx = create_eip1559_transaction(
        &signer1,
        Eip1559TxParams {
            to: addr2,
            value: U256::ZERO,
            nonce: 0,
            gas_limit: 50_000,
            max_fee_per_gas: 2_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            data: calldata,
        },
    );

    let input = BlockInput {
        block_number: 1,
        timestamp: 1234567890,
        transactions: vec![tx],
        parent_hash: alloy_primitives::B256::ZERO,
        gas_limit: 30_000_000,
        base_fee_per_gas: Some(1_000_000_000),
    };

    let result = engine.execute_block(input).unwrap();

    // Verify execution
    assert_eq!(result.receipts.len(), 1);
    assert!(result.gas_used > 21_000); // More than basic transfer

    println!("✅ Transaction with data test passed");
    println!("   Gas used: {}", result.gas_used);
}

#[test]
fn test_sequential_blocks_with_nonce() {
    let (mut engine, signer1, signer2) = create_test_engine_with_accounts();

    let addr2 = signer2.address();
    let transfer_amount = U256::from(1_000_000_000_000_000_000u64); // 1 ETH

    // Block 1: nonce 0
    let tx1 = create_eip1559_transaction(
        &signer1,
        Eip1559TxParams {
            to: addr2,
            value: transfer_amount,
            nonce: 0,
            gas_limit: 21_000,
            max_fee_per_gas: 2_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            data: Bytes::new(),
        },
    );

    let input1 = BlockInput {
        block_number: 1,
        timestamp: 1234567890,
        transactions: vec![tx1],
        parent_hash: alloy_primitives::B256::ZERO,
        gas_limit: 30_000_000,
        base_fee_per_gas: Some(1_000_000_000),
    };

    let result1 = engine.execute_block(input1).unwrap();
    assert_eq!(result1.receipts[0].status, 1);

    // Block 2: nonce 1
    let tx2 = create_eip1559_transaction(
        &signer1,
        Eip1559TxParams {
            to: addr2,
            value: transfer_amount,
            nonce: 1,
            gas_limit: 21_000,
            max_fee_per_gas: 2_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            data: Bytes::new(),
        },
    );

    let input2 = BlockInput {
        block_number: 2,
        timestamp: 1234567891,
        transactions: vec![tx2],
        parent_hash: result1.block_hash,
        gas_limit: 30_000_000,
        base_fee_per_gas: Some(1_000_000_000),
    };

    let result2 = engine.execute_block(input2).unwrap();
    assert_eq!(result2.receipts[0].status, 1);

    // Block 3: nonce 2
    let tx3 = create_eip1559_transaction(
        &signer1,
        Eip1559TxParams {
            to: addr2,
            value: transfer_amount,
            nonce: 2,
            gas_limit: 21_000,
            max_fee_per_gas: 2_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            data: Bytes::new(),
        },
    );

    let input3 = BlockInput {
        block_number: 3,
        timestamp: 1234567892,
        transactions: vec![tx3],
        parent_hash: result2.block_hash,
        gas_limit: 30_000_000,
        base_fee_per_gas: Some(1_000_000_000),
    };

    let result3 = engine.execute_block(input3).unwrap();
    assert_eq!(result3.receipts[0].status, 1);

    println!("✅ Sequential blocks with nonce test passed");
    println!("   Blocks executed: 3");
    println!("   All transactions succeeded");
}

#[test]
fn test_receipts_root_with_real_transactions() {
    let (mut engine, signer1, signer2) = create_test_engine_with_accounts();

    let addr2 = signer2.address();

    // Create transaction
    let tx = create_eip1559_transaction(
        &signer1,
        Eip1559TxParams {
            to: addr2,
            value: U256::from(1_000_000_000_000_000_000u64),
            nonce: 0,
            gas_limit: 21_000,
            max_fee_per_gas: 2_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            data: Bytes::new(),
        },
    );

    let input = BlockInput {
        block_number: 1,
        timestamp: 1234567890,
        transactions: vec![tx],
        parent_hash: alloy_primitives::B256::ZERO,
        gas_limit: 30_000_000,
        base_fee_per_gas: Some(1_000_000_000),
    };

    let result = engine.execute_block(input).unwrap();

    // Receipts root should be computed
    assert_ne!(result.receipts_root, alloy_primitives::B256::ZERO);
    assert_ne!(result.receipts_root, alloy_trie::EMPTY_ROOT_HASH);

    println!("✅ Receipts root computation test passed");
    println!("   Receipts root: {:?}", result.receipts_root);
}

#[test]
fn test_gas_usage_accuracy() {
    let (mut engine, signer1, signer2) = create_test_engine_with_accounts();

    let addr2 = signer2.address();

    // Test 1: Basic transfer should use exactly 21,000 gas
    let tx1 = create_eip1559_transaction(
        &signer1,
        Eip1559TxParams {
            to: addr2,
            value: U256::from(1_000_000_000_000_000_000u64),
            nonce: 0,
            gas_limit: 21_000,
            max_fee_per_gas: 2_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            data: Bytes::new(),
        },
    );

    let input1 = BlockInput {
        block_number: 1,
        timestamp: 1234567890,
        transactions: vec![tx1],
        parent_hash: alloy_primitives::B256::ZERO,
        gas_limit: 30_000_000,
        base_fee_per_gas: Some(1_000_000_000),
    };

    let result1 = engine.execute_block(input1).unwrap();
    assert_eq!(result1.gas_used, 21_000);
    assert_eq!(result1.receipts[0].gas_used, 21_000);

    println!("✅ Gas usage accuracy test passed");
    println!("   Basic transfer: {} gas", result1.gas_used);
}
