//! End-to-end test for transaction flow through the RPC server.
//!
//! This test verifies:
//! 1. RPC server starts and accepts connections
//! 2. eth_chainId returns the configured chain ID
//! 3. eth_sendRawTransaction accepts transactions
//! 4. eth_getBalance returns balances
//! 5. net_version returns the network version

use std::sync::Arc;
use std::time::Duration;

use alloy_consensus::{SignableTransaction, TxEip1559};
use alloy_primitives::{Address, Bytes, TxKind, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::HttpClientBuilder;
use jsonrpsee::rpc_params;

use cipherbft_rpc::{
    RpcConfig, RpcServer, StubDebugExecutionApi, StubExecutionApi, StubMempoolApi, StubNetworkApi,
    StubRpcStorage,
};

/// Test private key (well-known test key, do not use in production)
const TEST_PRIVATE_KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// CipherBFT testnet chain ID
const CHAIN_ID: u64 = 85300;

use std::sync::atomic::{AtomicU16, Ordering};

/// Atomic counter for unique port allocation across tests
static PORT_COUNTER: AtomicU16 = AtomicU16::new(0);

/// Helper to find an available port for testing
fn get_test_ports() -> (u16, u16) {
    // Use atomic counter to get unique ports for each test
    let offset = PORT_COUNTER.fetch_add(2, Ordering::SeqCst);
    let base = 19000 + offset;
    (base, base + 1)
}

/// Create a signed EIP-1559 transaction
fn create_signed_transaction(signer: &PrivateKeySigner, to: Address, nonce: u64) -> Bytes {
    let tx = TxEip1559 {
        chain_id: CHAIN_ID,
        nonce,
        gas_limit: 21_000,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 1_000_000_000,
        to: TxKind::Call(to),
        value: U256::from(1_000_000_000_000_000_000u64), // 1 ETH
        access_list: Default::default(),
        input: Bytes::new(),
    };

    let signature = signer.sign_hash_sync(&tx.signature_hash()).unwrap();
    let signed = tx.into_signed(signature);

    // Encode as EIP-1559 transaction (type prefix 0x02)
    let mut encoded = Vec::new();
    encoded.push(0x02);
    signed.rlp_encode(&mut encoded);
    Bytes::from(encoded)
}

/// Start a test RPC server and return the HTTP URL
async fn start_test_server() -> (
    String,
    Arc<
        RpcServer<
            StubRpcStorage,
            StubMempoolApi,
            StubExecutionApi,
            StubNetworkApi,
            StubDebugExecutionApi,
        >,
    >,
) {
    let (http_port, ws_port) = get_test_ports();

    let mut config = RpcConfig::with_chain_id(CHAIN_ID);
    config.http_port = http_port;
    config.ws_port = ws_port;

    let storage = Arc::new(StubRpcStorage::new(CHAIN_ID));
    let mempool = Arc::new(StubMempoolApi::new());
    let executor = Arc::new(StubExecutionApi::new());
    let network = Arc::new(StubNetworkApi::new());
    let debug_executor = Arc::new(StubDebugExecutionApi::new());

    let server = Arc::new(RpcServer::new(
        config,
        storage,
        mempool,
        executor,
        network,
        debug_executor,
    ));
    server.start().await.expect("Failed to start RPC server");

    // Give the server a moment to fully start
    tokio::time::sleep(Duration::from_millis(100)).await;

    let url = format!("http://127.0.0.1:{}", http_port);
    (url, server)
}

/// Test eth_chainId returns the configured chain ID
#[tokio::test]
async fn test_e2e_chain_id() {
    let (url, server) = start_test_server().await;

    let client = HttpClientBuilder::default()
        .request_timeout(Duration::from_secs(10))
        .build(&url)
        .expect("Failed to create HTTP client");

    // Call eth_chainId
    let chain_id: String = client
        .request("eth_chainId", rpc_params![])
        .await
        .expect("eth_chainId failed");

    // Parse hex response
    let chain_id_value = u64::from_str_radix(chain_id.trim_start_matches("0x"), 16)
        .expect("Failed to parse chain ID");

    assert_eq!(chain_id_value, CHAIN_ID);

    server.stop().await.expect("Failed to stop server");
    println!("✅ eth_chainId test passed: chain_id = {}", chain_id_value);
}

/// Test eth_blockNumber returns the current block number
#[tokio::test]
async fn test_e2e_block_number() {
    let (url, server) = start_test_server().await;

    let client = HttpClientBuilder::default()
        .request_timeout(Duration::from_secs(10))
        .build(&url)
        .expect("Failed to create HTTP client");

    // Call eth_blockNumber
    let block_number: String = client
        .request("eth_blockNumber", rpc_params![])
        .await
        .expect("eth_blockNumber failed");

    // Should return hex 0 for stub
    assert!(block_number.starts_with("0x"));

    server.stop().await.expect("Failed to stop server");
    println!("✅ eth_blockNumber test passed: block = {}", block_number);
}

/// Test eth_gasPrice returns a gas price
#[tokio::test]
async fn test_e2e_gas_price() {
    let (url, server) = start_test_server().await;

    let client = HttpClientBuilder::default()
        .request_timeout(Duration::from_secs(10))
        .build(&url)
        .expect("Failed to create HTTP client");

    // Call eth_gasPrice
    let gas_price: String = client
        .request("eth_gasPrice", rpc_params![])
        .await
        .expect("eth_gasPrice failed");

    // Should return a hex value
    assert!(gas_price.starts_with("0x"));

    let gas_price_value = u64::from_str_radix(gas_price.trim_start_matches("0x"), 16)
        .expect("Failed to parse gas price");
    assert!(gas_price_value > 0);

    server.stop().await.expect("Failed to stop server");
    println!(
        "✅ eth_gasPrice test passed: gas_price = {} wei",
        gas_price_value
    );
}

/// Test eth_sendRawTransaction accepts a signed transaction
#[tokio::test]
async fn test_e2e_send_raw_transaction() {
    let (url, server) = start_test_server().await;

    let client = HttpClientBuilder::default()
        .request_timeout(Duration::from_secs(10))
        .build(&url)
        .expect("Failed to create HTTP client");

    // Create a signed transaction
    let signer: PrivateKeySigner = TEST_PRIVATE_KEY
        .parse()
        .expect("Failed to parse private key");
    let to = Address::repeat_byte(0x42);
    let tx_bytes = create_signed_transaction(&signer, to, 0);

    // Send via eth_sendRawTransaction
    let tx_hash: String = client
        .request(
            "eth_sendRawTransaction",
            rpc_params![format!("0x{}", hex::encode(&tx_bytes))],
        )
        .await
        .expect("eth_sendRawTransaction failed");

    // Should return a transaction hash
    assert!(tx_hash.starts_with("0x"));
    assert_eq!(tx_hash.len(), 66); // 0x + 64 hex chars

    server.stop().await.expect("Failed to stop server");
    println!(
        "✅ eth_sendRawTransaction test passed: tx_hash = {}",
        tx_hash
    );
}

/// Test eth_getBalance returns balance for an address
#[tokio::test]
async fn test_e2e_get_balance() {
    let (url, server) = start_test_server().await;

    let client = HttpClientBuilder::default()
        .request_timeout(Duration::from_secs(10))
        .build(&url)
        .expect("Failed to create HTTP client");

    // Query balance for a test address
    let addr = "0x4242424242424242424242424242424242424242";
    let balance: String = client
        .request("eth_getBalance", rpc_params![addr, "latest"])
        .await
        .expect("eth_getBalance failed");

    // Should return hex value (stub returns 0)
    assert!(balance.starts_with("0x"));

    server.stop().await.expect("Failed to stop server");
    println!("✅ eth_getBalance test passed: balance = {}", balance);
}

/// Test net_version returns the network ID
#[tokio::test]
async fn test_e2e_net_version() {
    let (url, server) = start_test_server().await;

    let client = HttpClientBuilder::default()
        .request_timeout(Duration::from_secs(10))
        .build(&url)
        .expect("Failed to create HTTP client");

    // Call net_version
    let version: String = client
        .request("net_version", rpc_params![])
        .await
        .expect("net_version failed");

    // Should return chain ID as string
    let version_num: u64 = version.parse().expect("Failed to parse version");
    assert_eq!(version_num, CHAIN_ID);

    server.stop().await.expect("Failed to stop server");
    println!("✅ net_version test passed: version = {}", version);
}

/// Test web3_clientVersion returns version info
#[tokio::test]
async fn test_e2e_web3_client_version() {
    let (url, server) = start_test_server().await;

    let client = HttpClientBuilder::default()
        .request_timeout(Duration::from_secs(10))
        .build(&url)
        .expect("Failed to create HTTP client");

    // Call web3_clientVersion
    let version: String = client
        .request("web3_clientVersion", rpc_params![])
        .await
        .expect("web3_clientVersion failed");

    // Should contain "CipherBFT"
    assert!(version.contains("CipherBFT"));

    server.stop().await.expect("Failed to stop server");
    println!("✅ web3_clientVersion test passed: {}", version);
}

/// Test net_listening returns listening status
#[tokio::test]
async fn test_e2e_net_listening() {
    let (url, server) = start_test_server().await;

    let client = HttpClientBuilder::default()
        .request_timeout(Duration::from_secs(10))
        .build(&url)
        .expect("Failed to create HTTP client");

    // Call net_listening
    let listening: bool = client
        .request("net_listening", rpc_params![])
        .await
        .expect("net_listening failed");

    assert!(listening);

    server.stop().await.expect("Failed to stop server");
    println!("✅ net_listening test passed: listening = {}", listening);
}

/// Integration test: Full transaction flow simulation
#[tokio::test]
async fn test_e2e_full_transaction_flow() {
    let (url, server) = start_test_server().await;

    let client = HttpClientBuilder::default()
        .request_timeout(Duration::from_secs(10))
        .build(&url)
        .expect("Failed to create HTTP client");

    // Step 1: Check chain ID
    let chain_id: String = client
        .request("eth_chainId", rpc_params![])
        .await
        .expect("eth_chainId failed");
    println!("  Step 1: Chain ID = {}", chain_id);

    // Step 2: Check initial block number
    let block_before: String = client
        .request("eth_blockNumber", rpc_params![])
        .await
        .expect("eth_blockNumber failed");
    println!("  Step 2: Initial block = {}", block_before);

    // Step 3: Get gas price for transaction
    let gas_price: String = client
        .request("eth_gasPrice", rpc_params![])
        .await
        .expect("eth_gasPrice failed");
    println!("  Step 3: Gas price = {}", gas_price);

    // Step 4: Create and send transaction
    let signer: PrivateKeySigner = TEST_PRIVATE_KEY
        .parse()
        .expect("Failed to parse private key");
    let to = Address::repeat_byte(0x42);
    let tx_bytes = create_signed_transaction(&signer, to, 0);

    let tx_hash: String = client
        .request(
            "eth_sendRawTransaction",
            rpc_params![format!("0x{}", hex::encode(&tx_bytes))],
        )
        .await
        .expect("eth_sendRawTransaction failed");
    println!("  Step 4: Transaction submitted = {}", tx_hash);

    // Step 5: Query sender balance
    let sender_balance: String = client
        .request(
            "eth_getBalance",
            rpc_params![format!("{:?}", signer.address()), "latest"],
        )
        .await
        .expect("eth_getBalance failed");
    println!("  Step 5: Sender balance = {}", sender_balance);

    // Step 6: Query recipient balance
    let recipient_balance: String = client
        .request("eth_getBalance", rpc_params![format!("{:?}", to), "latest"])
        .await
        .expect("eth_getBalance failed");
    println!("  Step 6: Recipient balance = {}", recipient_balance);

    server.stop().await.expect("Failed to stop server");
    println!("✅ Full transaction flow test passed!");
}
