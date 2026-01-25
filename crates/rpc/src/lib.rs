//! CipherBFT JSON-RPC Server
//!
//! Ethereum-compatible JSON-RPC interface for the CipherBFT network.
//!
//! # Features
//!
//! - **HTTP JSON-RPC server** (default port: 8545)
//! - **WebSocket server** for real-time subscriptions (default port: 8546)
//! - **Standard namespaces**: eth_*, web3_*, net_*
//! - **Rate limiting** per IP with configurable burst
//! - **IP allowlist** for access control
//! - **Prometheus metrics** for monitoring
//!
//! # Architecture
//!
//! The RPC server is built around trait abstractions for backend services:
//!
//! - [`RpcStorage`] - Block and transaction storage queries
//! - [`MempoolApi`] - Transaction submission and pending pool
//! - [`ExecutionApi`] - Contract calls and gas estimation
//! - [`NetworkApi`] - P2P network status
//!
//! # Quick Start
//!
//! ```ignore
//! use std::sync::Arc;
//! use cipherbft_rpc::{RpcServer, RpcConfig, StubRpcStorage, StubMempoolApi, StubExecutionApi, StubNetworkApi};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let config = RpcConfig::with_chain_id(85300);
//!     let storage = Arc::new(StubRpcStorage::default());
//!     let mempool = Arc::new(StubMempoolApi::new());
//!     let executor = Arc::new(StubExecutionApi::new());
//!     let network = Arc::new(StubNetworkApi::new());
//!
//!     let server = RpcServer::new(config, storage, mempool, executor, network);
//!     server.start().await?;
//!     Ok(())
//! }
//! ```
//!
//! # Configuration
//!
//! See [`RpcConfig`] for available configuration options including:
//!
//! - HTTP and WebSocket ports
//! - Rate limiting (requests per second, burst size)
//! - IP allowlist for access control
//! - Maximum connections
//! - Enabled RPC namespaces
//!
//! # Supported RPC Methods
//!
//! ## eth_* namespace
//!
//! ### Chain & Sync
//! - `eth_chainId` - Returns the chain ID
//! - `eth_blockNumber` - Returns the latest block number
//! - `eth_syncing` - Returns sync status
//!
//! ### Block Queries
//! - `eth_getBlockByHash` - Get block by hash
//! - `eth_getBlockByNumber` - Get block by number
//! - `eth_getBlockTransactionCountByHash` - Get transaction count in block by hash
//! - `eth_getBlockTransactionCountByNumber` - Get transaction count in block by number
//!
//! ### Transaction Queries
//! - `eth_getTransactionByHash` - Get transaction by hash
//! - `eth_getTransactionByBlockHashAndIndex` - Get transaction by block hash and index
//! - `eth_getTransactionByBlockNumberAndIndex` - Get transaction by block number and index
//! - `eth_getTransactionReceipt` - Get transaction receipt
//! - `eth_pendingTransactions` - Get all pending transactions
//!
//! ### State Queries
//! - `eth_getBalance` - Get account balance
//! - `eth_getCode` - Get contract code
//! - `eth_getStorageAt` - Get storage slot value
//! - `eth_getTransactionCount` - Get account nonce
//!
//! ### Transaction Submission
//! - `eth_sendRawTransaction` - Submit signed transaction
//! - `eth_call` - Execute read-only contract call
//! - `eth_estimateGas` - Estimate gas for transaction
//!
//! ### Fee Estimation
//! - `eth_gasPrice` - Returns current gas price
//! - `eth_maxPriorityFeePerGas` - Returns suggested priority fee (EIP-1559)
//! - `eth_feeHistory` - Get historical gas information
//!
//! ### Filter API (Polling)
//! - `eth_newFilter` - Create log filter, returns filter ID
//! - `eth_newBlockFilter` - Create block filter, returns filter ID
//! - `eth_newPendingTransactionFilter` - Create pending tx filter
//! - `eth_getFilterChanges` - Poll for filter updates
//! - `eth_getFilterLogs` - Get all logs matching filter
//! - `eth_uninstallFilter` - Remove a filter
//! - `eth_getLogs` - Query event logs (one-shot, no filter ID)
//!
//! ### Node Status
//! - `eth_accounts` - Returns addresses owned by node (empty for external signing)
//! - `eth_coinbase` - Returns validator address (zero if not a validator)
//! - `eth_mining` - Returns mining status (always false for PoS)
//! - `eth_hashrate` - Returns hashrate (always 0 for PoS)
//!
//! ### Uncle Methods (PoS Stubs)
//! - `eth_getUncleByBlockHashAndIndex` - Get uncle by hash (always null in PoS)
//! - `eth_getUncleByBlockNumberAndIndex` - Get uncle by number (always null in PoS)
//! - `eth_getUncleCountByBlockHash` - Get uncle count by hash (always 0 in PoS)
//! - `eth_getUncleCountByBlockNumber` - Get uncle count by number (always 0 in PoS)
//!
//! ### Unsupported Methods
//! - `eth_getProof` - Get account/storage proof (unsupported, returns error)
//! - `eth_createAccessList` - Create access list (unsupported, returns error)
//!
//! ## web3_* namespace
//!
//! - `web3_clientVersion` - Returns client version string
//! - `web3_sha3` - Keccak-256 hash of input
//!
//! ## net_* namespace
//!
//! - `net_version` - Returns network ID
//! - `net_listening` - Returns listening status
//! - `net_peerCount` - Returns peer count
//!
//! ## txpool_* namespace
//!
//! - `txpool_status` - Returns pending and queued transaction counts
//! - `txpool_content` - Returns all transactions in the pool grouped by sender
//! - `txpool_inspect` - Returns a text summary of transactions in the pool
//!
//! ## Subscriptions (WebSocket)
//!
//! - `eth_subscribe("newHeads")` - New block headers
//! - `eth_subscribe("logs", filter)` - New logs matching filter
//! - `eth_subscribe("newPendingTransactions")` - New pending transaction hashes
//! - `eth_subscribe("syncing")` - Sync status changes
//! - `eth_unsubscribe` - Cancel subscription

// Modules
pub mod adapters;
pub mod config;
pub mod error;
pub mod eth;
pub mod filters;
pub mod metrics;
pub mod middleware;
pub mod net;
pub mod pubsub;
pub mod server;
pub mod traits;
pub mod txpool;
pub mod types;
pub mod web3;

// Core types
pub use config::RpcConfig;
pub use error::{RpcError, RpcResult};
pub use server::RpcServer;

// Backend trait abstractions
pub use traits::{BlockNumberOrTag, ExecutionApi, MempoolApi, NetworkApi, RpcStorage, SyncStatus};

// Stub implementations for testing and development
pub use adapters::{StubExecutionApi, StubMempoolApi, StubNetworkApi, StubRpcStorage};

// Real implementations backed by storage
pub use adapters::{EvmExecutionApi, MdbxRpcStorage, PoolMempoolApi, ProviderBasedRpcStorage};

// Block conversion utilities for subscription broadcasting
pub use adapters::storage_block_to_rpc_block;

// Custom RPC types with proper hex serialization
pub use types::RpcBlock;

// RPC server traits (for method registration)
pub use eth::EthRpcServer;
pub use net::NetRpcServer;
pub use txpool::TxPoolRpcServer;
pub use web3::Web3RpcServer;

// TxPool API types
pub use txpool::TxPoolApi;

// Middleware components
pub use middleware::{IpAllowlist, IpRateLimiter, RpcMiddleware};

// Pub/sub subscription types
pub use pubsub::{
    EthPubSubApi, EthPubSubRpcServer, SubscriptionId, SubscriptionKind, SubscriptionManager,
};

// Filter management
pub use filters::{FilterChanges, FilterManager, FilterType, DEFAULT_FILTER_TIMEOUT, MAX_FILTERS};
