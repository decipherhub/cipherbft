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
//! - `eth_chainId` - Returns the chain ID
//! - `eth_blockNumber` - Returns the latest block number
//! - `eth_syncing` - Returns sync status
//! - `eth_getBlockByHash` - Get block by hash
//! - `eth_getBlockByNumber` - Get block by number
//! - `eth_getBalance` - Get account balance
//! - `eth_getCode` - Get contract code
//! - `eth_getStorageAt` - Get storage slot value
//! - `eth_getTransactionCount` - Get account nonce
//! - `eth_getTransactionByHash` - Get transaction by hash
//! - `eth_getTransactionReceipt` - Get transaction receipt
//! - `eth_sendRawTransaction` - Submit signed transaction
//! - `eth_call` - Execute read-only contract call
//! - `eth_estimateGas` - Estimate gas for transaction
//! - `eth_getLogs` - Query event logs
//! - `eth_feeHistory` - Get historical gas information
//! - `eth_pendingTransactions` - Get all pending transactions
//! - `eth_getUncleByBlockHashAndIndex` - Get uncle by hash (always null in PoS)
//! - `eth_getUncleByBlockNumberAndIndex` - Get uncle by number (always null in PoS)
//! - `eth_getUncleCountByBlockHash` - Get uncle count by hash (always 0 in PoS)
//! - `eth_getUncleCountByBlockNumber` - Get uncle count by number (always 0 in PoS)
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
