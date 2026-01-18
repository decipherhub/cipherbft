//! CipherBFT JSON-RPC Server
//!
//! Ethereum-compatible JSON-RPC interface using Reth RPC components.
//!
//! # Features
//!
//! - HTTP JSON-RPC server (default port: 8545)
//! - WebSocket server for subscriptions (default port: 8546)
//! - eth_*, web3_*, net_* namespaces
//! - Rate limiting via tower middleware
//! - Prometheus metrics
//!
//! # Example
//!
//! ```ignore
//! use cipherbft_rpc::{RpcServer, RpcConfig};
//!
//! let config = RpcConfig::default();
//! let server = RpcServer::new(config, storage, mempool, executor, network);
//! server.start().await?;
//! ```

pub mod config;
pub mod error;
pub mod eth;
pub mod metrics;
pub mod net;
pub mod pubsub;
pub mod server;
pub mod traits;
pub mod web3;

// Re-export main types
pub use config::RpcConfig;
pub use error::{RpcError, RpcResult};
pub use server::RpcServer;
pub use traits::{BlockNumberOrTag, ExecutionApi, MempoolApi, NetworkApi, RpcStorage, SyncStatus};

// Re-export RPC server traits for method registration
pub use eth::EthRpcServer;
pub use net::NetRpcServer;
pub use pubsub::{EthPubSubApi, EthPubSubRpcServer, SubscriptionKind, SubscriptionManager};
pub use web3::Web3RpcServer;
