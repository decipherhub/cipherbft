//! CipherBFT Node - MVP for DCL testing
//!
//! This crate provides a multi-process node implementation for testing
//! the Data Chain Layer (DCL) with multiple validators communicating
//! via TCP on localhost.

pub mod client_config;
pub mod config;
pub mod execution_bridge;
pub mod genesis_bootstrap;
pub mod key_cli;
pub mod network;
pub mod network_api;
pub mod node;
pub mod supervisor;
pub mod sync_executor;
pub mod sync_network;
pub mod sync_runner;
pub mod sync_server;
pub mod util;

pub use client_config::ClientConfig;
pub use config::{
    generate_keypair, generate_local_configs, LocalTestConfig, NodeConfig, PeerConfig, SyncConfig,
    CIPHERD_GENESIS_PATH_ENV, CIPHERD_HOME_ENV, DEFAULT_GENESIS_FILENAME, DEFAULT_HOME_DIR,
    DEFAULT_KEYRING_BACKEND, DEFAULT_KEYS_DIR, DEFAULT_KEY_NAME, DEFAULT_METRICS_PORT,
    DEFAULT_MIN_SYNC_PEERS, DEFAULT_RPC_HTTP_PORT, DEFAULT_RPC_WS_PORT, DEFAULT_SNAP_SYNC_ENABLED,
    DEFAULT_SNAP_SYNC_THRESHOLD, DEFAULT_SYNC_TIMEOUT_SECS,
};
pub use execution_bridge::{create_default_bridge, ExecutionBridge};
pub use genesis_bootstrap::{
    GeneratedValidator, GenesisGenerationResult, GenesisGenerator, GenesisGeneratorConfig,
    GenesisLoader, ValidatorKeyFile,
};
pub use key_cli::{execute_keys_command, KeysCommand};
pub use network_api::{NodeNetworkApi, TcpNetworkApi};
pub use node::Node;
pub use supervisor::{NodeSupervisor, ShutdownError};
pub use sync_executor::ExecutionBridgeSyncExecutor;
pub use sync_network::{create_sync_adapter, wire_sync_to_network, SyncNetworkAdapter};
pub use sync_runner::{create_sync_manager, run_snap_sync, should_snap_sync, SyncResult};
pub use sync_server::SnapSyncServer;
