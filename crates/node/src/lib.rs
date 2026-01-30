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
pub mod util;

pub use client_config::ClientConfig;
pub use config::{
    generate_keypair, generate_local_configs, LocalTestConfig, NodeConfig, PeerConfig,
    CIPHERD_GENESIS_PATH_ENV, CIPHERD_HOME_ENV, DEFAULT_GENESIS_FILENAME, DEFAULT_HOME_DIR,
    DEFAULT_KEYRING_BACKEND, DEFAULT_KEYS_DIR, DEFAULT_KEY_NAME, DEFAULT_METRICS_PORT,
    DEFAULT_RPC_HTTP_PORT, DEFAULT_RPC_WS_PORT,
};
pub use execution_bridge::ExecutionBridge;
pub use genesis_bootstrap::{
    GeneratedValidator, GenesisGenerationResult, GenesisGenerator, GenesisGeneratorConfig,
    GenesisLoader, ValidatorKeyFile,
};
pub use key_cli::{execute_keys_command, KeysCommand};
pub use network_api::{NodeNetworkApi, TcpNetworkApi};
pub use node::Node;
pub use supervisor::{NodeSupervisor, ShutdownError};
