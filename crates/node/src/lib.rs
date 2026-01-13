//! CipherBFT Node - MVP for DCL testing
//!
//! This crate provides a multi-process node implementation for testing
//! the Data Chain Layer (DCL) with multiple validators communicating
//! via TCP on localhost.

pub mod config;
pub mod execution_bridge;
pub mod network;
pub mod node;
pub mod util;

pub use config::{generate_local_configs, NodeConfig, PeerConfig};
pub use execution_bridge::{create_default_bridge, ExecutionBridge};
pub use node::Node;
