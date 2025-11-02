//! P2P networking layer for CipherBFT.
//!
//! This crate provides peer discovery, message routing, and gossip protocols
//! for validator communication.

#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]

pub mod codec;
pub mod discovery;
pub mod network;
pub mod peer;

pub use network::P2PNetwork;
pub use peer::PeerConnection;
