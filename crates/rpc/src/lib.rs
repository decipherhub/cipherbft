//! JSON-RPC 2.0 server for CipherBFT.
//!
//! This crate provides query endpoints, transaction broadcasting, and
//! WebSocket subscriptions for external clients.

#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]

pub mod handlers;
pub mod server;
pub mod websocket;

pub use server::RPCServer;
