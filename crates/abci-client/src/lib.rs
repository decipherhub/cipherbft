//! ABCI 2.0 client implementation for CipherBFT.
//!
//! This crate provides an async client for communicating with ABCI applications
//! over TCP or Unix domain sockets.

#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]

pub mod client;
pub mod codec;
pub mod transport;

pub use client::ABCIClient;
