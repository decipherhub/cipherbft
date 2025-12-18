//! Primary process for DCL
//!
//! The Primary is responsible for:
//! - Receiving batch digests from Workers
//! - Creating and signing Cars
//! - Broadcasting Cars to peer Primaries
//! - Verifying received Cars and generating attestations
//! - Collecting and aggregating attestations
//! - Forming Cuts for consensus

pub mod attestation_collector;
pub mod config;
pub mod core;
pub mod cut_former;
pub mod proposer;
pub mod runner;
pub mod state;

pub use config::PrimaryConfig;
pub use runner::{Primary, PrimaryEvent, PrimaryHandle, PrimaryNetwork};
pub use state::PrimaryState;
