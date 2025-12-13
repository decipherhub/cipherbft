//! Data Chain Layer (DCL) for CipherBFT
//!
//! This crate implements Autobahn BFT's Car/Attestation/Cut mechanism with
//! Primary-Worker architecture for high-throughput data availability.
//!
//! # Architecture
//!
//! - **Primary**: Creates and broadcasts Cars, collects attestations, forms Cuts
//! - **Worker**: Batches transactions, disseminates batch data to peer Workers
//!
//! # Key Types
//!
//! - [`Car`]: Certified Available Record - a validator's contribution containing batch digests
//! - [`Attestation`]: Data availability confirmation from a validator
//! - [`AggregatedAttestation`]: BLS-aggregated attestations (f+1 threshold)
//! - [`Cut`]: Snapshot of highest attested Cars for consensus

pub mod attestation;
pub mod batch;
pub mod car;
pub mod cut;
pub mod error;
pub mod messages;

// Sub-modules for Primary and Worker processes
pub mod primary;
pub mod worker;

// Re-exports
pub use attestation::{AggregatedAttestation, Attestation};
pub use batch::{Batch, BatchDigest};
pub use car::Car;
pub use cut::Cut;
pub use error::DclError;
pub use messages::{DclMessage, PrimaryToWorker, WorkerMessage, WorkerToPrimary};
