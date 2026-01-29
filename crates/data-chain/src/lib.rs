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
//!
//! # DataChainLayer Trait
//!
//! The [`DataChainLayer`] trait defines the core DCL interface for Malachite integration.
//! It provides methods for:
//! - Creating and processing Cars
//! - Managing attestations
//! - Forming Cuts for consensus proposals

pub mod attestation;
pub mod batch;
pub mod car;
pub mod cut;
pub mod error;
pub mod messages;
pub mod storage;

// Sub-modules for Primary and Worker processes
pub mod primary;
pub mod worker;

// Re-exports
pub use attestation::{AggregatedAttestation, Attestation};
pub use batch::{Batch, BatchDigest};
pub use car::Car;
pub use cut::{Cut, CutAssembler, CutAssemblyError, CutPart};
pub use error::DclError;
pub use messages::{DclMessage, PrimaryToWorker, WorkerMessage, WorkerToPrimary};
pub use primary::PrimaryDcl;
pub use storage::{BatchStore, CarStore, CutStore, DclStorage};

use cipherbft_types::{Hash, ValidatorId};

/// Data Chain Layer trait for Malachite integration (per ADR-001)
///
/// This trait defines the interface that the consensus layer (Malachite) uses
/// to interact with the data chain layer. It abstracts the Primary process
/// operations for:
/// - Car creation and validation
/// - Attestation collection
/// - Cut formation for consensus proposals
///
/// # Implementors
///
/// - [`primary::Primary`]: The main implementation using async channels
#[allow(async_fn_in_trait)]
pub trait DataChainLayer {
    /// Create a new Car from pending batch digests
    ///
    /// This is called by the Primary process when it's time to propose new data.
    /// The Car will include all pending batch digests from Workers.
    ///
    /// # Returns
    /// - `Some(Car)` if a Car was created
    /// - `None` if no Car can be created (e.g., empty car limit reached)
    async fn create_car(&mut self) -> Option<Car>;

    /// Process a received Car from another validator
    ///
    /// Validates the Car and optionally creates an attestation if:
    /// 1. The Car signature is valid
    /// 2. The Car is monotonic (position >= last seen)
    /// 3. All batch data is available locally
    ///
    /// # Arguments
    /// * `car` - The Car to process
    ///
    /// # Returns
    /// - `Ok(Some(Attestation))` if the Car is valid and we created an attestation
    /// - `Ok(None)` if the Car is valid but we're missing batch data
    /// - `Err(DclError)` if the Car is invalid
    async fn process_car(&mut self, car: &Car) -> Result<Option<Attestation>, DclError>;

    /// Add a received attestation
    ///
    /// Collects attestations for Cars we proposed. When f+1 attestations
    /// (including our self-attestation) are collected, the Car becomes
    /// eligible for Cut inclusion.
    ///
    /// # Arguments
    /// * `attestation` - The attestation to add
    ///
    /// # Returns
    /// - `Ok(Some(AggregatedAttestation))` if threshold reached
    /// - `Ok(None)` if more attestations needed
    /// - `Err(DclError)` if attestation is invalid
    async fn add_attestation(
        &mut self,
        attestation: Attestation,
    ) -> Result<Option<AggregatedAttestation>, DclError>;

    /// Get the highest attested Car for a validator
    ///
    /// Returns the most recent Car from the validator that has
    /// received f+1 attestations.
    ///
    /// # Arguments
    /// * `validator` - The validator ID
    fn highest_attested_car(&self, validator: &ValidatorId) -> Option<&Car>;

    /// Form a Cut for consensus proposal
    ///
    /// Creates a Cut containing the highest attested Car from each validator
    /// that has one available. The Cut is used as the consensus value.
    ///
    /// # Arguments
    /// * `height` - The consensus height for this Cut
    ///
    /// # Returns
    /// - `Some(Cut)` if at least one attested Car is available
    /// - `None` if no attested Cars are available
    fn form_cut(&self, height: u64) -> Option<Cut>;

    /// Get the attestation threshold (2f+1)
    ///
    /// Returns the number of attestations required for a Car to be
    /// considered valid for Cut inclusion. This is 2f+1 (quorum) where f is
    /// the maximum number of Byzantine validators. Requiring quorum ensures
    /// that a majority of honest validators have synced the Car's batches
    /// before consensus decides on it.
    fn attestation_threshold(&self) -> usize;

    /// Check if a Car has sufficient attestations
    ///
    /// # Arguments
    /// * `car_hash` - Hash of the Car to check
    fn is_car_attested(&self, car_hash: &Hash) -> bool;

    /// Get our validator ID
    fn our_id(&self) -> ValidatorId;
}
