//! Primary process for DCL
//!
//! The Primary is responsible for:
//! - Receiving batch digests from Workers
//! - Creating and signing Cars
//! - Broadcasting Cars to peer Primaries
//! - Verifying received Cars and generating attestations
//! - Collecting and aggregating attestations
//! - Forming Cuts for consensus
//!
//! # DataChainLayer Implementation
//!
//! The [`PrimaryDcl`] struct provides a synchronous implementation of the
//! [`DataChainLayer`](crate::DataChainLayer) trait for use with Malachite.
//! It wraps the async Primary components and provides a simple interface
//! for consensus integration.

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

use crate::attestation::{AggregatedAttestation, Attestation};
use crate::car::Car;
use crate::cut::Cut;
use crate::error::DclError;
use crate::DataChainLayer;
use cipherbft_crypto::{BlsKeyPair, BlsPublicKey};
use cipherbft_types::{Hash, ValidatorId};
use std::collections::HashMap;

/// Synchronous DCL implementation for Malachite integration
///
/// This struct implements [`DataChainLayer`] and provides a non-async
/// interface suitable for use with Malachite's effect handlers.
///
/// It wraps the core Primary components (Proposer, Core, AttestationCollector,
/// CutFormer) without the async channel infrastructure.
pub struct PrimaryDcl {
    /// Our validator identity
    our_id: ValidatorId,
    /// Core message processor
    core: core::Core,
    /// Attestation collector
    attestation_collector: attestation_collector::AttestationCollector,
    /// Cut former
    cut_former: cut_former::CutFormer,
    /// Internal state
    state: state::PrimaryState,
    /// Validator public keys
    validator_pubkeys: HashMap<ValidatorId, BlsPublicKey>,
    /// Proposer for Car creation
    proposer: proposer::Proposer,
    /// Configuration
    config: PrimaryConfig,
}

impl PrimaryDcl {
    /// Create a new PrimaryDcl instance
    ///
    /// # Arguments
    /// * `our_id` - Our validator ID
    /// * `keypair` - BLS key pair for signing
    /// * `validator_pubkeys` - Map of validator ID to BLS public key
    /// * `config` - Primary configuration
    pub fn new(
        our_id: ValidatorId,
        keypair: BlsKeyPair,
        validator_pubkeys: HashMap<ValidatorId, BlsPublicKey>,
        config: PrimaryConfig,
    ) -> Self {
        let validator_count = validator_pubkeys.len();
        let f = (validator_count - 1) / 3;
        let threshold = f + 1;

        // Create validator indices
        let mut sorted_validators: Vec<_> = validator_pubkeys.keys().cloned().collect();
        sorted_validators.sort();
        let validator_indices: HashMap<ValidatorId, usize> = sorted_validators
            .iter()
            .enumerate()
            .map(|(i, v)| (*v, i))
            .collect();

        // Create proposer
        let proposer =
            proposer::Proposer::new(our_id, keypair.secret_key.clone(), config.max_empty_cars);

        // Create core message processor
        let core = core::Core::new(our_id, keypair.clone(), validator_pubkeys.clone());

        // Create attestation collector
        let attestation_collector = attestation_collector::AttestationCollector::new(
            our_id,
            threshold,
            validator_count,
            validator_indices.clone(),
            config.attestation_timeout_base,
            config.attestation_timeout_max,
        );

        // Create cut former
        let cut_former = cut_former::CutFormer::new(sorted_validators.clone());

        // Create state
        let state = state::PrimaryState::new(our_id, config.equivocation_retention);

        Self {
            our_id,
            core,
            attestation_collector,
            cut_former,
            state,
            validator_pubkeys,
            proposer,
            config,
        }
    }
}

impl DataChainLayer for PrimaryDcl {
    async fn create_car(&mut self) -> Option<Car> {
        let pending_digests = self.state.take_pending_digests();
        let is_empty = pending_digests.is_empty();

        // Check empty car policy
        if is_empty && !self.state.can_create_empty_car(self.config.max_empty_cars) {
            return None;
        }

        let position = self.state.our_position;
        let parent_ref = self.state.last_car_hash;

        match self.proposer.create_car(
            position,
            pending_digests,
            parent_ref,
            self.state.empty_car_count,
        ) {
            Ok(Some(car)) => {
                let car_hash = car.hash();

                // Update our state
                self.state.update_our_position(
                    position + 1,
                    car_hash,
                    car.batch_digests.is_empty(),
                );

                // Add to pending cars
                self.state.add_pending_car(car.clone());

                // Create self-attestation and start collection
                let self_att = self.core.create_attestation(&car);
                self.attestation_collector
                    .start_collection(car.clone(), self_att);

                Some(car)
            }
            Ok(None) => None,
            Err(_) => None,
        }
    }

    async fn process_car(&mut self, car: &Car) -> Result<Option<Attestation>, DclError> {
        // Validate and process via core
        // For now, assume we have all batch data (workers would provide this)
        let has_all_batches = true;

        self.core.handle_car(car, &mut self.state, has_all_batches)
    }

    async fn add_attestation(
        &mut self,
        attestation: Attestation,
    ) -> Result<Option<AggregatedAttestation>, DclError> {
        // Verify attestation
        self.core.verify_attestation(&attestation)?;

        // Add to collector
        match self.attestation_collector.add_attestation(attestation)? {
            Some(aggregated) => {
                // Move car from pending to attested
                if let Some(pending) = self.state.remove_pending_car(&aggregated.car_hash) {
                    self.state.mark_attested(pending.car, aggregated.clone());
                }
                Ok(Some(aggregated))
            }
            None => Ok(None),
        }
    }

    fn highest_attested_car(&self, validator: &ValidatorId) -> Option<&Car> {
        self.state.attested_cars.get(validator).map(|(car, _)| car)
    }

    fn form_cut(&self, height: u64) -> Option<Cut> {
        let attested_cars = self.state.get_attested_cars();
        if attested_cars.is_empty() {
            return None;
        }

        // Use cut former to create Cut
        match self.cut_former.form_cut(height, attested_cars, None) {
            Ok(cut) if !cut.is_empty() => Some(cut),
            _ => None,
        }
    }

    fn attestation_threshold(&self) -> usize {
        let f = (self.validator_pubkeys.len() - 1) / 3;
        f + 1
    }

    fn is_car_attested(&self, car_hash: &Hash) -> bool {
        // Check if any car in attested_cars has this hash
        self.state
            .attested_cars
            .values()
            .any(|(car, _)| car.hash() == *car_hash)
    }

    fn our_id(&self) -> ValidatorId {
        self.our_id
    }
}
