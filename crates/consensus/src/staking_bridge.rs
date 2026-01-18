//! Bridge between the staking precompile and consensus layer.
//!
//! This module provides the integration point for validator set changes
//! triggered by the staking precompile to be reflected in consensus.
//!
//! ## Architecture
//!
//! The staking precompile in the execution layer manages validator registration
//! and stake amounts. However, validators in CipherBFT need two key pairs:
//!
//! 1. **Ed25519** - for Malachite consensus signatures
//! 2. **BLS12-381** - for Data Chain Layer attestations
//!
//! The staking precompile stores BLS keys (used for DCL), while the consensus
//! layer needs Ed25519 keys. This bridge provides:
//!
//! - A trait for querying consensus-ready validator information
//! - Event types for validator set changes
//! - Integration with the `ValidatorSetManager`

use crate::error::ConsensusError;
use crate::validator_set::{ConsensusValidator, ConsensusValidatorSet};

/// Event representing a validator set change.
///
/// These events are emitted by the staking precompile and consumed
/// by the consensus layer to update validator sets at epoch boundaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidatorSetEvent {
    /// A new validator has been registered.
    ValidatorRegistered {
        /// The validator that was registered.
        validator: ConsensusValidator,
        /// The block height at which registration occurred.
        registered_at: u64,
    },

    /// A validator has been marked for exit.
    ValidatorExitRequested {
        /// The address of the validator (ValidatorId as bytes).
        validator_id: [u8; 32],
        /// The epoch at which the exit will take effect.
        exit_epoch: u64,
    },

    /// A validator has been slashed.
    ValidatorSlashed {
        /// The address of the validator.
        validator_id: [u8; 32],
        /// The new voting power after slashing.
        new_voting_power: u64,
        /// The block height at which slashing occurred.
        slashed_at: u64,
    },

    /// A validator's stake has been updated.
    StakeUpdated {
        /// The address of the validator.
        validator_id: [u8; 32],
        /// The new voting power (stake).
        new_voting_power: u64,
    },
}

/// Provider trait for querying consensus validator information.
///
/// Implementations of this trait bridge the gap between the execution layer's
/// staking state and the consensus layer's validator set requirements.
///
/// ## Implementation Notes
///
/// Implementors must handle the key type conversion:
/// - Execution layer stores Ethereum addresses and BLS public keys
/// - Consensus layer needs ValidatorId (Ed25519-derived) and Ed25519 public keys
///
/// The recommended approach is to require validators to register both key types
/// during the registration process, with the Ed25519 key stored alongside
/// the BLS key.
pub trait ConsensusValidatorProvider: Send + Sync {
    /// Get the current validator set for consensus.
    ///
    /// Returns the active validators with their Ed25519 public keys and voting power.
    /// This should exclude validators that are pending exit.
    fn get_active_validator_set(&self) -> Result<ConsensusValidatorSet, ConsensusError>;

    /// Get the validator set for a specific epoch.
    ///
    /// Returns `None` if the epoch's validator set is not available.
    fn get_validator_set_for_epoch(
        &self,
        epoch: u64,
    ) -> Result<Option<ConsensusValidatorSet>, ConsensusError>;

    /// Get the current epoch number.
    fn current_epoch(&self) -> Result<u64, ConsensusError>;

    /// Check if there are pending validator set changes for the next epoch.
    fn has_pending_changes(&self) -> Result<bool, ConsensusError>;

    /// Get the pending validator set for the next epoch (if any changes are pending).
    ///
    /// Returns `None` if no changes are pending (the current set will continue).
    fn get_pending_validator_set(&self) -> Result<Option<ConsensusValidatorSet>, ConsensusError>;
}

/// Observer trait for receiving validator set change notifications.
///
/// Implementors can subscribe to validator set changes and react accordingly.
/// This is primarily used by the `ValidatorSetManager` to track pending changes.
pub trait ValidatorSetObserver: Send + Sync {
    /// Called when a validator set event occurs.
    fn on_validator_event(&self, event: ValidatorSetEvent) -> Result<(), ConsensusError>;

    /// Called at an epoch boundary when the validator set should transition.
    ///
    /// The new epoch number and validator set are provided.
    fn on_epoch_transition(
        &self,
        new_epoch: u64,
        new_validator_set: ConsensusValidatorSet,
    ) -> Result<(), ConsensusError>;
}

/// Epoch transition trigger for coordinating between layers.
///
/// This is used by the execution layer to notify the consensus layer
/// that an epoch boundary has been reached and validator set changes
/// should take effect.
pub trait EpochTransitionTrigger: Send + Sync {
    /// Trigger an epoch transition at the given block height.
    ///
    /// This is called by the execution layer when a block at an epoch
    /// boundary is finalized. The consensus layer should:
    ///
    /// 1. Query the `ConsensusValidatorProvider` for the new validator set
    /// 2. Update the `ValidatorSetManager` with the new set
    /// 3. Notify Malachite of the validator set change
    ///
    /// # Arguments
    ///
    /// * `block_height` - The height of the epoch boundary block
    /// * `new_epoch` - The new epoch number
    ///
    /// # Returns
    ///
    /// The new validator set that is now active.
    fn trigger_epoch_transition(
        &self,
        block_height: u64,
        new_epoch: u64,
    ) -> Result<ConsensusValidatorSet, ConsensusError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbft_crypto::Ed25519KeyPair;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn make_validator(id: u8, power: u64) -> ConsensusValidator {
        let mut rng = StdRng::seed_from_u64(id as u64);
        let keypair = Ed25519KeyPair::generate(&mut rng);
        let validator_id = keypair.validator_id();
        ConsensusValidator::new(validator_id, keypair.public_key, power)
    }

    #[test]
    fn test_validator_set_event_equality() {
        let validator = make_validator(1, 100);
        let event1 = ValidatorSetEvent::ValidatorRegistered {
            validator: validator.clone(),
            registered_at: 100,
        };
        let event2 = ValidatorSetEvent::ValidatorRegistered {
            validator,
            registered_at: 100,
        };
        assert_eq!(event1, event2);
    }

    #[test]
    fn test_validator_slashed_event() {
        let event = ValidatorSetEvent::ValidatorSlashed {
            validator_id: [1u8; 32],
            new_voting_power: 50,
            slashed_at: 200,
        };

        if let ValidatorSetEvent::ValidatorSlashed {
            validator_id,
            new_voting_power,
            slashed_at,
        } = event
        {
            assert_eq!(validator_id, [1u8; 32]);
            assert_eq!(new_voting_power, 50);
            assert_eq!(slashed_at, 200);
        } else {
            panic!("Expected ValidatorSlashed event");
        }
    }
}
