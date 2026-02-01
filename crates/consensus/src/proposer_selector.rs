//! Tendermint weighted round-robin proposer selection.
//!
//! Implements the proposer selection algorithm from the Tendermint BFT spec:
//! <https://github.com/tendermint/tendermint/blob/v0.34.x/spec/consensus/proposer-selection.md>

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::types::ConsensusHeight;
use crate::validator_set::{ConsensusAddress, ConsensusValidator, ConsensusValidatorSet};
use informalsystems_malachitebft_core_types::Round;

/// Priority state for a single validator.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorPriority {
    pub address: ConsensusAddress,
    pub voting_power: u64,
    pub priority: i64,
}

/// Manages proposer selection using Tendermint's weighted round-robin algorithm.
///
/// Priority accumulates across heights, ensuring fair proposer distribution
/// proportional to voting power over time.
#[derive(Debug)]
pub struct ProposerSelector {
    /// Current priority state for all validators
    priorities: RwLock<Vec<ValidatorPriority>>,
    /// Total voting power (cached)
    total_voting_power: RwLock<u64>,
    /// Last (height, round) where priorities were synchronized
    last_synced: RwLock<(ConsensusHeight, Round)>,
    /// Proposer from the last advance (for idempotent queries)
    last_proposer: RwLock<Option<ConsensusAddress>>,
}

impl ProposerSelector {
    /// Create a new proposer selector from a validator set.
    ///
    /// All validators start with priority = 0.
    pub fn new(validator_set: &ConsensusValidatorSet, initial_height: ConsensusHeight) -> Self {
        let priorities: Vec<ValidatorPriority> = validator_set
            .as_slice()
            .iter()
            .map(|v| ValidatorPriority {
                address: v.address,
                voting_power: v.voting_power,
                priority: 0,
            })
            .collect();

        let total_voting_power: u64 = priorities.iter().map(|p| p.voting_power).sum();

        Self {
            priorities: RwLock::new(priorities),
            total_voting_power: RwLock::new(total_voting_power),
            last_synced: RwLock::new((initial_height, Round::Nil)),
            last_proposer: RwLock::new(None),
        }
    }

    /// Compute the proposer for a given height and round.
    ///
    /// This method advances the internal priority state to match the target
    /// (height, round) and returns the validator with highest priority.
    ///
    /// **IMPORTANT**: To ensure all nodes agree on the proposer regardless of their
    /// starting point (initial sync vs. running from genesis), advances are computed
    /// from the ABSOLUTE position (genesis height 1, round Nil), not from the node's
    /// `initial_height`. This ensures deterministic proposer selection across all nodes.
    pub fn select_proposer<'a>(
        &self,
        validator_set: &'a ConsensusValidatorSet,
        height: ConsensusHeight,
        round: Round,
    ) -> &'a ConsensusValidator {
        let mut priorities = self.priorities.write();
        let total_power = *self.total_voting_power.read();
        let mut last_synced = self.last_synced.write();
        let mut last_proposer = self.last_proposer.write();

        let (last_height, last_round) = *last_synced;

        // Calculate total advances needed from last synced point to (height, round).
        // If this is the first call (last_synced is at initial_height with Nil round),
        // we compute advances from GENESIS (height 1, Nil) to ensure all nodes get
        // the same result regardless of their starting height.
        let advances = if last_round == Round::Nil && last_proposer.is_none() {
            // First call: compute absolute advances from genesis
            Self::compute_advances(ConsensusHeight(1), Round::Nil, height, round)
        } else {
            // Subsequent calls: compute relative advances from last synced point
            Self::compute_advances(last_height, last_round, height, round)
        };

        // Track the proposer from advances (the proposer is determined DURING advance,
        // not after, because advance_one_round penalizes the proposer)
        let mut proposer_addr = None;
        for _ in 0..advances {
            proposer_addr = Self::advance_one_round(&mut priorities, total_power);
        }

        // If no advances needed, use the cached last_proposer (idempotent query)
        let proposer_addr = if advances == 0 {
            last_proposer.expect("last_proposer should be set after first advance")
        } else {
            let addr = proposer_addr.expect("should have proposer after advances");
            *last_proposer = Some(addr);
            addr
        };

        // Update sync point
        *last_synced = (height, round);

        // Return reference from the validator set
        validator_set
            .as_slice()
            .iter()
            .find(|v| v.address == proposer_addr)
            .expect("proposer must be in validator set")
    }

    /// Compute number of round advances needed from (from_height, from_round) to (to_height, to_round).
    ///
    /// Each (height, round) pair represents a unique proposer selection slot.
    /// Round::Nil (-1) represents "before any round at this height".
    pub(crate) fn compute_advances(
        from_height: ConsensusHeight,
        from_round: Round,
        to_height: ConsensusHeight,
        to_round: Round,
    ) -> u64 {
        let from_h = from_height.0;
        let to_h = to_height.0;
        // Round::Nil is -1; treat it as "before round 0" so that round 0 triggers an advance
        let from_r = from_round.as_i64(); // Can be -1 for Nil
        let to_r = to_round.as_i64().max(0); // Target is always >= 0

        if to_h < from_h {
            // Going backwards in height - shouldn't happen in normal operation
            return 0;
        }

        if to_h == from_h {
            // Same height: advance for round difference
            // from_r can be -1 (Nil), to_r >= 0
            // Examples:
            //   from_r=-1, to_r=0 → 1 advance
            //   from_r=0, to_r=0 → 0 advances (same slot)
            //   from_r=0, to_r=1 → 1 advance
            if to_r <= from_r {
                return 0;
            }
            // Both are i64, safe to subtract when to_r > from_r
            return (to_r - from_r) as u64;
        }

        // Different heights:
        // Each height transition counts as one advance, plus any rounds within the target height.
        // Example: (1,0) -> (2,0) = 1 advance, (1,0) -> (2,1) = 2 advances, (1,0) -> (3,0) = 2 advances
        //
        // IMPORTANT: When starting from Round::Nil, we need to add 1 for the "unspent" round 0
        // at the source height. Nil means "before any round", so we need to advance once to get
        // to round 0 at from_h before we can advance to the next height.
        // Example: (1,Nil) -> (2,0) = 2 advances, NOT 1!
        let height_diff = to_h - from_h;
        let nil_adjustment = if from_r < 0 { 1 } else { 0 };
        height_diff + (to_r as u64) + nil_adjustment
    }

    /// Single round advancement of the Tendermint algorithm.
    /// Returns the proposer address for this round.
    fn advance_one_round(
        priorities: &mut [ValidatorPriority],
        total_power: u64,
    ) -> Option<ConsensusAddress> {
        if priorities.is_empty() || total_power == 0 {
            return None;
        }

        // Step 1: Increase all priorities by their voting power
        for p in priorities.iter_mut() {
            p.priority = p.priority.saturating_add(p.voting_power as i64);
        }

        // Step 2: Find proposer (max priority, tie-break by smallest address per Tendermint spec)
        // When priorities are equal, choose the validator with the lexicographically smallest address.
        // This matches CometBFT behavior and ensures consistency with simple round-robin.
        let proposer_idx = priorities
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| {
                a.priority
                    .cmp(&b.priority)
                    // Reverse address comparison: prefer smaller address when priorities tie
                    .then_with(|| b.address.cmp(&a.address))
            })
            .map(|(idx, _)| idx)
            .unwrap();

        let proposer_addr = priorities[proposer_idx].address;

        // Step 3: Decrease proposer's priority by total voting power
        priorities[proposer_idx].priority = priorities[proposer_idx]
            .priority
            .saturating_sub(total_power as i64);

        Some(proposer_addr)
    }

    /// Center priorities around zero to prevent overflow.
    pub fn center_priorities(&self) {
        let mut priorities = self.priorities.write();
        if priorities.is_empty() {
            return;
        }

        let sum: i64 = priorities.iter().map(|p| p.priority).sum();
        let avg = sum / priorities.len() as i64;

        for p in priorities.iter_mut() {
            p.priority = p.priority.saturating_sub(avg);
        }
    }

    /// Scale priorities if range exceeds 2 * total_voting_power.
    pub fn scale_if_needed(&self) {
        let mut priorities = self.priorities.write();
        let total_power = *self.total_voting_power.read();

        if priorities.is_empty() || total_power == 0 {
            return;
        }

        let limit = 2 * total_power as i64;
        let min = priorities.iter().map(|p| p.priority).min().unwrap_or(0);
        let max = priorities.iter().map(|p| p.priority).max().unwrap_or(0);
        let range = max.saturating_sub(min);

        if range > limit {
            let scale = limit as f64 / range as f64;
            for p in priorities.iter_mut() {
                p.priority = (p.priority as f64 * scale) as i64;
            }
        }
    }

    /// Handle validator set changes at epoch boundaries.
    pub fn update_validator_set(&self, new_validator_set: &ConsensusValidatorSet) {
        let mut priorities = self.priorities.write();
        let mut total_power = self.total_voting_power.write();

        let old_total = *total_power;
        let new_total: u64 = new_validator_set
            .as_slice()
            .iter()
            .map(|v| v.voting_power)
            .sum();

        let mut new_priorities = Vec::with_capacity(new_validator_set.len());

        for validator in new_validator_set.as_slice() {
            let existing = priorities.iter().find(|p| p.address == validator.address);

            let priority = if let Some(existing) = existing {
                // Scale existing priority for power ratio change
                if old_total > 0 {
                    let scale = new_total as f64 / old_total as f64;
                    (existing.priority as f64 * scale) as i64
                } else {
                    existing.priority
                }
            } else {
                // New validator: penalty to prevent gaming
                (-1.125 * new_total as f64) as i64
            };

            new_priorities.push(ValidatorPriority {
                address: validator.address,
                voting_power: validator.voting_power,
                priority,
            });
        }

        *priorities = new_priorities;
        *total_power = new_total;

        // Center and scale after update (must release locks first)
        drop(priorities);
        drop(total_power);
        self.center_priorities();
        self.scale_if_needed();
    }
}

impl Clone for ProposerSelector {
    fn clone(&self) -> Self {
        Self {
            priorities: RwLock::new(self.priorities.read().clone()),
            total_voting_power: RwLock::new(*self.total_voting_power.read()),
            last_synced: RwLock::new(*self.last_synced.read()),
            last_proposer: RwLock::new(*self.last_proposer.read()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbft_crypto::ed25519::{Ed25519KeyPair, Ed25519SecretKey};

    fn make_validator(id: u8, power: u64) -> ConsensusValidator {
        // Use deterministic seed for reproducible tests
        let mut seed = [0u8; 32];
        seed[0] = id;
        let secret_key = Ed25519SecretKey::from_seed(&seed);
        let keypair = Ed25519KeyPair::from_secret_key(secret_key);
        ConsensusValidator::new(keypair.validator_id(), keypair.public_key, power)
    }

    fn make_validator_set(powers: &[u64]) -> ConsensusValidatorSet {
        let validators: Vec<ConsensusValidator> = powers
            .iter()
            .enumerate()
            .map(|(i, &power)| make_validator(i as u8, power))
            .collect();
        ConsensusValidatorSet::new(validators)
    }

    #[test]
    fn test_equal_power_rotation() {
        // 3 validators with equal power should rotate
        let vs = make_validator_set(&[100, 100, 100]);
        let selector = ProposerSelector::new(&vs, ConsensusHeight(1));

        let validators: Vec<_> = vs.as_slice().to_vec();
        let mut proposer_counts = [0usize; 3];

        for h in 1..=6 {
            let proposer = selector.select_proposer(&vs, ConsensusHeight(h), Round::new(0));
            for (i, v) in validators.iter().enumerate() {
                if proposer.address == v.address {
                    proposer_counts[i] += 1;
                    break;
                }
            }
        }

        // Each validator should propose twice in 6 heights
        assert_eq!(proposer_counts[0], 2, "Validator 0 should propose 2 times");
        assert_eq!(proposer_counts[1], 2, "Validator 1 should propose 2 times");
        assert_eq!(proposer_counts[2], 2, "Validator 2 should propose 2 times");
    }

    #[test]
    fn test_weighted_selection() {
        // Validator 0 has 2x power, should propose 2x as often
        let vs = make_validator_set(&[200, 100, 100]);
        let selector = ProposerSelector::new(&vs, ConsensusHeight(1));

        let validators: Vec<_> = vs.as_slice().to_vec();
        // Find which validator has 200 power (it gets sorted by power descending)
        let high_power_addr = validators
            .iter()
            .find(|v| v.voting_power == 200)
            .unwrap()
            .address;

        let mut high_power_count = 0;
        for h in 1..=8 {
            let proposer = selector.select_proposer(&vs, ConsensusHeight(h), Round::new(0));
            if proposer.address == high_power_addr {
                high_power_count += 1;
            }
        }

        // Over 8 rounds with total power 400:
        // High power (200): should propose ~4 times
        assert!(
            high_power_count >= 3,
            "High power validator should propose more, got {}",
            high_power_count
        );
    }

    #[test]
    fn test_single_validator() {
        let vs = make_validator_set(&[100]);
        let selector = ProposerSelector::new(&vs, ConsensusHeight(1));
        let single_addr = vs.as_slice()[0].address;

        for h in 1..=5 {
            let proposer = selector.select_proposer(&vs, ConsensusHeight(h), Round::new(0));
            assert_eq!(proposer.address, single_addr);
        }
    }

    #[test]
    fn test_round_advancement() {
        let vs = make_validator_set(&[100, 100]);
        let selector = ProposerSelector::new(&vs, ConsensusHeight(1));

        // Height 1, Round 0
        let p1 = selector.select_proposer(&vs, ConsensusHeight(1), Round::new(0));
        // Height 1, Round 1 (should be different)
        let p2 = selector.select_proposer(&vs, ConsensusHeight(1), Round::new(1));

        assert_ne!(p1.address, p2.address);
    }

    #[test]
    fn test_idempotent_same_height_round() {
        // Calling select_proposer multiple times for the same (height, round) should return same result
        let vs = make_validator_set(&[100, 100, 100]);
        let selector = ProposerSelector::new(&vs, ConsensusHeight(1));

        let p1 = selector.select_proposer(&vs, ConsensusHeight(5), Round::new(2));
        let p2 = selector.select_proposer(&vs, ConsensusHeight(5), Round::new(2));

        assert_eq!(p1.address, p2.address);
    }

    #[test]
    fn test_skip_heights_from_nil_matches_sequential() {
        // CRITICAL: A validator that skips from (1, Nil) directly to (H, 0)
        // must get the same proposer as one that goes through each height sequentially.
        // This ensures consensus doesn't stall due to proposer disagreement.
        let vs = make_validator_set(&[100, 100, 100]);

        // Validator A: goes through each height sequentially
        let selector_a = ProposerSelector::new(&vs, ConsensusHeight(1));
        selector_a.select_proposer(&vs, ConsensusHeight(1), Round::new(0));
        selector_a.select_proposer(&vs, ConsensusHeight(2), Round::new(0));
        selector_a.select_proposer(&vs, ConsensusHeight(3), Round::new(0));
        selector_a.select_proposer(&vs, ConsensusHeight(4), Round::new(0));
        let prop_5_sequential = selector_a.select_proposer(&vs, ConsensusHeight(5), Round::new(0));

        // Validator B: skips directly from Nil to height 5
        let selector_b = ProposerSelector::new(&vs, ConsensusHeight(1));
        let prop_5_skipped = selector_b.select_proposer(&vs, ConsensusHeight(5), Round::new(0));

        // Both must agree on the proposer for height 5!
        assert_eq!(
            prop_5_sequential.address, prop_5_skipped.address,
            "Validators must agree on proposer regardless of whether heights were skipped"
        );
    }

    #[test]
    fn test_compute_advances_from_nil_across_heights() {
        // Verify the compute_advances formula handles Nil correctly when crossing heights
        // From (1, Nil) to (2, 0) should be 2 advances:
        //   1. Advance for (1, 0)
        //   2. Advance for (2, 0)
        let advances = ProposerSelector::compute_advances(
            ConsensusHeight(1),
            Round::Nil,
            ConsensusHeight(2),
            Round::new(0),
        );
        assert_eq!(advances, 2, "(1, Nil) -> (2, 0) should be 2 advances");

        // From (1, Nil) to (5, 0) should be 5 advances
        let advances = ProposerSelector::compute_advances(
            ConsensusHeight(1),
            Round::Nil,
            ConsensusHeight(5),
            Round::new(0),
        );
        assert_eq!(advances, 5, "(1, Nil) -> (5, 0) should be 5 advances");

        // From (1, 0) to (5, 0) should be 4 advances (no Nil adjustment)
        let advances = ProposerSelector::compute_advances(
            ConsensusHeight(1),
            Round::new(0),
            ConsensusHeight(5),
            Round::new(0),
        );
        assert_eq!(advances, 4, "(1, 0) -> (5, 0) should be 4 advances");
    }

    #[test]
    fn test_different_initial_heights_agree_on_proposer() {
        // CRITICAL: Nodes that start at different initial heights (e.g., after syncing)
        // MUST agree on the proposer for the same (height, round).
        // This is the root cause of consensus stalls when nodes disagree on proposer.
        let vs = make_validator_set(&[100, 100, 100]);

        // Node A: started from genesis (height 1)
        let selector_from_genesis = ProposerSelector::new(&vs, ConsensusHeight(1));

        // Node B: synced and started at height 34 (simulating a node that joined later)
        let selector_synced = ProposerSelector::new(&vs, ConsensusHeight(34));

        // Both query for the proposer at height 34, round 6
        let proposer_genesis =
            selector_from_genesis.select_proposer(&vs, ConsensusHeight(34), Round::new(6));
        let proposer_synced =
            selector_synced.select_proposer(&vs, ConsensusHeight(34), Round::new(6));

        assert_eq!(
            proposer_genesis.address, proposer_synced.address,
            "Nodes starting at different heights MUST agree on the proposer for the same (height, round)"
        );
    }

    #[test]
    fn test_synced_node_continues_correctly() {
        // After initial query, synced node should continue correctly for subsequent rounds
        let vs = make_validator_set(&[100, 100, 100]);

        // Genesis node goes through all heights
        let selector_genesis = ProposerSelector::new(&vs, ConsensusHeight(1));
        for h in 1..34 {
            selector_genesis.select_proposer(&vs, ConsensusHeight(h), Round::new(0));
        }
        let gen_h34_r0 = selector_genesis.select_proposer(&vs, ConsensusHeight(34), Round::new(0));
        let gen_h34_r1 = selector_genesis.select_proposer(&vs, ConsensusHeight(34), Round::new(1));
        let gen_h34_r2 = selector_genesis.select_proposer(&vs, ConsensusHeight(34), Round::new(2));

        // Synced node starts at height 34
        let selector_synced = ProposerSelector::new(&vs, ConsensusHeight(34));
        let sync_h34_r0 = selector_synced.select_proposer(&vs, ConsensusHeight(34), Round::new(0));
        let sync_h34_r1 = selector_synced.select_proposer(&vs, ConsensusHeight(34), Round::new(1));
        let sync_h34_r2 = selector_synced.select_proposer(&vs, ConsensusHeight(34), Round::new(2));

        assert_eq!(
            gen_h34_r0.address, sync_h34_r0.address,
            "Must agree on round 0"
        );
        assert_eq!(
            gen_h34_r1.address, sync_h34_r1.address,
            "Must agree on round 1"
        );
        assert_eq!(
            gen_h34_r2.address, sync_h34_r2.address,
            "Must agree on round 2"
        );
    }

    #[test]
    fn test_weighted_matches_simple_round_robin_for_equal_power() {
        // CRITICAL: With equal voting power, weighted round-robin MUST produce the same
        // proposer sequence as simple round-robin (round % validator_count).
        // This ensures backwards compatibility when switching algorithms.
        let vs = make_validator_set(&[100, 100, 100, 100]);
        let selector = ProposerSelector::new(&vs, ConsensusHeight(1));

        // The validator set is sorted by (power desc, address asc).
        // For equal power, the sorted order is by address ascending.
        let validators: Vec<_> = vs.as_slice().to_vec();

        // For the first few rounds at height 1, verify rotation matches simple RR
        for round in 0..4u32 {
            let expected_idx = round as usize % validators.len();
            let expected_addr = validators[expected_idx].address;

            let actual = selector.select_proposer(&vs, ConsensusHeight(1), Round::new(round));

            assert_eq!(
                actual.address, expected_addr,
                "Round {} should select validator at index {} (simple round-robin)",
                round, expected_idx
            );
        }
    }

    #[test]
    fn test_tie_break_chooses_smallest_address() {
        // Per Tendermint spec: when priorities are equal, choose the validator
        // with the lexicographically smallest address.
        let vs = make_validator_set(&[100, 100]);
        let selector = ProposerSelector::new(&vs, ConsensusHeight(1));

        // With 2 validators of equal power, first proposer should have smallest address
        let first_proposer = selector.select_proposer(&vs, ConsensusHeight(1), Round::new(0));

        // Get the validator with smallest address from the set
        let smallest_addr = vs.as_slice().iter().map(|v| v.address).min().unwrap();

        assert_eq!(
            first_proposer.address, smallest_addr,
            "First proposer should be the validator with smallest address (tie-break rule)"
        );
    }
}
