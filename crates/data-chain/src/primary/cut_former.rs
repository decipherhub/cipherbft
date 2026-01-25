//! Cut formation logic for Primary
//!
//! Forms Cuts from highest attested Cars for consensus proposals.

use crate::attestation::AggregatedAttestation;
use crate::car::Car;
use crate::cut::Cut;
use crate::error::DclError;
use cipherbft_types::ValidatorId;
use std::collections::HashMap;

/// Cut former - creates Cuts from attested Cars
pub struct CutFormer {
    /// All validators in the network (sorted by ValidatorId)
    validators: Vec<ValidatorId>,
    /// Byzantine tolerance (f)
    f: usize,
    /// Attestation threshold (f+1)
    threshold: usize,
}

impl CutFormer {
    /// Create a new CutFormer
    pub fn new(validators: Vec<ValidatorId>) -> Self {
        let mut validators = validators;
        validators.sort(); // Ensure deterministic ordering

        let n = validators.len();
        let f = (n - 1) / 3;
        let threshold = f + 1;

        Self {
            validators,
            f,
            threshold,
        }
    }

    /// Form a Cut from the highest attested Cars
    ///
    /// # Arguments
    /// * `height` - Consensus height for this Cut
    /// * `attested_cars` - Map of validator -> (highest attested Car, aggregated attestation)
    /// * `last_cut` - Previous finalized Cut (for monotonicity check)
    pub fn form_cut(
        &self,
        height: u64,
        attested_cars: &HashMap<ValidatorId, (Car, AggregatedAttestation)>,
        last_cut: Option<&Cut>,
    ) -> Result<Cut, DclError> {
        let mut cut = Cut::new(height);

        // Add all attested Cars
        for (validator, (car, attestation)) in attested_cars {
            // Verify threshold is met
            if attestation.count() < self.threshold {
                continue; // Skip Cars without enough attestations
            }

            // Check monotonicity
            if let Some(last) = last_cut {
                if let Some(last_car) = last.get_car(validator) {
                    if car.position < last_car.position {
                        return Err(DclError::MonotonicityViolation {
                            validator: *validator,
                            old: last_car.position,
                            new: car.position,
                        });
                    }
                }
            }

            cut.add_car(car.clone(), attestation.clone());
        }

        Ok(cut)
    }

    /// Validate a Cut meets all requirements
    pub fn validate_cut(&self, cut: &Cut, last_cut: Option<&Cut>) -> Result<(), DclError> {
        // 1. Check monotonicity
        if let Some(last) = last_cut {
            if !cut.is_monotonic(last) {
                // Find the violating validator
                for (validator, car) in &cut.cars {
                    if let Some(last_car) = last.cars.get(validator) {
                        if car.position < last_car.position {
                            return Err(DclError::MonotonicityViolation {
                                validator: *validator,
                                old: last_car.position,
                                new: car.position,
                            });
                        }
                    }
                }
            }
        }

        // 2. Check attestation thresholds
        for car in cut.cars.values() {
            let car_hash = car.hash();
            if let Some(att) = cut.get_attestation(&car_hash) {
                if att.count() < self.threshold {
                    return Err(DclError::ThresholdNotMet {
                        got: att.count(),
                        threshold: self.threshold,
                    });
                }
            } else {
                return Err(DclError::ThresholdNotMet {
                    got: 0,
                    threshold: self.threshold,
                });
            }
        }

        Ok(())
    }

    /// Check anti-censorship rule
    ///
    /// Returns Err if more than f validators with available attested Cars are excluded
    pub fn check_anti_censorship(
        &self,
        cut: &Cut,
        available_validators: &[ValidatorId],
    ) -> Result<(), DclError> {
        let excluded_count = available_validators
            .iter()
            .filter(|v| !cut.contains_validator(v))
            .count();

        if excluded_count > self.f {
            return Err(DclError::AntiCensorshipViolation {
                excluded: excluded_count,
                max_allowed: self.f,
            });
        }

        Ok(())
    }

    /// Get validators in deterministic order
    pub fn ordered_validators(&self) -> &[ValidatorId] {
        &self.validators
    }

    /// Get validator count
    pub fn validator_count(&self) -> usize {
        self.validators.len()
    }

    /// Get f (Byzantine tolerance)
    pub fn f(&self) -> usize {
        self.f
    }

    /// Get attestation threshold
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Check if a validator is included
    pub fn contains_validator(&self, validator: &ValidatorId) -> bool {
        self.validators.contains(validator)
    }

    /// Select highest position Car per validator from multiple candidates
    pub fn select_highest_cars(
        &self,
        candidates: &HashMap<ValidatorId, Vec<(Car, AggregatedAttestation)>>,
    ) -> HashMap<ValidatorId, (Car, AggregatedAttestation)> {
        candidates
            .iter()
            .filter_map(|(validator, cars)| {
                // Find highest position Car with sufficient attestations
                cars.iter()
                    .filter(|(_, att)| att.count() >= self.threshold)
                    .max_by_key(|(car, _)| car.position)
                    .map(|(car, att)| (*validator, (car.clone(), att.clone())))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbft_crypto::BlsKeyPair;
    use cipherbft_types::VALIDATOR_ID_SIZE;

    fn make_validators(n: usize) -> Vec<ValidatorId> {
        (0..n)
            .map(|i| ValidatorId::from_bytes([i as u8; VALIDATOR_ID_SIZE]))
            .collect()
    }

    fn make_car_with_attestation(
        validator: ValidatorId,
        position: u64,
        attestation_count: usize,
        validator_count: usize,
    ) -> (Car, AggregatedAttestation) {
        use crate::attestation::Attestation;

        let car = Car::new(validator, position, vec![], None);

        // Generate keypairs for each attester and create proper signed attestations
        let attestations_with_indices: Vec<(Attestation, usize)> = (0..attestation_count)
            .map(|i| {
                let kp = BlsKeyPair::generate(&mut rand::thread_rng());
                let attester_id = ValidatorId::from_bytes([i as u8; VALIDATOR_ID_SIZE]);
                let mut att = Attestation::from_car(&car, attester_id);
                let signing_bytes = att.get_signing_bytes();
                att.signature = kp.sign_attestation(&signing_bytes);
                (att, i)
            })
            .collect();

        // Use proper aggregation instead of dummy signature
        let attestation = AggregatedAttestation::aggregate_with_indices(
            &attestations_with_indices,
            validator_count,
        )
        .expect("aggregation should succeed with valid attestations");

        (car, attestation)
    }

    #[test]
    fn test_form_cut_basic() {
        let validators = make_validators(4);
        let former = CutFormer::new(validators.clone());

        // threshold = 2 for n=4
        let mut attested_cars = HashMap::new();
        let (car, att) = make_car_with_attestation(validators[0], 0, 2, 4);
        attested_cars.insert(validators[0], (car, att));

        let cut = former.form_cut(1, &attested_cars, None).unwrap();
        assert_eq!(cut.validator_count(), 1);
        assert!(cut.contains_validator(&validators[0]));
    }

    #[test]
    fn test_form_cut_skips_insufficient_attestations() {
        let validators = make_validators(4);
        let former = CutFormer::new(validators.clone());

        let mut attested_cars = HashMap::new();

        // Car with sufficient attestations (2)
        let (car1, att1) = make_car_with_attestation(validators[0], 0, 2, 4);
        attested_cars.insert(validators[0], (car1, att1));

        // Car with insufficient attestations (1)
        let (car2, att2) = make_car_with_attestation(validators[1], 0, 1, 4);
        attested_cars.insert(validators[1], (car2, att2));

        let cut = former.form_cut(1, &attested_cars, None).unwrap();
        assert_eq!(cut.validator_count(), 1);
        assert!(cut.contains_validator(&validators[0]));
        assert!(!cut.contains_validator(&validators[1]));
    }

    #[test]
    fn test_monotonicity_violation() {
        let validators = make_validators(4);
        let former = CutFormer::new(validators.clone());

        // Last cut had position 5
        let mut last_cut = Cut::new(1);
        let (car_old, _) = make_car_with_attestation(validators[0], 5, 2, 4);
        last_cut.cars.insert(validators[0], car_old);

        // New cut tries position 3 (going backwards)
        let mut attested_cars = HashMap::new();
        let (car_new, att_new) = make_car_with_attestation(validators[0], 3, 2, 4);
        attested_cars.insert(validators[0], (car_new, att_new));

        let result = former.form_cut(2, &attested_cars, Some(&last_cut));
        assert!(matches!(
            result,
            Err(DclError::MonotonicityViolation { .. })
        ));
    }

    #[test]
    fn test_anti_censorship_pass() {
        let validators = make_validators(4);
        let former = CutFormer::new(validators.clone());

        // f=1 for n=4, so we can exclude at most 1 validator
        let mut cut = Cut::new(1);
        for v in &validators[0..3] {
            let (car, _) = make_car_with_attestation(*v, 0, 2, 4);
            cut.cars.insert(*v, car);
        }

        // 1 validator excluded (validators[3])
        let result = former.check_anti_censorship(&cut, &validators);
        assert!(result.is_ok());
    }

    #[test]
    fn test_anti_censorship_fail() {
        let validators = make_validators(4);
        let former = CutFormer::new(validators.clone());

        // f=1, but we exclude 2 validators
        let mut cut = Cut::new(1);
        for v in &validators[0..2] {
            let (car, _) = make_car_with_attestation(*v, 0, 2, 4);
            cut.cars.insert(*v, car);
        }

        // 2 validators excluded > f
        let result = former.check_anti_censorship(&cut, &validators);
        assert!(matches!(
            result,
            Err(DclError::AntiCensorshipViolation { .. })
        ));
    }

    #[test]
    fn test_select_highest_cars() {
        let validators = make_validators(4);
        let former = CutFormer::new(validators.clone());

        let mut candidates = HashMap::new();

        // Validator 0 has two cars at different positions
        let (car_0_pos_1, att_0_1) = make_car_with_attestation(validators[0], 1, 2, 4);
        let (car_0_pos_5, att_0_5) = make_car_with_attestation(validators[0], 5, 2, 4);
        candidates.insert(
            validators[0],
            vec![(car_0_pos_1, att_0_1), (car_0_pos_5.clone(), att_0_5)],
        );

        let selected = former.select_highest_cars(&candidates);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected.get(&validators[0]).unwrap().0.position, 5);
    }

    #[test]
    fn test_ordered_validators() {
        let validators = vec![
            ValidatorId::from_bytes([5u8; VALIDATOR_ID_SIZE]),
            ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]),
            ValidatorId::from_bytes([3u8; VALIDATOR_ID_SIZE]),
        ];
        let former = CutFormer::new(validators);

        let ordered = former.ordered_validators();
        assert!(ordered[0] < ordered[1]);
        assert!(ordered[1] < ordered[2]);
    }
}
