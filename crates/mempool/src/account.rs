//! BFT-specific account validation helpers.
//!
//! Reth keeps full account state inside the pool. We only need minimal checks
//! before delegating to the underlying pool.

use serde::{Deserialize, Serialize};

/// Helper that validates nonce gaps for a single account.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountValidator {
    /// Current executable nonce fetched from the execution layer.
    pub current_nonce: u64,
}

impl AccountValidator {
    /// Construct a validator for a given current nonce.
    pub fn new(current_nonce: u64) -> Self {
        Self { current_nonce }
    }

    /// Returns `true` if the provided transaction nonce exceeds the configured
    /// gap limit (i.e. would be queued indefinitely).
    pub fn exceeds_nonce_gap(&self, tx_nonce: u64, max_gap: u64) -> bool {
        if tx_nonce <= self.current_nonce {
            return false;
        }

        let gap = tx_nonce - self.current_nonce - 1;
        gap > max_gap
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_gap() {
        let validator = AccountValidator::new(100);
        assert!(!validator.exceeds_nonce_gap(101, 16));
    }

    #[test]
    fn test_gap_within_limit() {
        let validator = AccountValidator::new(100);
        assert!(!validator.exceeds_nonce_gap(116, 16));
    }

    #[test]
    fn test_gap_exceeds_limit() {
        let validator = AccountValidator::new(100);
        assert!(validator.exceeds_nonce_gap(117, 16));
    }

    #[test]
    fn test_old_nonce() {
        let validator = AccountValidator::new(100);
        assert!(!validator.exceeds_nonce_gap(98, 16));
    }
}
