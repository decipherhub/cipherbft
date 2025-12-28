//! Per-account transaction state

use serde::{Deserialize, Serialize};

/// Account state for nonce tracking
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountState {
    /// Current nonce (next expected for execution)
    pub current_nonce: u64,

    /// Highest nonce in pending pool
    pub highest_pending_nonce: u64,

    /// Number of pending transactions
    pub pending_count: usize,

    /// Number of queued transactions
    pub queued_count: usize,
}

impl AccountState {
    /// Create new account state
    pub fn new(current_nonce: u64) -> Self {
        Self {
            current_nonce,
            highest_pending_nonce: current_nonce,
            pending_count: 0,
            queued_count: 0,
        }
    }

    /// Check if transaction would create a nonce gap
    pub fn would_create_gap(&self, tx_nonce: u64, max_gap: u64) -> bool {
        if tx_nonce <= self.current_nonce {
            return false;
        }

        let gap = tx_nonce - self.current_nonce - 1;
        gap > max_gap
    }

    /// Simulate adding a transaction
    pub fn with_transaction(&self, tx_nonce: u64) -> Self {
        let mut new_state = self.clone();

        if tx_nonce == new_state.highest_pending_nonce + 1 {
            // Continuous with pending pool
            new_state.pending_count += 1;
            new_state.highest_pending_nonce = tx_nonce;
        } else if tx_nonce <= new_state.highest_pending_nonce {
            // Already covered
            return new_state;
        } else {
            // Creates a gap - goes to queued
            new_state.queued_count += 1;
        }

        new_state
    }

    /// Total transactions (pending + queued)
    pub fn total_transactions(&self) -> usize {
        self.pending_count + self.queued_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_account() {
        let acc = AccountState::new(100);
        assert_eq!(acc.current_nonce, 100);
        assert_eq!(acc.highest_pending_nonce, 100);
        assert_eq!(acc.pending_count, 0);
        assert_eq!(acc.queued_count, 0);
    }

    #[test]
    fn test_gap_detection() {
        let acc = AccountState::new(100);

        // No gap for nonce 101
        assert!(!acc.would_create_gap(101, 16));

        // No gap within limit
        assert!(!acc.would_create_gap(116, 16)); // gap = 15

        // Gap exceeds limit
        assert!(acc.would_create_gap(117, 16)); // gap = 16
    }

    #[test]
    fn test_with_transaction() {
        let acc = AccountState::new(100);

        let acc = acc.with_transaction(101);
        assert_eq!(acc.pending_count, 1);
        assert_eq!(acc.queued_count, 0);
        assert_eq!(acc.highest_pending_nonce, 101);

        let acc = acc.with_transaction(102);
        assert_eq!(acc.pending_count, 2);
        assert_eq!(acc.highest_pending_nonce, 102);

        let acc = acc.with_transaction(105); // gap
        assert_eq!(acc.pending_count, 2);
        assert_eq!(acc.queued_count, 1);
    }

    #[test]
    fn test_total_transactions() {
        let acc = AccountState::new(100);
        let acc = acc.with_transaction(101);
        let acc = acc.with_transaction(102);
        let acc = acc.with_transaction(105);

        assert_eq!(acc.total_transactions(), 3);
    }
}
