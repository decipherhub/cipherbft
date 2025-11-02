//! Consensus round type.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Consensus round number.
///
/// Rounds start from 0 and increment when timeouts occur.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
pub struct Round(u32);

impl Round {
    /// Create a new Round.
    pub fn new(value: u32) -> Self {
        Round(value)
    }

    /// Get the round value.
    pub fn value(&self) -> u32 {
        self.0
    }

    /// Get the next round.
    pub fn next(&self) -> Self {
        Round(self.0 + 1)
    }
}

impl fmt::Display for Round {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_creation() {
        let r = Round::new(0);
        assert_eq!(r.value(), 0);
    }

    #[test]
    fn test_round_ordering() {
        let r1 = Round::new(0);
        let r2 = Round::new(1);
        assert!(r1 < r2);
    }

    #[test]
    fn test_round_next() {
        let r1 = Round::new(0);
        let r2 = r1.next();
        assert_eq!(r2.value(), 1);
    }
}
