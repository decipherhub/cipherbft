//! Consensus height type for CipherBFT

use serde::{Deserialize, Serialize};
use std::fmt;

/// Consensus height (block number)
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
pub struct Height(pub u64);

impl Height {
    /// Genesis height
    pub const GENESIS: Self = Self(0);

    /// Create new height
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Get the underlying value
    pub const fn value(&self) -> u64 {
        self.0
    }

    /// Increment height by 1
    pub fn increment(&self) -> Self {
        Self(self.0.saturating_add(1))
    }

    /// Decrement height by 1, returns None at genesis
    pub fn decrement(&self) -> Option<Self> {
        self.0.checked_sub(1).map(Self)
    }
}

impl fmt::Debug for Height {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Height({})", self.0)
    }
}

impl fmt::Display for Height {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u64> for Height {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Height> for u64 {
    fn from(height: Height) -> Self {
        height.0
    }
}

impl std::ops::Add<u64> for Height {
    type Output = Self;

    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0.saturating_add(rhs))
    }
}

impl std::ops::Sub<u64> for Height {
    type Output = Self;

    fn sub(self, rhs: u64) -> Self::Output {
        Self(self.0.saturating_sub(rhs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_height_increment() {
        let h = Height::new(5);
        assert_eq!(h.increment(), Height::new(6));
    }

    #[test]
    fn test_height_decrement() {
        let h = Height::new(5);
        assert_eq!(h.decrement(), Some(Height::new(4)));
        assert_eq!(Height::GENESIS.decrement(), None);
    }

    #[test]
    fn test_height_ordering() {
        assert!(Height::new(1) < Height::new(2));
        assert!(Height::new(10) > Height::new(5));
    }
}
