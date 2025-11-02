//! Block height type.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Block height in the blockchain.
///
/// Heights start from 1 and increment sequentially.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Height(u64);

impl Height {
    /// Create a new Height.
    ///
    /// # Errors
    ///
    /// Returns an error if the height is 0 (heights must be >= 1).
    pub fn new(value: u64) -> Result<Self, HeightError> {
        if value == 0 {
            return Err(HeightError::InvalidHeight);
        }
        Ok(Height(value))
    }

    /// Get the height value.
    pub fn value(&self) -> u64 {
        self.0
    }

    /// Get the next height.
    pub fn next(&self) -> Self {
        Height(self.0 + 1)
    }
}

impl fmt::Display for Height {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Height error type.
#[derive(Debug, thiserror::Error)]
pub enum HeightError {
    /// Height cannot be zero.
    #[error("Height must be >= 1")]
    InvalidHeight,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_height_validation() {
        assert!(Height::new(0).is_err());
        assert!(Height::new(1).is_ok());
        assert_eq!(Height::new(1).unwrap().value(), 1);
    }

    #[test]
    fn test_height_ordering() {
        let h1 = Height::new(1).unwrap();
        let h2 = Height::new(2).unwrap();
        assert!(h1 < h2);
    }

    #[test]
    fn test_height_next() {
        let h1 = Height::new(1).unwrap();
        let h2 = h1.next();
        assert_eq!(h2.value(), 2);
    }
}
