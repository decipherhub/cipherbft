//! Cryptographic hash type.

use serde::{Deserialize, Serialize};
use std::fmt;

/// 32-byte hash for blocks and transactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Hash([u8; 32]);

impl Hash {
    /// Create a new Hash from bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Hash(bytes)
    }

    /// Get the hash bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Create hash from slice.
    ///
    /// # Errors
    ///
    /// Returns an error if slice length is not 32 bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, HashError> {
        if bytes.len() != 32 {
            return Err(HashError::InvalidLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Hash(arr))
    }
}

impl From<[u8; 32]> for Hash {
    fn from(bytes: [u8; 32]) -> Self {
        Hash(bytes)
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// Hash error type.
#[derive(Debug, thiserror::Error)]
pub enum HashError {
    /// Invalid hash length.
    #[error("Hash must be 32 bytes")]
    InvalidLength,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_creation() {
        let bytes = [0u8; 32];
        let hash = Hash::new(bytes);
        assert_eq!(hash.as_bytes(), &bytes);
    }

    #[test]
    fn test_hash_from_slice() {
        let bytes = vec![0u8; 32];
        let hash = Hash::from_slice(&bytes).unwrap();
        assert_eq!(hash.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_hash_display() {
        let hash = Hash::new([0u8; 32]);
        let display = format!("{}", hash);
        assert_eq!(display.len(), 64); // 32 bytes = 64 hex chars
    }
}
