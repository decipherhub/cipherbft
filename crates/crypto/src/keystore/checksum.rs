//! SHA-256 checksum implementation for keystore integrity verification
//!
//! The checksum is computed over: decryption_key[16:32] || ciphertext
//! This ensures that both the correct passphrase was used AND the ciphertext
//! hasn't been tampered with.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::error::{KeystoreError, KeystoreResult};

/// Checksum module for EIP-2335 keystore
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChecksumModule {
    /// Checksum function identifier (e.g., "sha256")
    pub function: String,
    /// Empty params (sha256 has no params)
    pub params: ChecksumParams,
    /// Checksum value as hex string
    pub message: String,
}

impl ChecksumModule {
    /// Create a new SHA-256 checksum module
    pub fn new(checksum: Vec<u8>) -> Self {
        Self {
            function: "sha256".to_string(),
            params: ChecksumParams {},
            message: hex::encode(&checksum),
        }
    }

    /// Get the checksum bytes
    pub fn checksum(&self) -> KeystoreResult<Vec<u8>> {
        hex::decode(&self.message)
            .map_err(|e| KeystoreError::HexError(format!("invalid checksum hex: {}", e)))
    }

    /// Verify the checksum against the provided derived key and ciphertext
    pub fn verify(&self, derived_key: &[u8], ciphertext: &[u8]) -> KeystoreResult<bool> {
        let expected = self.checksum()?;
        let computed = compute_checksum(derived_key, ciphertext)?;
        Ok(constant_time_eq(&expected, &computed))
    }
}

/// Empty params struct for SHA-256 (required by EIP-2335 schema)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ChecksumParams {}

/// Compute checksum over derived_key[16:32] || ciphertext
///
/// # Arguments
///
/// * `derived_key` - The 32-byte key derived from passphrase
/// * `ciphertext` - The encrypted secret data
///
/// # Returns
///
/// 32-byte SHA-256 checksum
pub fn compute_checksum(derived_key: &[u8], ciphertext: &[u8]) -> KeystoreResult<Vec<u8>> {
    if derived_key.len() < 32 {
        return Err(KeystoreError::InvalidKdfParams(format!(
            "derived key must be at least 32 bytes, got {}",
            derived_key.len()
        )));
    }

    let mut hasher = Sha256::new();
    // Use bytes 16-32 of derived key (the "checksum key" portion)
    hasher.update(&derived_key[16..32]);
    hasher.update(ciphertext);

    Ok(hasher.finalize().to_vec())
}

/// Verify checksum matches expected value
///
/// # Arguments
///
/// * `derived_key` - The 32-byte key derived from passphrase
/// * `ciphertext` - The encrypted secret data
/// * `expected` - The expected checksum to verify against
///
/// # Returns
///
/// `Ok(())` if checksum matches, `Err(ChecksumMismatch)` otherwise
pub fn verify_checksum(
    derived_key: &[u8],
    ciphertext: &[u8],
    expected: &[u8],
) -> KeystoreResult<()> {
    let computed = compute_checksum(derived_key, ciphertext)?;

    if constant_time_eq(&computed, expected) {
        Ok(())
    } else {
        Err(KeystoreError::ChecksumMismatch)
    }
}

/// Constant-time comparison to prevent timing attacks
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_checksum() {
        let derived_key = vec![0xAA; 32];
        let ciphertext = vec![0xBB; 32];

        let checksum = compute_checksum(&derived_key, &ciphertext).unwrap();

        // SHA-256 produces 32 bytes
        assert_eq!(checksum.len(), 32);

        // Same inputs produce same checksum
        let checksum2 = compute_checksum(&derived_key, &ciphertext).unwrap();
        assert_eq!(checksum, checksum2);
    }

    #[test]
    fn test_verify_checksum_valid() {
        let derived_key = vec![0xAA; 32];
        let ciphertext = vec![0xBB; 32];

        let checksum = compute_checksum(&derived_key, &ciphertext).unwrap();

        // Verification should succeed
        let result = verify_checksum(&derived_key, &ciphertext, &checksum);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_checksum_invalid() {
        let derived_key = vec![0xAA; 32];
        let ciphertext = vec![0xBB; 32];

        let wrong_checksum = vec![0x00; 32];

        // Verification should fail
        let result = verify_checksum(&derived_key, &ciphertext, &wrong_checksum);
        assert!(matches!(result, Err(KeystoreError::ChecksumMismatch)));
    }

    #[test]
    fn test_checksum_uses_second_half_of_key() {
        let ciphertext = vec![0xCC; 32];

        // Create two keys that differ only in first half
        let mut key1 = vec![0xAA; 32];
        let mut key2 = vec![0xBB; 32];

        // Make second half identical
        key1[16..32].copy_from_slice(&[0xFF; 16]);
        key2[16..32].copy_from_slice(&[0xFF; 16]);

        let checksum1 = compute_checksum(&key1, &ciphertext).unwrap();
        let checksum2 = compute_checksum(&key2, &ciphertext).unwrap();

        // Checksums should be identical (only second half matters)
        assert_eq!(checksum1, checksum2);

        // Now make second half different
        key2[16..32].copy_from_slice(&[0xEE; 16]);
        let checksum3 = compute_checksum(&key2, &ciphertext).unwrap();

        // Checksum should now differ
        assert_ne!(checksum1, checksum3);
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2, 4]));
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2]));
    }

    #[test]
    fn test_checksum_module() {
        let checksum = vec![0xDD; 32];
        let module = ChecksumModule::new(checksum.clone());

        assert_eq!(module.function, "sha256");
        assert_eq!(module.checksum().unwrap(), checksum);
    }

    #[test]
    fn test_checksum_module_serialization() {
        let checksum = vec![0xEE; 32];
        let module = ChecksumModule::new(checksum);

        let json = serde_json::to_string(&module).unwrap();
        let parsed: ChecksumModule = serde_json::from_str(&json).unwrap();

        assert_eq!(module, parsed);
    }

    #[test]
    fn test_checksum_module_verify() {
        let derived_key = vec![0x11; 32];
        let ciphertext = vec![0x22; 32];

        let checksum = compute_checksum(&derived_key, &ciphertext).unwrap();
        let module = ChecksumModule::new(checksum);

        assert!(module.verify(&derived_key, &ciphertext).unwrap());

        // Wrong key should fail verification
        let wrong_key = vec![0x33; 32];
        assert!(!module.verify(&wrong_key, &ciphertext).unwrap());
    }
}
