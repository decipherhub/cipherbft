//! Key Derivation Function (KDF) implementation
//!
//! Implements scrypt-based key derivation following EIP-2335 specification.
//! Default parameters use N=262144 (2^18) as per EIP-2335 standard.

use serde::{Deserialize, Serialize};

use super::error::{KeystoreError, KeystoreResult};
use crate::secure::SecretBytes;

/// Standard scrypt parameters following EIP-2335 specification
/// N=262144 (2^18) provides strong security for key derivation
pub const SCRYPT_N: u32 = 262144; // 2^18 - EIP-2335 standard
pub const SCRYPT_R: u32 = 8; // block size
pub const SCRYPT_P: u32 = 1; // parallelization
pub const SCRYPT_DKLEN: usize = 32; // derived key length

/// Salt length in bytes
pub const SALT_LENGTH: usize = 32;

/// KDF module for EIP-2335 keystore
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KdfModule {
    /// KDF function identifier (e.g., "scrypt")
    pub function: String,
    /// KDF parameters
    pub params: KdfParams,
    /// Empty message field (required by EIP-2335 schema)
    pub message: String,
}

impl KdfModule {
    /// Create a new scrypt KDF module with standard EIP-2335 parameters
    pub fn new_scrypt(salt: Vec<u8>) -> Self {
        Self {
            function: "scrypt".to_string(),
            params: KdfParams::Scrypt {
                dklen: SCRYPT_DKLEN as u32,
                n: SCRYPT_N,
                r: SCRYPT_R,
                p: SCRYPT_P,
                salt: hex::encode(&salt),
            },
            message: String::new(),
        }
    }

    /// Derive a key from the given passphrase
    pub fn derive_key(&self, passphrase: &str) -> KeystoreResult<SecretBytes> {
        match &self.params {
            KdfParams::Scrypt {
                dklen,
                n,
                r,
                p,
                salt,
            } => {
                let salt_bytes =
                    hex::decode(salt).map_err(|e| KeystoreError::HexError(e.to_string()))?;
                scrypt_derive_key(passphrase, &salt_bytes, *n, *r, *p, *dklen as usize)
            }
        }
    }
}

/// KDF parameters supporting different algorithms
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum KdfParams {
    /// scrypt parameters (EIP-2335 standard)
    Scrypt {
        /// Derived key length in bytes
        dklen: u32,
        /// CPU/memory cost parameter (must be power of 2)
        n: u32,
        /// Block size parameter
        r: u32,
        /// Parallelization parameter
        p: u32,
        /// Salt as hex string
        salt: String,
    },
}

impl KdfParams {
    /// Validate the parameters
    pub fn validate(&self) -> KeystoreResult<()> {
        match self {
            KdfParams::Scrypt {
                dklen,
                n,
                r,
                p,
                salt,
            } => {
                // dklen must be at least 32 bytes
                if *dklen < 32 {
                    return Err(KeystoreError::InvalidKdfParams(
                        "dklen must be at least 32".to_string(),
                    ));
                }
                // n must be a power of 2
                if *n == 0 || (*n & (*n - 1)) != 0 {
                    return Err(KeystoreError::InvalidKdfParams(
                        "n must be a power of 2".to_string(),
                    ));
                }
                // r must be positive
                if *r == 0 {
                    return Err(KeystoreError::InvalidKdfParams(
                        "r must be positive".to_string(),
                    ));
                }
                // p must be positive
                if *p == 0 {
                    return Err(KeystoreError::InvalidKdfParams(
                        "p must be positive".to_string(),
                    ));
                }
                // salt must be valid hex
                hex::decode(salt).map_err(|e| {
                    KeystoreError::InvalidKdfParams(format!("invalid salt hex: {}", e))
                })?;
                Ok(())
            }
        }
    }
}

/// Derive a key using scrypt KDF
///
/// # Arguments
///
/// * `passphrase` - User passphrase
/// * `salt` - Random salt bytes
/// * `n` - CPU/memory cost parameter (must be power of 2)
/// * `r` - Block size parameter
/// * `p` - Parallelization parameter
/// * `dklen` - Desired key length in bytes
///
/// # Returns
///
/// Derived key as SecretBytes
pub fn scrypt_derive_key(
    passphrase: &str,
    salt: &[u8],
    n: u32,
    r: u32,
    p: u32,
    dklen: usize,
) -> KeystoreResult<SecretBytes> {
    // Calculate log_n for scrypt params
    let log_n = (n as f64).log2() as u8;

    let params = scrypt::Params::new(log_n, r, p, dklen)
        .map_err(|e| KeystoreError::InvalidKdfParams(e.to_string()))?;

    let mut output = vec![0u8; dklen];
    scrypt::scrypt(passphrase.as_bytes(), salt, &params, &mut output)
        .map_err(|e| KeystoreError::KdfError(e.to_string()))?;

    Ok(secrecy::SecretBox::new(Box::new(output)))
}

/// Generate a random salt
pub fn generate_salt() -> Vec<u8> {
    use rand::RngCore;
    let mut salt = vec![0u8; SALT_LENGTH];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn test_scrypt_derive_key() {
        let passphrase = "test-passphrase";
        let salt = vec![0xAA; 32];

        let derived = scrypt_derive_key(passphrase, &salt, 16384, 8, 1, 32).unwrap();

        // Verify length
        assert_eq!(derived.expose_secret().len(), 32);

        // Verify determinism - same inputs produce same output
        let derived2 = scrypt_derive_key(passphrase, &salt, 16384, 8, 1, 32).unwrap();
        assert_eq!(derived.expose_secret(), derived2.expose_secret());

        // Verify different passphrase produces different key
        let derived3 = scrypt_derive_key("different", &salt, 16384, 8, 1, 32).unwrap();
        assert_ne!(derived.expose_secret(), derived3.expose_secret());
    }

    #[test]
    fn test_kdf_params_validation() {
        // Valid params
        let params = KdfParams::Scrypt {
            dklen: 32,
            n: 16384,
            r: 8,
            p: 1,
            salt: hex::encode([0xAA; 32]),
        };
        assert!(params.validate().is_ok());

        // Invalid: n not power of 2
        let params = KdfParams::Scrypt {
            dklen: 32,
            n: 12345,
            r: 8,
            p: 1,
            salt: hex::encode([0xAA; 32]),
        };
        assert!(params.validate().is_err());

        // Invalid: dklen too small
        let params = KdfParams::Scrypt {
            dklen: 16,
            n: 16384,
            r: 8,
            p: 1,
            salt: hex::encode([0xAA; 32]),
        };
        assert!(params.validate().is_err());
    }

    #[test]
    fn test_kdf_module_derive() {
        let salt = vec![0xBB; 32];
        let kdf = KdfModule::new_scrypt(salt);

        let key = kdf.derive_key("my-passphrase").unwrap();
        assert_eq!(key.expose_secret().len(), 32);
    }

    #[test]
    fn test_generate_salt() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();

        assert_eq!(salt1.len(), SALT_LENGTH);
        assert_eq!(salt2.len(), SALT_LENGTH);
        // Salts should be different (extremely high probability)
        assert_ne!(salt1, salt2);
    }

    #[test]
    fn test_kdf_module_serialization() {
        let salt = vec![0xCC; 32];
        let kdf = KdfModule::new_scrypt(salt.clone());

        let json = serde_json::to_string(&kdf).unwrap();
        let parsed: KdfModule = serde_json::from_str(&json).unwrap();

        assert_eq!(kdf, parsed);
    }
}
