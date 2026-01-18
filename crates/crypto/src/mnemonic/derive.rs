//! Key derivation from mnemonic phrases
//!
//! Implements hierarchical deterministic (HD) key derivation for CipherBFT validators
//! using a BLS12-381 compatible path structure.

use super::error::{MnemonicError, MnemonicResult};
use super::generate::Mnemonic;
use crate::bls::{BlsKeyPair, BlsSecretKey};
use crate::ed25519::{Ed25519KeyPair, Ed25519SecretKey};
use crate::keys::ValidatorKeys;
use crate::secure::DerivationInfo;
use sha2::{Digest, Sha256};

/// CipherBFT coin type for BIP-44 style derivation
///
/// Uses 8888 as a placeholder. In production, this should be registered
/// with SLIP-0044 if the project becomes widely adopted.
pub const CIPHERBFT_COIN_TYPE: u32 = 8888;

/// BLS curve identifier (from EIP-2333)
pub const BLS_CURVE_ID: u32 = 12381;

/// Default derivation path for Ed25519 (consensus) keys
/// Format: m/12381/8888/{account}/0
pub const DEFAULT_DERIVATION_PATH_ED25519: &str = "m/12381/8888/0/0";

/// Default derivation path for BLS (data chain) keys
/// Format: m/12381/8888/{account}/1
pub const DEFAULT_DERIVATION_PATH_BLS: &str = "m/12381/8888/0/1";

/// Configuration for key derivation
#[derive(Debug, Clone, Default)]
pub struct DerivationConfig {
    /// Account index (default: 0)
    pub account: u32,
    /// Optional passphrase for additional security
    pub passphrase: Option<String>,
}

impl DerivationConfig {
    /// Create a new derivation config for the given account
    pub fn new(account: u32) -> Self {
        Self {
            account,
            passphrase: None,
        }
    }

    /// Set the passphrase
    pub fn with_passphrase(mut self, passphrase: &str) -> Self {
        self.passphrase = Some(passphrase.to_string());
        self
    }

    /// Get the Ed25519 derivation path
    pub fn ed25519_path(&self) -> String {
        format!(
            "m/{}/{}/{}/0",
            BLS_CURVE_ID, CIPHERBFT_COIN_TYPE, self.account
        )
    }

    /// Get the BLS derivation path
    pub fn bls_path(&self) -> String {
        format!(
            "m/{}/{}/{}/1",
            BLS_CURVE_ID, CIPHERBFT_COIN_TYPE, self.account
        )
    }
}

/// Derive both consensus (Ed25519) and data chain (BLS) keys from a mnemonic
///
/// This is the main entry point for generating validator keys from a mnemonic.
///
/// # Arguments
///
/// * `mnemonic` - The BIP-39 mnemonic phrase
/// * `account` - Account index (0-based)
/// * `passphrase` - Optional passphrase for additional security
///
/// # Returns
///
/// `ValidatorKeys` with both key pairs and derivation info attached
///
/// # Example
///
/// ```rust
/// use cipherbft_crypto::mnemonic::{Mnemonic, derive_validator_keys};
///
/// let mnemonic = Mnemonic::from_phrase(
///     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
/// ).unwrap();
///
/// let keys = derive_validator_keys(&mnemonic, 0, None).unwrap();
/// println!("Validator ID: {:?}", keys.validator_id());
/// ```
pub fn derive_validator_keys(
    mnemonic: &Mnemonic,
    account: u32,
    passphrase: Option<&str>,
) -> MnemonicResult<ValidatorKeys> {
    let config = DerivationConfig {
        account,
        passphrase: passphrase.map(|s| s.to_string()),
    };

    let ed25519_keypair = derive_ed25519_key(mnemonic, &config)?;
    let bls_keypair = derive_bls_key(mnemonic, &config)?;

    let derivation_info = DerivationInfo {
        account_index: account,
        consensus_path: config.ed25519_path(),
        data_chain_path: config.bls_path(),
    };

    Ok(ValidatorKeys::from_keypairs_with_derivation(
        ed25519_keypair,
        bls_keypair,
        derivation_info,
    ))
}

/// Derive an Ed25519 key pair from a mnemonic
///
/// Uses a deterministic derivation based on the seed and path.
///
/// # Arguments
///
/// * `mnemonic` - The BIP-39 mnemonic
/// * `config` - Derivation configuration
///
/// # Returns
///
/// `Ed25519KeyPair` derived from the mnemonic
pub fn derive_ed25519_key(
    mnemonic: &Mnemonic,
    config: &DerivationConfig,
) -> MnemonicResult<Ed25519KeyPair> {
    let seed = mnemonic.to_seed(config.passphrase.as_deref());
    let path = config.ed25519_path();

    // Derive Ed25519 seed using HKDF-style derivation
    let derived_seed = derive_seed_for_path(&seed, &path)?;

    let secret = Ed25519SecretKey::from_seed(&derived_seed);
    let public = secret.public_key();

    Ok(Ed25519KeyPair {
        secret_key: secret,
        public_key: public,
    })
}

/// Derive a BLS key pair from a mnemonic
///
/// Uses EIP-2333 style derivation for BLS12-381 keys.
///
/// # Arguments
///
/// * `mnemonic` - The BIP-39 mnemonic
/// * `config` - Derivation configuration
///
/// # Returns
///
/// `BlsKeyPair` derived from the mnemonic
pub fn derive_bls_key(
    mnemonic: &Mnemonic,
    config: &DerivationConfig,
) -> MnemonicResult<BlsKeyPair> {
    let seed = mnemonic.to_seed(config.passphrase.as_deref());
    let path = config.bls_path();

    // Derive BLS seed using HKDF-style derivation
    let derived_seed = derive_seed_for_path(&seed, &path)?;

    let secret = BlsSecretKey::from_seed(&derived_seed);
    let public = secret.public_key();

    Ok(BlsKeyPair {
        secret_key: secret,
        public_key: public,
    })
}

/// Derive a 32-byte seed from a master seed and derivation path
///
/// Uses HKDF-style derivation with SHA-256 to produce deterministic
/// seeds for any path.
///
/// Note: This is a simplified derivation scheme. For production use with
/// BLS keys, consider implementing full EIP-2333 derivation.
fn derive_seed_for_path(master_seed: &[u8; 64], path: &str) -> MnemonicResult<[u8; 32]> {
    // Parse the path
    let components = parse_derivation_path(path)?;

    // Start with the master seed
    let mut current = master_seed.to_vec();

    // Derive for each path component
    for index in components {
        current = derive_child(&current, index);
    }

    // Take the first 32 bytes as the final seed
    let mut result = [0u8; 32];
    result.copy_from_slice(&current[..32]);

    Ok(result)
}

/// Parse a BIP-32 style derivation path
///
/// Supports paths like "m/12381/8888/0/0" and "m/12381'/8888'/0'/0'"
fn parse_derivation_path(path: &str) -> MnemonicResult<Vec<u32>> {
    let path = path.trim();

    // Must start with "m" or "M"
    if !path.starts_with('m') && !path.starts_with('M') {
        return Err(MnemonicError::InvalidPath(
            "path must start with 'm'".to_string(),
        ));
    }

    let mut components = Vec::new();

    for part in path.split('/').skip(1) {
        // Skip empty parts
        if part.is_empty() {
            continue;
        }

        // Handle hardened notation (')
        let (num_str, _hardened) =
            if part.ends_with('\'') || part.ends_with('h') || part.ends_with('H') {
                (&part[..part.len() - 1], true)
            } else {
                (part, false)
            };

        let index: u32 = num_str
            .parse()
            .map_err(|_| MnemonicError::InvalidPath(format!("invalid path component: {}", part)))?;

        components.push(index);
    }

    if components.is_empty() {
        return Err(MnemonicError::InvalidPath(
            "path has no components".to_string(),
        ));
    }

    Ok(components)
}

/// Derive a child key from a parent key and index
///
/// Uses SHA-256 based derivation for simplicity.
fn derive_child(parent: &[u8], index: u32) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(parent);
    hasher.update(b"cipherbft-derive");
    hasher.update(index.to_be_bytes());

    let hash = hasher.finalize();

    // Double hash for extra mixing
    let mut hasher2 = Sha256::new();
    hasher2.update(hash);
    hasher2.update(parent);

    hasher2.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Standard test mnemonic (DO NOT USE IN PRODUCTION)
    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn test_derive_validator_keys() {
        let mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC).unwrap();
        let keys = derive_validator_keys(&mnemonic, 0, None).unwrap();

        // Keys should be derived
        assert!(keys.is_derived());

        // Derivation info should be set
        let info = keys.derivation_info().unwrap();
        assert_eq!(info.account_index, 0);
        assert_eq!(info.consensus_path, "m/12381/8888/0/0");
        assert_eq!(info.data_chain_path, "m/12381/8888/0/1");
    }

    #[test]
    fn test_deterministic_derivation() {
        let mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC).unwrap();

        let keys1 = derive_validator_keys(&mnemonic, 0, None).unwrap();
        let keys2 = derive_validator_keys(&mnemonic, 0, None).unwrap();

        // Same mnemonic + account should produce same keys
        assert_eq!(keys1.validator_id(), keys2.validator_id());
        assert_eq!(
            keys1.consensus_pubkey().to_bytes(),
            keys2.consensus_pubkey().to_bytes()
        );
        assert_eq!(
            keys1.data_chain_pubkey().to_bytes(),
            keys2.data_chain_pubkey().to_bytes()
        );
    }

    #[test]
    fn test_different_accounts_different_keys() {
        let mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC).unwrap();

        let keys0 = derive_validator_keys(&mnemonic, 0, None).unwrap();
        let keys1 = derive_validator_keys(&mnemonic, 1, None).unwrap();

        // Different accounts should produce different keys
        assert_ne!(keys0.validator_id(), keys1.validator_id());
        assert_ne!(
            keys0.consensus_pubkey().to_bytes(),
            keys1.consensus_pubkey().to_bytes()
        );
    }

    #[test]
    fn test_passphrase_changes_keys() {
        let mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC).unwrap();

        let keys_no_pass = derive_validator_keys(&mnemonic, 0, None).unwrap();
        let keys_with_pass = derive_validator_keys(&mnemonic, 0, Some("test-passphrase")).unwrap();

        // Different passphrase should produce different keys
        assert_ne!(keys_no_pass.validator_id(), keys_with_pass.validator_id());
    }

    #[test]
    fn test_derive_ed25519_key() {
        let mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC).unwrap();
        let config = DerivationConfig::new(0);

        let keypair = derive_ed25519_key(&mnemonic, &config).unwrap();

        // Should produce valid keypair
        let msg = b"test message";
        let sig = keypair.sign(msg);
        assert!(keypair.public_key.verify(msg, &sig));
    }

    #[test]
    fn test_derive_bls_key() {
        let mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC).unwrap();
        let config = DerivationConfig::new(0);

        let keypair = derive_bls_key(&mnemonic, &config).unwrap();

        // Should produce valid keypair
        let msg = b"test message";
        let sig = keypair.sign_car(msg);
        assert!(keypair.public_key.verify(msg, crate::bls::DST_CAR, &sig));
    }

    #[test]
    fn test_parse_derivation_path() {
        let path = "m/12381/8888/0/0";
        let components = parse_derivation_path(path).unwrap();
        assert_eq!(components, vec![12381, 8888, 0, 0]);
    }

    #[test]
    fn test_parse_hardened_path() {
        let path = "m/12381'/8888'/0'/0'";
        let components = parse_derivation_path(path).unwrap();
        assert_eq!(components, vec![12381, 8888, 0, 0]);
    }

    #[test]
    fn test_invalid_path() {
        // Must start with m
        assert!(parse_derivation_path("12381/8888/0/0").is_err());

        // Invalid component
        assert!(parse_derivation_path("m/abc/0").is_err());

        // Empty path
        assert!(parse_derivation_path("m/").is_err());
    }

    #[test]
    fn test_derivation_config() {
        let config = DerivationConfig::new(5);
        assert_eq!(config.ed25519_path(), "m/12381/8888/5/0");
        assert_eq!(config.bls_path(), "m/12381/8888/5/1");
    }

    #[test]
    fn test_multiple_accounts() {
        let mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC).unwrap();

        // Derive keys for accounts 0-4
        let mut validator_ids = Vec::new();
        for account in 0..5 {
            let keys = derive_validator_keys(&mnemonic, account, None).unwrap();
            let id = keys.validator_id();

            // Each account should have unique validator ID
            assert!(
                !validator_ids.contains(&id),
                "duplicate validator ID for account {}",
                account
            );
            validator_ids.push(id);
        }

        assert_eq!(validator_ids.len(), 5);
    }
}
