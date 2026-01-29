//! Key derivation from mnemonic phrases
//!
//! Implements hierarchical deterministic (HD) key derivation for CipherBFT validators
//! using a BLS12-381 compatible path structure.
//!
//! # Key Types
//!
//! - Ed25519: Consensus Layer (CL) - uses HKDF-style derivation
//! - BLS12-381: Data Chain Layer (DCL) - uses HKDF-style derivation
//! - Secp256k1: EVM Layer - uses BIP-32 derivation (Ethereum standard)
//!
//! # Derivation Paths
//!
//! - Ed25519/BLS: `m/12381/8888/{account}/{key_type}` (CipherBFT custom)
//! - Secp256k1: `m/44'/60'/0'/0/{account}` (BIP-44 Ethereum standard)

use super::error::{MnemonicError, MnemonicResult};
use super::generate::Mnemonic;
use crate::bls::{BlsKeyPair, BlsSecretKey};
use crate::ed25519::{Ed25519KeyPair, Ed25519SecretKey};
use crate::keys::ValidatorKeys;
use crate::secp256k1::{Secp256k1KeyPair, Secp256k1SecretKey};
use crate::secure::DerivationInfo;
use bip32::{DerivationPath, XPrv};
use sha2::{Digest, Sha256};
use std::str::FromStr;

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

/// Default derivation path for secp256k1 (EVM) keys
/// Format: m/44'/60'/0'/0/{account} (BIP-44 Ethereum standard)
pub const DEFAULT_DERIVATION_PATH_SECP256K1: &str = "m/44'/60'/0'/0/0";

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

    /// Get the secp256k1 (EVM) derivation path
    ///
    /// Uses BIP-44 Ethereum standard: m/44'/60'/0'/0/{account}
    pub fn secp256k1_path(&self) -> String {
        format!("m/44'/60'/0'/0/{}", self.account)
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
    let secp256k1_keypair = derive_secp256k1_key(mnemonic, &config)?;

    let derivation_info = DerivationInfo {
        account_index: account,
        consensus_path: config.ed25519_path(),
        data_chain_path: config.bls_path(),
        evm_path: Some(config.secp256k1_path()),
    };

    Ok(ValidatorKeys::from_keypairs_with_derivation(
        ed25519_keypair,
        bls_keypair,
        secp256k1_keypair,
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

/// Derive a secp256k1 key pair from a mnemonic
///
/// Uses BIP-32 HD derivation with BIP-44 Ethereum path: m/44'/60'/0'/0/{account}
///
/// # Arguments
///
/// * `mnemonic` - The BIP-39 mnemonic
/// * `config` - Derivation configuration
///
/// # Returns
///
/// `Secp256k1KeyPair` derived from the mnemonic
///
/// # Example
///
/// ```rust
/// use cipherbft_crypto::mnemonic::{Mnemonic, derive_secp256k1_key, DerivationConfig};
///
/// // Test mnemonic (Hardhat default)
/// let mnemonic = Mnemonic::from_phrase(
///     "test test test test test test test test test test test junk"
/// ).unwrap();
///
/// let config = DerivationConfig::new(0);
/// let keypair = derive_secp256k1_key(&mnemonic, &config).unwrap();
///
/// // Should produce the Hardhat account 0 address
/// assert_eq!(
///     keypair.evm_address().to_string().to_lowercase(),
///     "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
/// );
/// ```
pub fn derive_secp256k1_key(
    mnemonic: &Mnemonic,
    config: &DerivationConfig,
) -> MnemonicResult<Secp256k1KeyPair> {
    let seed = mnemonic.to_seed(config.passphrase.as_deref());
    let path = config.secp256k1_path();

    // Parse the derivation path
    let derivation_path = DerivationPath::from_str(&path)
        .map_err(|e| MnemonicError::InvalidPath(format!("invalid BIP-32 path: {}", e)))?;

    // Derive the extended private key using BIP-32
    let xprv = XPrv::derive_from_path(&seed, &derivation_path)
        .map_err(|e| MnemonicError::DerivationFailed(format!("BIP-32 derivation failed: {}", e)))?;

    // Extract the 32-byte private key
    let private_key_bytes: [u8; 32] = xprv.private_key().to_bytes().into();

    // Create the secp256k1 secret key
    let secret = Secp256k1SecretKey::from_bytes(&private_key_bytes)
        .map_err(|e| MnemonicError::DerivationFailed(format!("invalid secp256k1 key: {:?}", e)))?;
    let public = secret.public_key();

    Ok(Secp256k1KeyPair {
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
        assert_eq!(config.secp256k1_path(), "m/44'/60'/0'/0/5");
    }

    // Hardhat test mnemonic (DO NOT USE IN PRODUCTION)
    const HARDHAT_MNEMONIC: &str =
        "test test test test test test test test test test test junk";

    #[test]
    fn test_derive_secp256k1_key_hardhat_account0() {
        // Test with Hardhat's default mnemonic and account 0
        // Expected address: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
        let mnemonic = Mnemonic::from_phrase(HARDHAT_MNEMONIC).unwrap();
        let config = DerivationConfig::new(0);

        let keypair = derive_secp256k1_key(&mnemonic, &config).unwrap();
        let address = keypair.evm_address();

        // Hardhat account 0 address
        let expected_address = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
        assert_eq!(
            address.to_string().to_lowercase(),
            expected_address.to_lowercase(),
            "Hardhat account 0 address mismatch"
        );
    }

    #[test]
    fn test_derive_secp256k1_key_hardhat_account1() {
        // Test with Hardhat's default mnemonic and account 1
        // Expected address: 0x70997970C51812dc3A010C7d01b50e0d17dc79C8
        let mnemonic = Mnemonic::from_phrase(HARDHAT_MNEMONIC).unwrap();
        let config = DerivationConfig::new(1);

        let keypair = derive_secp256k1_key(&mnemonic, &config).unwrap();
        let address = keypair.evm_address();

        let expected_address = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8";
        assert_eq!(
            address.to_string().to_lowercase(),
            expected_address.to_lowercase(),
            "Hardhat account 1 address mismatch"
        );
    }

    #[test]
    fn test_derive_secp256k1_key_deterministic() {
        let mnemonic = Mnemonic::from_phrase(HARDHAT_MNEMONIC).unwrap();
        let config = DerivationConfig::new(0);

        let keypair1 = derive_secp256k1_key(&mnemonic, &config).unwrap();
        let keypair2 = derive_secp256k1_key(&mnemonic, &config).unwrap();

        // Same mnemonic + account should produce same keys
        assert_eq!(
            keypair1.public_key.to_bytes(),
            keypair2.public_key.to_bytes()
        );
        assert_eq!(keypair1.evm_address(), keypair2.evm_address());
    }

    #[test]
    fn test_derive_secp256k1_key_different_accounts() {
        let mnemonic = Mnemonic::from_phrase(HARDHAT_MNEMONIC).unwrap();

        let keypair0 = derive_secp256k1_key(&mnemonic, &DerivationConfig::new(0)).unwrap();
        let keypair1 = derive_secp256k1_key(&mnemonic, &DerivationConfig::new(1)).unwrap();

        // Different accounts should produce different keys
        assert_ne!(
            keypair0.public_key.to_bytes(),
            keypair1.public_key.to_bytes()
        );
        assert_ne!(keypair0.evm_address(), keypair1.evm_address());
    }

    #[test]
    fn test_derive_secp256k1_key_passphrase_changes_keys() {
        let mnemonic = Mnemonic::from_phrase(HARDHAT_MNEMONIC).unwrap();

        let config_no_pass = DerivationConfig::new(0);
        let config_with_pass = DerivationConfig::new(0).with_passphrase("test-passphrase");

        let keypair_no_pass = derive_secp256k1_key(&mnemonic, &config_no_pass).unwrap();
        let keypair_with_pass = derive_secp256k1_key(&mnemonic, &config_with_pass).unwrap();

        // Different passphrase should produce different keys
        assert_ne!(
            keypair_no_pass.public_key.to_bytes(),
            keypair_with_pass.public_key.to_bytes()
        );
    }

    #[test]
    fn test_derive_secp256k1_key_sign_verify() {
        let mnemonic = Mnemonic::from_phrase(HARDHAT_MNEMONIC).unwrap();
        let config = DerivationConfig::new(0);

        let keypair = derive_secp256k1_key(&mnemonic, &config).unwrap();

        // Should produce valid keypair that can sign and verify
        let msg = b"test message";
        let sig = keypair.sign(msg);
        assert!(keypair.public_key.verify(msg, &sig));
    }

    #[test]
    fn test_derivation_info_includes_evm_path() {
        let mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC).unwrap();
        let keys = derive_validator_keys(&mnemonic, 0, None).unwrap();

        let info = keys.derivation_info().unwrap();
        assert_eq!(info.evm_path, Some("m/44'/60'/0'/0/0".to_string()));
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
