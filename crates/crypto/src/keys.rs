//! Dual key structure for CipherBFT validators
//!
//! CipherBFT uses two key types:
//! - Ed25519: Consensus Layer (CL) - Malachite BFT voting/proposals
//! - BLS12-381: Data Chain Layer (DCL) - Car/Attestation signing
//!
//! ValidatorId is derived from the Ed25519 public key to match Malachite's
//! address format: keccak256(ed25519_pubkey)[12..] (20 bytes, Ethereum style)
//!
//! # Security
//!
//! Keys can optionally be associated with:
//! - Derivation info (if generated from mnemonic)
//! - Keystore paths (if loaded from encrypted files)
//! - Secure key material (for explicit memory zeroing)

use std::path::PathBuf;

use crate::bls::{BlsKeyPair, BlsPublicKey, BlsSecretKey};
use crate::ed25519::{Ed25519KeyPair, Ed25519PublicKey, Ed25519SecretKey};
use crate::secure::DerivationInfo;
use cipherbft_types::ValidatorId;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Paths to keystore files for a validator
#[derive(Clone, Debug, Default)]
pub struct KeystorePaths {
    /// Path to consensus (Ed25519) keystore file
    pub consensus: Option<PathBuf>,
    /// Path to data chain (BLS) keystore file
    pub data_chain: Option<PathBuf>,
}

impl KeystorePaths {
    /// Create new keystore paths
    pub fn new(consensus: PathBuf, data_chain: PathBuf) -> Self {
        Self {
            consensus: Some(consensus),
            data_chain: Some(data_chain),
        }
    }

    /// Check if both keystore paths are set
    pub fn is_complete(&self) -> bool {
        self.consensus.is_some() && self.data_chain.is_some()
    }
}

/// Complete key set for a CipherBFT validator
///
/// Contains both:
/// - Consensus keys (Ed25519) for CL operations
/// - Data chain keys (BLS12-381) for DCL operations
///
/// The ValidatorId is derived from the Ed25519 public key to ensure
/// consistency with Malachite's address format.
///
/// # Security
///
/// - Keys can be associated with derivation info (if from mnemonic)
/// - Keys can track their keystore file paths
/// - Implements secure cleanup via custom Drop (though underlying
///   key types should also implement zeroize)
#[derive(Clone)]
pub struct ValidatorKeys {
    /// Ed25519 keys for Consensus Layer (Malachite)
    pub consensus: Ed25519KeyPair,
    /// BLS12-381 keys for Data Chain Layer
    pub data_chain: BlsKeyPair,
    /// Cached validator ID (derived from Ed25519 pubkey)
    validator_id: ValidatorId,
    /// Derivation info (if derived from mnemonic)
    derivation_info: Option<DerivationInfo>,
    /// Paths to keystore files (if loaded from disk)
    keystore_paths: Option<KeystorePaths>,
}

impl ValidatorKeys {
    /// Generate a new validator key set
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let consensus = Ed25519KeyPair::generate(rng);
        let data_chain = BlsKeyPair::generate(rng);
        let validator_id = consensus.validator_id();

        Self {
            consensus,
            data_chain,
            validator_id,
            derivation_info: None,
            keystore_paths: None,
        }
    }

    /// Create from existing key pairs
    pub fn from_keypairs(consensus: Ed25519KeyPair, data_chain: BlsKeyPair) -> Self {
        let validator_id = consensus.validator_id();
        Self {
            consensus,
            data_chain,
            validator_id,
            derivation_info: None,
            keystore_paths: None,
        }
    }

    /// Create from key pairs with derivation info
    ///
    /// Use this when keys are derived from a mnemonic phrase.
    pub fn from_keypairs_with_derivation(
        consensus: Ed25519KeyPair,
        data_chain: BlsKeyPair,
        derivation_info: DerivationInfo,
    ) -> Self {
        let validator_id = consensus.validator_id();
        Self {
            consensus,
            data_chain,
            validator_id,
            derivation_info: Some(derivation_info),
            keystore_paths: None,
        }
    }

    /// Get the validator ID (derived from Ed25519 pubkey)
    pub fn validator_id(&self) -> ValidatorId {
        self.validator_id
    }

    /// Get the Ed25519 public key (for CL operations)
    pub fn consensus_pubkey(&self) -> &Ed25519PublicKey {
        &self.consensus.public_key
    }

    /// Get the BLS public key (for DCL operations)
    pub fn data_chain_pubkey(&self) -> &BlsPublicKey {
        &self.data_chain.public_key
    }

    /// Get the Ed25519 secret key (for CL signing)
    pub fn consensus_secret(&self) -> &Ed25519SecretKey {
        &self.consensus.secret_key
    }

    /// Get the BLS secret key (for DCL signing)
    pub fn data_chain_secret(&self) -> &BlsSecretKey {
        &self.data_chain.secret_key
    }

    /// Get derivation info if available
    pub fn derivation_info(&self) -> Option<&DerivationInfo> {
        self.derivation_info.as_ref()
    }

    /// Set derivation info
    pub fn set_derivation_info(&mut self, info: DerivationInfo) {
        self.derivation_info = Some(info);
    }

    /// Check if keys were derived from a mnemonic
    pub fn is_derived(&self) -> bool {
        self.derivation_info.is_some()
    }

    /// Get keystore paths if available
    pub fn keystore_paths(&self) -> Option<&KeystorePaths> {
        self.keystore_paths.as_ref()
    }

    /// Set keystore paths
    pub fn set_keystore_paths(&mut self, paths: KeystorePaths) {
        self.keystore_paths = Some(paths);
    }

    /// Check if keys are backed by keystore files
    pub fn has_keystore(&self) -> bool {
        self.keystore_paths
            .as_ref()
            .map(|p| p.is_complete())
            .unwrap_or(false)
    }
}

impl std::fmt::Debug for ValidatorKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidatorKeys")
            .field("validator_id", &self.validator_id)
            .field("consensus", &self.consensus.public_key)
            .field("data_chain", &self.data_chain.public_key)
            .finish()
    }
}

impl Drop for ValidatorKeys {
    fn drop(&mut self) {
        // Best-effort zeroing of secret key material
        //
        // Note: The underlying crypto libraries (ed25519_consensus, blst) don't
        // implement Zeroize, so we can only zero our local copies of the key bytes.
        // The library's internal memory may still contain key material.
        //
        // This provides defense-in-depth but is not a complete solution.
        // For production use, consider:
        // - Using libraries that implement Zeroize natively
        // - Memory-locked allocations (mlock)
        // - Hardware security modules (HSM)

        // Zero Ed25519 secret key bytes
        let mut ed_bytes = self.consensus.secret_key.to_bytes();
        ed_bytes.zeroize();

        // Zero BLS secret key bytes
        let mut bls_bytes = self.data_chain.secret_key.to_bytes();
        bls_bytes.zeroize();

        // Clear derivation info if present
        if let Some(ref mut info) = self.derivation_info {
            info.consensus_path.zeroize();
            info.data_chain_path.zeroize();
        }
    }
}

/// Public key set for a validator (for verification)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorPublicKeys {
    /// Ed25519 public key for CL verification
    pub consensus: Ed25519PublicKey,
    /// BLS12-381 public key for DCL verification
    pub data_chain: BlsPublicKey,
    /// Validator ID (derived from Ed25519 pubkey)
    #[serde(skip_serializing_if = "Option::is_none")]
    validator_id: Option<ValidatorId>,
}

impl ValidatorPublicKeys {
    /// Create from public keys
    pub fn new(consensus: Ed25519PublicKey, data_chain: BlsPublicKey) -> Self {
        let validator_id = consensus.validator_id();
        Self {
            consensus,
            data_chain,
            validator_id: Some(validator_id),
        }
    }

    /// Create from ValidatorKeys
    pub fn from_keys(keys: &ValidatorKeys) -> Self {
        Self::new(
            keys.consensus.public_key.clone(),
            keys.data_chain.public_key.clone(),
        )
    }

    /// Get the validator ID
    pub fn validator_id(&self) -> ValidatorId {
        self.validator_id
            .unwrap_or_else(|| self.consensus.validator_id())
    }

    /// Get the Ed25519 public key
    pub fn consensus_pubkey(&self) -> &Ed25519PublicKey {
        &self.consensus
    }

    /// Get the BLS public key
    pub fn data_chain_pubkey(&self) -> &BlsPublicKey {
        &self.data_chain
    }
}

impl PartialEq for ValidatorPublicKeys {
    fn eq(&self, other: &Self) -> bool {
        self.consensus.to_bytes() == other.consensus.to_bytes()
            && self.data_chain.to_bytes() == other.data_chain.to_bytes()
    }
}

impl Eq for ValidatorPublicKeys {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validator_keys_generation() {
        let keys = ValidatorKeys::generate(&mut rand::thread_rng());

        // Validator ID should be derived from Ed25519 pubkey
        assert_eq!(keys.validator_id(), keys.consensus.validator_id());

        // Should not be zero
        assert_ne!(keys.validator_id(), ValidatorId::ZERO);
    }

    #[test]
    fn test_validator_id_consistency() {
        let keys = ValidatorKeys::generate(&mut rand::thread_rng());

        // Multiple calls should return same ID
        let id1 = keys.validator_id();
        let id2 = keys.validator_id();
        assert_eq!(id1, id2);

        // Should match Ed25519 derivation
        let id3 = keys.consensus_pubkey().validator_id();
        assert_eq!(id1, id3);
    }

    #[test]
    fn test_different_keys_different_ids() {
        let keys1 = ValidatorKeys::generate(&mut rand::thread_rng());
        let keys2 = ValidatorKeys::generate(&mut rand::thread_rng());

        assert_ne!(keys1.validator_id(), keys2.validator_id());
    }

    #[test]
    fn test_public_keys_extraction() {
        let keys = ValidatorKeys::generate(&mut rand::thread_rng());
        let pub_keys = ValidatorPublicKeys::from_keys(&keys);

        assert_eq!(pub_keys.validator_id(), keys.validator_id());
        assert_eq!(
            pub_keys.consensus_pubkey().to_bytes(),
            keys.consensus_pubkey().to_bytes()
        );
        assert_eq!(
            pub_keys.data_chain_pubkey().to_bytes(),
            keys.data_chain_pubkey().to_bytes()
        );
    }

    #[test]
    fn test_sign_with_both_keys() {
        let keys = ValidatorKeys::generate(&mut rand::thread_rng());
        let msg = b"test message";

        // Sign with Ed25519
        let ed_sig = keys.consensus.sign(msg);
        assert!(keys.consensus_pubkey().verify(msg, &ed_sig));

        // Sign with BLS
        let bls_sig = keys.data_chain.sign_car(msg);
        assert!(keys
            .data_chain_pubkey()
            .verify(msg, crate::bls::DST_CAR, &bls_sig));
    }

    #[test]
    fn test_public_keys_serialization() {
        let keys = ValidatorKeys::generate(&mut rand::thread_rng());
        let pub_keys = ValidatorPublicKeys::from_keys(&keys);

        // JSON roundtrip
        let json = serde_json::to_string(&pub_keys).unwrap();
        let restored: ValidatorPublicKeys = serde_json::from_str(&json).unwrap();

        assert_eq!(pub_keys.validator_id(), restored.validator_id());
        assert_eq!(pub_keys, restored);
    }
}
