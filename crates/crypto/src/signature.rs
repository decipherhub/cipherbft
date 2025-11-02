//! Ed25519 signature operations.
//!
//! Provides cryptographic signature operations using Ed25519 with
//! constant-time verification to prevent timing attacks.

use ed25519_consensus::{SigningKey, VerificationKey};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// Ed25519 public key for signature verification.
pub type PublicKey = VerificationKey;

/// Ed25519 private key for signing.
pub type PrivateKey = SigningKey;

/// Ed25519 signature.
pub type Signature = ed25519_consensus::Signature;

/// Key pair containing both private and public keys.
#[derive(Clone)]
pub struct KeyPair {
    /// Private signing key.
    pub private_key: PrivateKey,
    /// Public verification key.
    pub public_key: PublicKey,
}

impl KeyPair {
    /// Generate a new random keypair.
    ///
    /// Uses a cryptographically secure random number generator.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let private_key = PrivateKey::new(rng);
        let public_key = VerificationKey::from(&private_key);
        Self {
            private_key,
            public_key,
        }
    }

    /// Create keypair from existing private key bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are invalid (not 32 bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        if bytes.len() != 32 {
            return Err(SignatureError::InvalidKeyLength);
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(bytes);

        let private_key = PrivateKey::from(key_bytes);
        let public_key = VerificationKey::from(&private_key);

        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Sign a message with this keypair.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.private_key.sign(message)
    }

    /// Verify a signature with this keypair's public key.
    pub fn verify(&self, signature: &Signature, message: &[u8]) -> Result<(), SignatureError> {
        self.public_key
            .verify(signature, message)
            .map_err(|_| SignatureError::InvalidSignature)
    }

    /// Get the public key bytes (32 bytes).
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public_key.to_bytes()
    }

    /// Get the private key bytes (32 bytes).
    ///
    /// WARNING: This exposes the private key. Handle with care.
    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.private_key.to_bytes()
    }
}

/// Address derived from a public key (first 20 bytes of hash).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address([u8; 20]);

impl Address {
    /// Create address from public key.
    ///
    /// Uses SHA-256 hash and takes first 20 bytes (like Ethereum).
    pub fn from_public_key(public_key: &PublicKey) -> Self {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(public_key.to_bytes());
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[..20]);
        Address(addr)
    }

    /// Get address bytes.
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// Create address from bytes.
    pub fn from_bytes(bytes: [u8; 20]) -> Self {
        Address(bytes)
    }
}

impl From<&PublicKey> for Address {
    fn from(public_key: &PublicKey) -> Self {
        Address::from_public_key(public_key)
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// Signature operation errors.
#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    /// Invalid signature verification.
    #[error("Invalid signature")]
    InvalidSignature,
    /// Invalid key length.
    #[error("Invalid key length, expected 32 bytes")]
    InvalidKeyLength,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = KeyPair::generate(&mut rand::thread_rng());
        let message = b"test message";

        let signature = keypair.sign(message);
        assert!(keypair.verify(&signature, message).is_ok());
    }

    #[test]
    fn test_keypair_from_bytes() {
        let keypair1 = KeyPair::generate(&mut rand::thread_rng());
        let bytes = keypair1.private_key_bytes();

        let keypair2 = KeyPair::from_bytes(&bytes).expect("valid key bytes");

        assert_eq!(
            keypair1.public_key_bytes(),
            keypair2.public_key_bytes()
        );
    }

    #[test]
    fn test_invalid_key_length() {
        let result = KeyPair::from_bytes(&[0u8; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn test_signature_verification() {
        let keypair = KeyPair::generate(&mut rand::thread_rng());
        let message = b"test message";

        let signature = keypair.sign(message);

        // Valid signature should verify
        assert!(keypair.verify(&signature, message).is_ok());

        // Invalid signature should fail
        let wrong_message = b"wrong message";
        assert!(keypair.verify(&signature, wrong_message).is_err());
    }

    #[test]
    fn test_address_derivation() {
        let keypair = KeyPair::generate(&mut rand::thread_rng());
        let addr1 = Address::from_public_key(&keypair.public_key);
        let addr2 = Address::from(&keypair.public_key);

        assert_eq!(addr1, addr2);
        assert_eq!(addr1.as_bytes().len(), 20);
    }

    #[test]
    fn test_address_display() {
        let keypair = KeyPair::generate(&mut rand::thread_rng());
        let address = Address::from_public_key(&keypair.public_key);
        let display = format!("{}", address);

        // Should be 40 hex characters (20 bytes)
        assert_eq!(display.len(), 40);
    }

    #[test]
    fn test_sign_verify_basic() {
        let private_key = PrivateKey::new(rand::thread_rng());
        let public_key = VerificationKey::from(&private_key);

        let message = b"test message";
        let signature = private_key.sign(message);

        assert!(public_key.verify(&signature, message).is_ok());
    }
}
