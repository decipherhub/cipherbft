//! Ed25519 cryptographic operations for Consensus Layer (CL)
//!
//! This module provides Ed25519 signatures compatible with Malachite BFT.
//! Ed25519 is used for:
//! - Consensus Layer message signing (votes, proposals)
//! - ValidatorId derivation (keccak256(pubkey)[12..])
//!
//! For DCL operations (Car/Attestation signing), use BLS12-381 from bls.rs.

use crate::error::CryptoError;
use cipherbft_types::ValidatorId;
use ed25519_consensus::{
    Signature as Ed25519Sig, SigningKey as Ed25519Secret, VerificationKey as Ed25519Pubkey,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// Ed25519 secret key (32 bytes seed)
#[derive(Clone)]
pub struct Ed25519SecretKey(Ed25519Secret);

impl Ed25519SecretKey {
    /// Generate a new random secret key
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self::from_seed(&seed)
    }

    /// Create from seed bytes (32 bytes)
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(Ed25519Secret::from(*seed))
    }

    /// Load from raw bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(Ed25519Secret::from(*bytes))
    }

    /// Serialize to bytes (32-byte seed)
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Get the corresponding public key
    pub fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey(self.0.verification_key())
    }

    /// Sign a message
    pub fn sign(&self, msg: &[u8]) -> Ed25519Signature {
        Ed25519Signature(self.0.sign(msg))
    }
}

impl std::fmt::Debug for Ed25519SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ed25519SecretKey")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// Ed25519 public key (32 bytes)
#[derive(Clone, PartialEq, Eq)]
pub struct Ed25519PublicKey(Ed25519Pubkey);

impl Ed25519PublicKey {
    /// Load from bytes (32 bytes)
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        Ed25519Pubkey::try_from(*bytes)
            .map(Self)
            .map_err(|_| CryptoError::InvalidPublicKey)
    }

    /// Serialize to bytes (32 bytes)
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Verify a signature
    pub fn verify(&self, msg: &[u8], sig: &Ed25519Signature) -> bool {
        self.0.verify(&sig.0, msg).is_ok()
    }

    /// Derive ValidatorId from this public key
    ///
    /// Uses keccak256(pubkey)[12..] (Ethereum address format, 20 bytes)
    pub fn validator_id(&self) -> ValidatorId {
        ValidatorId::from_ed25519_pubkey(&self.to_bytes())
    }
}

impl std::fmt::Debug for Ed25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = self.to_bytes();
        write!(f, "Ed25519PublicKey({})", hex::encode(&bytes[..8]))
    }
}

impl Serialize for Ed25519PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeTuple;

        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(self.to_bytes()))
        } else {
            let bytes = self.to_bytes();
            let mut tuple = serializer.serialize_tuple(32)?;
            for byte in bytes {
                tuple.serialize_element(&byte)?;
            }
            tuple.end()
        }
    }
}

impl<'de> Deserialize<'de> for Ed25519PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{SeqAccess, Visitor};

        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
            if bytes.len() != 32 {
                return Err(serde::de::Error::custom("invalid public key length"));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Self::from_bytes(&arr).map_err(serde::de::Error::custom)
        } else {
            struct ArrayVisitor;

            impl<'de> Visitor<'de> for ArrayVisitor {
                type Value = [u8; 32];

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("32 bytes")
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: SeqAccess<'de>,
                {
                    let mut arr = [0u8; 32];
                    for (i, byte) in arr.iter_mut().enumerate() {
                        *byte = seq
                            .next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                    }
                    Ok(arr)
                }
            }

            let arr = deserializer.deserialize_tuple(32, ArrayVisitor)?;
            Self::from_bytes(&arr).map_err(serde::de::Error::custom)
        }
    }
}

/// Ed25519 signature (64 bytes)
#[derive(Clone)]
pub struct Ed25519Signature(Ed25519Sig);

impl Ed25519Signature {
    /// Load from bytes (64 bytes)
    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self, CryptoError> {
        // Ed25519Sig::from is infallible for 64-byte arrays
        Ok(Self(Ed25519Sig::from(*bytes)))
    }

    /// Serialize to bytes (64 bytes)
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0.to_bytes()
    }

    /// Verify signature against public key
    pub fn verify(&self, msg: &[u8], pubkey: &Ed25519PublicKey) -> bool {
        pubkey.verify(msg, self)
    }
}

impl std::fmt::Debug for Ed25519Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = self.to_bytes();
        write!(f, "Ed25519Signature({})", hex::encode(&bytes[..8]))
    }
}

impl PartialEq for Ed25519Signature {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for Ed25519Signature {}

impl Serialize for Ed25519Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeTuple;

        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(self.to_bytes()))
        } else {
            let bytes = self.to_bytes();
            let mut tuple = serializer.serialize_tuple(64)?;
            for byte in bytes {
                tuple.serialize_element(&byte)?;
            }
            tuple.end()
        }
    }
}

impl<'de> Deserialize<'de> for Ed25519Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{SeqAccess, Visitor};

        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
            if bytes.len() != 64 {
                return Err(serde::de::Error::custom("invalid signature length"));
            }
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&bytes);
            Self::from_bytes(&arr).map_err(serde::de::Error::custom)
        } else {
            struct ArrayVisitor;

            impl<'de> Visitor<'de> for ArrayVisitor {
                type Value = [u8; 64];

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("64 bytes")
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: SeqAccess<'de>,
                {
                    let mut arr = [0u8; 64];
                    for (i, byte) in arr.iter_mut().enumerate() {
                        *byte = seq
                            .next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                    }
                    Ok(arr)
                }
            }

            let arr = deserializer.deserialize_tuple(64, ArrayVisitor)?;
            Self::from_bytes(&arr).map_err(serde::de::Error::custom)
        }
    }
}

/// Ed25519 key pair (convenience wrapper)
#[derive(Clone)]
pub struct Ed25519KeyPair {
    pub secret_key: Ed25519SecretKey,
    pub public_key: Ed25519PublicKey,
}

impl Ed25519KeyPair {
    /// Generate a new random key pair
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let secret_key = Ed25519SecretKey::generate(rng);
        let public_key = secret_key.public_key();
        Self {
            secret_key,
            public_key,
        }
    }

    /// Create from secret key
    pub fn from_secret_key(secret_key: Ed25519SecretKey) -> Self {
        let public_key = secret_key.public_key();
        Self {
            secret_key,
            public_key,
        }
    }

    /// Sign a message
    pub fn sign(&self, msg: &[u8]) -> Ed25519Signature {
        self.secret_key.sign(msg)
    }

    /// Get the ValidatorId derived from this key pair
    pub fn validator_id(&self) -> ValidatorId {
        self.public_key.validator_id()
    }
}

impl std::fmt::Debug for Ed25519KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ed25519KeyPair")
            .field("public_key", &self.public_key)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let keypair = Ed25519KeyPair::generate(&mut rand::thread_rng());
        let bytes = keypair.public_key.to_bytes();
        let restored = Ed25519PublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(keypair.public_key.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_sign_verify() {
        let keypair = Ed25519KeyPair::generate(&mut rand::thread_rng());
        let msg = b"test message";
        let sig = keypair.sign(msg);
        assert!(keypair.public_key.verify(msg, &sig));
    }

    #[test]
    fn test_wrong_message_fails() {
        let keypair = Ed25519KeyPair::generate(&mut rand::thread_rng());
        let sig = keypair.sign(b"correct message");
        assert!(!keypair.public_key.verify(b"wrong message", &sig));
    }

    #[test]
    fn test_validator_id_derivation() {
        let keypair = Ed25519KeyPair::generate(&mut rand::thread_rng());
        let vid = keypair.validator_id();

        // Verify deterministic derivation
        let vid2 = keypair.public_key.validator_id();
        assert_eq!(vid, vid2);

        // Different keys should have different IDs
        let keypair2 = Ed25519KeyPair::generate(&mut rand::thread_rng());
        let vid3 = keypair2.validator_id();
        assert_ne!(vid, vid3);
    }

    #[test]
    fn test_signature_serialization() {
        let keypair = Ed25519KeyPair::generate(&mut rand::thread_rng());
        let sig = keypair.sign(b"test");

        let bytes = sig.to_bytes();
        let restored = Ed25519Signature::from_bytes(&bytes).unwrap();
        assert_eq!(sig.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_public_key_serialization() {
        let keypair = Ed25519KeyPair::generate(&mut rand::thread_rng());

        // JSON roundtrip
        let json = serde_json::to_string(&keypair.public_key).unwrap();
        let restored: Ed25519PublicKey = serde_json::from_str(&json).unwrap();
        assert_eq!(keypair.public_key.to_bytes(), restored.to_bytes());
    }
}
