//! Secp256k1 cryptographic operations for EVM-compatible key operations
//!
//! This module provides secp256k1 ECDSA signatures for:
//! - EVM address derivation (keccak256(uncompressed_pubkey[1..])[12..])
//! - EVM-compatible signing and verification
//!
//! Uses the k256 crate for secp256k1 curve operations.

use crate::error::CryptoError;
use alloy_primitives::{keccak256, Address};
use k256::{
    ecdsa::{
        signature::{Signer, Verifier},
        Signature as K256Signature, SigningKey, VerifyingKey,
    },
    elliptic_curve::sec1::ToEncodedPoint,
    SecretKey as K256SecretKey,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// Secp256k1 secret key (32 bytes scalar)
#[derive(Clone)]
pub struct Secp256k1SecretKey(K256SecretKey);

impl Secp256k1SecretKey {
    /// Generate a new random secret key
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let sk = K256SecretKey::random(rng);
        Self(sk)
    }

    /// Load from raw bytes (32 bytes scalar)
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        K256SecretKey::from_slice(bytes)
            .map(Self)
            .map_err(|_| CryptoError::InvalidSecretKey)
    }

    /// Serialize to bytes (32 bytes scalar)
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes().into()
    }

    /// Get the corresponding public key
    pub fn public_key(&self) -> Secp256k1PublicKey {
        Secp256k1PublicKey(self.0.public_key())
    }

    /// Sign a message (applies keccak256 hash internally for EVM compatibility)
    pub fn sign(&self, msg: &[u8]) -> Secp256k1Signature {
        let signing_key = SigningKey::from(&self.0);
        let digest = keccak256(msg);
        let sig: K256Signature = signing_key.sign(digest.as_slice());
        Secp256k1Signature(sig)
    }
}

impl std::fmt::Debug for Secp256k1SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secp256k1SecretKey")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// Secp256k1 public key
#[derive(Clone, PartialEq, Eq)]
pub struct Secp256k1PublicKey(k256::PublicKey);

impl Secp256k1PublicKey {
    /// Load from compressed bytes (33 bytes)
    pub fn from_bytes(bytes: &[u8; 33]) -> Result<Self, CryptoError> {
        k256::PublicKey::from_sec1_bytes(bytes)
            .map(Self)
            .map_err(|_| CryptoError::InvalidPublicKey)
    }

    /// Load from uncompressed bytes (65 bytes, with 0x04 prefix)
    pub fn from_uncompressed_bytes(bytes: &[u8; 65]) -> Result<Self, CryptoError> {
        k256::PublicKey::from_sec1_bytes(bytes)
            .map(Self)
            .map_err(|_| CryptoError::InvalidPublicKey)
    }

    /// Serialize to compressed bytes (33 bytes)
    pub fn to_bytes(&self) -> [u8; 33] {
        let encoded = self.0.to_encoded_point(true);
        let bytes = encoded.as_bytes();
        let mut result = [0u8; 33];
        result.copy_from_slice(bytes);
        result
    }

    /// Serialize to uncompressed bytes (65 bytes, with 0x04 prefix)
    pub fn to_uncompressed_bytes(&self) -> [u8; 65] {
        let encoded = self.0.to_encoded_point(false);
        let bytes = encoded.as_bytes();
        let mut result = [0u8; 65];
        result.copy_from_slice(bytes);
        result
    }

    /// Derive EVM address from this public key
    ///
    /// Uses keccak256(uncompressed_pubkey[1..])[12..] (Ethereum address format, 20 bytes)
    pub fn evm_address(&self) -> Address {
        let uncompressed = self.to_uncompressed_bytes();
        // Skip the 0x04 prefix byte
        let hash = keccak256(&uncompressed[1..]);
        Address::from_slice(&hash[12..])
    }

    /// Verify a signature (applies keccak256 hash internally for EVM compatibility)
    pub fn verify(&self, msg: &[u8], sig: &Secp256k1Signature) -> bool {
        let verifying_key = VerifyingKey::from(&self.0);
        let digest = keccak256(msg);
        verifying_key.verify(digest.as_slice(), &sig.0).is_ok()
    }
}

impl std::fmt::Debug for Secp256k1PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = self.to_bytes();
        write!(f, "Secp256k1PublicKey({})", hex::encode(&bytes[..8]))
    }
}

impl Serialize for Secp256k1PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeTuple;

        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(self.to_bytes()))
        } else {
            let bytes = self.to_bytes();
            let mut tuple = serializer.serialize_tuple(33)?;
            for byte in bytes {
                tuple.serialize_element(&byte)?;
            }
            tuple.end()
        }
    }
}

impl<'de> Deserialize<'de> for Secp256k1PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{SeqAccess, Visitor};

        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
            if bytes.len() != 33 {
                return Err(serde::de::Error::custom("invalid public key length"));
            }
            let mut arr = [0u8; 33];
            arr.copy_from_slice(&bytes);
            Self::from_bytes(&arr).map_err(serde::de::Error::custom)
        } else {
            struct ArrayVisitor;

            impl<'de> Visitor<'de> for ArrayVisitor {
                type Value = [u8; 33];

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("33 bytes")
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: SeqAccess<'de>,
                {
                    let mut arr = [0u8; 33];
                    for (i, byte) in arr.iter_mut().enumerate() {
                        *byte = seq
                            .next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                    }
                    Ok(arr)
                }
            }

            let arr = deserializer.deserialize_tuple(33, ArrayVisitor)?;
            Self::from_bytes(&arr).map_err(serde::de::Error::custom)
        }
    }
}

/// Secp256k1 ECDSA signature (64 bytes: r || s)
#[derive(Clone)]
pub struct Secp256k1Signature(K256Signature);

impl Secp256k1Signature {
    /// Load from bytes (64 bytes: r || s)
    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self, CryptoError> {
        K256Signature::from_slice(bytes)
            .map(Self)
            .map_err(|_| CryptoError::InvalidSignature)
    }

    /// Serialize to bytes (64 bytes: r || s)
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0.to_bytes().into()
    }

    /// Verify signature against public key
    pub fn verify(&self, msg: &[u8], pubkey: &Secp256k1PublicKey) -> bool {
        pubkey.verify(msg, self)
    }
}

impl std::fmt::Debug for Secp256k1Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = self.to_bytes();
        write!(f, "Secp256k1Signature({})", hex::encode(&bytes[..8]))
    }
}

impl PartialEq for Secp256k1Signature {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for Secp256k1Signature {}

impl Serialize for Secp256k1Signature {
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

impl<'de> Deserialize<'de> for Secp256k1Signature {
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

/// Secp256k1 key pair (convenience wrapper)
#[derive(Clone)]
pub struct Secp256k1KeyPair {
    pub secret_key: Secp256k1SecretKey,
    pub public_key: Secp256k1PublicKey,
}

impl Secp256k1KeyPair {
    /// Generate a new random key pair
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let secret_key = Secp256k1SecretKey::generate(rng);
        let public_key = secret_key.public_key();
        Self {
            secret_key,
            public_key,
        }
    }

    /// Create from secret key
    pub fn from_secret_key(secret_key: Secp256k1SecretKey) -> Self {
        let public_key = secret_key.public_key();
        Self {
            secret_key,
            public_key,
        }
    }

    /// Sign a message
    pub fn sign(&self, msg: &[u8]) -> Secp256k1Signature {
        self.secret_key.sign(msg)
    }

    /// Get the EVM address derived from this key pair
    pub fn evm_address(&self) -> Address {
        self.public_key.evm_address()
    }
}

impl std::fmt::Debug for Secp256k1KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secp256k1KeyPair")
            .field("public_key", &self.public_key)
            .field("evm_address", &self.evm_address())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let keypair = Secp256k1KeyPair::generate(&mut rand::thread_rng());
        let bytes = keypair.public_key.to_bytes();
        let restored = Secp256k1PublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(keypair.public_key.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_secret_key_serialization() {
        let keypair = Secp256k1KeyPair::generate(&mut rand::thread_rng());
        let bytes = keypair.secret_key.to_bytes();
        let restored = Secp256k1SecretKey::from_bytes(&bytes).unwrap();
        assert_eq!(keypair.secret_key.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_sign_verify() {
        let keypair = Secp256k1KeyPair::generate(&mut rand::thread_rng());
        let msg = b"test message";
        let sig = keypair.sign(msg);
        assert!(keypair.public_key.verify(msg, &sig));
    }

    #[test]
    fn test_wrong_message_fails() {
        let keypair = Secp256k1KeyPair::generate(&mut rand::thread_rng());
        let sig = keypair.sign(b"correct message");
        assert!(!keypair.public_key.verify(b"wrong message", &sig));
    }

    #[test]
    fn test_wrong_key_fails() {
        let keypair1 = Secp256k1KeyPair::generate(&mut rand::thread_rng());
        let keypair2 = Secp256k1KeyPair::generate(&mut rand::thread_rng());
        let msg = b"test message";
        let sig = keypair1.sign(msg);
        assert!(!keypair2.public_key.verify(msg, &sig));
    }

    #[test]
    fn test_evm_address_derivation() {
        let keypair = Secp256k1KeyPair::generate(&mut rand::thread_rng());
        let addr = keypair.evm_address();

        // Verify deterministic derivation
        let addr2 = keypair.public_key.evm_address();
        assert_eq!(addr, addr2);

        // Different keys should have different addresses
        let keypair2 = Secp256k1KeyPair::generate(&mut rand::thread_rng());
        let addr3 = keypair2.evm_address();
        assert_ne!(addr, addr3);

        // Address should be 20 bytes
        assert_eq!(addr.len(), 20);
    }

    #[test]
    fn test_evm_address_known_vector() {
        // Test vector: known private key and expected address
        // Private key: 0x0000000000000000000000000000000000000000000000000000000000000001
        // Expected address: 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf
        let secret_bytes: [u8; 32] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ];
        let secret = Secp256k1SecretKey::from_bytes(&secret_bytes).unwrap();
        let keypair = Secp256k1KeyPair::from_secret_key(secret);
        let addr = keypair.evm_address();

        // The expected address for private key = 1
        let expected =
            Address::from_slice(&hex::decode("7E5F4552091A69125d5DfCb7b8C2659029395Bdf").unwrap());
        assert_eq!(addr, expected);
    }

    #[test]
    fn test_uncompressed_bytes() {
        let keypair = Secp256k1KeyPair::generate(&mut rand::thread_rng());
        let uncompressed = keypair.public_key.to_uncompressed_bytes();

        // Uncompressed key should start with 0x04
        assert_eq!(uncompressed[0], 0x04);

        // Should be 65 bytes
        assert_eq!(uncompressed.len(), 65);

        // Should be able to restore from uncompressed
        let restored = Secp256k1PublicKey::from_uncompressed_bytes(&uncompressed).unwrap();
        assert_eq!(keypair.public_key.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_signature_serialization() {
        let keypair = Secp256k1KeyPair::generate(&mut rand::thread_rng());
        let sig = keypair.sign(b"test");

        let bytes = sig.to_bytes();
        let restored = Secp256k1Signature::from_bytes(&bytes).unwrap();
        assert_eq!(sig.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_public_key_json_serialization() {
        let keypair = Secp256k1KeyPair::generate(&mut rand::thread_rng());

        // JSON roundtrip
        let json = serde_json::to_string(&keypair.public_key).unwrap();
        let restored: Secp256k1PublicKey = serde_json::from_str(&json).unwrap();
        assert_eq!(keypair.public_key.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_signature_json_serialization() {
        let keypair = Secp256k1KeyPair::generate(&mut rand::thread_rng());
        let sig = keypair.sign(b"test");

        // JSON roundtrip
        let json = serde_json::to_string(&sig).unwrap();
        let restored: Secp256k1Signature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_public_key_bincode_roundtrip() {
        let keypair = Secp256k1KeyPair::generate(&mut rand::thread_rng());

        // Bincode roundtrip
        let encoded = bincode::serialize(&keypair.public_key).unwrap();
        let decoded: Secp256k1PublicKey = bincode::deserialize(&encoded).unwrap();
        assert_eq!(keypair.public_key.to_bytes(), decoded.to_bytes());
    }

    #[test]
    fn test_signature_bincode_roundtrip() {
        let keypair = Secp256k1KeyPair::generate(&mut rand::thread_rng());
        let sig = keypair.sign(b"test message");

        // Bincode roundtrip
        let encoded = bincode::serialize(&sig).unwrap();
        let decoded: Secp256k1Signature = bincode::deserialize(&encoded).unwrap();
        assert_eq!(sig.to_bytes(), decoded.to_bytes());
    }
}
