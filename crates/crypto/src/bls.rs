//! BLS12-381 cryptographic operations for DCL
//!
//! This module provides BLS12-381 signatures with:
//! - Domain separation tags for Car and Attestation signing
//! - Signature aggregation for f+1 attestation threshold
//! - min_pk variant (smaller public keys, larger signatures)

use crate::error::BlsError;
use blst::min_pk::{
    AggregateSignature as BlstAggSig, PublicKey as BlstPubKey, SecretKey as BlstSecKey,
    Signature as BlstSig,
};
use blst::BLST_ERROR;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain separation tag for Car signing
pub const DST_CAR: &[u8] = b"CIPHERBFT_CAR_V1";

/// Domain separation tag for Attestation signing
pub const DST_ATTESTATION: &[u8] = b"CIPHERBFT_ATTESTATION_V1";

/// BLS12-381 secret key (32 bytes)
#[derive(Clone)]
pub struct BlsSecretKey(BlstSecKey);

impl BlsSecretKey {
    /// Generate a new random secret key
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let mut ikm = [0u8; 32];
        rng.fill_bytes(&mut ikm);
        Self::from_seed(&ikm)
    }

    /// Derive from seed bytes (32 bytes, uses key derivation)
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let sk = BlstSecKey::key_gen(seed, &[]).expect("seed is valid length");
        Self(sk)
    }

    /// Load from raw bytes (32 bytes scalar)
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, BlsError> {
        BlstSecKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| BlsError::InvalidSecretKey)
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Get the corresponding public key
    pub fn public_key(&self) -> BlsPublicKey {
        BlsPublicKey(self.0.sk_to_pk())
    }

    /// Sign a message with domain separation
    pub fn sign(&self, msg: &[u8], dst: &[u8]) -> BlsSignature {
        let sig = self.0.sign(msg, dst, &[]);
        BlsSignature(sig)
    }
}

impl std::fmt::Debug for BlsSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlsSecretKey")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// BLS12-381 public key (48 bytes compressed)
#[derive(Clone, PartialEq, Eq)]
pub struct BlsPublicKey(BlstPubKey);

impl BlsPublicKey {
    /// Load from bytes (48 bytes compressed)
    pub fn from_bytes(bytes: &[u8; 48]) -> Result<Self, BlsError> {
        BlstPubKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| BlsError::InvalidPublicKey)
    }

    /// Serialize to bytes (48 bytes compressed)
    pub fn to_bytes(&self) -> [u8; 48] {
        self.0.to_bytes()
    }

    /// Verify a signature
    pub fn verify(&self, msg: &[u8], dst: &[u8], sig: &BlsSignature) -> bool {
        sig.0.verify(true, msg, dst, &[], &self.0, true) == BLST_ERROR::BLST_SUCCESS
    }

    /// Get a hash of this public key (for ValidatorId derivation)
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.to_bytes());
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        bytes
    }
}

impl std::fmt::Debug for BlsPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = self.to_bytes();
        write!(f, "BlsPublicKey({})", hex::encode(&bytes[..8]))
    }
}

impl Serialize for BlsPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeTuple;

        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(self.to_bytes()))
        } else {
            // Use serialize_tuple to match deserialize_tuple (no length prefix)
            let bytes = self.to_bytes();
            let mut tuple = serializer.serialize_tuple(48)?;
            for byte in bytes {
                tuple.serialize_element(&byte)?;
            }
            tuple.end()
        }
    }
}

impl<'de> Deserialize<'de> for BlsPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{SeqAccess, Visitor};

        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
            if bytes.len() != 48 {
                return Err(serde::de::Error::custom("invalid public key length"));
            }
            let mut arr = [0u8; 48];
            arr.copy_from_slice(&bytes);
            Self::from_bytes(&arr).map_err(serde::de::Error::custom)
        } else {
            // Use a visitor for fixed-size array deserialization
            struct ArrayVisitor;

            impl<'de> Visitor<'de> for ArrayVisitor {
                type Value = [u8; 48];

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("48 bytes")
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: SeqAccess<'de>,
                {
                    let mut arr = [0u8; 48];
                    for (i, byte) in arr.iter_mut().enumerate() {
                        *byte = seq
                            .next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                    }
                    Ok(arr)
                }
            }

            let arr = deserializer.deserialize_tuple(48, ArrayVisitor)?;
            Self::from_bytes(&arr).map_err(serde::de::Error::custom)
        }
    }
}

/// BLS12-381 signature (96 bytes)
#[derive(Clone)]
pub struct BlsSignature(pub(crate) BlstSig);

impl BlsSignature {
    /// Load from bytes (96 bytes)
    pub fn from_bytes(bytes: &[u8; 96]) -> Result<Self, BlsError> {
        BlstSig::from_bytes(bytes)
            .map(Self)
            .map_err(|_| BlsError::InvalidSignature)
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; 96] {
        self.0.to_bytes()
    }

    /// Verify signature against public key
    pub fn verify(&self, msg: &[u8], dst: &[u8], pubkey: &BlsPublicKey) -> bool {
        self.0.verify(true, msg, dst, &[], &pubkey.0, true) == BLST_ERROR::BLST_SUCCESS
    }

    /// Get the inner blst signature for aggregation
    pub fn inner(&self) -> &BlstSig {
        &self.0
    }
}

impl Default for BlsSignature {
    fn default() -> Self {
        // Zero signature (invalid, used as placeholder)
        Self(BlstSig::from_bytes(&[0u8; 96]).unwrap_or_else(|_| {
            // If zero bytes don't work, create a valid but meaningless signature
            let sk = BlsSecretKey::from_seed(&[0u8; 32]);
            sk.sign(&[], DST_CAR).0
        }))
    }
}

impl std::fmt::Debug for BlsSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = self.to_bytes();
        write!(f, "BlsSignature({})", hex::encode(&bytes[..8]))
    }
}

impl PartialEq for BlsSignature {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for BlsSignature {}

impl Serialize for BlsSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeTuple;

        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(self.to_bytes()))
        } else {
            // Use serialize_tuple to match deserialize_tuple (no length prefix)
            let bytes = self.to_bytes();
            let mut tuple = serializer.serialize_tuple(96)?;
            for byte in bytes {
                tuple.serialize_element(&byte)?;
            }
            tuple.end()
        }
    }
}

impl<'de> Deserialize<'de> for BlsSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{SeqAccess, Visitor};

        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
            if bytes.len() != 96 {
                return Err(serde::de::Error::custom("invalid signature length"));
            }
            let mut arr = [0u8; 96];
            arr.copy_from_slice(&bytes);
            Self::from_bytes(&arr).map_err(serde::de::Error::custom)
        } else {
            // Use a visitor for fixed-size array deserialization
            struct ArrayVisitor;

            impl<'de> Visitor<'de> for ArrayVisitor {
                type Value = [u8; 96];

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("96 bytes")
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: SeqAccess<'de>,
                {
                    let mut arr = [0u8; 96];
                    for (i, byte) in arr.iter_mut().enumerate() {
                        *byte = seq
                            .next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                    }
                    Ok(arr)
                }
            }

            let arr = deserializer.deserialize_tuple(96, ArrayVisitor)?;
            Self::from_bytes(&arr).map_err(serde::de::Error::custom)
        }
    }
}

/// Aggregated BLS12-381 signature
#[derive(Clone)]
pub struct BlsAggregateSignature(BlstAggSig);

impl BlsAggregateSignature {
    /// Aggregate multiple signatures into one
    /// All signatures must be over the same message for verification to work
    pub fn aggregate(signatures: &[&BlsSignature]) -> Result<Self, BlsError> {
        if signatures.is_empty() {
            return Err(BlsError::EmptyAggregation);
        }

        let sigs: Vec<&BlstSig> = signatures.iter().map(|s| &s.0).collect();
        BlstAggSig::aggregate(&sigs, true)
            .map(Self)
            .map_err(|_| BlsError::AggregationFailed)
    }

    /// Create from a single signature
    pub fn from_signature(sig: &BlsSignature) -> Self {
        let agg = BlstAggSig::from_signature(&sig.0);
        Self(agg)
    }

    /// Add another signature to the aggregate
    pub fn add(&mut self, sig: &BlsSignature) -> Result<(), BlsError> {
        self.0
            .add_signature(&sig.0, true)
            .map_err(|_| BlsError::AggregationFailed)
    }

    /// Verify aggregate signature against multiple public keys
    /// All signers must have signed the same message
    pub fn verify_same_message(&self, msg: &[u8], dst: &[u8], pubkeys: &[&BlsPublicKey]) -> bool {
        if pubkeys.is_empty() {
            return false;
        }

        let pks: Vec<&BlstPubKey> = pubkeys.iter().map(|p| &p.0).collect();
        let sig = self.0.to_signature();

        // For same-message verification, we use aggregate_verify with repeated messages
        let msgs: Vec<&[u8]> = vec![msg; pubkeys.len()];

        sig.aggregate_verify(true, &msgs, dst, &pks, true) == BLST_ERROR::BLST_SUCCESS
    }

    /// Convert to final signature
    pub fn to_signature(&self) -> BlsSignature {
        BlsSignature(self.0.to_signature())
    }

    /// Load from bytes (96 bytes)
    pub fn from_bytes(bytes: &[u8; 96]) -> Result<Self, BlsError> {
        let sig = BlstSig::from_bytes(bytes).map_err(|_| BlsError::InvalidSignature)?;
        Ok(Self(BlstAggSig::from_signature(&sig)))
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; 96] {
        self.0.to_signature().to_bytes()
    }
}

impl std::fmt::Debug for BlsAggregateSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = self.to_bytes();
        write!(f, "BlsAggregateSignature({})", hex::encode(&bytes[..8]))
    }
}

impl Serialize for BlsAggregateSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeTuple;

        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(self.to_bytes()))
        } else {
            // Use serialize_tuple to match deserialize_tuple (no length prefix)
            let bytes = self.to_bytes();
            let mut tuple = serializer.serialize_tuple(96)?;
            for byte in bytes {
                tuple.serialize_element(&byte)?;
            }
            tuple.end()
        }
    }
}

impl<'de> Deserialize<'de> for BlsAggregateSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{SeqAccess, Visitor};

        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
            if bytes.len() != 96 {
                return Err(serde::de::Error::custom(
                    "invalid aggregate signature length",
                ));
            }
            let mut arr = [0u8; 96];
            arr.copy_from_slice(&bytes);
            Self::from_bytes(&arr).map_err(serde::de::Error::custom)
        } else {
            // Use a visitor for fixed-size array deserialization
            struct ArrayVisitor;

            impl<'de> Visitor<'de> for ArrayVisitor {
                type Value = [u8; 96];

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("96 bytes")
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: SeqAccess<'de>,
                {
                    let mut arr = [0u8; 96];
                    for (i, byte) in arr.iter_mut().enumerate() {
                        *byte = seq
                            .next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                    }
                    Ok(arr)
                }
            }

            let arr = deserializer.deserialize_tuple(96, ArrayVisitor)?;
            Self::from_bytes(&arr).map_err(serde::de::Error::custom)
        }
    }
}

/// BLS key pair (convenience wrapper)
#[derive(Clone)]
pub struct BlsKeyPair {
    pub secret_key: BlsSecretKey,
    pub public_key: BlsPublicKey,
}

impl BlsKeyPair {
    /// Generate a new random key pair
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let secret_key = BlsSecretKey::generate(rng);
        let public_key = secret_key.public_key();
        Self {
            secret_key,
            public_key,
        }
    }

    /// Create from secret key
    pub fn from_secret_key(secret_key: BlsSecretKey) -> Self {
        let public_key = secret_key.public_key();
        Self {
            secret_key,
            public_key,
        }
    }

    /// Sign a Car
    pub fn sign_car(&self, car_bytes: &[u8]) -> BlsSignature {
        self.secret_key.sign(car_bytes, DST_CAR)
    }

    /// Sign an attestation
    pub fn sign_attestation(&self, attestation_bytes: &[u8]) -> BlsSignature {
        self.secret_key.sign(attestation_bytes, DST_ATTESTATION)
    }
}

impl std::fmt::Debug for BlsKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlsKeyPair")
            .field("public_key", &self.public_key)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let keypair = BlsKeyPair::generate(&mut rand::thread_rng());
        let bytes = keypair.public_key.to_bytes();
        let restored = BlsPublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(keypair.public_key.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_sign_verify_car() {
        let keypair = BlsKeyPair::generate(&mut rand::thread_rng());
        let msg = b"test car data";
        let sig = keypair.sign_car(msg);
        assert!(keypair.public_key.verify(msg, DST_CAR, &sig));
    }

    #[test]
    fn test_sign_verify_attestation() {
        let keypair = BlsKeyPair::generate(&mut rand::thread_rng());
        let msg = b"test attestation data";
        let sig = keypair.sign_attestation(msg);
        assert!(keypair.public_key.verify(msg, DST_ATTESTATION, &sig));
    }

    #[test]
    fn test_domain_separation() {
        let keypair = BlsKeyPair::generate(&mut rand::thread_rng());
        let msg = b"same message";

        // Sign with CAR DST
        let car_sig = keypair.sign_car(msg);

        // Should NOT verify with ATTESTATION DST
        assert!(!keypair.public_key.verify(msg, DST_ATTESTATION, &car_sig));

        // Should verify with CAR DST
        assert!(keypair.public_key.verify(msg, DST_CAR, &car_sig));
    }

    #[test]
    fn test_signature_aggregation() {
        let keypairs: Vec<_> = (0..5)
            .map(|_| BlsKeyPair::generate(&mut rand::thread_rng()))
            .collect();

        let msg = b"same message for all";
        let sigs: Vec<_> = keypairs.iter().map(|kp| kp.sign_attestation(msg)).collect();
        let sig_refs: Vec<_> = sigs.iter().collect();

        let agg = BlsAggregateSignature::aggregate(&sig_refs).unwrap();

        let pubkeys: Vec<_> = keypairs.iter().map(|kp| &kp.public_key).collect();
        assert!(agg.verify_same_message(msg, DST_ATTESTATION, &pubkeys));
    }

    #[test]
    fn test_aggregate_wrong_message() {
        let keypairs: Vec<_> = (0..3)
            .map(|_| BlsKeyPair::generate(&mut rand::thread_rng()))
            .collect();

        let msg = b"correct message";
        let sigs: Vec<_> = keypairs.iter().map(|kp| kp.sign_attestation(msg)).collect();
        let sig_refs: Vec<_> = sigs.iter().collect();

        let agg = BlsAggregateSignature::aggregate(&sig_refs).unwrap();

        let pubkeys: Vec<_> = keypairs.iter().map(|kp| &kp.public_key).collect();

        // Should fail with wrong message
        assert!(!agg.verify_same_message(b"wrong message", DST_ATTESTATION, &pubkeys));
    }

    #[test]
    fn test_empty_aggregation_fails() {
        let result = BlsAggregateSignature::aggregate(&[]);
        assert!(matches!(result, Err(BlsError::EmptyAggregation)));
    }

    #[test]
    fn test_signature_serialization() {
        let keypair = BlsKeyPair::generate(&mut rand::thread_rng());
        let sig = keypair.sign_car(b"test");

        let bytes = sig.to_bytes();
        let restored = BlsSignature::from_bytes(&bytes).unwrap();
        assert_eq!(sig.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_pubkey_hash() {
        let keypair1 = BlsKeyPair::generate(&mut rand::thread_rng());
        let keypair2 = BlsKeyPair::generate(&mut rand::thread_rng());

        // Different keys should have different hashes
        assert_ne!(keypair1.public_key.hash(), keypair2.public_key.hash());

        // Same key should have same hash
        let hash1 = keypair1.public_key.hash();
        let hash2 = keypair1.public_key.hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_signature_bincode_roundtrip() {
        let keypair = BlsKeyPair::generate(&mut rand::thread_rng());
        let sig = keypair.sign_car(b"test message");

        // Debug: Check original signature bytes
        let orig_bytes = sig.to_bytes();
        println!("Original sig bytes len: {}", orig_bytes.len());
        println!("Original sig first 8 bytes: {:?}", &orig_bytes[..8]);

        // Test bincode serialization/deserialization
        let encoded = bincode::serialize(&sig).unwrap();
        println!("Encoded len: {}", encoded.len());
        println!(
            "Encoded first 16 bytes: {:?}",
            &encoded[..16.min(encoded.len())]
        );

        let decoded: BlsSignature = bincode::deserialize(&encoded).unwrap();

        assert_eq!(sig.to_bytes(), decoded.to_bytes());
    }

    #[test]
    fn test_pubkey_bincode_roundtrip() {
        let keypair = BlsKeyPair::generate(&mut rand::thread_rng());

        // Test bincode serialization/deserialization
        let encoded = bincode::serialize(&keypair.public_key).unwrap();
        let decoded: BlsPublicKey = bincode::deserialize(&encoded).unwrap();

        assert_eq!(keypair.public_key.to_bytes(), decoded.to_bytes());
    }
}
