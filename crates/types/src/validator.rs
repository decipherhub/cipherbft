//! Validator identifier type for CipherBFT
//!
//! ValidatorId is a 20-byte Ethereum address format derived from Ed25519 public key.
//! This matches Malachite's address format for Consensus Layer compatibility.
//!
//! Derivation: `keccak256(ed25519_pubkey)[12..]` (last 20 bytes)

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::fmt;
use std::io::{Read, Write};

/// Size of ValidatorId in bytes (Ethereum address format)
pub const VALIDATOR_ID_SIZE: usize = 20;

/// Unique identifier for a validator (20 bytes, Ethereum address format)
///
/// Derived from Ed25519 public key via `keccak256(pubkey)[12..]`
/// This matches Malachite's address derivation for CL compatibility.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default, Serialize, Deserialize)]
pub struct ValidatorId(#[serde(with = "hex_bytes")] pub [u8; VALIDATOR_ID_SIZE]);

impl BorshSerialize for ValidatorId {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.0)
    }
}

impl BorshDeserialize for ValidatorId {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut bytes = [0u8; VALIDATOR_ID_SIZE];
        reader.read_exact(&mut bytes)?;
        Ok(Self(bytes))
    }
}

impl ValidatorId {
    /// Zero validator ID (invalid, used as placeholder)
    pub const ZERO: Self = Self([0u8; VALIDATOR_ID_SIZE]);

    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; VALIDATOR_ID_SIZE]) -> Self {
        Self(bytes)
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; VALIDATOR_ID_SIZE] {
        &self.0
    }

    /// Convert to byte slice
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Create from a byte slice (must be exactly 20 bytes)
    pub fn try_from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() == VALIDATOR_ID_SIZE {
            let mut bytes = [0u8; VALIDATOR_ID_SIZE];
            bytes.copy_from_slice(slice);
            Some(Self(bytes))
        } else {
            None
        }
    }

    /// Derive ValidatorId from Ed25519 public key bytes (32 bytes)
    ///
    /// Uses keccak256 hash and takes the last 20 bytes (Ethereum address format).
    /// This matches Malachite's address derivation for CL compatibility.
    ///
    /// # Arguments
    /// * `pubkey` - 32-byte Ed25519 public key
    ///
    /// # Returns
    /// 20-byte ValidatorId derived as `keccak256(pubkey)[12..]`
    pub fn from_ed25519_pubkey(pubkey: &[u8; 32]) -> Self {
        let hash = Keccak256::digest(pubkey);
        let mut bytes = [0u8; VALIDATOR_ID_SIZE];
        // Take last 20 bytes of keccak256 hash (bytes 12..32)
        bytes.copy_from_slice(&hash[12..]);
        Self(bytes)
    }
}

impl AsRef<[u8]> for ValidatorId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ValidatorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ValidatorId(0x{})", hex::encode(self.0))
    }
}

impl fmt::Display for ValidatorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Display as 0x-prefixed hex (Ethereum address style)
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl From<[u8; VALIDATOR_ID_SIZE]> for ValidatorId {
    fn from(bytes: [u8; VALIDATOR_ID_SIZE]) -> Self {
        Self(bytes)
    }
}

/// Hex serialization helper for 20-byte arrays
mod hex_bytes {
    use super::VALIDATOR_ID_SIZE;
    use serde::de::{SeqAccess, Visitor};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; VALIDATOR_ID_SIZE], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeTuple;

        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(bytes))
        } else {
            // Use serialize_tuple to match deserialize_tuple (no length prefix)
            let mut tuple = serializer.serialize_tuple(VALIDATOR_ID_SIZE)?;
            for byte in bytes {
                tuple.serialize_element(byte)?;
            }
            tuple.end()
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; VALIDATOR_ID_SIZE], D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
            bytes.try_into().map_err(|_| {
                serde::de::Error::custom("invalid validator id length (expected 20 bytes)")
            })
        } else {
            // Use a visitor for fixed-size array deserialization
            struct ArrayVisitor;

            impl<'de> Visitor<'de> for ArrayVisitor {
                type Value = [u8; VALIDATOR_ID_SIZE];

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("20 bytes")
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: SeqAccess<'de>,
                {
                    let mut arr = [0u8; VALIDATOR_ID_SIZE];
                    for (i, byte) in arr.iter_mut().enumerate() {
                        *byte = seq
                            .next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                    }
                    Ok(arr)
                }
            }

            deserializer.deserialize_tuple(VALIDATOR_ID_SIZE, ArrayVisitor)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validator_id_ordering() {
        let v1 = ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]);
        let v2 = ValidatorId::from_bytes([2u8; VALIDATOR_ID_SIZE]);
        assert!(v1 < v2);
    }

    #[test]
    fn test_validator_id_display() {
        let v = ValidatorId::from_bytes([0xab; VALIDATOR_ID_SIZE]);
        let s = v.to_string();
        // Should be 0x-prefixed full address
        assert_eq!(s, "0xabababababababababababababababababababab");
    }

    #[test]
    fn test_validator_id_debug() {
        let v = ValidatorId::from_bytes([0x12; VALIDATOR_ID_SIZE]);
        let s = format!("{:?}", v);
        assert_eq!(s, "ValidatorId(0x1212121212121212121212121212121212121212)");
    }

    #[test]
    fn test_try_from_slice() {
        let bytes = [42u8; VALIDATOR_ID_SIZE];
        let v = ValidatorId::try_from_slice(&bytes).unwrap();
        assert_eq!(v.as_bytes(), &bytes);

        // Invalid length (old 32-byte format should fail)
        assert!(ValidatorId::try_from_slice(&[1u8; 32]).is_none());

        // Invalid length (too short)
        assert!(ValidatorId::try_from_slice(&[1, 2, 3]).is_none());
    }

    #[test]
    fn test_from_ed25519_pubkey() {
        // Create a test Ed25519 public key (32 bytes)
        let ed25519_pubkey = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];

        let validator_id = ValidatorId::from_ed25519_pubkey(&ed25519_pubkey);

        // Verify we get 20 bytes back
        assert_eq!(validator_id.as_bytes().len(), VALIDATOR_ID_SIZE);

        // Verify deterministic derivation
        let validator_id2 = ValidatorId::from_ed25519_pubkey(&ed25519_pubkey);
        assert_eq!(validator_id, validator_id2);

        // Different pubkeys should produce different IDs
        let different_pubkey = [0xffu8; 32];
        let different_id = ValidatorId::from_ed25519_pubkey(&different_pubkey);
        assert_ne!(validator_id, different_id);
    }

    #[test]
    fn test_validator_id_zero() {
        let zero = ValidatorId::ZERO;
        assert_eq!(zero.as_bytes(), &[0u8; VALIDATOR_ID_SIZE]);
        assert_eq!(
            zero.to_string(),
            "0x0000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn test_validator_id_size_constant() {
        assert_eq!(VALIDATOR_ID_SIZE, 20);
    }

    #[test]
    fn test_json_serialization() {
        let v = ValidatorId::from_bytes([0xab; VALIDATOR_ID_SIZE]);
        let json = serde_json::to_string(&v).unwrap();
        // Should serialize as hex string
        assert!(json.contains("abababab"));

        // Roundtrip
        let v2: ValidatorId = serde_json::from_str(&json).unwrap();
        assert_eq!(v, v2);
    }
}
