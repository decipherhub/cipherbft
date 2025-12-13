//! SHA-256 hash type for CipherBFT

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// SHA-256 hash (32 bytes)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct Hash(#[serde(with = "hex_bytes")] pub [u8; 32]);

impl Hash {
    /// Zero hash constant
    pub const ZERO: Self = Self([0u8; 32]);

    /// Compute SHA-256 hash of data
    pub fn compute(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Self(bytes)
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to byte slice
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({})", hex::encode(&self.0[..8]))
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl From<[u8; 32]> for Hash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Hex serialization helper for byte arrays
mod hex_bytes {
    use serde::de::{SeqAccess, Visitor};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeTuple;

        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(bytes))
        } else {
            // Use serialize_tuple to match deserialize_tuple (no length prefix)
            let mut tuple = serializer.serialize_tuple(32)?;
            for byte in bytes {
                tuple.serialize_element(byte)?;
            }
            tuple.end()
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
            bytes
                .try_into()
                .map_err(|_| serde::de::Error::custom("invalid hash length"))
        } else {
            // Use a visitor for fixed-size array deserialization
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

            deserializer.deserialize_tuple(32, ArrayVisitor)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_compute() {
        let data = b"hello world";
        let hash = Hash::compute(data);
        assert_ne!(hash, Hash::ZERO);
    }

    #[test]
    fn test_hash_deterministic() {
        let data = b"test data";
        let hash1 = Hash::compute(data);
        let hash2 = Hash::compute(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_display() {
        let hash = Hash::compute(b"test");
        let s = hash.to_string();
        assert_eq!(s.len(), 64); // 32 bytes * 2 hex chars
    }
}
