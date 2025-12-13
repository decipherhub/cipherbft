//! Validator identifier type for CipherBFT

use serde::{Deserialize, Serialize};
use std::fmt;

/// Unique identifier for a validator (32 bytes, derived from BLS public key hash)
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default, Serialize, Deserialize)]
pub struct ValidatorId(#[serde(with = "hex_bytes")] pub [u8; 32]);

impl ValidatorId {
    /// Zero validator ID (invalid, used as placeholder)
    pub const ZERO: Self = Self([0u8; 32]);

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

    /// Create from a byte slice (must be exactly 32 bytes)
    pub fn try_from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() == 32 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(slice);
            Some(Self(bytes))
        } else {
            None
        }
    }
}

impl AsRef<[u8]> for ValidatorId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ValidatorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ValidatorId({})", hex::encode(&self.0[..8]))
    }
}

impl fmt::Display for ValidatorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..8]))
    }
}

impl From<[u8; 32]> for ValidatorId {
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
                .map_err(|_| serde::de::Error::custom("invalid validator id length"))
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
    fn test_validator_id_ordering() {
        let v1 = ValidatorId::from_bytes([1u8; 32]);
        let v2 = ValidatorId::from_bytes([2u8; 32]);
        assert!(v1 < v2);
    }

    #[test]
    fn test_validator_id_display() {
        let v = ValidatorId::from_bytes([0xab; 32]);
        let s = v.to_string();
        assert_eq!(s, "abababababababab"); // First 8 bytes
    }

    #[test]
    fn test_try_from_slice() {
        let bytes = [42u8; 32];
        let v = ValidatorId::try_from_slice(&bytes).unwrap();
        assert_eq!(v.as_bytes(), &bytes);

        // Invalid length
        assert!(ValidatorId::try_from_slice(&[1, 2, 3]).is_none());
    }
}
