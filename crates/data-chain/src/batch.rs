//! Transaction batch types for DCL Workers
//!
//! # Security
//!
//! The [`Batch`] type implements bounded deserialization to prevent OOM attacks.
//! Transaction count and individual transaction sizes are limited to prevent
//! malicious peers from causing memory exhaustion.

use crate::error::{MAX_TRANSACTIONS_PER_BATCH, MAX_TRANSACTION_SIZE};
use cipherbft_types::Hash;
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

/// Raw transaction data
pub type Transaction = Vec<u8>;

/// Metadata about a transaction batch created by a Worker
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchDigest {
    /// Worker that created this batch (0-7)
    pub worker_id: u8,
    /// SHA-256 hash of the batch contents
    pub digest: Hash,
    /// Number of transactions in the batch
    pub tx_count: u32,
    /// Total byte size of the batch
    pub byte_size: u32,
}

impl BatchDigest {
    /// Create a new batch digest
    pub fn new(worker_id: u8, digest: Hash, tx_count: u32, byte_size: u32) -> Self {
        Self {
            worker_id,
            digest,
            tx_count,
            byte_size,
        }
    }

    /// Canonical serialization for inclusion in Car signing bytes
    /// Format: worker_id (1) || digest (32) || tx_count (4) || byte_size (4) = 41 bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(41);
        buf.push(self.worker_id);
        buf.extend_from_slice(self.digest.as_bytes());
        buf.extend_from_slice(&self.tx_count.to_le_bytes());
        buf.extend_from_slice(&self.byte_size.to_le_bytes());
        buf
    }
}

/// Deserialize a Vec<Transaction> with bounds checking to prevent OOM attacks.
fn deserialize_bounded_transactions<'de, D>(deserializer: D) -> Result<Vec<Transaction>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedTransactionVecVisitor;

    impl<'de> Visitor<'de> for BoundedTransactionVecVisitor {
        type Value = Vec<Transaction>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(
                formatter,
                "a sequence of at most {} transactions, each at most {} bytes",
                MAX_TRANSACTIONS_PER_BATCH, MAX_TRANSACTION_SIZE
            )
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            // Check size hint to reject early
            if let Some(size) = seq.size_hint() {
                if size > MAX_TRANSACTIONS_PER_BATCH {
                    return Err(serde::de::Error::custom(format!(
                        "transaction count {} exceeds maximum of {}",
                        size, MAX_TRANSACTIONS_PER_BATCH
                    )));
                }
            }

            let capacity = seq.size_hint().unwrap_or(0).min(MAX_TRANSACTIONS_PER_BATCH);
            let mut transactions = Vec::with_capacity(capacity);

            while let Some(tx) = seq.next_element::<Transaction>()? {
                if transactions.len() >= MAX_TRANSACTIONS_PER_BATCH {
                    return Err(serde::de::Error::custom(format!(
                        "transaction count exceeds maximum of {}",
                        MAX_TRANSACTIONS_PER_BATCH
                    )));
                }
                if tx.len() > MAX_TRANSACTION_SIZE {
                    return Err(serde::de::Error::custom(format!(
                        "transaction size {} exceeds maximum of {}",
                        tx.len(),
                        MAX_TRANSACTION_SIZE
                    )));
                }
                transactions.push(tx);
            }

            Ok(transactions)
        }
    }

    deserializer.deserialize_seq(BoundedTransactionVecVisitor)
}

/// Full transaction batch (stored by Workers)
///
/// # Security
///
/// This type implements bounded deserialization. When deserializing:
/// - Transaction count is limited to [`MAX_TRANSACTIONS_PER_BATCH`]
/// - Individual transaction size is limited to [`MAX_TRANSACTION_SIZE`]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Batch {
    /// Worker that created this batch
    pub worker_id: u8,
    /// Raw transaction data (bounded by MAX_TRANSACTIONS_PER_BATCH)
    #[serde(deserialize_with = "deserialize_bounded_transactions")]
    pub transactions: Vec<Transaction>,
    /// Creation timestamp (unix millis)
    pub timestamp: u64,
}

impl Batch {
    /// Create a new batch
    pub fn new(worker_id: u8, transactions: Vec<Transaction>, timestamp: u64) -> Self {
        Self {
            worker_id,
            transactions,
            timestamp,
        }
    }

    /// Compute the batch digest
    pub fn digest(&self) -> BatchDigest {
        let data = bincode::serialize(self).expect("batch serialization cannot fail");
        let byte_size = data.len() as u32;
        let digest = Hash::compute(&data);

        BatchDigest {
            worker_id: self.worker_id,
            digest,
            tx_count: self.transactions.len() as u32,
            byte_size,
        }
    }

    /// Check if batch is empty
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    /// Get total byte size of transactions
    pub fn total_bytes(&self) -> usize {
        self.transactions.iter().map(|tx| tx.len()).sum()
    }

    /// Compute hash of the batch (same as digest().digest)
    pub fn hash(&self) -> Hash {
        self.digest().digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_digest_to_bytes() {
        let digest = BatchDigest {
            worker_id: 1,
            digest: Hash::compute(b"test"),
            tx_count: 100,
            byte_size: 1024,
        };

        let bytes = digest.to_bytes();
        assert_eq!(bytes.len(), 41);
        assert_eq!(bytes[0], 1); // worker_id
    }

    #[test]
    fn test_batch_digest_deterministic() {
        let batch = Batch {
            worker_id: 0,
            transactions: vec![vec![1, 2, 3], vec![4, 5, 6]],
            timestamp: 12345,
        };

        let d1 = batch.digest();
        let d2 = batch.digest();
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_batch_digest_bytes_deterministic() {
        let digest = BatchDigest {
            worker_id: 2,
            digest: Hash::compute(b"data"),
            tx_count: 50,
            byte_size: 512,
        };

        let b1 = digest.to_bytes();
        let b2 = digest.to_bytes();
        assert_eq!(b1, b2);
    }

    #[test]
    fn test_empty_batch() {
        let batch = Batch::new(0, vec![], 0);
        assert!(batch.is_empty());
        assert_eq!(batch.total_bytes(), 0);
    }
}
