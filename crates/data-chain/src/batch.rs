//! Transaction batch types for DCL Workers

use cipherbft_types::Hash;
use serde::{Deserialize, Serialize};

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

/// Full transaction batch (stored by Workers)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Batch {
    /// Worker that created this batch
    pub worker_id: u8,
    /// Raw transaction data
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
