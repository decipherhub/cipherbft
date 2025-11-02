//! Car data availability proof module for Autobahn BFT Layer 1.
//!
//! Cars represent parallel data dissemination lanes in Autobahn BFT.
//! Each validator maintains their own car lane for broadcasting transactions.

use chrono::{DateTime, Utc};
use crypto::hash;
use serde::{Deserialize, Serialize};
use types::{CarMetadata, Hash};

/// A Car in the Autobahn BFT protocol.
///
/// Cars are validator-specific data dissemination lanes that carry
/// transaction batches in parallel.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Car {
    /// Car metadata.
    pub metadata: CarMetadata,
    /// Transactions in this car.
    pub transactions: Vec<Vec<u8>>,
    /// Hash of this car (for verification).
    pub hash: Hash,
}

impl Car {
    /// Create a new car.
    pub fn new(
        car_id: u64,
        sequence: u64,
        transactions: Vec<Vec<u8>>,
        previous_car_hash: Hash,
        timestamp: DateTime<Utc>,
    ) -> Self {
        let metadata = CarMetadata::new(car_id, sequence, previous_car_hash, timestamp);

        // Compute car hash
        let hash = Self::compute_hash(&metadata, &transactions);

        Self {
            metadata,
            transactions,
            hash,
        }
    }

    /// Compute the hash of a car.
    fn compute_hash(metadata: &CarMetadata, transactions: &[Vec<u8>]) -> Hash {
        use crypto::merkle_root_from_txs;

        // Hash combines metadata and transaction merkle root
        let mut data = Vec::new();

        // Add car_id
        data.extend_from_slice(&metadata.car_id.to_be_bytes());

        // Add sequence
        data.extend_from_slice(&metadata.sequence.to_be_bytes());

        // Add previous hash
        data.extend_from_slice(metadata.previous_car_hash.as_bytes());

        // Add timestamp (as unix timestamp)
        data.extend_from_slice(&metadata.timestamp.timestamp().to_be_bytes());

        // Add transaction merkle root
        let tx_refs: Vec<&[u8]> = transactions.iter().map(|t| t.as_slice()).collect();
        let tx_root = merkle_root_from_txs(&tx_refs);
        data.extend_from_slice(&tx_root);

        Hash::from(hash(&data))
    }

    /// Verify the car hash is correct.
    pub fn verify_hash(&self) -> bool {
        let computed = Self::compute_hash(&self.metadata, &self.transactions);
        computed == self.hash
    }

    /// Get car ID.
    pub fn car_id(&self) -> u64 {
        self.metadata.car_id
    }

    /// Get sequence number.
    pub fn sequence(&self) -> u64 {
        self.metadata.sequence
    }

    /// Get number of transactions.
    pub fn tx_count(&self) -> usize {
        self.transactions.len()
    }

    /// Check if car is empty.
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }
}

/// Builder for creating Cars.
pub struct CarBuilder {
    car_id: u64,
    sequence: u64,
    transactions: Vec<Vec<u8>>,
    previous_car_hash: Hash,
    max_tx_count: usize,
    max_size_bytes: usize,
    current_size: usize,
}

impl CarBuilder {
    /// Create a new car builder.
    pub fn new(car_id: u64, sequence: u64, previous_car_hash: Hash) -> Self {
        Self {
            car_id,
            sequence,
            transactions: Vec::new(),
            previous_car_hash,
            max_tx_count: 1000,
            max_size_bytes: 1024 * 1024, // 1 MB default
            current_size: 0,
        }
    }

    /// Set maximum transaction count.
    pub fn with_max_tx_count(mut self, max: usize) -> Self {
        self.max_tx_count = max;
        self
    }

    /// Set maximum size in bytes.
    pub fn with_max_size(mut self, max: usize) -> Self {
        self.max_size_bytes = max;
        self
    }

    /// Add a transaction to the car.
    ///
    /// Returns false if the transaction would exceed limits.
    pub fn add_transaction(&mut self, tx: Vec<u8>) -> bool {
        let tx_size = tx.len();

        // Check limits
        if self.transactions.len() >= self.max_tx_count {
            return false;
        }

        if self.current_size + tx_size > self.max_size_bytes {
            return false;
        }

        self.transactions.push(tx);
        self.current_size += tx_size;
        true
    }

    /// Build the car.
    pub fn build(self, timestamp: DateTime<Utc>) -> Car {
        Car::new(
            self.car_id,
            self.sequence,
            self.transactions,
            self.previous_car_hash,
            timestamp,
        )
    }

    /// Get current transaction count.
    pub fn tx_count(&self) -> usize {
        self.transactions.len()
    }

    /// Check if the car is full.
    pub fn is_full(&self) -> bool {
        self.transactions.len() >= self.max_tx_count
            || self.current_size >= self.max_size_bytes
    }

    /// Check if the car has any transactions.
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_car_creation() {
        let car = Car::new(
            1,
            0,
            vec![vec![1, 2, 3], vec![4, 5, 6]],
            Hash::new([0; 32]),
            Utc::now(),
        );

        assert_eq!(car.car_id(), 1);
        assert_eq!(car.sequence(), 0);
        assert_eq!(car.tx_count(), 2);
        assert!(!car.is_empty());
    }

    #[test]
    fn test_car_hash_verification() {
        let car = Car::new(
            1,
            0,
            vec![vec![1, 2, 3]],
            Hash::new([0; 32]),
            Utc::now(),
        );

        assert!(car.verify_hash());
    }

    #[test]
    fn test_car_builder() {
        let mut builder = CarBuilder::new(1, 0, Hash::new([0; 32]))
            .with_max_tx_count(10)
            .with_max_size(100);

        assert!(builder.add_transaction(vec![1, 2, 3]));
        assert!(builder.add_transaction(vec![4, 5, 6]));
        assert_eq!(builder.tx_count(), 2);

        let car = builder.build(Utc::now());
        assert_eq!(car.tx_count(), 2);
        assert!(car.verify_hash());
    }

    #[test]
    fn test_car_builder_max_tx_limit() {
        let mut builder = CarBuilder::new(1, 0, Hash::new([0; 32]))
            .with_max_tx_count(2);

        assert!(builder.add_transaction(vec![1]));
        assert!(builder.add_transaction(vec![2]));
        assert!(builder.is_full());
        assert!(!builder.add_transaction(vec![3])); // Should fail

        assert_eq!(builder.tx_count(), 2);
    }

    #[test]
    fn test_car_builder_max_size_limit() {
        let mut builder = CarBuilder::new(1, 0, Hash::new([0; 32]))
            .with_max_size(10);

        assert!(builder.add_transaction(vec![1, 2, 3]));
        assert!(builder.add_transaction(vec![4, 5, 6]));

        // This should fail as it would exceed 10 bytes
        assert!(!builder.add_transaction(vec![7, 8, 9, 10, 11]));

        assert_eq!(builder.tx_count(), 2);
    }

    #[test]
    fn test_empty_car() {
        let builder = CarBuilder::new(1, 0, Hash::new([0; 32]));
        assert!(builder.is_empty());

        let car = builder.build(Utc::now());
        assert!(car.is_empty());
        assert_eq!(car.tx_count(), 0);
    }

    #[test]
    fn test_car_sequence() {
        let car1 = Car::new(1, 0, vec![], Hash::new([0; 32]), Utc::now());
        let car2 = Car::new(1, 1, vec![], car1.hash, Utc::now());
        let car3 = Car::new(1, 2, vec![], car2.hash, Utc::now());

        assert_eq!(car1.sequence(), 0);
        assert_eq!(car2.sequence(), 1);
        assert_eq!(car3.sequence(), 2);
        assert_eq!(car2.metadata.previous_car_hash, car1.hash);
        assert_eq!(car3.metadata.previous_car_hash, car2.hash);
    }
}
