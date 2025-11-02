//! Proposal creation and validation for Autobahn BFT.
//!
//! Implements Cut proposals (Layer 2) which represent consensus
//! snapshots of all validator Cars.

use crate::car::Car;
use chrono::{DateTime, Utc};
use crypto::{hash, merkle_root};
use serde::{Deserialize, Serialize};
use types::{Block, BlockData, BlockHeader, CutMetadata, Hash, Height, Round};

/// A Cut proposal in Autobahn BFT (Layer 2).
///
/// Cuts represent consensus snapshots across all validator cars.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Cut {
    /// Cut metadata.
    pub metadata: CutMetadata,
    /// Cars included in this cut (one per validator).
    pub cars: Vec<Car>,
    /// Hash of this cut.
    pub hash: Hash,
}

impl Cut {
    /// Create a new cut from cars.
    pub fn new(
        cut_id: u64,
        round: Round,
        cars: Vec<Car>,
        timestamp: DateTime<Utc>,
    ) -> Self {
        let car_hashes: Vec<Hash> = cars.iter().map(|c| c.hash).collect();
        let metadata = CutMetadata::new(cut_id, car_hashes.clone(), round, timestamp);

        // Compute cut hash
        let hash = Self::compute_hash(&metadata, &cars);

        Self {
            metadata,
            cars,
            hash,
        }
    }

    /// Compute the hash of a cut.
    fn compute_hash(metadata: &CutMetadata, _cars: &[Car]) -> Hash {
        let mut data = Vec::new();

        // Add cut_id
        data.extend_from_slice(&metadata.cut_id.to_be_bytes());

        // Add round
        data.extend_from_slice(&metadata.round.value().to_be_bytes());

        // Add timestamp
        data.extend_from_slice(&metadata.timestamp.timestamp().to_be_bytes());

        // Add merkle root of car hashes
        let car_hash_bytes: Vec<[u8; 32]> = metadata.car_hashes.iter().map(|h| *h.as_bytes()).collect();
        let root = merkle_root(&car_hash_bytes);
        data.extend_from_slice(&root);

        Hash::from(hash(&data))
    }

    /// Verify cut hash is correct.
    pub fn verify_hash(&self) -> bool {
        let computed = Self::compute_hash(&self.metadata, &self.cars);
        computed == self.hash
    }

    /// Verify all cars in the cut.
    pub fn verify_cars(&self) -> bool {
        // Check car count matches metadata
        if self.cars.len() != self.metadata.car_hashes.len() {
            return false;
        }

        // Verify each car hash matches metadata
        for (i, car) in self.cars.iter().enumerate() {
            if car.hash != self.metadata.car_hashes[i] {
                return false;
            }

            // Verify car's internal hash
            if !car.verify_hash() {
                return false;
            }
        }

        true
    }

    /// Get all transactions from all cars in the cut.
    pub fn all_transactions(&self) -> Vec<Vec<u8>> {
        self.cars
            .iter()
            .flat_map(|car| car.transactions.clone())
            .collect()
    }

    /// Get total transaction count across all cars.
    pub fn total_tx_count(&self) -> usize {
        self.cars.iter().map(|car| car.tx_count()).sum()
    }

    /// Convert cut to a block.
    pub fn to_block(
        &self,
        height: Height,
        proposer: Vec<u8>,
        previous_hash: Hash,
        app_hash: Hash,
    ) -> Block {
        let transactions = self.all_transactions();

        // Compute transaction merkle root
        let tx_refs: Vec<&[u8]> = transactions.iter().map(|t| t.as_slice()).collect();
        let tx_merkle_root = Hash::from(crypto::merkle_root_from_txs(&tx_refs));

        let header = BlockHeader::new(
            height,
            self.hash,
            self.metadata.round,
            self.metadata.timestamp,
            proposer,
            previous_hash,
            app_hash,
            tx_merkle_root,
        );

        let data = BlockData::new(transactions);

        Block::new(
            header,
            data,
            None, // Car metadata will be added by consensus engine if needed
            Some(self.metadata.clone()),
            vec![], // Validator signatures added during voting
        )
    }
}

/// Builder for creating Cut proposals.
pub struct CutBuilder {
    cut_id: u64,
    round: Round,
    cars: Vec<Car>,
    max_cars: usize,
}

impl CutBuilder {
    /// Create a new cut builder.
    pub fn new(cut_id: u64, round: Round) -> Self {
        Self {
            cut_id,
            round,
            cars: Vec::new(),
            max_cars: 100, // Default max validators
        }
    }

    /// Set maximum number of cars.
    pub fn with_max_cars(mut self, max: usize) -> Self {
        self.max_cars = max;
        self
    }

    /// Add a car to the cut.
    ///
    /// Returns false if max cars reached.
    pub fn add_car(&mut self, car: Car) -> bool {
        if self.cars.len() >= self.max_cars {
            return false;
        }

        self.cars.push(car);
        true
    }

    /// Build the cut.
    pub fn build(self, timestamp: DateTime<Utc>) -> Cut {
        Cut::new(self.cut_id, self.round, self.cars, timestamp)
    }

    /// Get current car count.
    pub fn car_count(&self) -> usize {
        self.cars.len()
    }

    /// Check if cut is empty.
    pub fn is_empty(&self) -> bool {
        self.cars.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::car::CarBuilder;

    fn create_test_car(car_id: u64, sequence: u64, tx_count: usize) -> Car {
        let mut builder = CarBuilder::new(car_id, sequence, Hash::new([0; 32]));

        for i in 0..tx_count {
            builder.add_transaction(vec![i as u8]);
        }

        builder.build(Utc::now())
    }

    #[test]
    fn test_cut_creation() {
        let car1 = create_test_car(1, 0, 5);
        let car2 = create_test_car(2, 0, 3);

        let cut = Cut::new(
            0,
            Round::new(0),
            vec![car1.clone(), car2.clone()],
            Utc::now(),
        );

        assert_eq!(cut.metadata.cut_id, 0);
        assert_eq!(cut.metadata.car_hashes.len(), 2);
        assert_eq!(cut.cars.len(), 2);
        assert_eq!(cut.total_tx_count(), 8);
    }

    #[test]
    fn test_cut_hash_verification() {
        let car = create_test_car(1, 0, 2);
        let cut = Cut::new(0, Round::new(0), vec![car], Utc::now());

        assert!(cut.verify_hash());
        assert!(cut.verify_cars());
    }

    #[test]
    fn test_cut_all_transactions() {
        let car1 = create_test_car(1, 0, 2);
        let car2 = create_test_car(2, 0, 3);

        let cut = Cut::new(0, Round::new(0), vec![car1, car2], Utc::now());

        let all_txs = cut.all_transactions();
        assert_eq!(all_txs.len(), 5);
    }

    #[test]
    fn test_cut_to_block() {
        let car = create_test_car(1, 0, 3);
        let cut = Cut::new(0, Round::new(0), vec![car], Utc::now());

        let block = cut.to_block(
            Height::new(1).expect("valid height"),
            vec![1, 2, 3],
            Hash::new([0; 32]),
            Hash::new([1; 32]),
        );

        assert_eq!(block.height(), Height::new(1).expect("valid height"));
        assert_eq!(block.tx_count(), 3);
        assert!(block.cut_metadata.is_some());
    }

    #[test]
    fn test_cut_builder() {
        let mut builder = CutBuilder::new(0, Round::new(0))
            .with_max_cars(2);

        let car1 = create_test_car(1, 0, 2);
        let car2 = create_test_car(2, 0, 3);
        let car3 = create_test_car(3, 0, 1);

        assert!(builder.add_car(car1));
        assert!(builder.add_car(car2));
        assert!(!builder.add_car(car3)); // Should fail (max 2)

        assert_eq!(builder.car_count(), 2);

        let cut = builder.build(Utc::now());
        assert_eq!(cut.cars.len(), 2);
        assert!(cut.verify_hash());
    }

    #[test]
    fn test_empty_cut() {
        let builder = CutBuilder::new(0, Round::new(0));
        assert!(builder.is_empty());

        let cut = builder.build(Utc::now());
        assert_eq!(cut.cars.len(), 0);
        assert_eq!(cut.total_tx_count(), 0);
    }
}
