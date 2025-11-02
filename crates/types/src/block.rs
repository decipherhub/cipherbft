//! Block types for Autobahn BFT consensus.
//!
//! Blocks in CipherBFT combine traditional BFT block structure with
//! Autobahn's two-layer architecture (Cars for data dissemination,
//! Cuts for consensus ordering).

use crate::{Hash, Height, Round};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A blockchain block.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Block {
    /// Block header.
    pub header: BlockHeader,
    /// Block data.
    pub data: BlockData,
    /// Autobahn Car metadata.
    pub car_metadata: Option<CarMetadata>,
    /// Autobahn Cut metadata.
    pub cut_metadata: Option<CutMetadata>,
    /// Validator commit signatures.
    pub validator_signatures: Vec<ValidatorSignature>,
}

impl Block {
    /// Create a new block.
    pub fn new(
        header: BlockHeader,
        data: BlockData,
        car_metadata: Option<CarMetadata>,
        cut_metadata: Option<CutMetadata>,
        validator_signatures: Vec<ValidatorSignature>,
    ) -> Self {
        Self {
            header,
            data,
            car_metadata,
            cut_metadata,
            validator_signatures,
        }
    }

    /// Get the block height.
    pub fn height(&self) -> Height {
        self.header.height
    }

    /// Get the block hash.
    pub fn hash(&self) -> Hash {
        self.header.hash
    }

    /// Get the proposer address.
    pub fn proposer(&self) -> &[u8] {
        &self.header.proposer
    }

    /// Get the number of transactions.
    pub fn tx_count(&self) -> usize {
        self.data.transactions.len()
    }

    /// Check if block is finalized (has 2f+1 signatures).
    pub fn is_finalized(&self, total_voting_power: u64) -> bool {
        let signature_power: u64 = self.validator_signatures.iter().map(|s| s.voting_power).sum();
        let quorum = 2 * ((total_voting_power - 1) / 3) + 1;
        signature_power >= quorum
    }
}

/// Block header containing metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Block height.
    pub height: Height,
    /// Block hash.
    pub hash: Hash,
    /// Consensus round.
    pub round: Round,
    /// Block timestamp.
    pub timestamp: DateTime<Utc>,
    /// Proposer address.
    pub proposer: Vec<u8>,
    /// Previous block hash.
    pub previous_hash: Hash,
    /// Application state hash after executing this block.
    pub app_hash: Hash,
    /// Merkle root of transactions.
    pub tx_merkle_root: Hash,
}

impl BlockHeader {
    /// Create a new block header.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        height: Height,
        hash: Hash,
        round: Round,
        timestamp: DateTime<Utc>,
        proposer: Vec<u8>,
        previous_hash: Hash,
        app_hash: Hash,
        tx_merkle_root: Hash,
    ) -> Self {
        Self {
            height,
            hash,
            round,
            timestamp,
            proposer,
            previous_hash,
            app_hash,
            tx_merkle_root,
        }
    }
}

/// Block data containing transactions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockData {
    /// Transactions in this block.
    pub transactions: Vec<Vec<u8>>,
}

impl BlockData {
    /// Create new block data.
    pub fn new(transactions: Vec<Vec<u8>>) -> Self {
        Self { transactions }
    }

    /// Get transaction count.
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Check if block data is empty.
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }
}

/// Autobahn Car metadata for data dissemination.
///
/// Cars represent parallel data dissemination lanes in Autobahn BFT.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CarMetadata {
    /// Car identifier (validator lane).
    pub car_id: u64,
    /// Sequence number within this car.
    pub sequence: u64,
    /// Hash of previous car in this lane.
    pub previous_car_hash: Hash,
    /// Timestamp when car was created.
    pub timestamp: DateTime<Utc>,
}

impl CarMetadata {
    /// Create new car metadata.
    pub fn new(car_id: u64, sequence: u64, previous_car_hash: Hash, timestamp: DateTime<Utc>) -> Self {
        Self {
            car_id,
            sequence,
            previous_car_hash,
            timestamp,
        }
    }
}

/// Autobahn Cut metadata for consensus ordering.
///
/// Cuts represent snapshots of all validator cars at consensus points.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CutMetadata {
    /// Cut identifier (consensus sequence).
    pub cut_id: u64,
    /// Hashes of cars included in this cut (one per validator).
    pub car_hashes: Vec<Hash>,
    /// Round when this cut was agreed upon.
    pub round: Round,
    /// Timestamp when cut was finalized.
    pub timestamp: DateTime<Utc>,
}

impl CutMetadata {
    /// Create new cut metadata.
    pub fn new(cut_id: u64, car_hashes: Vec<Hash>, round: Round, timestamp: DateTime<Utc>) -> Self {
        Self {
            cut_id,
            car_hashes,
            round,
            timestamp,
        }
    }

    /// Get number of cars in this cut.
    pub fn car_count(&self) -> usize {
        self.car_hashes.len()
    }
}

/// Validator signature on a block commit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidatorSignature {
    /// Validator address.
    pub validator_address: Vec<u8>,
    /// Voting power of this validator.
    pub voting_power: u64,
    /// Signature bytes.
    pub signature: Vec<u8>,
    /// Timestamp of the signature.
    pub timestamp: DateTime<Utc>,
}

impl ValidatorSignature {
    /// Create a new validator signature.
    pub fn new(
        validator_address: Vec<u8>,
        voting_power: u64,
        signature: Vec<u8>,
        timestamp: DateTime<Utc>,
    ) -> Self {
        Self {
            validator_address,
            voting_power,
            signature,
            timestamp,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_hash(value: u8) -> Hash {
        Hash::new([value; 32])
    }

    fn create_test_header() -> BlockHeader {
        BlockHeader::new(
            Height::new(1).expect("valid height"),
            create_test_hash(1),
            Round::new(0),
            Utc::now(),
            vec![1, 2, 3],
            create_test_hash(0),
            create_test_hash(2),
            create_test_hash(3),
        )
    }

    #[test]
    fn test_block_creation() {
        let header = create_test_header();
        let data = BlockData::new(vec![vec![1, 2, 3]]);
        let block = Block::new(header.clone(), data.clone(), None, None, vec![]);

        assert_eq!(block.height(), header.height);
        assert_eq!(block.hash(), header.hash);
        assert_eq!(block.tx_count(), 1);
    }

    #[test]
    fn test_block_finalization() {
        let header = create_test_header();
        let data = BlockData::new(vec![]);

        // Create signatures with total power 100, need 67 for quorum (2f+1)
        let signatures = vec![
            ValidatorSignature::new(vec![1], 30, vec![0; 64], Utc::now()),
            ValidatorSignature::new(vec![2], 40, vec![0; 64], Utc::now()),
        ];

        let block = Block::new(header, data, None, None, signatures);

        // 70 power >= 67 quorum
        assert!(block.is_finalized(100));
    }

    #[test]
    fn test_car_metadata() {
        let metadata = CarMetadata::new(1, 42, create_test_hash(1), Utc::now());
        assert_eq!(metadata.car_id, 1);
        assert_eq!(metadata.sequence, 42);
    }

    #[test]
    fn test_cut_metadata() {
        let car_hashes = vec![create_test_hash(1), create_test_hash(2), create_test_hash(3)];
        let metadata = CutMetadata::new(1, car_hashes.clone(), Round::new(0), Utc::now());

        assert_eq!(metadata.cut_id, 1);
        assert_eq!(metadata.car_count(), 3);
        assert_eq!(metadata.car_hashes, car_hashes);
    }

    #[test]
    fn test_block_data_operations() {
        let data = BlockData::new(vec![vec![1], vec![2], vec![3]]);
        assert_eq!(data.len(), 3);
        assert!(!data.is_empty());

        let empty_data = BlockData::new(vec![]);
        assert!(empty_data.is_empty());
    }
}
