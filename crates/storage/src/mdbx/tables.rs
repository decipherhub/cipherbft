//! MDBX table definitions for CipherBFT per ADR-010
//!
//! This module defines custom tables for DCL and consensus data using reth-db macros.
//! EVM state tables are reused from reth-db directly.
//!
//! # Table Categories
//!
//! ## DCL Tables (Custom)
//! - `Batches`: Transaction batches from Workers
//! - `Cars`: Certified Available Records indexed by (validator, position)
//! - `CarsByHash`: Secondary index for Car lookup by hash
//! - `Attestations`: Aggregated BLS attestations
//! - `PendingCuts`: Cuts awaiting consensus
//! - `FinalizedCuts`: Consensus-finalized Cuts
//!
//! ## Consensus Tables (Custom)
//! - `ConsensusState`: Current height/round/step
//! - `ConsensusWal`: Write-ahead log entries
//! - `ValidatorSets`: Validator sets by epoch
//! - `Votes`: Collected votes by (height, round)
//! - `Proposals`: Block proposals by (height, round)

use reth_db_api::table::{Compress, Decode, Decompress, Encode};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

// ============================================================
// Key Types
// ============================================================

/// Key for Cars table: (ValidatorId bytes, position)
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct CarTableKey {
    /// First 20 bytes of validator ID (truncated for efficiency)
    pub validator_prefix: [u8; 20],
    /// Position in validator's lane
    pub position: u64,
}

impl CarTableKey {
    /// Create a new car table key
    pub fn new(validator_bytes: &[u8], position: u64) -> Self {
        let mut validator_prefix = [0u8; 20];
        let copy_len = validator_bytes.len().min(20);
        validator_prefix[..copy_len].copy_from_slice(&validator_bytes[..copy_len]);
        Self {
            validator_prefix,
            position,
        }
    }
}

impl Encode for CarTableKey {
    type Encoded = [u8; 28]; // 20 + 8

    fn encode(self) -> Self::Encoded {
        let mut buf = [0u8; 28];
        buf[..20].copy_from_slice(&self.validator_prefix);
        buf[20..28].copy_from_slice(&self.position.to_be_bytes());
        buf
    }
}

impl Decode for CarTableKey {
    fn decode(value: &[u8]) -> Result<Self, reth_db_api::DatabaseError> {
        if value.len() < 28 {
            return Err(reth_db_api::DatabaseError::Decode);
        }
        let mut validator_prefix = [0u8; 20];
        validator_prefix.copy_from_slice(&value[..20]);
        let position = u64::from_be_bytes(value[20..28].try_into().unwrap());
        Ok(Self {
            validator_prefix,
            position,
        })
    }
}

// CarTableKey is also used as a Value in CarsByHash table
impl Compress for CarTableKey {
    type Compressed = Vec<u8>;

    fn compress(self) -> Self::Compressed {
        self.encode().to_vec()
    }

    fn compress_to_buf<B: bytes::BufMut + AsMut<[u8]>>(self, buf: &mut B) {
        buf.put_slice(&self.encode());
    }
}

impl Decompress for CarTableKey {
    fn decompress(value: &[u8]) -> Result<Self, reth_db_api::DatabaseError> {
        Self::decode(value)
    }
}

/// Key for Votes/Proposals table: (height, round)
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct HeightRoundKey {
    /// Consensus height
    pub height: u64,
    /// Consensus round
    pub round: u32,
}

impl HeightRoundKey {
    /// Create a new height-round key
    pub fn new(height: u64, round: u32) -> Self {
        Self { height, round }
    }
}

impl Encode for HeightRoundKey {
    type Encoded = [u8; 12]; // 8 + 4

    fn encode(self) -> Self::Encoded {
        let mut buf = [0u8; 12];
        buf[..8].copy_from_slice(&self.height.to_be_bytes());
        buf[8..12].copy_from_slice(&self.round.to_be_bytes());
        buf
    }
}

impl Decode for HeightRoundKey {
    fn decode(value: &[u8]) -> Result<Self, reth_db_api::DatabaseError> {
        if value.len() < 12 {
            return Err(reth_db_api::DatabaseError::Decode);
        }
        let height = u64::from_be_bytes(value[..8].try_into().unwrap());
        let round = u32::from_be_bytes(value[8..12].try_into().unwrap());
        Ok(Self { height, round })
    }
}

/// 32-byte hash key
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct HashKey(pub [u8; 32]);

impl HashKey {
    /// Create from a slice
    pub fn from_slice(slice: &[u8]) -> Self {
        let mut bytes = [0u8; 32];
        let copy_len = slice.len().min(32);
        bytes[..copy_len].copy_from_slice(&slice[..copy_len]);
        Self(bytes)
    }
}

impl Encode for HashKey {
    type Encoded = [u8; 32];

    fn encode(self) -> Self::Encoded {
        self.0
    }
}

impl Decode for HashKey {
    fn decode(value: &[u8]) -> Result<Self, reth_db_api::DatabaseError> {
        if value.len() < 32 {
            return Err(reth_db_api::DatabaseError::Decode);
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&value[..32]);
        Ok(Self(bytes))
    }
}

/// Height key (u64) for height-indexed tables
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct HeightKey(pub u64);

impl HeightKey {
    /// Create a new height key
    pub fn new(height: u64) -> Self {
        Self(height)
    }
}

impl Encode for HeightKey {
    type Encoded = [u8; 8];

    fn encode(self) -> Self::Encoded {
        self.0.to_be_bytes()
    }
}

impl Decode for HeightKey {
    fn decode(value: &[u8]) -> Result<Self, reth_db_api::DatabaseError> {
        if value.len() < 8 {
            return Err(reth_db_api::DatabaseError::Decode);
        }
        Ok(Self(u64::from_be_bytes(value[..8].try_into().unwrap())))
    }
}

/// Unit key for singleton tables (e.g., ConsensusState)
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct UnitKey;

impl Encode for UnitKey {
    type Encoded = [u8; 1];

    fn encode(self) -> Self::Encoded {
        [0]
    }
}

impl Decode for UnitKey {
    fn decode(_value: &[u8]) -> Result<Self, reth_db_api::DatabaseError> {
        Ok(Self)
    }
}

// ============================================================
// Value Types (stored as bincode-serialized bytes)
// ============================================================

/// Wrapper for bincode-serializable values
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BincodeValue<T>(pub T);

impl<T> From<T> for BincodeValue<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T: Serialize + for<'de> Deserialize<'de> + Debug + Send + Sync> Compress for BincodeValue<T> {
    type Compressed = Vec<u8>;

    fn compress(self) -> Self::Compressed {
        bincode::serialize(&self.0).expect("bincode serialization failed")
    }

    fn compress_to_buf<B: bytes::BufMut + AsMut<[u8]>>(self, buf: &mut B) {
        let serialized = bincode::serialize(&self.0).expect("bincode serialization failed");
        buf.put_slice(&serialized);
    }
}

impl<T: Serialize + for<'de> Deserialize<'de> + Debug + Send + Sync> Decompress
    for BincodeValue<T>
{
    fn decompress(value: &[u8]) -> Result<Self, reth_db_api::DatabaseError> {
        bincode::deserialize(value)
            .map(BincodeValue)
            .map_err(|_| reth_db_api::DatabaseError::Decode)
    }
}

// ============================================================
// Stored Value Types
// ============================================================

/// Stored batch value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredBatch {
    /// Worker ID that created this batch
    pub worker_id: u8,
    /// Serialized transactions
    pub transactions: Vec<Vec<u8>>,
    /// Timestamp when batch was created
    pub timestamp: u64,
}

/// Stored Car value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCar {
    /// Proposer validator ID bytes
    pub proposer: Vec<u8>,
    /// Position in lane
    pub position: u64,
    /// Batch digests included
    pub batch_digests: Vec<StoredBatchDigest>,
    /// Parent Car hash (if not genesis)
    pub parent_ref: Option<[u8; 32]>,
    /// BLS signature bytes
    pub signature: Vec<u8>,
    /// Computed hash
    pub hash: [u8; 32],
}

/// Stored batch digest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredBatchDigest {
    /// Worker ID
    pub worker_id: u8,
    /// Batch hash
    pub hash: [u8; 32],
    /// Transaction count
    pub tx_count: u32,
    /// Total size in bytes
    pub size_bytes: u64,
}

/// Stored aggregated attestation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAggregatedAttestation {
    /// Car hash being attested
    pub car_hash: [u8; 32],
    /// Car position
    pub car_position: u64,
    /// Car proposer
    pub car_proposer: Vec<u8>,
    /// Aggregated BLS signature
    pub aggregated_signature: Vec<u8>,
    /// Bit vector of signers
    pub signers_bitvec: Vec<u8>,
    /// Number of signers
    pub signer_count: u32,
}

/// Stored Cut value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCut {
    /// Consensus height
    pub height: u64,
    /// Car entries in this Cut (validator -> car + attestation)
    pub cars: Vec<StoredCarEntry>,
}

/// Stored Car entry in a Cut (includes full car and attestation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCarEntry {
    /// Validator ID bytes
    pub validator: Vec<u8>,
    /// The full stored Car
    pub car: StoredCar,
    /// Attestation (if available)
    pub attestation: Option<StoredAggregatedAttestation>,
}

/// Stored consensus state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredConsensusState {
    /// Current height
    pub height: u64,
    /// Current round
    pub round: u32,
    /// Last committed height
    pub last_committed_height: u64,
    /// WAL index to start replay from
    pub wal_replay_index: u64,
}

/// Stored WAL entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredWalEntry {
    /// Entry type tag
    pub entry_type: u8,
    /// Serialized entry data
    pub data: Vec<u8>,
}

/// Stored validator set
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredValidatorSet {
    /// Epoch number
    pub epoch: u64,
    /// Validators in this set
    pub validators: Vec<StoredValidator>,
    /// Total voting power
    pub total_power: u64,
}

/// Stored validator info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredValidator {
    /// Validator ID bytes
    pub id: Vec<u8>,
    /// Ed25519 public key for consensus
    pub ed25519_pubkey: Vec<u8>,
    /// BLS public key for attestations
    pub bls_pubkey: Vec<u8>,
    /// Voting power
    pub power: u64,
}

/// Stored votes collection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredVotes {
    /// Height
    pub height: u64,
    /// Round
    pub round: u32,
    /// Collected votes
    pub votes: Vec<StoredVote>,
}

/// Stored vote
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredVote {
    /// Vote type (prevote=0, precommit=1)
    pub vote_type: u8,
    /// Voter ID
    pub voter: Vec<u8>,
    /// Block hash (None for nil vote)
    pub block_hash: Option<[u8; 32]>,
    /// Signature
    pub signature: Vec<u8>,
}

/// Stored proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredProposal {
    /// Height
    pub height: u64,
    /// Round
    pub round: u32,
    /// Proposer ID
    pub proposer: Vec<u8>,
    /// Cut being proposed
    pub cut: StoredCut,
    /// Signature
    pub signature: Vec<u8>,
}

// ============================================================
// Table Definitions using reth-db Table trait
// ============================================================

use reth_db_api::table::Table;

/// Batches table: Hash -> StoredBatch
/// Stores transaction batches from Workers
#[derive(Debug, Clone, Copy, Default)]
pub struct Batches;

impl Table for Batches {
    const NAME: &'static str = "Batches";
    type Key = HashKey;
    type Value = BincodeValue<StoredBatch>;
}

/// Cars table: (ValidatorPrefix, Position) -> StoredCar
/// Stores Certified Available Records indexed by validator and position
#[derive(Debug, Clone, Copy, Default)]
pub struct Cars;

impl Table for Cars {
    const NAME: &'static str = "Cars";
    type Key = CarTableKey;
    type Value = BincodeValue<StoredCar>;
}

/// CarsByHash table: Hash -> CarTableKey
/// Secondary index for Car lookup by hash
#[derive(Debug, Clone, Copy, Default)]
pub struct CarsByHash;

impl Table for CarsByHash {
    const NAME: &'static str = "CarsByHash";
    type Key = HashKey;
    type Value = CarTableKey;
}

/// Attestations table: CarHash -> StoredAggregatedAttestation
/// Stores aggregated BLS attestations
#[derive(Debug, Clone, Copy, Default)]
pub struct Attestations;

impl Table for Attestations {
    const NAME: &'static str = "Attestations";
    type Key = HashKey;
    type Value = BincodeValue<StoredAggregatedAttestation>;
}

/// PendingCuts table: Height -> StoredCut
/// Stores Cuts awaiting consensus finalization
#[derive(Debug, Clone, Copy, Default)]
pub struct PendingCuts;

impl Table for PendingCuts {
    const NAME: &'static str = "PendingCuts";
    type Key = HeightKey;
    type Value = BincodeValue<StoredCut>;
}

/// FinalizedCuts table: Height -> StoredCut
/// Stores consensus-finalized Cuts
#[derive(Debug, Clone, Copy, Default)]
pub struct FinalizedCuts;

impl Table for FinalizedCuts {
    const NAME: &'static str = "FinalizedCuts";
    type Key = HeightKey;
    type Value = BincodeValue<StoredCut>;
}

/// ConsensusWal table: Index -> WalEntry bytes
/// Write-ahead log for crash recovery
#[derive(Debug, Clone, Copy, Default)]
pub struct ConsensusWal;

impl Table for ConsensusWal {
    const NAME: &'static str = "ConsensusWal";
    type Key = HeightKey;
    type Value = BincodeValue<StoredWalEntry>;
}

/// ConsensusState table: () -> StoredConsensusState
/// Current consensus state (height, round, step)
#[derive(Debug, Clone, Copy, Default)]
pub struct ConsensusState;

impl Table for ConsensusState {
    const NAME: &'static str = "ConsensusState";
    type Key = UnitKey;
    type Value = BincodeValue<StoredConsensusState>;
}

/// ValidatorSets table: Epoch -> StoredValidatorSet
/// Validator sets by epoch
#[derive(Debug, Clone, Copy, Default)]
pub struct ValidatorSets;

impl Table for ValidatorSets {
    const NAME: &'static str = "ValidatorSets";
    type Key = HeightKey;
    type Value = BincodeValue<StoredValidatorSet>;
}

/// Votes table: (Height, Round) -> StoredVotes
/// Collected votes by height and round
#[derive(Debug, Clone, Copy, Default)]
pub struct Votes;

impl Table for Votes {
    const NAME: &'static str = "Votes";
    type Key = HeightRoundKey;
    type Value = BincodeValue<StoredVotes>;
}

/// Proposals table: (Height, Round) -> StoredProposal
/// Block proposals by height and round
#[derive(Debug, Clone, Copy, Default)]
pub struct Proposals;

impl Table for Proposals {
    const NAME: &'static str = "Proposals";
    type Key = HeightRoundKey;
    type Value = BincodeValue<StoredProposal>;
}

/// All CipherBFT tables
pub struct Tables;

impl Tables {
    /// All table names (for iteration/creation)
    pub const ALL: &'static [&'static str] = &[
        Batches::NAME,
        Cars::NAME,
        CarsByHash::NAME,
        Attestations::NAME,
        PendingCuts::NAME,
        FinalizedCuts::NAME,
        ConsensusWal::NAME,
        ConsensusState::NAME,
        ValidatorSets::NAME,
        Votes::NAME,
        Proposals::NAME,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_car_table_key_encode_decode() {
        let validator = [1u8; 32];
        let key = CarTableKey::new(&validator, 42);
        let encoded = key.encode();
        let decoded = CarTableKey::decode(&encoded).unwrap();
        assert_eq!(key.validator_prefix, decoded.validator_prefix);
        assert_eq!(key.position, decoded.position);
    }

    #[test]
    fn test_height_round_key_encode_decode() {
        let key = HeightRoundKey::new(100, 5);
        let encoded = key.encode();
        let decoded = HeightRoundKey::decode(&encoded).unwrap();
        assert_eq!(key.height, decoded.height);
        assert_eq!(key.round, decoded.round);
    }

    #[test]
    fn test_hash_key_encode_decode() {
        let hash = [42u8; 32];
        let key = HashKey(hash);
        let encoded = key.encode();
        let decoded = HashKey::decode(&encoded).unwrap();
        assert_eq!(key.0, decoded.0);
    }

    #[test]
    fn test_bincode_value_compress_decompress() {
        let stored = StoredConsensusState {
            height: 100,
            round: 5,
            last_committed_height: 99,
            wal_replay_index: 1000,
        };
        let value = BincodeValue(stored.clone());
        let compressed = value.compress();
        let decompressed: BincodeValue<StoredConsensusState> =
            BincodeValue::decompress(&compressed).unwrap();
        assert_eq!(decompressed.0.height, stored.height);
        assert_eq!(decompressed.0.round, stored.round);
    }
}
