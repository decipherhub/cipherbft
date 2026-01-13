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

use reth_db_api::table::{Compress, Decode, Decompress, Encode, Table, TableInfo};
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

    fn compress_to_buf<B: bytes::BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
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

    fn compress_to_buf<B: bytes::BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
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

/// Batches table: Hash -> StoredBatch
/// Stores transaction batches from Workers
#[derive(Debug, Clone, Copy, Default)]
pub struct Batches;

impl Table for Batches {
    const NAME: &'static str = "Batches";
    const DUPSORT: bool = false;
    type Key = HashKey;
    type Value = BincodeValue<StoredBatch>;
}

/// Cars table: (ValidatorPrefix, Position) -> StoredCar
/// Stores Certified Available Records indexed by validator and position
#[derive(Debug, Clone, Copy, Default)]
pub struct Cars;

impl Table for Cars {
    const NAME: &'static str = "Cars";
    const DUPSORT: bool = false;
    type Key = CarTableKey;
    type Value = BincodeValue<StoredCar>;
}

/// CarsByHash table: Hash -> CarTableKey
/// Secondary index for Car lookup by hash
#[derive(Debug, Clone, Copy, Default)]
pub struct CarsByHash;

impl Table for CarsByHash {
    const NAME: &'static str = "CarsByHash";
    const DUPSORT: bool = false;
    type Key = HashKey;
    type Value = CarTableKey;
}

/// Attestations table: CarHash -> StoredAggregatedAttestation
/// Stores aggregated BLS attestations
#[derive(Debug, Clone, Copy, Default)]
pub struct Attestations;

impl Table for Attestations {
    const NAME: &'static str = "Attestations";
    const DUPSORT: bool = false;
    type Key = HashKey;
    type Value = BincodeValue<StoredAggregatedAttestation>;
}

/// PendingCuts table: Height -> StoredCut
/// Stores Cuts awaiting consensus finalization
#[derive(Debug, Clone, Copy, Default)]
pub struct PendingCuts;

impl Table for PendingCuts {
    const NAME: &'static str = "PendingCuts";
    const DUPSORT: bool = false;
    type Key = HeightKey;
    type Value = BincodeValue<StoredCut>;
}

/// FinalizedCuts table: Height -> StoredCut
/// Stores consensus-finalized Cuts
#[derive(Debug, Clone, Copy, Default)]
pub struct FinalizedCuts;

impl Table for FinalizedCuts {
    const NAME: &'static str = "FinalizedCuts";
    const DUPSORT: bool = false;
    type Key = HeightKey;
    type Value = BincodeValue<StoredCut>;
}

/// ConsensusWal table: Index -> WalEntry bytes
/// Write-ahead log for crash recovery
#[derive(Debug, Clone, Copy, Default)]
pub struct ConsensusWal;

impl Table for ConsensusWal {
    const NAME: &'static str = "ConsensusWal";
    const DUPSORT: bool = false;
    type Key = HeightKey;
    type Value = BincodeValue<StoredWalEntry>;
}

/// ConsensusState table: () -> StoredConsensusState
/// Current consensus state (height, round, step)
#[derive(Debug, Clone, Copy, Default)]
pub struct ConsensusState;

impl Table for ConsensusState {
    const NAME: &'static str = "ConsensusState";
    const DUPSORT: bool = false;
    type Key = UnitKey;
    type Value = BincodeValue<StoredConsensusState>;
}

/// ValidatorSets table: Epoch -> StoredValidatorSet
/// Validator sets by epoch
#[derive(Debug, Clone, Copy, Default)]
pub struct ValidatorSets;

impl Table for ValidatorSets {
    const NAME: &'static str = "ValidatorSets";
    const DUPSORT: bool = false;
    type Key = HeightKey;
    type Value = BincodeValue<StoredValidatorSet>;
}

/// Votes table: (Height, Round) -> StoredVotes
/// Collected votes by height and round
#[derive(Debug, Clone, Copy, Default)]
pub struct Votes;

impl Table for Votes {
    const NAME: &'static str = "Votes";
    const DUPSORT: bool = false;
    type Key = HeightRoundKey;
    type Value = BincodeValue<StoredVotes>;
}

/// Proposals table: (Height, Round) -> StoredProposal
/// Block proposals by height and round
#[derive(Debug, Clone, Copy, Default)]
pub struct Proposals;

impl Table for Proposals {
    const NAME: &'static str = "Proposals";
    const DUPSORT: bool = false;
    type Key = HeightRoundKey;
    type Value = BincodeValue<StoredProposal>;
}

// =============================================================================
// EVM Tables (for Execution Layer integration)
// =============================================================================

/// Key for EVM accounts table: 20-byte address
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct AddressKey(pub [u8; 20]);

impl AddressKey {
    /// Create a new AddressKey from a byte slice
    pub fn new(address: &[u8; 20]) -> Self {
        Self(*address)
    }

    /// Encode to bytes (for MDBX key)
    pub fn encode(&self) -> [u8; 20] {
        self.0
    }

    /// Decode from bytes
    pub fn decode(data: &[u8]) -> Result<Self, reth_db_api::DatabaseError> {
        if data.len() != 20 {
            return Err(reth_db_api::DatabaseError::Decode);
        }
        let mut arr = [0u8; 20];
        arr.copy_from_slice(data);
        Ok(Self(arr))
    }
}

impl Encode for AddressKey {
    type Encoded = [u8; 20];

    fn encode(self) -> Self::Encoded {
        self.0
    }
}

impl Decode for AddressKey {
    fn decode(value: &[u8]) -> Result<Self, reth_db_api::DatabaseError> {
        Self::decode(value)
    }
}

/// Key for EVM storage table: (address, storage slot)
/// Storage slot is U256 (32 bytes)
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct StorageSlotKey {
    /// Account address (20 bytes)
    pub address: [u8; 20],
    /// Storage slot (32 bytes, big-endian U256)
    pub slot: [u8; 32],
}

impl StorageSlotKey {
    /// Create a new StorageSlotKey
    pub fn new(address: &[u8; 20], slot: &[u8; 32]) -> Self {
        Self {
            address: *address,
            slot: *slot,
        }
    }

    /// Total encoded size: 20 + 32 = 52 bytes
    pub const ENCODED_SIZE: usize = 52;

    /// Encode to bytes
    pub fn encode(&self) -> [u8; Self::ENCODED_SIZE] {
        let mut buf = [0u8; Self::ENCODED_SIZE];
        buf[..20].copy_from_slice(&self.address);
        buf[20..].copy_from_slice(&self.slot);
        buf
    }

    /// Decode from bytes
    pub fn decode(data: &[u8]) -> Result<Self, reth_db_api::DatabaseError> {
        if data.len() != Self::ENCODED_SIZE {
            return Err(reth_db_api::DatabaseError::Decode);
        }
        let mut address = [0u8; 20];
        let mut slot = [0u8; 32];
        address.copy_from_slice(&data[..20]);
        slot.copy_from_slice(&data[20..]);
        Ok(Self { address, slot })
    }
}

impl Encode for StorageSlotKey {
    type Encoded = [u8; StorageSlotKey::ENCODED_SIZE];

    fn encode(self) -> Self::Encoded {
        StorageSlotKey::encode(&self)
    }
}

impl Decode for StorageSlotKey {
    fn decode(value: &[u8]) -> Result<Self, reth_db_api::DatabaseError> {
        StorageSlotKey::decode(value)
    }
}

/// Key for block hashes table: block number (u64)
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct BlockNumberKey(pub u64);

impl BlockNumberKey {
    /// Create a new BlockNumberKey
    pub fn new(number: u64) -> Self {
        Self(number)
    }

    /// Encode to bytes (big-endian for ordering)
    pub fn encode(&self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    /// Decode from bytes
    pub fn decode(data: &[u8]) -> Result<Self, reth_db_api::DatabaseError> {
        if data.len() != 8 {
            return Err(reth_db_api::DatabaseError::Decode);
        }
        let arr: [u8; 8] = data
            .try_into()
            .map_err(|_| reth_db_api::DatabaseError::Decode)?;
        Ok(Self(u64::from_be_bytes(arr)))
    }
}

impl Encode for BlockNumberKey {
    type Encoded = [u8; 8];

    fn encode(self) -> Self::Encoded {
        self.0.to_be_bytes()
    }
}

impl Decode for BlockNumberKey {
    fn decode(value: &[u8]) -> Result<Self, reth_db_api::DatabaseError> {
        BlockNumberKey::decode(value)
    }
}

/// Stored EVM account data
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StoredAccount {
    /// Account nonce
    pub nonce: u64,
    /// Account balance (stored as big-endian bytes)
    pub balance: [u8; 32],
    /// Code hash (keccak256 of bytecode)
    pub code_hash: [u8; 32],
    /// Storage root (for state trie, currently unused)
    pub storage_root: [u8; 32],
}

/// Stored bytecode
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StoredBytecode {
    /// Raw bytecode bytes
    pub code: Vec<u8>,
}

/// Stored storage value (32 bytes U256)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StoredStorageValue {
    /// Storage value (big-endian U256)
    pub value: [u8; 32],
}

/// EvmAccounts table: Address -> Account
/// Stores EVM account state (nonce, balance, code_hash, storage_root)
#[derive(Debug, Clone, Copy, Default)]
pub struct EvmAccounts;

impl Table for EvmAccounts {
    const NAME: &'static str = "EvmAccounts";
    const DUPSORT: bool = false;
    type Key = AddressKey;
    type Value = BincodeValue<StoredAccount>;
}

/// EvmCode table: CodeHash -> Bytecode
/// Stores contract bytecode indexed by keccak256 hash
#[derive(Debug, Clone, Copy, Default)]
pub struct EvmCode;

impl Table for EvmCode {
    const NAME: &'static str = "EvmCode";
    const DUPSORT: bool = false;
    type Key = HashKey;
    type Value = BincodeValue<StoredBytecode>;
}

/// EvmStorage table: (Address, Slot) -> Value
/// Stores EVM storage slots
#[derive(Debug, Clone, Copy, Default)]
pub struct EvmStorage;

impl Table for EvmStorage {
    const NAME: &'static str = "EvmStorage";
    const DUPSORT: bool = false;
    type Key = StorageSlotKey;
    type Value = BincodeValue<StoredStorageValue>;
}

/// EvmBlockHashes table: BlockNumber -> Hash
/// Stores block hashes for BLOCKHASH opcode
#[derive(Debug, Clone, Copy, Default)]
pub struct EvmBlockHashes;

impl Table for EvmBlockHashes {
    const NAME: &'static str = "EvmBlockHashes";
    const DUPSORT: bool = false;
    type Key = BlockNumberKey;
    type Value = HashKey;
}

// =============================================================================
// Staking Tables (for Staking Precompile persistence)
// =============================================================================

/// Stored validator information for staking precompile
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StoredValidatorInfo {
    /// Ethereum address (20 bytes)
    pub address: [u8; 20],
    /// BLS12-381 public key (48 bytes, stored as Vec for serde compatibility)
    pub bls_pubkey: Vec<u8>,
    /// Staked amount (big-endian U256)
    pub stake: [u8; 32],
    /// Registration block height
    pub registered_at: u64,
    /// Pending deregistration epoch (0 = no pending exit)
    pub pending_exit: u64,
    /// Whether there's a pending exit
    pub has_pending_exit: bool,
}

/// Stored staking metadata (total_stake, epoch)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StoredStakingMetadata {
    /// Total staked amount (big-endian U256)
    pub total_stake: [u8; 32],
    /// Current epoch number
    pub epoch: u64,
}

/// StakingValidators table: Address -> ValidatorInfo
/// Stores registered validator information
#[derive(Debug, Clone, Copy, Default)]
pub struct StakingValidators;

impl Table for StakingValidators {
    const NAME: &'static str = "StakingValidators";
    const DUPSORT: bool = false;
    type Key = AddressKey;
    type Value = BincodeValue<StoredValidatorInfo>;
}

/// StakingMetadata table: () -> StakingMetadata
/// Stores global staking state (total_stake, epoch)
#[derive(Debug, Clone, Copy, Default)]
pub struct StakingMetadata;

impl Table for StakingMetadata {
    const NAME: &'static str = "StakingMetadata";
    const DUPSORT: bool = false;
    type Key = UnitKey;
    type Value = BincodeValue<StoredStakingMetadata>;
}

// Compress/Decompress implementations for EVM keys used as values

impl Compress for HashKey {
    type Compressed = Vec<u8>;

    fn compress(self) -> Self::Compressed {
        self.0.to_vec()
    }

    fn compress_to_buf<B: bytes::BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
        buf.put_slice(&self.0);
    }
}

impl Decompress for HashKey {
    fn decompress(value: &[u8]) -> Result<Self, reth_db_api::DatabaseError> {
        Self::decode(value)
    }
}

// =============================================================================
// TableInfo and TableSet implementation for CipherBFT custom tables
// =============================================================================

/// Enum representing all CipherBFT tables for TableSet implementation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherBftTable {
    // Consensus tables
    Batches,
    Cars,
    CarsByHash,
    Attestations,
    PendingCuts,
    FinalizedCuts,
    ConsensusWal,
    ConsensusState,
    ValidatorSets,
    Votes,
    Proposals,
    // EVM tables
    EvmAccounts,
    EvmCode,
    EvmStorage,
    EvmBlockHashes,
    // Staking tables
    StakingValidators,
    StakingMetadata,
}

impl CipherBftTable {
    /// All CipherBFT tables
    pub const ALL: &'static [Self] = &[
        // Consensus tables
        Self::Batches,
        Self::Cars,
        Self::CarsByHash,
        Self::Attestations,
        Self::PendingCuts,
        Self::FinalizedCuts,
        Self::ConsensusWal,
        Self::ConsensusState,
        Self::ValidatorSets,
        Self::Votes,
        Self::Proposals,
        // EVM tables
        Self::EvmAccounts,
        Self::EvmCode,
        Self::EvmStorage,
        Self::EvmBlockHashes,
        // Staking tables
        Self::StakingValidators,
        Self::StakingMetadata,
    ];
}

impl TableInfo for CipherBftTable {
    fn name(&self) -> &'static str {
        match self {
            Self::Batches => Batches::NAME,
            Self::Cars => Cars::NAME,
            Self::CarsByHash => CarsByHash::NAME,
            Self::Attestations => Attestations::NAME,
            Self::PendingCuts => PendingCuts::NAME,
            Self::FinalizedCuts => FinalizedCuts::NAME,
            Self::ConsensusWal => ConsensusWal::NAME,
            Self::ConsensusState => ConsensusState::NAME,
            Self::ValidatorSets => ValidatorSets::NAME,
            Self::Votes => Votes::NAME,
            Self::Proposals => Proposals::NAME,
            Self::EvmAccounts => EvmAccounts::NAME,
            Self::EvmCode => EvmCode::NAME,
            Self::EvmStorage => EvmStorage::NAME,
            Self::EvmBlockHashes => EvmBlockHashes::NAME,
            Self::StakingValidators => StakingValidators::NAME,
            Self::StakingMetadata => StakingMetadata::NAME,
        }
    }

    fn is_dupsort(&self) -> bool {
        match self {
            Self::Batches => Batches::DUPSORT,
            Self::Cars => Cars::DUPSORT,
            Self::CarsByHash => CarsByHash::DUPSORT,
            Self::Attestations => Attestations::DUPSORT,
            Self::PendingCuts => PendingCuts::DUPSORT,
            Self::FinalizedCuts => FinalizedCuts::DUPSORT,
            Self::ConsensusWal => ConsensusWal::DUPSORT,
            Self::ConsensusState => ConsensusState::DUPSORT,
            Self::ValidatorSets => ValidatorSets::DUPSORT,
            Self::Votes => Votes::DUPSORT,
            Self::Proposals => Proposals::DUPSORT,
            Self::EvmAccounts => EvmAccounts::DUPSORT,
            Self::EvmCode => EvmCode::DUPSORT,
            Self::EvmStorage => EvmStorage::DUPSORT,
            Self::EvmBlockHashes => EvmBlockHashes::DUPSORT,
            Self::StakingValidators => StakingValidators::DUPSORT,
            Self::StakingMetadata => StakingMetadata::DUPSORT,
        }
    }
}

/// All CipherBFT tables - implements TableSet for database initialization
pub struct Tables;

impl Tables {
    /// All table names (for iteration/creation)
    pub const ALL: &'static [&'static str] = &[
        // Consensus tables
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
        // EVM tables
        EvmAccounts::NAME,
        EvmCode::NAME,
        EvmStorage::NAME,
        EvmBlockHashes::NAME,
        // Staking tables
        StakingValidators::NAME,
        StakingMetadata::NAME,
    ];
}

/// TableSet implementation allows reth-db to create our custom tables
impl reth_db::TableSet for Tables {
    fn tables() -> Box<dyn Iterator<Item = Box<dyn TableInfo>>> {
        Box::new(
            CipherBftTable::ALL
                .iter()
                .map(|table| Box::new(*table) as Box<dyn TableInfo>),
        )
    }
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
