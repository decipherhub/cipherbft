//! MDBX storage backend for CipherBFT
//!
//! This module provides persistent storage using reth-db (MDBX) per ADR-010.
//!
//! # Architecture
//!
//! The MDBX backend consists of:
//! - [`Database`]: Main database wrapper around reth-db
//! - [`Tables`]: Custom table definitions for DCL, EVM, and staking data
//! - [`MdbxDclStore`]: Implementation of [`DclStore`] trait
//! - [`MdbxEvmStore`]: Implementation of [`EvmStore`] trait
//! - [`MdbxStakingStore`]: Implementation of [`StakingStore`] trait
//! - [`MdbxWal`]: Persistent WAL implementation
//!
//! # Feature Flag
//!
//! This module is only available when the `mdbx` feature is enabled:
//! ```toml
//! cipherbft-storage = { version = "0.1", features = ["mdbx"] }
//! ```

mod database;
mod evm;
mod provider;
mod staking;
mod tables;
mod wal;

pub use database::{Database, DatabaseConfig, DatabaseEnv};
pub use evm::MdbxEvmStore;
pub use provider::{MdbxDclStore, MdbxDclStoreTx};
pub use staking::MdbxStakingStore;
pub use tables::{
    // Consensus table types
    Attestations,
    Batches,
    // Key types
    CarTableKey,
    Cars,
    CarsByHash,
    ConsensusState,
    ConsensusWal,
    FinalizedCuts,
    HashKey,
    HeightKey,
    HeightRoundKey,
    PendingCuts,
    Proposals,
    // Consensus value types
    StoredAggregatedAttestation,
    StoredBatch,
    StoredBatchDigest,
    StoredCar,
    StoredCarEntry,
    StoredConsensusState,
    StoredCut,
    StoredProposal,
    StoredValidator,
    StoredValidatorSet,
    StoredVote,
    StoredVotes,
    StoredWalEntry,
    Tables,
    UnitKey,
    ValidatorSets,
    Votes,
    // EVM table types
    AddressKey,
    BlockNumberKey,
    EvmAccounts,
    EvmBlockHashes,
    EvmCode,
    EvmStorage,
    StorageSlotKey,
    StoredAccount,
    StoredBytecode,
    StoredStorageValue,
    // Staking table types
    StakingMetadata,
    StakingValidators,
    StoredStakingMetadata,
    StoredValidatorInfo,
};
pub use wal::MdbxWal;
