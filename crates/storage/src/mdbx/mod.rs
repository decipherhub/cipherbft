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
//! - [`MdbxBatchStore`]: Implementation of [`BatchStore`] trait for worker batches
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

mod batch;
mod database;
mod evm;
mod provider;
mod receipts;
mod staking;
mod tables;
mod wal;

pub use batch::MdbxBatchStore;
pub use receipts::MdbxReceiptStore;
pub use database::{Database, DatabaseConfig, DatabaseEnv};
pub use evm::MdbxEvmStore;
pub use provider::{MdbxDclStore, MdbxDclStoreTx};
pub use staking::MdbxStakingStore;
pub use tables::{
    // EVM table types
    AddressKey,
    // Consensus table types
    Attestations,
    Batches,
    BlockNumberKey,
    // Key types
    CarTableKey,
    Cars,
    CarsByHash,
    ConsensusState,
    ConsensusWal,
    EvmAccounts,
    EvmBlockHashes,
    EvmCode,
    EvmStorage,
    FinalizedCuts,
    HashKey,
    HeightKey,
    HeightRoundKey,
    PendingCuts,
    Proposals,
    // Receipt table types
    Receipts,
    ReceiptsByBlock,
    // Staking table types
    StakingMetadata,
    StakingValidators,
    StorageSlotKey,
    StoredAccount,
    // Consensus value types
    StoredAggregatedAttestation,
    StoredBatch,
    StoredBatchDigest,
    StoredBytecode,
    StoredCar,
    StoredCarEntry,
    StoredConsensusState,
    StoredCut,
    // Receipt value types
    StoredLog,
    StoredProposal,
    StoredReceipt,
    StoredStakingMetadata,
    StoredStorageValue,
    StoredValidator,
    StoredValidatorInfo,
    StoredValidatorSet,
    StoredVote,
    StoredVotes,
    StoredWalEntry,
    Tables,
    UnitKey,
    ValidatorSets,
    Votes,
};
pub use wal::MdbxWal;
