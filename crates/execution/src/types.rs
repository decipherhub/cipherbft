//! Core types for the execution layer.
//!
//! This module defines the data structures used for execution, including
//! blocks, transactions, execution results, and state management.

use alloy_consensus::Header as AlloyHeader;
use alloy_primitives::{Address, Bloom, Bytes, B256, B64, U256};
use serde::{Deserialize, Serialize};

/// State root computation interval (every N blocks).
///
/// State roots are computed periodically to balance performance with state commitment.
/// Default is every 100 blocks as per spec (configurable via consensus parameter).
pub const STATE_ROOT_SNAPSHOT_INTERVAL: u64 = 100;

/// Delayed commitment depth (block N includes hash of block N-DELAYED_COMMITMENT_DEPTH).
///
/// This allows validators to finalize block N-2 while producing block N,
/// ensuring deterministic block hashes in the header.
pub const DELAYED_COMMITMENT_DEPTH: u64 = 2;

/// Input to the execution layer from the consensus layer.
///
/// Contains the ordered transactions to execute for a specific block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockInput {
    /// Block number.
    pub block_number: u64,

    /// Block timestamp (Unix timestamp in seconds).
    pub timestamp: u64,

    /// Ordered list of transactions to execute.
    ///
    /// Transactions are ordered deterministically by the consensus layer:
    /// 1. Sort by validator ID
    /// 2. Iterate through Cars in order
    /// 3. Execute transactions within each Car sequentially
    pub transactions: Vec<Bytes>,

    /// Previous block hash (parent hash).
    pub parent_hash: B256,

    /// Gas limit for this block.
    pub gas_limit: u64,

    /// Base fee per gas (EIP-1559).
    pub base_fee_per_gas: Option<u64>,
}

/// Block data from consensus layer (Cut).
///
/// This represents a finalized, ordered set of transactions ready for execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusBlock {
    /// Block number.
    pub number: u64,

    /// Block timestamp.
    pub timestamp: u64,

    /// Parent block hash.
    pub parent_hash: B256,

    /// Ordered transactions from the consensus layer.
    pub transactions: Vec<Bytes>,

    /// Gas limit for this block.
    pub gas_limit: u64,

    /// Base fee per gas.
    pub base_fee_per_gas: Option<u64>,
}

/// Block after execution, ready for sealing.
///
/// Contains execution results including state root, receipts root, and gas used.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionBlock {
    /// Block number.
    pub number: u64,

    /// Block timestamp.
    pub timestamp: u64,

    /// Parent block hash.
    pub parent_hash: B256,

    /// State root after execution.
    ///
    /// May be empty (B256::ZERO) for non-checkpoint blocks.
    /// Computed only at STATE_ROOT_SNAPSHOT_INTERVAL intervals (default: every 100 blocks).
    pub state_root: B256,

    /// Receipts root (computed every block).
    pub receipts_root: B256,

    /// Transactions root (computed every block).
    pub transactions_root: B256,

    /// Logs bloom filter.
    pub logs_bloom: Bloom,

    /// Total gas used by all transactions in this block.
    pub gas_used: u64,

    /// Gas limit for this block.
    pub gas_limit: u64,

    /// Base fee per gas.
    pub base_fee_per_gas: Option<u64>,

    /// Extra data (arbitrary bytes).
    pub extra_data: Bytes,

    /// Transactions included in this block.
    pub transactions: Vec<Bytes>,
}

/// Sealed block with final hash.
///
/// This represents a fully executed and committed block with its hash computed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedBlock {
    /// Block header.
    pub header: BlockHeader,

    /// Block hash (hash of the header).
    pub hash: B256,

    /// Transactions in this block.
    pub transactions: Vec<Bytes>,

    /// Total difficulty (not used in PoS, kept for compatibility).
    pub total_difficulty: U256,
}

/// Block header structure.
///
/// Contains all metadata about a block, matching Ethereum's header format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Parent block hash.
    pub parent_hash: B256,

    /// Ommers/uncles hash (always empty hash in PoS).
    pub ommers_hash: B256,

    /// Beneficiary/coinbase address (validator address or zero in PoS).
    pub beneficiary: Address,

    /// State root.
    ///
    /// May be empty (B256::ZERO) for non-checkpoint blocks.
    pub state_root: B256,

    /// Transactions root.
    pub transactions_root: B256,

    /// Receipts root.
    pub receipts_root: B256,

    /// Logs bloom filter.
    pub logs_bloom: Bloom,

    /// Difficulty (always zero in PoS).
    pub difficulty: U256,

    /// Block number.
    pub number: u64,

    /// Gas limit.
    pub gas_limit: u64,

    /// Gas used.
    pub gas_used: u64,

    /// Timestamp.
    pub timestamp: u64,

    /// Extra data.
    pub extra_data: Bytes,

    /// Mix hash (prevrandao in PoS).
    pub mix_hash: B256,

    /// Nonce (always zero in PoS).
    pub nonce: B64,

    /// Base fee per gas (EIP-1559).
    pub base_fee_per_gas: Option<u64>,

    /// Withdrawals root (EIP-4895, not used in CipherBFT).
    pub withdrawals_root: Option<B256>,

    /// Blob gas used (EIP-4844).
    pub blob_gas_used: Option<u64>,

    /// Excess blob gas (EIP-4844).
    pub excess_blob_gas: Option<u64>,

    /// Parent beacon block root (EIP-4788).
    pub parent_beacon_block_root: Option<B256>,
}

/// Result of executing a block.
///
/// Returned to the consensus layer after successful execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// Block number.
    pub block_number: u64,

    /// State root after execution.
    ///
    /// May be empty (B256::ZERO) for non-checkpoint blocks.
    /// Computed only at STATE_ROOT_SNAPSHOT_INTERVAL intervals.
    pub state_root: B256,

    /// Receipts root (computed every block).
    pub receipts_root: B256,

    /// Transactions root (computed every block).
    pub transactions_root: B256,

    /// Total gas used by all transactions.
    pub gas_used: u64,

    /// Block hash of block N-DELAYED_COMMITMENT_DEPTH.
    ///
    /// For block N, this is the hash of block N-2.
    /// Allows finalization of previous blocks while producing current block.
    pub block_hash: B256,

    /// Individual transaction receipts.
    pub receipts: Vec<TransactionReceipt>,

    /// Logs bloom filter.
    pub logs_bloom: Bloom,
}

/// Transaction receipt.
///
/// Records the outcome of a transaction execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionReceipt {
    /// Transaction hash.
    pub transaction_hash: B256,

    /// Transaction index in the block.
    pub transaction_index: u64,

    /// Block hash.
    pub block_hash: B256,

    /// Block number.
    pub block_number: u64,

    /// Sender address.
    pub from: Address,

    /// Recipient address (None for contract creation).
    pub to: Option<Address>,

    /// Cumulative gas used in the block up to and including this transaction.
    pub cumulative_gas_used: u64,

    /// Gas used by this transaction.
    pub gas_used: u64,

    /// Contract address created (if contract creation transaction).
    pub contract_address: Option<Address>,

    /// Logs emitted by this transaction.
    pub logs: Vec<Log>,

    /// Logs bloom filter.
    pub logs_bloom: Bloom,

    /// Status: 1 for success, 0 for failure.
    pub status: u64,

    /// Effective gas price paid.
    pub effective_gas_price: u64,

    /// Transaction type (0 = legacy, 1 = EIP-2930, 2 = EIP-1559, 3 = EIP-4844).
    pub transaction_type: u8,
}

/// Log entry emitted during transaction execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Log {
    /// Address that emitted the log.
    pub address: Address,

    /// Topics (indexed parameters).
    pub topics: Vec<B256>,

    /// Data (non-indexed parameters).
    pub data: Bytes,
}

impl From<SealedBlock> for AlloyHeader {
    fn from(block: SealedBlock) -> Self {
        AlloyHeader {
            parent_hash: block.header.parent_hash,
            ommers_hash: block.header.ommers_hash,
            beneficiary: block.header.beneficiary,
            state_root: block.header.state_root,
            transactions_root: block.header.transactions_root,
            receipts_root: block.header.receipts_root,
            logs_bloom: block.header.logs_bloom,
            difficulty: block.header.difficulty,
            number: block.header.number,
            gas_limit: block.header.gas_limit,
            gas_used: block.header.gas_used,
            timestamp: block.header.timestamp,
            extra_data: block.header.extra_data,
            mix_hash: block.header.mix_hash,
            nonce: block.header.nonce,
            base_fee_per_gas: block.header.base_fee_per_gas,
            withdrawals_root: block.header.withdrawals_root,
            blob_gas_used: block.header.blob_gas_used,
            excess_blob_gas: block.header.excess_blob_gas,
            parent_beacon_block_root: block.header.parent_beacon_block_root,
            requests_hash: None, // EIP-7685, not used in CipherBFT
            target_blobs_per_block: Some(3), // EIP-4844 default target
        }
    }
}

impl Default for BlockHeader {
    fn default() -> Self {
        Self {
            parent_hash: B256::ZERO,
            ommers_hash: B256::ZERO,
            beneficiary: Address::ZERO,
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: Bloom::ZERO,
            difficulty: U256::ZERO,
            number: 0,
            gas_limit: 30_000_000, // Default 30M gas limit
            gas_used: 0,
            timestamp: 0,
            extra_data: Bytes::new(),
            mix_hash: B256::ZERO,
            nonce: B64::ZERO,
            base_fee_per_gas: Some(1_000_000_000), // 1 gwei default
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(STATE_ROOT_SNAPSHOT_INTERVAL, 100);
        assert_eq!(DELAYED_COMMITMENT_DEPTH, 2);
    }

    #[test]
    fn test_sealed_block_to_alloy_header_conversion() {
        let sealed_block = SealedBlock {
            header: BlockHeader {
                number: 42,
                gas_limit: 30_000_000,
                timestamp: 1234567890,
                ..Default::default()
            },
            hash: B256::ZERO,
            transactions: vec![],
            total_difficulty: U256::ZERO,
        };

        let alloy_header: AlloyHeader = sealed_block.clone().into();
        assert_eq!(alloy_header.number, 42);
        assert_eq!(alloy_header.gas_limit, 30_000_000);
        assert_eq!(alloy_header.timestamp, 1234567890);
    }

    #[test]
    fn test_default_block_header() {
        let header = BlockHeader::default();
        assert_eq!(header.number, 0);
        assert_eq!(header.gas_limit, 30_000_000);
        assert_eq!(header.base_fee_per_gas, Some(1_000_000_000));
        assert_eq!(header.difficulty, U256::ZERO);
    }
}
