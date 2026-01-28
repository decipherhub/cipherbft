//! Custom RPC types with Ethereum-compatible hex serialization.
//!
//! This module provides custom block and header types that serialize numeric fields
//! as hex strings (e.g., `"0x1fd"` instead of `509`) to comply with the Ethereum
//! JSON-RPC specification and ensure compatibility with block explorers like Blockscout.
//!
//! # Why Custom Types?
//!
//! The standard `alloy_consensus::Header` uses `U64HexOrNumber` for numeric fields,
//! which serializes as integers. While this is valid for deserializing, it causes
//! compatibility issues with Elixir-based clients (like Blockscout) that expect
//! strict Ethereum JSON-RPC format with hex-encoded quantities.

use alloy_eips::eip4895::Withdrawal;
use alloy_primitives::{Address, Bloom, Bytes, B256, B64, U256};
use alloy_rpc_types_eth::Block;
use serde::{Deserialize, Serialize};
use tracing::warn;

/// RPC transaction representation with proper hex serialization.
///
/// This struct represents a full transaction object as returned by
/// `eth_getBlockByNumber` and `eth_getBlockByHash` when `full_transactions=true`.
/// All numeric fields are serialized as hex strings per Ethereum JSON-RPC spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcTransaction {
    /// Transaction hash
    pub hash: B256,
    /// Block hash containing this transaction
    pub block_hash: Option<B256>,
    /// Block number containing this transaction
    #[serde(serialize_with = "alloy_serde::quantity::opt::serialize")]
    pub block_number: Option<u64>,
    /// Index of this transaction within the block
    #[serde(serialize_with = "alloy_serde::quantity::opt::serialize")]
    pub transaction_index: Option<u64>,
    /// Sender address
    pub from: Address,
    /// Recipient address (None for contract creation)
    pub to: Option<Address>,
    /// Value transferred in wei
    pub value: U256,
    /// Input data (contract call data or deployment bytecode)
    pub input: Bytes,
    /// Transaction nonce
    #[serde(serialize_with = "alloy_serde::quantity::serialize")]
    pub nonce: u64,
    /// Gas limit
    #[serde(serialize_with = "alloy_serde::quantity::serialize")]
    pub gas: u64,
    /// Gas price (for legacy and EIP-2930 transactions)
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "alloy_serde::quantity::opt::serialize"
    )]
    pub gas_price: Option<u64>,
    /// Max fee per gas (EIP-1559)
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "alloy_serde::quantity::opt::serialize"
    )]
    pub max_fee_per_gas: Option<u64>,
    /// Max priority fee per gas (EIP-1559)
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "alloy_serde::quantity::opt::serialize"
    )]
    pub max_priority_fee_per_gas: Option<u64>,
    /// Chain ID
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "alloy_serde::quantity::opt::serialize"
    )]
    pub chain_id: Option<u64>,
    /// Transaction type (0 = legacy, 1 = EIP-2930, 2 = EIP-1559)
    #[serde(rename = "type", serialize_with = "alloy_serde::quantity::serialize")]
    pub transaction_type: u8,
    /// ECDSA signature v value
    #[serde(serialize_with = "alloy_serde::quantity::serialize")]
    pub v: u64,
    /// ECDSA signature r value
    pub r: B256,
    /// ECDSA signature s value
    pub s: B256,
}

impl RpcTransaction {
    /// Create an RpcTransaction from a storage Transaction.
    ///
    /// This conversion is used when `full_transactions=true` is requested
    /// in `eth_getBlockByNumber` or `eth_getBlockByHash`.
    pub fn from_storage(tx: cipherbft_storage::transactions::Transaction) -> Self {
        Self {
            hash: B256::from(tx.hash),
            block_hash: Some(B256::from(tx.block_hash)),
            block_number: Some(tx.block_number),
            transaction_index: Some(tx.transaction_index as u64),
            from: Address::from(tx.from),
            to: tx.to.map(Address::from),
            value: U256::from_be_bytes(tx.value),
            input: Bytes::from(tx.input),
            nonce: tx.nonce,
            gas: tx.gas,
            gas_price: tx.gas_price,
            max_fee_per_gas: tx.max_fee_per_gas,
            max_priority_fee_per_gas: tx.max_priority_fee_per_gas,
            chain_id: tx.chain_id,
            transaction_type: tx.transaction_type,
            v: tx.v,
            r: B256::from(tx.r),
            s: B256::from(tx.s),
        }
    }
}

/// Block transactions - either hashes or full transaction objects.
///
/// Uses untagged serde to match Ethereum JSON-RPC format where the
/// `transactions` field contains either an array of hashes (when
/// `full_transactions=false`) or an array of full transaction objects
/// (when `full_transactions=true`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BlockTransactions {
    /// Transaction hashes only (full_transactions=false)
    Hashes(Vec<B256>),
    /// Full transaction objects (full_transactions=true)
    Full(Vec<RpcTransaction>),
}

impl BlockTransactions {
    /// Get the transaction hash at the given index.
    ///
    /// For `Hashes` variant, returns the hash at the index.
    /// For `Full` variant, returns the hash from the transaction at the index.
    pub fn get_hash(&self, index: usize) -> Option<&B256> {
        match self {
            BlockTransactions::Hashes(hashes) => hashes.get(index),
            BlockTransactions::Full(txs) => txs.get(index).map(|tx| &tx.hash),
        }
    }

    /// Get the number of transactions.
    pub fn len(&self) -> usize {
        match self {
            BlockTransactions::Hashes(hashes) => hashes.len(),
            BlockTransactions::Full(txs) => txs.len(),
        }
    }

    /// Check if there are no transactions.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get all transaction hashes as a vector.
    pub fn hashes(&self) -> Vec<&B256> {
        match self {
            BlockTransactions::Hashes(hashes) => hashes.iter().collect(),
            BlockTransactions::Full(txs) => txs.iter().map(|tx| &tx.hash).collect(),
        }
    }
}

/// RPC Block representation with proper hex serialization.
///
/// All numeric fields are serialized as hex strings following the Ethereum
/// JSON-RPC "quantity" format (e.g., `"0x1fd"` for 509).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcBlock {
    /// Block hash
    pub hash: B256,
    /// Parent block hash
    pub parent_hash: B256,
    /// Ommers/uncles hash (always empty hash in PoS)
    #[serde(rename = "sha3Uncles")]
    pub ommers_hash: B256,
    /// Coinbase/miner address
    pub miner: Address,
    /// State root
    pub state_root: B256,
    /// Transactions root
    pub transactions_root: B256,
    /// Receipts root
    pub receipts_root: B256,
    /// Logs bloom filter
    pub logs_bloom: Bloom,
    /// Difficulty (always 0 in PoS)
    #[serde(serialize_with = "serialize_u256_hex")]
    pub difficulty: U256,
    /// Block number
    #[serde(serialize_with = "alloy_serde::quantity::serialize")]
    pub number: u64,
    /// Gas limit
    #[serde(serialize_with = "alloy_serde::quantity::serialize")]
    pub gas_limit: u64,
    /// Gas used
    #[serde(serialize_with = "alloy_serde::quantity::serialize")]
    pub gas_used: u64,
    /// Block timestamp
    #[serde(serialize_with = "alloy_serde::quantity::serialize")]
    pub timestamp: u64,
    /// Extra data
    pub extra_data: Bytes,
    /// Mix hash (used in PoW, random value in PoS)
    pub mix_hash: B256,
    /// Nonce (always zero bytes in PoS)
    pub nonce: B64,
    /// Total difficulty (sum of all block difficulties).
    /// Returns `None` for post-merge (PoS) blocks per EIP-3675.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_opt_u256_hex"
    )]
    pub total_difficulty: Option<U256>,
    /// Base fee per gas (EIP-1559)
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "alloy_serde::quantity::opt::serialize"
    )]
    pub base_fee_per_gas: Option<u64>,
    /// Block size in bytes (optional)
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "alloy_serde::quantity::opt::serialize"
    )]
    pub size: Option<u64>,
    /// Withdrawals root (EIP-4895)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawals_root: Option<B256>,
    /// Blob gas used (EIP-4844)
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "alloy_serde::quantity::opt::serialize"
    )]
    pub blob_gas_used: Option<u64>,
    /// Excess blob gas (EIP-4844)
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "alloy_serde::quantity::opt::serialize"
    )]
    pub excess_blob_gas: Option<u64>,
    /// Parent beacon block root (EIP-4788)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_beacon_block_root: Option<B256>,
    /// Block transactions.
    ///
    /// Contains either transaction hashes (when `full_transactions=false`)
    /// or full transaction objects (when `full_transactions=true`).
    pub transactions: BlockTransactions,
    /// Uncle block hashes (always empty in PoS)
    pub uncles: Vec<B256>,
    /// Withdrawals (EIP-4895).
    /// Contains validator withdrawals with proper hex serialization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawals: Option<Vec<Withdrawal>>,
}

/// Serialize U256 as a hex string using alloy's default serialization.
///
/// This uses alloy_primitives' built-in U256 serialization. Note that this may
/// produce a different format than Ethereum's "quantity" encoding (which strips
/// leading zeros). For strict Ethereum JSON-RPC compliance on u64 fields, we use
/// `alloy_serde::quantity::serialize` which properly implements the quantity format.
///
/// For U256 fields like `difficulty` and `total_difficulty`, clients generally
/// accept both formats since these are typically zero in PoS chains.
fn serialize_u256_hex<S>(value: &U256, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    value.serialize(serializer)
}

/// Serialize Option<U256> as a hex string.
fn serialize_opt_u256_hex<S>(value: &Option<U256>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match value {
        Some(v) => v.serialize(serializer),
        None => serializer.serialize_none(),
    }
}

impl RpcBlock {
    /// Create a new RpcBlock from storage block data with transaction hashes only.
    ///
    /// This is the primary constructor for converting internal storage format
    /// to the RPC-compatible format with proper hex serialization.
    /// Returns transaction hashes only (for `full_transactions=false`).
    pub fn from_storage(storage_block: cipherbft_storage::blocks::Block) -> Self {
        let tx_hashes: Vec<B256> = storage_block
            .transaction_hashes
            .iter()
            .map(|h| B256::from(*h))
            .collect();

        Self::from_storage_with_txs(storage_block, BlockTransactions::Hashes(tx_hashes))
    }

    /// Create a new RpcBlock from storage block data with full transaction objects.
    ///
    /// This constructor is used when `full_transactions=true` is requested.
    /// The caller must provide the full transaction objects.
    pub fn from_storage_full(
        storage_block: cipherbft_storage::blocks::Block,
        transactions: Vec<RpcTransaction>,
    ) -> Self {
        Self::from_storage_with_txs(storage_block, BlockTransactions::Full(transactions))
    }

    /// Internal constructor that accepts pre-built BlockTransactions.
    fn from_storage_with_txs(
        storage_block: cipherbft_storage::blocks::Block,
        transactions: BlockTransactions,
    ) -> Self {
        Self {
            hash: B256::from(storage_block.hash),
            parent_hash: B256::from(storage_block.parent_hash),
            ommers_hash: B256::from(storage_block.ommers_hash),
            miner: Address::from(storage_block.beneficiary),
            state_root: B256::from(storage_block.state_root),
            transactions_root: B256::from(storage_block.transactions_root),
            receipts_root: B256::from(storage_block.receipts_root),
            // Use try_from for safe conversion - log and fall back to zero bloom on invalid data
            logs_bloom: <Bloom as TryFrom<&[u8]>>::try_from(&storage_block.logs_bloom)
                .unwrap_or_else(|_| {
                    warn!(
                        block_number = storage_block.number,
                        bloom_len = storage_block.logs_bloom.len(),
                        "Invalid logs_bloom data in storage block, using zero bloom"
                    );
                    Bloom::ZERO
                }),
            difficulty: U256::from_be_bytes(storage_block.difficulty),
            number: storage_block.number,
            gas_limit: storage_block.gas_limit,
            gas_used: storage_block.gas_used,
            timestamp: storage_block.timestamp,
            extra_data: Bytes::from(storage_block.extra_data),
            mix_hash: B256::from(storage_block.mix_hash),
            nonce: B64::from(storage_block.nonce),
            total_difficulty: Some(U256::from_be_bytes(storage_block.total_difficulty)),
            base_fee_per_gas: storage_block.base_fee_per_gas,
            size: Some(storage_block.size),
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: None,
            transactions,
            uncles: Vec::new(),
            withdrawals: None,
        }
    }
}

/// Convert from alloy_rpc_types_eth::Block to RpcBlock.
///
/// This conversion enables seamless transition from the standard Alloy Block type
/// (which serializes numeric fields as integers) to our RpcBlock type (which
/// serializes numeric fields as hex strings per Ethereum JSON-RPC spec).
///
/// Note: This conversion always returns transaction hashes only, not full objects.
impl From<Block> for RpcBlock {
    fn from(block: Block) -> Self {
        let header = &block.header.inner;

        Self {
            hash: block.header.hash,
            parent_hash: header.parent_hash,
            ommers_hash: header.ommers_hash,
            miner: header.beneficiary,
            state_root: header.state_root,
            transactions_root: header.transactions_root,
            receipts_root: header.receipts_root,
            logs_bloom: header.logs_bloom,
            difficulty: header.difficulty,
            number: header.number,
            gas_limit: header.gas_limit,
            gas_used: header.gas_used,
            timestamp: header.timestamp,
            extra_data: header.extra_data.clone(),
            mix_hash: header.mix_hash,
            nonce: header.nonce,
            total_difficulty: block.header.total_difficulty,
            base_fee_per_gas: header.base_fee_per_gas,
            size: block.header.size.map(|v| v.to::<u64>()),
            withdrawals_root: header.withdrawals_root,
            blob_gas_used: header.blob_gas_used,
            excess_blob_gas: header.excess_blob_gas,
            parent_beacon_block_root: header.parent_beacon_block_root,
            transactions: BlockTransactions::Hashes(block.transactions.hashes().collect()),
            uncles: block.uncles.clone(),
            withdrawals: block.withdrawals.clone().map(|w| w.into_inner()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_serializes_numbers_as_hex() {
        let block = RpcBlock {
            hash: B256::ZERO,
            parent_hash: B256::ZERO,
            ommers_hash: B256::ZERO,
            miner: Address::ZERO,
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: Bloom::ZERO,
            difficulty: U256::ZERO,
            number: 509,
            gas_limit: 30_000_000,
            gas_used: 21000,
            timestamp: 1706163600,
            extra_data: Bytes::new(),
            mix_hash: B256::ZERO,
            nonce: B64::ZERO,
            total_difficulty: Some(U256::ZERO),
            base_fee_per_gas: Some(1_000_000_000),
            size: None,
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: None,
            transactions: BlockTransactions::Hashes(Vec::new()),
            uncles: Vec::new(),
            withdrawals: None,
        };

        let json = serde_json::to_string(&block).unwrap();

        // Verify numeric fields are hex-encoded
        assert!(
            json.contains("\"number\":\"0x1fd\""),
            "number should be hex: {}",
            json
        );
        assert!(
            json.contains("\"gasLimit\":\"0x1c9c380\""),
            "gasLimit should be hex: {}",
            json
        );
        assert!(
            json.contains("\"gasUsed\":\"0x5208\""),
            "gasUsed should be hex: {}",
            json
        );
        // 1706163600 = 0x65b1fd90
        assert!(
            json.contains("\"timestamp\":\"0x65b1fd90\""),
            "timestamp should be hex: {}",
            json
        );
        assert!(
            json.contains("\"baseFeePerGas\":\"0x3b9aca00\""),
            "baseFeePerGas should be hex: {}",
            json
        );

        // Verify hash fields remain as full hex strings with 0x prefix
        assert!(
            json.contains(
                "\"hash\":\"0x0000000000000000000000000000000000000000000000000000000000000000\""
            ),
            "hash should be full hex: {}",
            json
        );
    }
}
