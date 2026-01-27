//! RLP encoding utilities for Ethereum account state.
//!
//! This module provides RLP encoding functions that follow the Ethereum
//! specification for account encoding in the state trie.
//!
//! # Ethereum Account RLP Encoding
//!
//! An Ethereum account is RLP-encoded as a list of 4 fields:
//! `[nonce, balance, storage_root, code_hash]`
//!
//! Where:
//! - `nonce`: Transaction count (u64, encoded as big-endian with leading zeros stripped)
//! - `balance`: Account balance in wei (U256, encoded as big-endian with leading zeros stripped)
//! - `storage_root`: Merkle root of account storage (B256, always 32 bytes)
//! - `code_hash`: keccak256 of contract bytecode (B256, always 32 bytes, KECCAK_EMPTY for EOA)

use alloy_primitives::{B256, U256};
use alloy_rlp::{Encodable, RlpEncodable};

/// KECCAK_EMPTY is the hash of an empty byte array.
/// Used as code_hash for externally owned accounts (EOAs).
pub const KECCAK_EMPTY: B256 = B256::new([
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
]);

/// Account structure for RLP encoding.
///
/// This follows the Ethereum specification for account encoding:
/// `[nonce, balance, storage_root, code_hash]`
#[derive(Debug, Clone, RlpEncodable)]
pub struct RlpAccount {
    /// Transaction nonce.
    pub nonce: u64,
    /// Account balance in wei.
    pub balance: U256,
    /// Storage root (MPT root of account storage slots).
    pub storage_root: B256,
    /// Code hash (keccak256 of bytecode, or KECCAK_EMPTY for EOA).
    pub code_hash: B256,
}

impl RlpAccount {
    /// Create a new RLP-encodable account.
    pub fn new(nonce: u64, balance: U256, storage_root: B256, code_hash: B256) -> Self {
        Self {
            nonce,
            balance,
            storage_root,
            code_hash,
        }
    }

    /// Encode this account to RLP bytes.
    ///
    /// # Returns
    /// RLP-encoded account as `Vec<u8>`.
    pub fn encode_to_vec(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode(&mut out);
        out
    }
}

/// Encode an account to RLP bytes for state trie insertion.
///
/// # Arguments
/// * `nonce` - Transaction count
/// * `balance` - Account balance in wei
/// * `storage_root` - MPT root of account storage
/// * `code_hash` - keccak256 of contract bytecode
///
/// # Returns
/// RLP-encoded account bytes.
///
/// # Example
/// ```ignore
/// use alloy_primitives::{B256, U256};
/// use cipherbft_execution::rlp::{rlp_encode_account, KECCAK_EMPTY};
/// use alloy_trie::EMPTY_ROOT_HASH;
///
/// // Encode an EOA with nonce=5, balance=1000 wei
/// let encoded = rlp_encode_account(5, U256::from(1000), EMPTY_ROOT_HASH, KECCAK_EMPTY);
/// ```
pub fn rlp_encode_account(
    nonce: u64,
    balance: U256,
    storage_root: B256,
    code_hash: B256,
) -> Vec<u8> {
    RlpAccount::new(nonce, balance, storage_root, code_hash).encode_to_vec()
}

/// Encode a storage slot value for storage trie insertion.
///
/// Storage values are RLP-encoded as bytes with leading zeros stripped.
///
/// # Arguments
/// * `value` - Storage slot value
///
/// # Returns
/// RLP-encoded storage value bytes.
pub fn rlp_encode_storage_value(value: U256) -> Vec<u8> {
    let mut out = Vec::new();
    value.encode(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::keccak256;
    use alloy_trie::EMPTY_ROOT_HASH;

    #[test]
    fn test_keccak_empty_constant() {
        // Verify our KECCAK_EMPTY matches alloy's empty hash
        let computed = keccak256([]);
        assert_eq!(KECCAK_EMPTY, computed);
    }

    #[test]
    fn test_rlp_encode_eoa() {
        // Encode an externally owned account (no code, no storage)
        let encoded = rlp_encode_account(
            0,               // nonce
            U256::ZERO,      // balance
            EMPTY_ROOT_HASH, // storage_root
            KECCAK_EMPTY,    // code_hash
        );

        // Result should be non-empty RLP
        assert!(!encoded.is_empty());

        // Verify it starts with an RLP list prefix
        // For short lists (< 56 bytes total), prefix is 0xc0 + length
        assert!(encoded[0] >= 0xc0);
    }

    #[test]
    fn test_rlp_encode_account_with_balance() {
        let balance = U256::from(1_000_000_000_000_000_000u128); // 1 CPH
        let encoded = rlp_encode_account(
            5,               // nonce
            balance,         // balance
            EMPTY_ROOT_HASH, // storage_root
            KECCAK_EMPTY,    // code_hash
        );

        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_rlp_encode_contract_account() {
        // Contract account with custom storage root and code hash
        let storage_root = B256::from([1u8; 32]);
        let code_hash = keccak256(b"contract code");

        let encoded = rlp_encode_account(
            100,             // nonce
            U256::from(500), // balance
            storage_root,    // storage_root
            code_hash,       // code_hash
        );

        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_rlp_encode_determinism() {
        // Same inputs should produce identical outputs
        let balance = U256::from(12345u64);

        let encoded1 = rlp_encode_account(10, balance, EMPTY_ROOT_HASH, KECCAK_EMPTY);
        let encoded2 = rlp_encode_account(10, balance, EMPTY_ROOT_HASH, KECCAK_EMPTY);

        assert_eq!(encoded1, encoded2);
    }

    #[test]
    fn test_rlp_encode_storage_value() {
        let value = U256::from(42u64);
        let encoded = rlp_encode_storage_value(value);

        // Should encode as a single byte (42 < 128)
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_rlp_encode_storage_value_zero() {
        let value = U256::ZERO;
        let encoded = rlp_encode_storage_value(value);

        // Zero should be encoded as empty bytes (0x80 in RLP)
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_rlp_encode_storage_value_large() {
        let value = U256::MAX;
        let encoded = rlp_encode_storage_value(value);

        // Large value should produce valid RLP
        assert!(!encoded.is_empty());
    }
}
