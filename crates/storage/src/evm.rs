//! EVM storage traits and types for execution layer integration.
//!
//! This module provides the `EvmStore` trait that abstracts EVM state storage,
//! allowing the execution layer to work with different storage backends.

use crate::error::StorageError;

/// EVM Account information.
///
/// Mirrors the Account struct from the execution layer, using raw byte arrays
/// to avoid circular dependencies.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvmAccount {
    /// Account nonce.
    pub nonce: u64,
    /// Account balance (big-endian U256).
    pub balance: [u8; 32],
    /// Code hash (keccak256 of bytecode).
    pub code_hash: [u8; 32],
    /// Storage root (for Merkle Patricia Trie).
    pub storage_root: [u8; 32],
}

impl EvmAccount {
    /// Create a new EvmAccount with zero balance and empty code.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if this is an empty account (zero nonce, zero balance, no code).
    pub fn is_empty(&self) -> bool {
        self.nonce == 0 && self.balance == [0u8; 32] && self.code_hash == [0u8; 32]
    }
}

/// EVM bytecode.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvmBytecode {
    /// Raw bytecode bytes.
    pub code: Vec<u8>,
}

impl EvmBytecode {
    /// Create new bytecode from raw bytes.
    pub fn new(code: Vec<u8>) -> Self {
        Self { code }
    }

    /// Check if bytecode is empty.
    pub fn is_empty(&self) -> bool {
        self.code.is_empty()
    }
}

/// Result type for EVM storage operations.
pub type EvmStoreResult<T> = Result<T, StorageError>;

/// Trait for EVM state storage.
///
/// This trait provides the interface for storing and retrieving EVM state,
/// including accounts, code, storage slots, and block hashes.
///
/// Implementations can be in-memory (for testing) or persistent (MDBX).
pub trait EvmStore: Send + Sync {
    /// Get account information by address.
    ///
    /// # Arguments
    /// * `address` - 20-byte Ethereum address
    ///
    /// # Returns
    /// * `Ok(Some(account))` - Account exists
    /// * `Ok(None)` - Account does not exist
    /// * `Err(e)` - Storage error
    fn get_account(&self, address: &[u8; 20]) -> EvmStoreResult<Option<EvmAccount>>;

    /// Set account information.
    ///
    /// # Arguments
    /// * `address` - 20-byte Ethereum address
    /// * `account` - Account state to store
    fn set_account(&self, address: &[u8; 20], account: EvmAccount) -> EvmStoreResult<()>;

    /// Delete an account.
    ///
    /// # Arguments
    /// * `address` - 20-byte Ethereum address
    fn delete_account(&self, address: &[u8; 20]) -> EvmStoreResult<()>;

    /// Get contract bytecode by code hash.
    ///
    /// # Arguments
    /// * `code_hash` - 32-byte keccak256 hash of the bytecode
    ///
    /// # Returns
    /// * `Ok(Some(bytecode))` - Code exists
    /// * `Ok(None)` - Code not found
    /// * `Err(e)` - Storage error
    fn get_code(&self, code_hash: &[u8; 32]) -> EvmStoreResult<Option<EvmBytecode>>;

    /// Set contract bytecode.
    ///
    /// # Arguments
    /// * `code_hash` - 32-byte keccak256 hash of the bytecode
    /// * `bytecode` - Contract bytecode to store
    fn set_code(&self, code_hash: &[u8; 32], bytecode: EvmBytecode) -> EvmStoreResult<()>;

    /// Get storage slot value.
    ///
    /// # Arguments
    /// * `address` - 20-byte Ethereum address
    /// * `slot` - 32-byte storage slot (big-endian U256)
    ///
    /// # Returns
    /// * Storage value as 32-byte big-endian U256 (zero if not set)
    fn get_storage(&self, address: &[u8; 20], slot: &[u8; 32]) -> EvmStoreResult<[u8; 32]>;

    /// Set storage slot value.
    ///
    /// # Arguments
    /// * `address` - 20-byte Ethereum address
    /// * `slot` - 32-byte storage slot (big-endian U256)
    /// * `value` - 32-byte value (big-endian U256)
    fn set_storage(
        &self,
        address: &[u8; 20],
        slot: &[u8; 32],
        value: [u8; 32],
    ) -> EvmStoreResult<()>;

    /// Get block hash by block number.
    ///
    /// # Arguments
    /// * `number` - Block number
    ///
    /// # Returns
    /// * `Ok(Some(hash))` - Block hash found
    /// * `Ok(None)` - Block hash not found
    /// * `Err(e)` - Storage error
    fn get_block_hash(&self, number: u64) -> EvmStoreResult<Option<[u8; 32]>>;

    /// Set block hash.
    ///
    /// # Arguments
    /// * `number` - Block number
    /// * `hash` - 32-byte block hash
    fn set_block_hash(&self, number: u64, hash: [u8; 32]) -> EvmStoreResult<()>;

    /// Get the current block number (last executed block).
    ///
    /// This method retrieves the persisted block number for execution engine recovery.
    /// Returns `None` if no block has been executed yet (first startup).
    ///
    /// # Returns
    /// * `Ok(Some(block_number))` - The last executed block number
    /// * `Ok(None)` - No block has been executed yet
    fn get_current_block(&self) -> EvmStoreResult<Option<u64>>;

    /// Set the current block number (last executed block).
    ///
    /// This method persists the block number after each block execution to enable
    /// proper recovery after node restart.
    ///
    /// # Arguments
    /// * `block_number` - The block number to persist
    fn set_current_block(&self, block_number: u64) -> EvmStoreResult<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evm_account_is_empty() {
        let account = EvmAccount::default();
        assert!(account.is_empty());

        let account = EvmAccount {
            nonce: 1,
            ..Default::default()
        };
        assert!(!account.is_empty());
    }

    #[test]
    fn test_evm_bytecode() {
        let code = EvmBytecode::new(vec![0x60, 0x00, 0x60, 0x00]);
        assert!(!code.is_empty());
        assert_eq!(code.code.len(), 4);

        let empty = EvmBytecode::default();
        assert!(empty.is_empty());
    }
}
