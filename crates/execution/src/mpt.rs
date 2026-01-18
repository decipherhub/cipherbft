//! Merkle Patricia Trie (MPT) computation utilities.
//!
//! This module provides functions for computing cryptographically verifiable
//! state roots using the Ethereum-compatible Merkle Patricia Trie structure.
//!
//! # State Root Computation
//!
//! The state root is computed by:
//! 1. Iterating over all accounts in sorted order (by address)
//! 2. For each account, computing its storage root from storage slots
//! 3. RLP encoding the account as `[nonce, balance, storage_root, code_hash]`
//! 4. Inserting `keccak256(address) -> rlp_account` into the trie
//! 5. Computing the trie root hash
//!
//! # Storage Root Computation
//!
//! Each account's storage root is computed by:
//! 1. Iterating over all storage slots in sorted order (by slot key)
//! 2. RLP encoding each non-zero value
//! 3. Inserting `keccak256(slot) -> rlp_value` into the trie
//! 4. Computing the trie root hash

use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_trie::{HashBuilder, Nibbles, EMPTY_ROOT_HASH};
use std::collections::BTreeMap;

use crate::database::Account;
use crate::rlp::{rlp_encode_account, rlp_encode_storage_value, KECCAK_EMPTY};

/// Compute the state root from a map of accounts.
///
/// This function computes a cryptographically verifiable state root using
/// the Merkle Patricia Trie structure, compatible with Ethereum's state trie.
///
/// # Arguments
/// * `accounts` - Map of address to account state
/// * `storage_getter` - Function to retrieve storage slots for an account
///
/// # Returns
/// The 32-byte state root hash.
///
/// # Algorithm
/// 1. Sort accounts by keccak256(address)
/// 2. For each account:
///    - Compute storage root from storage slots
///    - RLP encode account with storage root
///    - Add to trie with keccak256(address) as key
/// 3. Compute and return trie root
///
/// # Example
/// ```ignore
/// use alloy_primitives::{Address, U256};
/// use std::collections::BTreeMap;
/// use cipherbft_execution::mpt::compute_state_root;
/// use cipherbft_execution::database::Account;
///
/// let mut accounts = BTreeMap::new();
/// accounts.insert(Address::ZERO, Account::default());
///
/// let root = compute_state_root(&accounts, |_| Ok(BTreeMap::new()))?;
/// ```
pub fn compute_state_root<F>(
    accounts: &BTreeMap<Address, Account>,
    storage_getter: F,
) -> crate::Result<B256>
where
    F: Fn(Address) -> crate::Result<BTreeMap<U256, U256>>,
{
    if accounts.is_empty() {
        return Ok(EMPTY_ROOT_HASH);
    }

    // Collect and sort entries by keccak256(address)
    let mut entries: Vec<(B256, Vec<u8>)> = Vec::with_capacity(accounts.len());

    for (address, account) in accounts {
        // Get storage for this account and compute storage root
        let storage = storage_getter(*address)?;
        let storage_root = compute_storage_root(&storage);

        // Determine code hash (use KECCAK_EMPTY for EOAs)
        let code_hash = if account.code_hash == B256::ZERO {
            KECCAK_EMPTY
        } else {
            account.code_hash
        };

        // RLP encode the account
        let account_rlp =
            rlp_encode_account(account.nonce, account.balance, storage_root, code_hash);

        // Key is keccak256(address)
        let key = keccak256(address);
        entries.push((key, account_rlp));
    }

    // Sort by key (keccak256(address)) for deterministic ordering
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    // Build the trie
    Ok(compute_root_from_entries(&entries))
}

/// Compute the storage root for an account from its storage slots.
///
/// # Arguments
/// * `storage` - Map of storage slot key to value
///
/// # Returns
/// The 32-byte storage root hash. Returns `EMPTY_ROOT_HASH` if storage is empty.
///
/// # Algorithm
/// 1. Filter out zero values (empty slots)
/// 2. Sort by keccak256(slot_key)
/// 3. RLP encode each value
/// 4. Build trie and return root
pub fn compute_storage_root(storage: &BTreeMap<U256, U256>) -> B256 {
    // Filter out zero values and prepare entries
    let non_zero_storage: Vec<_> = storage.iter().filter(|(_, v)| !v.is_zero()).collect();

    if non_zero_storage.is_empty() {
        return EMPTY_ROOT_HASH;
    }

    // Collect entries with keccak256(slot) as key
    let mut entries: Vec<(B256, Vec<u8>)> = non_zero_storage
        .iter()
        .map(|(slot, value)| {
            let key = keccak256(slot.to_be_bytes::<32>());
            let value_rlp = rlp_encode_storage_value(**value);
            (key, value_rlp)
        })
        .collect();

    // Sort by key for deterministic ordering
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    compute_root_from_entries(&entries)
}

/// Compute MPT root hash from sorted key-value entries.
///
/// # Arguments
/// * `entries` - Sorted vector of (key, value) pairs where key is already hashed
///
/// # Returns
/// The 32-byte trie root hash.
fn compute_root_from_entries(entries: &[(B256, Vec<u8>)]) -> B256 {
    if entries.is_empty() {
        return EMPTY_ROOT_HASH;
    }

    let mut builder = HashBuilder::default();

    for (key, value) in entries {
        // Convert B256 key to Nibbles for trie insertion
        let nibbles = Nibbles::unpack(key);
        builder.add_leaf(nibbles, value.as_slice());
    }

    builder.root()
}

/// Compute state root directly from a list of (address, account_rlp) entries.
///
/// This is a lower-level function useful when you already have RLP-encoded accounts.
///
/// # Arguments
/// * `entries` - Vector of (address, rlp_encoded_account) pairs
///
/// # Returns
/// The 32-byte state root hash.
pub fn compute_state_root_from_entries(entries: &[(Address, Vec<u8>)]) -> B256 {
    if entries.is_empty() {
        return EMPTY_ROOT_HASH;
    }

    // Convert to (keccak256(address), value) and sort
    let mut hashed_entries: Vec<(B256, Vec<u8>)> = entries
        .iter()
        .map(|(addr, rlp)| (keccak256(addr), rlp.clone()))
        .collect();

    hashed_entries.sort_by(|a, b| a.0.cmp(&b.0));

    compute_root_from_entries(&hashed_entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    #[test]
    fn test_empty_state_root() {
        let accounts = BTreeMap::new();
        let root = compute_state_root(&accounts, |_| Ok(BTreeMap::new())).unwrap();
        assert_eq!(root, EMPTY_ROOT_HASH);
    }

    #[test]
    fn test_empty_storage_root() {
        let storage = BTreeMap::new();
        let root = compute_storage_root(&storage);
        assert_eq!(root, EMPTY_ROOT_HASH);
    }

    #[test]
    fn test_single_account_state_root() {
        let mut accounts = BTreeMap::new();
        let addr = address!("1111111111111111111111111111111111111111");
        accounts.insert(
            addr,
            Account {
                balance: U256::from(1000u64),
                nonce: 1,
                code_hash: B256::ZERO, // EOA
                storage_root: EMPTY_ROOT_HASH,
            },
        );

        let root = compute_state_root(&accounts, |_| Ok(BTreeMap::new())).unwrap();

        // Root should not be empty
        assert_ne!(root, EMPTY_ROOT_HASH);
        // Root should be deterministic
        let root2 = compute_state_root(&accounts, |_| Ok(BTreeMap::new())).unwrap();
        assert_eq!(root, root2);
    }

    #[test]
    fn test_storage_root_with_values() {
        let mut storage = BTreeMap::new();
        storage.insert(U256::from(0u64), U256::from(100u64));
        storage.insert(U256::from(1u64), U256::from(200u64));

        let root = compute_storage_root(&storage);

        // Root should not be empty
        assert_ne!(root, EMPTY_ROOT_HASH);
        // Root should be deterministic
        let root2 = compute_storage_root(&storage);
        assert_eq!(root, root2);
    }

    #[test]
    fn test_storage_root_ignores_zero_values() {
        let mut storage = BTreeMap::new();
        storage.insert(U256::from(0u64), U256::ZERO); // Zero value, should be ignored
        storage.insert(U256::from(1u64), U256::from(100u64));

        let root_with_zero = compute_storage_root(&storage);

        // Remove zero entry and compute again
        let mut storage_no_zero = BTreeMap::new();
        storage_no_zero.insert(U256::from(1u64), U256::from(100u64));
        let root_without_zero = compute_storage_root(&storage_no_zero);

        // Should produce identical roots since zero values are ignored
        assert_eq!(root_with_zero, root_without_zero);
    }

    #[test]
    fn test_state_root_determinism_with_multiple_accounts() {
        let mut accounts = BTreeMap::new();
        let addr1 = address!("1111111111111111111111111111111111111111");
        let addr2 = address!("2222222222222222222222222222222222222222");
        let addr3 = address!("3333333333333333333333333333333333333333");

        accounts.insert(
            addr1,
            Account {
                balance: U256::from(1000u64),
                nonce: 1,
                code_hash: B256::ZERO,
                storage_root: EMPTY_ROOT_HASH,
            },
        );
        accounts.insert(
            addr2,
            Account {
                balance: U256::from(2000u64),
                nonce: 5,
                code_hash: B256::ZERO,
                storage_root: EMPTY_ROOT_HASH,
            },
        );
        accounts.insert(
            addr3,
            Account {
                balance: U256::from(3000u64),
                nonce: 10,
                code_hash: B256::ZERO,
                storage_root: EMPTY_ROOT_HASH,
            },
        );

        // Compute multiple times
        let root1 = compute_state_root(&accounts, |_| Ok(BTreeMap::new())).unwrap();
        let root2 = compute_state_root(&accounts, |_| Ok(BTreeMap::new())).unwrap();
        let root3 = compute_state_root(&accounts, |_| Ok(BTreeMap::new())).unwrap();

        // All should be identical
        assert_eq!(root1, root2);
        assert_eq!(root2, root3);
    }

    #[test]
    fn test_state_root_with_storage() {
        let mut accounts = BTreeMap::new();
        let addr = address!("1111111111111111111111111111111111111111");
        let code_hash = keccak256(b"contract code");

        accounts.insert(
            addr,
            Account {
                balance: U256::from(1000u64),
                nonce: 1,
                code_hash,
                storage_root: EMPTY_ROOT_HASH,
            },
        );

        // Storage getter that returns some storage
        let storage_getter = |address: Address| -> crate::Result<BTreeMap<U256, U256>> {
            if address == addr {
                let mut storage = BTreeMap::new();
                storage.insert(U256::from(0u64), U256::from(42u64));
                storage.insert(U256::from(1u64), U256::from(100u64));
                Ok(storage)
            } else {
                Ok(BTreeMap::new())
            }
        };

        let root_with_storage = compute_state_root(&accounts, storage_getter).unwrap();

        // Compute without storage
        let root_without_storage = compute_state_root(&accounts, |_| Ok(BTreeMap::new())).unwrap();

        // Roots should be different due to different storage roots
        assert_ne!(root_with_storage, root_without_storage);
    }

    #[test]
    fn test_different_accounts_different_roots() {
        let addr = address!("1111111111111111111111111111111111111111");

        let mut accounts1 = BTreeMap::new();
        accounts1.insert(
            addr,
            Account {
                balance: U256::from(1000u64),
                nonce: 1,
                code_hash: B256::ZERO,
                storage_root: EMPTY_ROOT_HASH,
            },
        );

        let mut accounts2 = BTreeMap::new();
        accounts2.insert(
            addr,
            Account {
                balance: U256::from(2000u64), // Different balance
                nonce: 1,
                code_hash: B256::ZERO,
                storage_root: EMPTY_ROOT_HASH,
            },
        );

        let root1 = compute_state_root(&accounts1, |_| Ok(BTreeMap::new())).unwrap();
        let root2 = compute_state_root(&accounts2, |_| Ok(BTreeMap::new())).unwrap();

        // Different accounts should produce different roots
        assert_ne!(root1, root2);
    }
}
