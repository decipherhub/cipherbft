//! Merkle proof generation for eth_getProof (EIP-1186).
//!
//! This module provides functionality to generate Merkle proofs for:
//! - Account existence/state in the state trie
//! - Storage slot values in an account's storage trie
//!
//! These proofs can be used to verify account state and storage values
//! against a known state root without accessing the full state.

use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_trie::{proof::ProofRetainer, HashBuilder, Nibbles, EMPTY_ROOT_HASH};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::database::Account;
use crate::rlp::{rlp_encode_account, rlp_encode_storage_value, KECCAK_EMPTY};
use crate::Result;

/// Storage proof for a single slot.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageProof {
    /// The storage key.
    pub key: U256,
    /// The value at this storage key.
    pub value: U256,
    /// Merkle proof for this storage slot.
    pub proof: Vec<Bytes>,
}

/// Account proof response for eth_getProof.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountProof {
    /// The address of the account.
    pub address: Address,
    /// Account balance.
    pub balance: U256,
    /// Code hash of the account (keccak256 of empty for EOA).
    pub code_hash: B256,
    /// Account nonce.
    pub nonce: u64,
    /// Storage root hash.
    pub storage_hash: B256,
    /// Merkle proof for the account in the state trie.
    pub account_proof: Vec<Bytes>,
    /// Proofs for the requested storage keys.
    pub storage_proof: Vec<StorageProof>,
}

/// Generate an account proof and storage proofs for the given address and storage keys.
///
/// # Arguments
///
/// * `accounts` - All accounts in the state
/// * `storage_getter` - Function to get storage for an account
/// * `address` - The address to generate proof for
/// * `storage_keys` - Storage keys to generate proofs for
///
/// # Returns
///
/// Returns an `AccountProof` containing the account state and Merkle proofs.
pub fn generate_account_proof<F>(
    accounts: &BTreeMap<Address, Account>,
    storage_getter: F,
    address: Address,
    storage_keys: Vec<U256>,
) -> Result<AccountProof>
where
    F: Fn(Address) -> Result<BTreeMap<U256, U256>>,
{
    // Get account state (default if not found)
    let account = accounts.get(&address).cloned().unwrap_or_default();

    // Get storage for this account
    let storage = storage_getter(address)?;

    // Compute storage root and storage proofs
    let (storage_hash, storage_proofs) = generate_storage_proofs(&storage, &storage_keys);

    // Generate account proof
    let account_proof = generate_state_proof(accounts, &storage_getter, address)?;

    // Determine proper code hash
    let code_hash = if account.code_hash == B256::ZERO {
        KECCAK_EMPTY
    } else {
        account.code_hash
    };

    Ok(AccountProof {
        address,
        balance: account.balance,
        code_hash,
        nonce: account.nonce,
        storage_hash,
        account_proof,
        storage_proof: storage_proofs,
    })
}

/// Generate a Merkle proof for an account in the state trie.
fn generate_state_proof<F>(
    accounts: &BTreeMap<Address, Account>,
    storage_getter: &F,
    target_address: Address,
) -> Result<Vec<Bytes>>
where
    F: Fn(Address) -> Result<BTreeMap<U256, U256>>,
{
    if accounts.is_empty() {
        // Empty trie - return empty proof
        return Ok(vec![]);
    }

    // The target key in the state trie
    let target_key = keccak256(target_address);
    let target_nibbles = Nibbles::unpack(target_key);

    // Create proof retainer for the target account
    let retainer = ProofRetainer::new(vec![target_nibbles]);

    // Build the state trie with proof retainer
    let mut builder = HashBuilder::default().with_proof_retainer(retainer);

    // Collect and sort entries by keccak256(address)
    let mut entries: Vec<(B256, Vec<u8>)> = Vec::with_capacity(accounts.len());

    for (address, account) in accounts {
        // Get storage for this account and compute storage root
        let storage = storage_getter(*address)?;
        let storage_root = compute_storage_root_internal(&storage);

        // Determine code hash
        let code_hash = if account.code_hash == B256::ZERO {
            KECCAK_EMPTY
        } else {
            account.code_hash
        };

        // RLP encode the account
        let account_rlp =
            rlp_encode_account(account.nonce, account.balance, storage_root, code_hash);

        let key = keccak256(address);
        entries.push((key, account_rlp));
    }

    // Sort by key for deterministic ordering
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    // Add all leaves to the builder
    for (key, value) in &entries {
        let nibbles = Nibbles::unpack(key);
        builder.add_leaf(nibbles, value.as_slice());
    }

    // Compute root and get proof nodes
    let _ = builder.root();
    let proof_nodes = builder.take_proof_nodes();

    // Convert proof nodes to sorted proof bytes
    let mut proof: Vec<(Nibbles, Bytes)> =
        proof_nodes.iter().map(|(k, v)| (*k, v.clone())).collect();
    proof.sort_by(|a, b| a.0.cmp(&b.0));

    Ok(proof.into_iter().map(|(_, bytes)| bytes).collect())
}

/// Generate storage proofs for the given keys.
fn generate_storage_proofs(
    storage: &BTreeMap<U256, U256>,
    keys: &[U256],
) -> (B256, Vec<StorageProof>) {
    if storage.is_empty() && keys.is_empty() {
        return (EMPTY_ROOT_HASH, vec![]);
    }

    // Build target nibbles for all requested keys
    let target_nibbles: Vec<Nibbles> = keys
        .iter()
        .map(|key| {
            let hashed = keccak256(key.to_be_bytes::<32>());
            Nibbles::unpack(hashed)
        })
        .collect();

    // Create proof retainer
    let retainer = ProofRetainer::new(target_nibbles.clone());

    // Build the storage trie with proof retainer
    let mut builder = HashBuilder::default().with_proof_retainer(retainer);

    // Filter and collect non-zero storage entries
    let mut entries: Vec<(B256, Vec<u8>)> = storage
        .iter()
        .filter(|(_, v)| !v.is_zero())
        .map(|(slot, value)| {
            let key = keccak256(slot.to_be_bytes::<32>());
            let value_rlp = rlp_encode_storage_value(*value);
            (key, value_rlp)
        })
        .collect();

    // Sort by key
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    // Add all leaves
    for (key, value) in &entries {
        let nibbles = Nibbles::unpack(key);
        builder.add_leaf(nibbles, value.as_slice());
    }

    // Compute root
    let root = if entries.is_empty() {
        EMPTY_ROOT_HASH
    } else {
        builder.root()
    };

    // Get proof nodes
    let proof_nodes = builder.take_proof_nodes();

    // Build storage proofs for each key
    let storage_proofs: Vec<StorageProof> = keys
        .iter()
        .map(|key| {
            let hashed = keccak256(key.to_be_bytes::<32>());
            let target = Nibbles::unpack(hashed);

            // Get the value (default to zero if not found)
            let value = storage.get(key).copied().unwrap_or(U256::ZERO);

            // Filter proof nodes that are on the path to this key
            let proof: Vec<Bytes> = proof_nodes
                .iter()
                .filter(|(path, _)| target.starts_with(path) || path.is_empty())
                .map(|(_, bytes)| bytes.clone())
                .collect();

            StorageProof {
                key: *key,
                value,
                proof,
            }
        })
        .collect();

    (root, storage_proofs)
}

/// Compute storage root (internal helper).
fn compute_storage_root_internal(storage: &BTreeMap<U256, U256>) -> B256 {
    let non_zero_storage: Vec<_> = storage.iter().filter(|(_, v)| !v.is_zero()).collect();

    if non_zero_storage.is_empty() {
        return EMPTY_ROOT_HASH;
    }

    let mut entries: Vec<(B256, Vec<u8>)> = non_zero_storage
        .iter()
        .map(|(slot, value)| {
            let key = keccak256(slot.to_be_bytes::<32>());
            let value_rlp = rlp_encode_storage_value(**value);
            (key, value_rlp)
        })
        .collect();

    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut builder = HashBuilder::default();
    for (key, value) in &entries {
        let nibbles = Nibbles::unpack(key);
        builder.add_leaf(nibbles, value.as_slice());
    }

    builder.root()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    #[test]
    fn test_generate_account_proof_empty_state() {
        let accounts = BTreeMap::new();
        let addr = address!("1111111111111111111111111111111111111111");

        let proof =
            generate_account_proof(&accounts, |_| Ok(BTreeMap::new()), addr, vec![]).unwrap();

        // Empty state should return default account
        assert_eq!(proof.address, addr);
        assert_eq!(proof.balance, U256::ZERO);
        assert_eq!(proof.nonce, 0);
        assert_eq!(proof.storage_hash, EMPTY_ROOT_HASH);
    }

    #[test]
    fn test_generate_account_proof_with_account() {
        let mut accounts = BTreeMap::new();
        let addr = address!("1111111111111111111111111111111111111111");

        accounts.insert(
            addr,
            Account {
                balance: U256::from(1000u64),
                nonce: 5,
                code_hash: B256::ZERO,
                storage_root: EMPTY_ROOT_HASH,
            },
        );

        let proof =
            generate_account_proof(&accounts, |_| Ok(BTreeMap::new()), addr, vec![]).unwrap();

        assert_eq!(proof.address, addr);
        assert_eq!(proof.balance, U256::from(1000u64));
        assert_eq!(proof.nonce, 5);
        assert_eq!(proof.code_hash, KECCAK_EMPTY);
        // Should have some proof nodes
        assert!(!proof.account_proof.is_empty());
    }

    #[test]
    fn test_generate_storage_proofs() {
        let mut storage = BTreeMap::new();
        storage.insert(U256::from(0u64), U256::from(42u64));
        storage.insert(U256::from(1u64), U256::from(100u64));

        let keys = vec![U256::from(0u64), U256::from(1u64), U256::from(99u64)];

        let (root, proofs) = generate_storage_proofs(&storage, &keys);

        // Root should not be empty
        assert_ne!(root, EMPTY_ROOT_HASH);

        // Should have 3 proofs
        assert_eq!(proofs.len(), 3);

        // First two should have values
        assert_eq!(proofs[0].key, U256::from(0u64));
        assert_eq!(proofs[0].value, U256::from(42u64));

        assert_eq!(proofs[1].key, U256::from(1u64));
        assert_eq!(proofs[1].value, U256::from(100u64));

        // Third should be zero (not in storage)
        assert_eq!(proofs[2].key, U256::from(99u64));
        assert_eq!(proofs[2].value, U256::ZERO);
    }

    #[test]
    fn test_storage_proof_empty() {
        let storage = BTreeMap::new();
        let keys = vec![U256::from(0u64)];

        let (root, proofs) = generate_storage_proofs(&storage, &keys);

        assert_eq!(root, EMPTY_ROOT_HASH);
        assert_eq!(proofs.len(), 1);
        assert_eq!(proofs[0].value, U256::ZERO);
    }

    #[test]
    fn test_account_proof_with_storage() {
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

        let storage_getter = |address: Address| -> Result<BTreeMap<U256, U256>> {
            if address == addr {
                let mut storage = BTreeMap::new();
                storage.insert(U256::from(0u64), U256::from(42u64));
                Ok(storage)
            } else {
                Ok(BTreeMap::new())
            }
        };

        let storage_keys = vec![U256::from(0u64)];
        let proof = generate_account_proof(&accounts, storage_getter, addr, storage_keys).unwrap();

        assert_eq!(proof.code_hash, code_hash);
        assert_ne!(proof.storage_hash, EMPTY_ROOT_HASH);
        assert_eq!(proof.storage_proof.len(), 1);
        assert_eq!(proof.storage_proof[0].value, U256::from(42u64));
    }
}
