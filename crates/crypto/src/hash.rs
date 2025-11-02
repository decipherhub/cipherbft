//! Hashing utilities using SHA-256.
//!
//! Provides standard cryptographic hashing functions and Merkle tree
//! computation for transaction batches.

use sha2::{Digest, Sha256};

/// Hash arbitrary data using SHA-256.
pub fn hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Hash a block header.
pub fn hash_block(data: &[u8]) -> [u8; 32] {
    hash(data)
}

/// Hash a transaction.
pub fn hash_tx(data: &[u8]) -> [u8; 32] {
    hash(data)
}

/// Compute Merkle root of transaction hashes using binary tree.
///
/// Implementation follows Bitcoin's Merkle tree algorithm:
/// - If empty, returns zero hash
/// - If single hash, returns that hash
/// - Otherwise, recursively combines pairs of hashes
/// - If odd number of hashes, duplicates the last one
pub fn merkle_root(hashes: &[[u8; 32]]) -> [u8; 32] {
    if hashes.is_empty() {
        return [0u8; 32];
    }
    if hashes.len() == 1 {
        return hashes[0];
    }

    // Recursively build merkle tree
    merkle_root_recursive(hashes)
}

/// Internal recursive merkle tree builder.
fn merkle_root_recursive(hashes: &[[u8; 32]]) -> [u8; 32] {
    if hashes.len() == 1 {
        return hashes[0];
    }

    let mut next_level = Vec::new();

    // Process pairs of hashes
    for chunk in hashes.chunks(2) {
        let combined = if chunk.len() == 2 {
            // Hash the concatenation of two hashes
            hash_pair(&chunk[0], &chunk[1])
        } else {
            // Odd number: duplicate the last hash
            hash_pair(&chunk[0], &chunk[0])
        };
        next_level.push(combined);
    }

    merkle_root_recursive(&next_level)
}

/// Hash a pair of hashes together.
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Compute merkle root from raw transaction data.
///
/// This is a convenience function that hashes transactions first,
/// then computes the merkle root.
pub fn merkle_root_from_txs(transactions: &[&[u8]]) -> [u8; 32] {
    let tx_hashes: Vec<[u8; 32]> = transactions.iter().map(|tx| hash_tx(tx)).collect();
    merkle_root(&tx_hashes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_deterministic() {
        let data = b"test";
        let hash1 = hash_tx(data);
        let hash2 = hash_tx(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_merkle_root_empty() {
        let hashes = [];
        let root = merkle_root(&hashes);
        assert_eq!(root, [0u8; 32]);
    }

    #[test]
    fn test_merkle_root_single() {
        let hash = [1u8; 32];
        let root = merkle_root(&[hash]);
        assert_eq!(root, hash);
    }

    #[test]
    fn test_merkle_root_two() {
        let hash1 = [1u8; 32];
        let hash2 = [2u8; 32];
        let root = merkle_root(&[hash1, hash2]);

        // Should be hash of concatenation
        let expected = hash_pair(&hash1, &hash2);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_root_four() {
        let hashes = [
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            [4u8; 32],
        ];
        let root = merkle_root(&hashes);

        // Manually compute expected root
        let h12 = hash_pair(&hashes[0], &hashes[1]);
        let h34 = hash_pair(&hashes[2], &hashes[3]);
        let expected = hash_pair(&h12, &h34);

        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_root_odd() {
        let hashes = [
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
        ];
        let root = merkle_root(&hashes);

        // Third hash should be duplicated
        let h12 = hash_pair(&hashes[0], &hashes[1]);
        let h33 = hash_pair(&hashes[2], &hashes[2]);
        let expected = hash_pair(&h12, &h33);

        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_root_deterministic() {
        let hashes = [
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            [4u8; 32],
        ];

        let root1 = merkle_root(&hashes);
        let root2 = merkle_root(&hashes);

        assert_eq!(root1, root2);
    }

    #[test]
    fn test_merkle_root_from_txs() {
        let txs = vec![b"tx1".as_slice(), b"tx2".as_slice(), b"tx3".as_slice()];
        let root = merkle_root_from_txs(&txs);

        // Should match manual calculation
        let tx_hashes: Vec<[u8; 32]> = txs.iter().map(|tx| hash_tx(tx)).collect();
        let expected = merkle_root(&tx_hashes);

        assert_eq!(root, expected);
    }

    #[test]
    fn test_different_order_different_root() {
        let hashes1 = [[1u8; 32], [2u8; 32]];
        let hashes2 = [[2u8; 32], [1u8; 32]];

        let root1 = merkle_root(&hashes1);
        let root2 = merkle_root(&hashes2);

        // Order matters
        assert_ne!(root1, root2);
    }
}
