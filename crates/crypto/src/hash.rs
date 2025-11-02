//! Hashing utilities.

use sha2::{Digest, Sha256};

/// Hash a block header.
pub fn hash_block(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Hash a transaction.
pub fn hash_tx(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute Merkle root of transaction hashes.
pub fn merkle_root(hashes: &[[u8; 32]]) -> [u8; 32] {
    if hashes.is_empty() {
        return [0u8; 32];
    }
    if hashes.len() == 1 {
        return hashes[0];
    }

    // Simplified Merkle tree (not production-ready)
    let mut hasher = Sha256::new();
    for hash in hashes {
        hasher.update(hash);
    }
    hasher.finalize().into()
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
}
