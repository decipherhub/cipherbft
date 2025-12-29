//! Transaction receipts and Merkle root computation.
//!
//! This module provides functions for:
//! - Computing receipts root from transaction receipts
//! - Computing transactions root from transaction list
//! - Computing logs bloom filters
//! - Aggregating bloom filters

use crate::{types::Log, Result};
use alloy_primitives::{Bloom, Bytes, B256};
use alloy_trie::root::ordered_trie_root;

/// Compute the Merkle Patricia Trie root of transaction receipts.
///
/// This function creates an ordered Merkle Patricia Trie from the given receipts
/// and returns the root hash. The root is used in the block header for verification.
///
/// # Arguments
/// * `receipts` - RLP-encoded transaction receipts
///
/// # Returns
/// * Receipts root hash (B256)
///
/// # Example
/// ```rust,ignore
/// let receipts = vec![receipt1_rlp, receipt2_rlp, receipt3_rlp];
/// let root = compute_receipts_root(&receipts)?;
/// ```
pub fn compute_receipts_root(receipts: &[Bytes]) -> Result<B256> {
    if receipts.is_empty() {
        // Empty trie has a well-known root (Keccak256 of RLP-encoded empty array)
        return Ok(alloy_trie::EMPTY_ROOT_HASH);
    }

    // Convert Bytes to Vec<u8> for ordered_trie_root
    let receipt_data: Vec<Vec<u8>> = receipts.iter().map(|r| r.to_vec()).collect();

    // Compute ordered trie root
    let root = ordered_trie_root(&receipt_data);

    Ok(root)
}

/// Compute the Merkle Patricia Trie root of transactions.
///
/// This function creates an ordered Merkle Patricia Trie from the given transactions
/// and returns the root hash. The root is used in the block header for verification.
///
/// # Arguments
/// * `transactions` - RLP-encoded transactions
///
/// # Returns
/// * Transactions root hash (B256)
///
/// # Example
/// ```rust,ignore
/// let transactions = vec![tx1_rlp, tx2_rlp, tx3_rlp];
/// let root = compute_transactions_root(&transactions)?;
/// ```
pub fn compute_transactions_root(transactions: &[Bytes]) -> Result<B256> {
    if transactions.is_empty() {
        // Empty trie has a well-known root (Keccak256 of RLP-encoded empty array)
        return Ok(alloy_trie::EMPTY_ROOT_HASH);
    }

    // Convert Bytes to Vec<u8> for ordered_trie_root
    let tx_data: Vec<Vec<u8>> = transactions.iter().map(|t| t.to_vec()).collect();

    // Compute ordered trie root
    let root = ordered_trie_root(&tx_data);

    Ok(root)
}

/// Compute a bloom filter from a list of logs.
///
/// The bloom filter is a probabilistic data structure used to quickly test
/// whether a log might be present in a set. It's used for efficient log filtering.
///
/// # Arguments
/// * `logs` - Logs to include in the bloom filter
///
/// # Returns
/// * Bloom filter containing all logs
///
/// # Example
/// ```rust,ignore
/// let logs = vec![log1, log2, log3];
/// let bloom = logs_bloom(&logs);
/// ```
pub fn logs_bloom(logs: &[Log]) -> Bloom {
    let mut bloom = Bloom::ZERO;

    for log in logs {
        // Add the log address to the bloom filter
        bloom.accrue(alloy_primitives::BloomInput::Raw(&log.address[..]));

        // Add each topic to the bloom filter
        for topic in &log.topics {
            bloom.accrue(alloy_primitives::BloomInput::Raw(&topic[..]));
        }
    }

    bloom
}

/// Aggregate multiple bloom filters into a single bloom filter.
///
/// This is used to combine bloom filters from multiple transactions
/// into a single block-level bloom filter.
///
/// # Arguments
/// * `blooms` - Individual bloom filters to aggregate
///
/// # Returns
/// * Aggregated bloom filter
///
/// # Example
/// ```rust,ignore
/// let blooms = vec![bloom1, bloom2, bloom3];
/// let aggregated = aggregate_bloom(&blooms);
/// ```
pub fn aggregate_bloom(blooms: &[Bloom]) -> Bloom {
    let mut result = Bloom::ZERO;

    for bloom in blooms {
        result |= *bloom;
    }

    result
}

/// Compute logs bloom from multiple transaction logs.
///
/// This is a convenience function that computes individual blooms for each
/// transaction's logs and then aggregates them.
///
/// # Arguments
/// * `transaction_logs` - Logs grouped by transaction
///
/// # Returns
/// * Aggregated bloom filter for all logs
pub fn compute_logs_bloom_from_transactions(transaction_logs: &[Vec<Log>]) -> Bloom {
    let blooms: Vec<Bloom> = transaction_logs.iter().map(|logs| logs_bloom(logs)).collect();
    aggregate_bloom(&blooms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Address;

    #[test]
    fn test_empty_receipts_root() {
        let receipts: Vec<Bytes> = vec![];
        let root = compute_receipts_root(&receipts).unwrap();
        assert_eq!(root, alloy_trie::EMPTY_ROOT_HASH);
    }

    #[test]
    fn test_empty_transactions_root() {
        let transactions: Vec<Bytes> = vec![];
        let root = compute_transactions_root(&transactions).unwrap();
        assert_eq!(root, alloy_trie::EMPTY_ROOT_HASH);
    }

    #[test]
    fn test_single_receipt_root() {
        // Create a simple receipt (just some dummy data)
        let receipt_data = Bytes::from(vec![0x01, 0x02, 0x03]);
        let receipts = vec![receipt_data];

        let root = compute_receipts_root(&receipts).unwrap();
        assert_ne!(root, B256::ZERO);
        assert_ne!(root, alloy_trie::EMPTY_ROOT_HASH);
    }

    #[test]
    fn test_single_transaction_root() {
        // Create a simple transaction (just some dummy data)
        let tx_data = Bytes::from(vec![0x04, 0x05, 0x06]);
        let transactions = vec![tx_data];

        let root = compute_transactions_root(&transactions).unwrap();
        assert_ne!(root, B256::ZERO);
        assert_ne!(root, alloy_trie::EMPTY_ROOT_HASH);
    }

    #[test]
    fn test_deterministic_receipts_root() {
        let receipt1 = Bytes::from(vec![0x01, 0x02, 0x03]);
        let receipt2 = Bytes::from(vec![0x04, 0x05, 0x06]);
        let receipts = vec![receipt1.clone(), receipt2.clone()];

        // Compute root twice
        let root1 = compute_receipts_root(&receipts).unwrap();
        let root2 = compute_receipts_root(&receipts).unwrap();

        // Should be deterministic
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_deterministic_transactions_root() {
        let tx1 = Bytes::from(vec![0x07, 0x08, 0x09]);
        let tx2 = Bytes::from(vec![0x0a, 0x0b, 0x0c]);
        let transactions = vec![tx1.clone(), tx2.clone()];

        // Compute root twice
        let root1 = compute_transactions_root(&transactions).unwrap();
        let root2 = compute_transactions_root(&transactions).unwrap();

        // Should be deterministic
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_order_matters() {
        let receipt1 = Bytes::from(vec![0x01, 0x02, 0x03]);
        let receipt2 = Bytes::from(vec![0x04, 0x05, 0x06]);

        let receipts_forward = vec![receipt1.clone(), receipt2.clone()];
        let receipts_backward = vec![receipt2.clone(), receipt1.clone()];

        let root_forward = compute_receipts_root(&receipts_forward).unwrap();
        let root_backward = compute_receipts_root(&receipts_backward).unwrap();

        // Order matters - roots should be different
        assert_ne!(root_forward, root_backward);
    }

    #[test]
    fn test_empty_logs_bloom() {
        let logs: Vec<Log> = vec![];
        let bloom = logs_bloom(&logs);
        assert_eq!(bloom, Bloom::ZERO);
    }

    #[test]
    fn test_logs_bloom_with_logs() {
        let log = Log {
            address: Address::from([1u8; 20]),
            topics: vec![B256::from([2u8; 32])],
            data: Bytes::from(vec![3u8, 4u8, 5u8]),
        };

        let logs = vec![log];
        let bloom = logs_bloom(&logs);

        // Bloom should not be zero after adding logs
        assert_ne!(bloom, Bloom::ZERO);
    }

    #[test]
    fn test_bloom_contains_address() {
        let address = Address::from([1u8; 20]);
        let log = Log {
            address,
            topics: vec![],
            data: Bytes::new(),
        };

        let bloom = logs_bloom(&[log]);

        // The bloom filter should contain the address
        assert!(bloom.contains_input(alloy_primitives::BloomInput::Raw(&address[..])));
    }

    #[test]
    fn test_bloom_contains_topic() {
        let topic = B256::from([2u8; 32]);
        let log = Log {
            address: Address::ZERO,
            topics: vec![topic],
            data: Bytes::new(),
        };

        let bloom = logs_bloom(&[log]);

        // The bloom filter should contain the topic
        assert!(bloom.contains_input(alloy_primitives::BloomInput::Raw(&topic[..])));
    }

    #[test]
    fn test_aggregate_bloom_empty() {
        let blooms: Vec<Bloom> = vec![];
        let aggregated = aggregate_bloom(&blooms);
        assert_eq!(aggregated, Bloom::ZERO);
    }

    #[test]
    fn test_aggregate_bloom_single() {
        let log = Log {
            address: Address::from([1u8; 20]),
            topics: vec![B256::from([2u8; 32])],
            data: Bytes::new(),
        };

        let bloom = logs_bloom(&[log]);
        let aggregated = aggregate_bloom(&[bloom]);

        assert_eq!(aggregated, bloom);
    }

    #[test]
    fn test_aggregate_bloom_multiple() {
        let log1 = Log {
            address: Address::from([1u8; 20]),
            topics: vec![],
            data: Bytes::new(),
        };

        let log2 = Log {
            address: Address::from([2u8; 20]),
            topics: vec![],
            data: Bytes::new(),
        };

        let bloom1 = logs_bloom(&[log1.clone()]);
        let bloom2 = logs_bloom(&[log2.clone()]);

        let aggregated = aggregate_bloom(&[bloom1, bloom2]);

        // Aggregated bloom should contain both addresses
        assert!(aggregated.contains_input(alloy_primitives::BloomInput::Raw(&log1.address[..])));
        assert!(aggregated.contains_input(alloy_primitives::BloomInput::Raw(&log2.address[..])));
    }

    #[test]
    fn test_compute_logs_bloom_from_transactions() {
        let log1 = Log {
            address: Address::from([1u8; 20]),
            topics: vec![B256::from([1u8; 32])],
            data: Bytes::new(),
        };

        let log2 = Log {
            address: Address::from([2u8; 20]),
            topics: vec![B256::from([2u8; 32])],
            data: Bytes::new(),
        };

        let log3 = Log {
            address: Address::from([3u8; 20]),
            topics: vec![B256::from([3u8; 32])],
            data: Bytes::new(),
        };

        let tx1_logs = vec![log1.clone()];
        let tx2_logs = vec![log2.clone(), log3.clone()];

        let transaction_logs = vec![tx1_logs, tx2_logs];
        let bloom = compute_logs_bloom_from_transactions(&transaction_logs);

        // All addresses should be in the bloom
        assert!(bloom.contains_input(alloy_primitives::BloomInput::Raw(&log1.address[..])));
        assert!(bloom.contains_input(alloy_primitives::BloomInput::Raw(&log2.address[..])));
        assert!(bloom.contains_input(alloy_primitives::BloomInput::Raw(&log3.address[..])));

        // All topics should be in the bloom
        assert!(bloom.contains_input(alloy_primitives::BloomInput::Raw(&log1.topics[0][..])));
        assert!(bloom.contains_input(alloy_primitives::BloomInput::Raw(&log2.topics[0][..])));
        assert!(bloom.contains_input(alloy_primitives::BloomInput::Raw(&log3.topics[0][..])));
    }

    #[test]
    fn test_bloom_deterministic() {
        let log = Log {
            address: Address::from([1u8; 20]),
            topics: vec![B256::from([2u8; 32])],
            data: Bytes::new(),
        };

        let bloom1 = logs_bloom(&[log.clone()]);
        let bloom2 = logs_bloom(&[log.clone()]);

        assert_eq!(bloom1, bloom2);
    }
}
