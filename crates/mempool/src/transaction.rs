//! Transaction metadata and ordering

use reth_primitives::{B256, Address, TransactionSigned};
use serde::{Deserialize, Serialize};
use crate::error::MempoolError;

/// Transaction information tracked in mempool
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionInfo {
    /// Transaction hash
    pub hash: B256,

    /// Sender address
    pub sender: Address,

    /// Nonce
    pub nonce: u64,

    /// Gas limit
    pub gas_limit: u64,

    /// Effective gas price (wei)
    pub effective_gas_price: u128,

    /// Transaction size (bytes)
    pub size: usize,

    /// Whether in pending pool (true) or queued (false)
    pub is_pending: bool,
}

impl TransactionInfo {
    /// Create from a signed transaction
    pub fn from_signed(tx: &TransactionSigned, is_pending: bool) -> Result<Self, MempoolError> {
        let sender = tx
            .recover_signer()
            .ok_or_else(|| MempoolError::InvalidTransaction("Invalid signature".to_string()))?;

        Ok(Self {
            hash: tx.hash(),
            sender,
            nonce: tx.nonce(),
            gas_limit: tx.gas_limit(),
            effective_gas_price: tx.effective_gas_price(None),
            size: tx.encoded_2718().len(),
            is_pending,
        })
    }

    /// Calculate effective gas price with base fee
    pub fn with_base_fee(&self, base_fee: u128) -> u128 {
        self.effective_gas_price.max(base_fee)
    }
}

/// Transaction ordering by gas price (descending)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionOrdering {
    pub effective_gas_price: u128,
    pub nonce: u64,
}

impl Ord for TransactionOrdering {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Higher gas price comes first
        other
            .effective_gas_price
            .cmp(&self.effective_gas_price)
            .then_with(|| self.nonce.cmp(&other.nonce))
    }
}

impl PartialOrd for TransactionOrdering {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ordering() {
        let tx1 = TransactionOrdering {
            effective_gas_price: 100,
            nonce: 0,
        };
        let tx2 = TransactionOrdering {
            effective_gas_price: 200,
            nonce: 1,
        };

        // Higher gas price should come first
        assert!(tx2 < tx1);
    }
}
