//! Transaction ordering helpers built on top of Reth's pool traits.

use reth_transaction_pool::PoolTransaction;

/// Ordering key derived from a pool transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionOrdering {
    pub effective_gas_price: u128,
    pub nonce: u64,
}

impl TransactionOrdering {
    /// Build an ordering key from any Reth pool transaction.
    pub fn from_pool_transaction<T: PoolTransaction>(tx: &T) -> Self {
        Self {
            effective_gas_price: tx.priority_fee_or_price(),
            nonce: tx.nonce(),
        }
    }
}

impl Ord for TransactionOrdering {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Higher gas price comes first
        match other.effective_gas_price.cmp(&self.effective_gas_price) {
            std::cmp::Ordering::Equal => self.nonce.cmp(&other.nonce),
            ordering => ordering,
        }
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
    fn test_ordering_manual() {
        let high = TransactionOrdering {
            effective_gas_price: 200,
            nonce: 1,
        };
        let low = TransactionOrdering {
            effective_gas_price: 100,
            nonce: 0,
        };

        assert!(high < low);
    }
}
