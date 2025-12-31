//! CipherBFT transaction validator wrapper for Reth's pool.

use reth_primitives::InvalidTransactionError;
use reth_transaction_pool::{
    error::InvalidPoolTransactionError, PoolTransaction, TransactionOrigin,
    TransactionValidationOutcome, TransactionValidator,
};

/// CipherBFT-specific validation that wraps a Reth `TransactionValidator`.
#[derive(Debug, Clone)]
pub struct CipherBftValidator<V: TransactionValidator> {
    inner: V,
    chain_id: u64,
}

impl<V: TransactionValidator> CipherBftValidator<V> {
    /// Create a new wrapper around the given validator.
    pub fn new(inner: V, chain_id: u64) -> Self {
        Self { inner, chain_id }
    }
}
// to add custom validation logic, modify the validate_transaction method
impl<V: TransactionValidator> TransactionValidator for CipherBftValidator<V> {
    type Transaction = V::Transaction;

    async fn validate_transaction(
        &self,
        origin: TransactionOrigin,
        transaction: Self::Transaction,
    ) -> TransactionValidationOutcome<Self::Transaction> {

        self.inner.validate_transaction(origin, transaction).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_transaction_pool::noop::MockTransactionValidator;
    use reth_transaction_pool::test_utils::MockTransaction;

    #[tokio::test]
    async fn test_chain_id_mismatch_invalid() {
        let inner = MockTransactionValidator::<MockTransaction>::default();
        let validator = CipherBftValidator::new(inner, 2);
        let tx = MockTransaction::legacy();

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, tx)
            .await;

        assert!(outcome.is_invalid());
    }

    #[tokio::test]
    async fn test_chain_id_match_valid() {
        let inner = MockTransactionValidator::<MockTransaction>::default();
        let validator = CipherBftValidator::new(inner, 1);
        let tx = MockTransaction::legacy();

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, tx)
            .await;

        assert!(outcome.is_valid());
    }
}
