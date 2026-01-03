//! CipherBFT transaction validator wrapper for Reth's pool.

use reth_storage_api::StateProviderFactory;
use reth_transaction_pool::{
    blobstore::BlobStore,
    validate::{EthTransactionValidator, EthTransactionValidatorBuilder},
    EthPoolTransaction, TransactionOrigin, TransactionValidationOutcome, TransactionValidator,
};
use std::sync::Arc;

/// CipherBFT-specific validation that wraps a Reth `TransactionValidator`.
#[derive(Debug, Clone)]
pub struct CipherBftValidator<V: TransactionValidator> {
    inner: V,
    chain_id: u64,
}

impl<V: TransactionValidator> CipherBftValidator<V> {
    /// Create a new wrapper around the given validator.
    pub fn wrap(inner: V, chain_id: u64) -> Self {
        Self { inner, chain_id }
    }
}

impl<Client, Tx> CipherBftValidator<EthTransactionValidator<Client, Tx>>
where
    Client: StateProviderFactory,
    Tx: EthPoolTransaction,
{
    /// Build a wrapper with a reth EthTransactionValidator.
    pub fn new<S>(
        chain_spec: Arc<reth_chainspec::ChainSpec>,
        client: Client,
        blob_store: S,
        chain_id: u64,
    ) -> Self
    where
        S: BlobStore,
    {
        let validator = EthTransactionValidatorBuilder::new(chain_spec).build(client, blob_store);
        Self::wrap(validator, chain_id)
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
        let _ = self.chain_id;
        self.inner.validate_transaction(origin, transaction).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U256};
    use reth_chainspec::{Chain, ChainSpecBuilder, MAINNET};
    use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
    use reth_transaction_pool::blobstore::InMemoryBlobStore;
    use reth_transaction_pool::test_utils::TransactionBuilder;
    use reth_transaction_pool::validate::EthTransactionValidator;
    use reth_transaction_pool::EthPooledTransaction;
    use reth_transaction_pool::PoolTransaction;
    use std::sync::Arc;

    fn build_test_pooled_tx(chain_id: u64) -> EthPooledTransaction {
        TransactionBuilder::default()
            .chain_id(chain_id)
            .to(Address::ZERO)
            .gas_limit(100_000)
            .max_fee_per_gas(1_000_000_000)
            .max_priority_fee_per_gas(1_000_000_000)
            .into_eip1559()
            .into_ecrecovered()
            .expect("recover signed transaction")
            .try_into()
            .expect("convert to pooled transaction")
    }

    fn build_test_validator(
        chain_id: u64,
        tx: &EthPooledTransaction,
    ) -> CipherBftValidator<EthTransactionValidator<MockEthProvider, EthPooledTransaction>> {
        let chain_spec = ChainSpecBuilder::mainnet()
            .chain(Chain::from_id(chain_id))
            .build();
        let provider = MockEthProvider::default();
        provider.add_account(tx.sender(), ExtendedAccount::new(tx.nonce(), U256::MAX));
        let blob_store = InMemoryBlobStore::default();
        CipherBftValidator::new(Arc::new(chain_spec), provider, blob_store, chain_id)
    }

    #[tokio::test]
    async fn test_chain_id_mismatch_invalid() {
        let tx = build_test_pooled_tx(MAINNET.chain.id());
        let validator = build_test_validator(2, &tx);

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, tx)
            .await;

        assert!(outcome.is_invalid());
    }

    #[tokio::test]
    async fn test_chain_id_match_valid() {
        let chain_id = MAINNET.chain.id();
        let tx = build_test_pooled_tx(chain_id);
        let validator = build_test_validator(chain_id, &tx);

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, tx)
            .await;

        assert!(outcome.is_valid());
    }
}
