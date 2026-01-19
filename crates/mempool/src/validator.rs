//! CipherBFT transaction validator wrapper for Reth's pool.
//!
//! This module provides transaction validation that combines:
//! 1. Reth's `EthTransactionValidator` for standard Ethereum validation
//! 2. CipherBFT's execution layer validation for state-dependent checks
//!
//! The execution layer validation ensures transactions are validated against
//! CipherBFT's own state (balance, nonce, gas) rather than relying solely on
//! Reth's provider state.

use alloy_eips::Encodable2718;
use reth_chainspec::{ChainSpecProvider, EthereumHardforks};
use reth_storage_api::StateProviderFactory;
use reth_transaction_pool::{
    blobstore::BlobStore,
    error::{InvalidPoolTransactionError, PoolTransactionError},
    validate::{EthTransactionValidator, EthTransactionValidatorBuilder},
    EthPoolTransaction, PoolTransaction, TransactionOrigin, TransactionValidationOutcome,
    TransactionValidator,
};
use std::any::Any;
use std::sync::Arc;
use tracing::warn;

/// Error type for execution layer validation failures.
///
/// This error is used when a transaction passes Reth's basic validation
/// but fails CipherBFT's execution layer state validation.
#[derive(Debug, Clone, thiserror::Error)]
#[error("Execution layer validation failed: {reason}")]
pub struct ExecutionValidationError {
    /// Description of why validation failed
    pub reason: String,
}

impl ExecutionValidationError {
    /// Create a new execution validation error
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl PoolTransactionError for ExecutionValidationError {
    /// Execution layer validation failures are considered bad transactions
    /// since they represent actual state violations (insufficient balance, wrong nonce, etc.)
    fn is_bad_transaction(&self) -> bool {
        true
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Trait for execution layer transaction validation.
///
/// This trait allows the mempool validator to call into the execution layer
/// for state-dependent validation (balance, nonce, gas checks) without
/// creating a direct dependency on the execution crate.
///
/// Implementations should validate:
/// - Sender has sufficient balance for gas cost + value
/// - Nonce is correct (>= account nonce for pending txs)
/// - Gas limit is within block limits
/// - Transaction is well-formed for EVM execution
#[async_trait::async_trait]
pub trait ExecutionLayerValidator: Send + Sync + std::fmt::Debug {
    /// Validate a transaction against execution layer state.
    ///
    /// # Arguments
    ///
    /// * `tx_bytes` - EIP-2718 encoded transaction bytes
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the transaction passes all execution layer checks
    /// * `Err(reason)` if validation fails, with a description of the failure
    async fn validate_transaction(&self, tx_bytes: &[u8]) -> Result<(), String>;
}

/// CipherBFT-specific validation that wraps a Reth `TransactionValidator`.
///
/// This validator performs two-phase validation:
/// 1. **Reth validation**: Standard Ethereum checks via `EthTransactionValidator`
/// 2. **Execution layer validation**: CipherBFT-specific state checks
///
/// The execution layer validation is optional but recommended. Without it,
/// invalid transactions (insufficient balance, bad nonce) may enter the mempool
/// and only fail at block production time.
pub struct CipherBftValidator<V: TransactionValidator> {
    /// Inner Reth validator for standard Ethereum checks
    inner: V,
    /// Optional execution layer validator for state-dependent checks
    execution_validator: Option<Arc<dyn ExecutionLayerValidator>>,
}

impl<V: TransactionValidator> std::fmt::Debug for CipherBftValidator<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CipherBftValidator")
            .field("inner", &std::any::type_name::<V>())
            .field(
                "execution_validator",
                &self.execution_validator.as_ref().map(|_| "Some(...)"),
            )
            .finish()
    }
}

impl<V: TransactionValidator + Clone> Clone for CipherBftValidator<V> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            execution_validator: self.execution_validator.clone(),
        }
    }
}

impl<V: TransactionValidator> CipherBftValidator<V> {
    /// Create a new wrapper around the given validator without execution layer validation.
    ///
    /// **Warning**: Without execution layer validation, invalid transactions may enter
    /// the mempool. Consider using `wrap_with_execution` instead.
    pub fn wrap(inner: V) -> Self {
        Self {
            inner,
            execution_validator: None,
        }
    }

    /// Create a new wrapper with both Reth and execution layer validation.
    ///
    /// This is the recommended constructor as it provides complete validation.
    pub fn wrap_with_execution(
        inner: V,
        execution_validator: Arc<dyn ExecutionLayerValidator>,
    ) -> Self {
        Self {
            inner,
            execution_validator: Some(execution_validator),
        }
    }

    /// Set the execution layer validator.
    ///
    /// This allows adding execution validation after construction.
    pub fn with_execution_validator(
        mut self,
        validator: Arc<dyn ExecutionLayerValidator>,
    ) -> Self {
        self.execution_validator = Some(validator);
        self
    }

    /// Check if execution layer validation is configured.
    pub fn has_execution_validator(&self) -> bool {
        self.execution_validator.is_some()
    }
}

impl<Client, Tx> CipherBftValidator<EthTransactionValidator<Arc<Client>, Tx>>
where
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec: EthereumHardforks>,
    Tx: EthPoolTransaction,
{
    /// Build a wrapper with a Reth EthTransactionValidator.
    ///
    /// In reth v1.9.3+, the client provides the chain spec via the ChainSpecProvider trait,
    /// so we pass the client directly to the validator builder.
    ///
    /// **Note**: This constructor does not include execution layer validation.
    /// Use `new_with_execution` for complete validation.
    pub fn new<S>(client: Arc<Client>, blob_store: S) -> Self
    where
        S: BlobStore,
    {
        let validator = EthTransactionValidatorBuilder::new(client).build(blob_store);
        Self::wrap(validator)
    }

    /// Build a wrapper with both Reth and execution layer validation.
    ///
    /// This is the recommended constructor for production use.
    pub fn new_with_execution<S>(
        client: Arc<Client>,
        blob_store: S,
        execution_validator: Arc<dyn ExecutionLayerValidator>,
    ) -> Self
    where
        S: BlobStore,
    {
        let validator = EthTransactionValidatorBuilder::new(client).build(blob_store);
        Self::wrap_with_execution(validator, execution_validator)
    }
}

impl<V> TransactionValidator for CipherBftValidator<V>
where
    V: TransactionValidator,
    V::Transaction: PoolTransaction,
    <V::Transaction as PoolTransaction>::Consensus: Encodable2718,
{
    type Transaction = V::Transaction;

    async fn validate_transaction(
        &self,
        origin: TransactionOrigin,
        transaction: Self::Transaction,
    ) -> TransactionValidationOutcome<Self::Transaction> {
        // Phase 1: Reth validation (signature, format, basic checks)
        let reth_outcome = self.inner.validate_transaction(origin, transaction).await;

        // If Reth validation failed, return immediately
        if !reth_outcome.is_valid() {
            return reth_outcome;
        }

        // Phase 2: Execution layer validation (state-dependent checks)
        if let Some(ref exec_validator) = self.execution_validator {
            // Extract the validated transaction for encoding
            let valid_tx = match &reth_outcome {
                TransactionValidationOutcome::Valid { transaction, .. } => transaction,
                _ => return reth_outcome, // Should not happen since we checked is_valid()
            };

            // Encode consensus transaction to EIP-2718 bytes for execution layer validation
            // Get the pool transaction from ValidTransaction, convert to consensus format
            let pool_tx = valid_tx.transaction();
            // clone_into_consensus() returns Recovered<Consensus>, which derefs to Consensus
            let recovered_consensus = pool_tx.clone_into_consensus();
            let mut tx_bytes = Vec::new();
            // Recovered<T> derefs to T, so encode_2718 works directly via deref coercion
            recovered_consensus.encode_2718(&mut tx_bytes);

            // Call execution layer validation
            match exec_validator.validate_transaction(&tx_bytes).await {
                Ok(()) => {
                    // Both validations passed
                    reth_outcome
                }
                Err(reason) => {
                    // Execution layer validation failed
                    warn!(
                        tx_hash = %valid_tx.hash(),
                        reason = %reason,
                        "Transaction failed execution layer validation"
                    );

                    // Convert valid outcome back to invalid
                    match reth_outcome {
                        TransactionValidationOutcome::Valid { transaction, .. } => {
                            // Extract the inner transaction from ValidTransaction
                            let inner_tx = transaction.into_transaction();
                            TransactionValidationOutcome::Invalid(
                                inner_tx,
                                InvalidPoolTransactionError::Other(Box::new(
                                    ExecutionValidationError::new(reason),
                                )),
                            )
                        }
                        other => other, // Should not happen
                    }
                }
            }
        } else {
            // No execution validator configured, return Reth result only
            // Log a warning in debug builds to encourage proper configuration
            #[cfg(debug_assertions)]
            {
                static WARNED: std::sync::atomic::AtomicBool =
                    std::sync::atomic::AtomicBool::new(false);
                if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    warn!(
                        "CipherBftValidator has no execution layer validator configured. \
                         Transactions may enter mempool without full state validation."
                    );
                }
            }
            reth_outcome
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::Transaction;
    use alloy_primitives::{Address, U256};
    use reth_chainspec::{Chain, ChainSpecBuilder, MAINNET};
    use reth_primitives_traits::SignedTransaction;
    use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
    use reth_transaction_pool::blobstore::InMemoryBlobStore;
    use reth_transaction_pool::test_utils::TransactionBuilder;
    use reth_transaction_pool::validate::EthTransactionValidator;
    use reth_transaction_pool::EthPooledTransaction;
    use std::sync::Arc;

    fn build_test_pooled_tx(chain_id: u64) -> EthPooledTransaction {
        let signed_tx = TransactionBuilder::default()
            .chain_id(chain_id)
            .to(Address::ZERO)
            .gas_limit(100_000)
            .max_fee_per_gas(1_000_000_000)
            .max_priority_fee_per_gas(1_000_000_000)
            .into_eip1559();
        // New API: SignedTransaction::try_into_recovered() replaces into_ecrecovered()
        let recovered = signed_tx
            .try_into_recovered()
            .expect("recover signed transaction");
        EthPooledTransaction::try_from_consensus(recovered).expect("convert to pooled transaction")
    }

    fn build_test_validator(
        chain_id: u64,
        tx: &EthPooledTransaction,
    ) -> CipherBftValidator<EthTransactionValidator<Arc<MockEthProvider>, EthPooledTransaction>>
    {
        // Note: with_chain_spec() wraps the chain spec in Arc internally,
        // so we don't wrap it ourselves to avoid Arc<Arc<ChainSpec>>
        let chain_spec = ChainSpecBuilder::mainnet()
            .chain(Chain::from_id(chain_id))
            .build();
        let provider = Arc::new(MockEthProvider::default().with_chain_spec(chain_spec));
        provider.add_account(tx.sender(), ExtendedAccount::new(tx.nonce(), U256::MAX));
        let blob_store = InMemoryBlobStore::default();
        CipherBftValidator::new(provider, blob_store)
    }

    /// Mock execution validator that always succeeds
    #[derive(Debug)]
    struct AlwaysValidExecutionValidator;

    #[async_trait::async_trait]
    impl ExecutionLayerValidator for AlwaysValidExecutionValidator {
        async fn validate_transaction(&self, _tx_bytes: &[u8]) -> Result<(), String> {
            Ok(())
        }
    }

    /// Mock execution validator that always fails
    #[derive(Debug)]
    struct AlwaysInvalidExecutionValidator {
        reason: String,
    }

    impl AlwaysInvalidExecutionValidator {
        fn new(reason: &str) -> Self {
            Self {
                reason: reason.to_string(),
            }
        }
    }

    #[async_trait::async_trait]
    impl ExecutionLayerValidator for AlwaysInvalidExecutionValidator {
        async fn validate_transaction(&self, _tx_bytes: &[u8]) -> Result<(), String> {
            Err(self.reason.clone())
        }
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

    #[tokio::test]
    async fn test_execution_layer_validation_success() {
        let chain_id = MAINNET.chain.id();
        let tx = build_test_pooled_tx(chain_id);
        let validator = build_test_validator(chain_id, &tx)
            .with_execution_validator(Arc::new(AlwaysValidExecutionValidator));

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, tx)
            .await;

        assert!(outcome.is_valid());
    }

    #[tokio::test]
    async fn test_execution_layer_validation_failure() {
        let chain_id = MAINNET.chain.id();
        let tx = build_test_pooled_tx(chain_id);
        let validator = build_test_validator(chain_id, &tx).with_execution_validator(Arc::new(
            AlwaysInvalidExecutionValidator::new("Insufficient balance"),
        ));

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, tx)
            .await;

        // Should be invalid due to execution layer failure
        assert!(outcome.is_invalid());
    }

    #[tokio::test]
    async fn test_reth_fails_before_execution_layer() {
        // Use wrong chain ID so Reth validation fails
        let tx = build_test_pooled_tx(MAINNET.chain.id());
        let validator = build_test_validator(2, &tx) // Wrong chain ID
            .with_execution_validator(Arc::new(AlwaysValidExecutionValidator));

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, tx)
            .await;

        // Should be invalid due to Reth (chain ID) failure, even though execution would pass
        assert!(outcome.is_invalid());
    }

    #[test]
    fn test_has_execution_validator() {
        let chain_id = MAINNET.chain.id();
        let tx = build_test_pooled_tx(chain_id);

        let validator_without = build_test_validator(chain_id, &tx);
        assert!(!validator_without.has_execution_validator());

        let validator_with = build_test_validator(chain_id, &tx)
            .with_execution_validator(Arc::new(AlwaysValidExecutionValidator));
        assert!(validator_with.has_execution_validator());
    }
}
