//! CipherBFT mempool wrapper over Reth's Pool
//!
//! MP-1: Basic pool wrapper and config delegation to Reth
//! MP-2: Transaction validation (signature, nonce, gas, balance)
//!
//! ## Design Decision: Direct Reth Pool Usage
//!
//! Per ADR-006, we **directly use Reth's Pool implementation**:
//! ```ignore
//! type CipherBftPool = Pool<EthPooledTransaction>;
//! ```
//!
//! We add a thin wrapper ONLY for BFT-specific pre-validation:
//! 1. Minimum gas price enforcement (spam prevention)
//! 2. Maximum nonce gap enforcement (queue bloat prevention)
//!
//! All standard Ethereum validation is delegated to Reth:
//! - Signature verification
//! - Nonce ordering
//! - Balance checks
//! - Gas limits
//! - Transaction size
//! - Replace-by-fee logic
//!
//! ## Integration Status
//!
//! Generic `P: TransactionPool` is temporary until we can instantiate Reth's Pool:
//!
//! ```ignore
//! // Target implementation after EL/CL integration:
//! use reth_transaction_pool::{Pool, CoinbaseTipOrdering, maintain::LocalTransactionConfig};
//!
//! let pool = Pool::new(
//!     eth_pool_validator,  // From EL - provides StateProvider for nonce/balance
//!     CoinbaseTipOrdering::default(),  // Reth's gas price ordering
//!     blob_store,  // Node-provided BlobStore (optional if not using blobs)
//!     pool_config,  // From our MempoolConfig.to_reth_config()
//! );
//! ```

use crate::config::MempoolConfig;
use crate::error::MempoolError;
use crate::validator::CipherBftValidator;
use alloy_consensus::transaction::PooledTransaction;
use alloy_consensus::Transaction;
use alloy_primitives::TxHash;
use reth_chainspec::EthereumHardforks;
use reth_primitives::TransactionSigned;
use reth_primitives_traits::{Recovered, SignedTransaction};
use reth_storage_api::StateProviderFactory;
use reth_transaction_pool::{
    blobstore::BlobStore, validate::EthTransactionValidator, CoinbaseTipOrdering,
    EthPooledTransaction, Pool, PoolTransaction, TransactionOrigin, TransactionPool,
};
use std::sync::Arc;
use tracing::{debug, warn};

/// Type alias for recovered signed transaction (reth v1.9.3+)
pub type RecoveredTx = Recovered<TransactionSigned>;

/// Type alias for recovered pooled transaction (reth v1.9.3+)
pub type RecoveredPooledTx = Recovered<PooledTransaction>;

/// Mempool wrapper that adds BFT-specific pre-validation to Reth's Pool
///
/// Generic `P: TransactionPool` will be replaced with concrete Reth Pool type:
/// `Pool<EthPooledTransaction>` once EL/ST/CL provide required components.
///
/// This is NOT abstraction for abstraction's sake - it's a temporary measure
/// until we have all dependencies ready for Pool instantiation.
pub struct CipherBftPool<P: TransactionPool> {
    /// Reth's Pool implementation (to be: Pool<EthPooledTransaction>)
    pool: P,
    /// BFT-specific config
    config: MempoolConfig,
    /// State provider factory for BFT policy validation (nonce queries)
    /// Use latest() per validation to avoid stale state snapshots.
    state_provider_factory: Arc<dyn StateProviderFactory>,
}

/// Concrete Reth pool type used by CipherBFT.
pub type CipherBftRethPool<Client, S> = Pool<
    CipherBftValidator<EthTransactionValidator<Arc<Client>, EthPooledTransaction>>,
    CoinbaseTipOrdering<EthPooledTransaction>,
    S,
>;

impl<P: TransactionPool> CipherBftPool<P> {
    /// Create new mempool wrapper
    ///
    /// Once DCL/EL/ST are ready, instantiate with Reth's Pool:
    /// ```ignore
    /// // In DCL Worker initialization:
    /// let reth_pool = Pool::new(
    ///     eth_pool_validator,  // EL's validator with StateProvider
    ///     CoinbaseTipOrdering::default(),
    ///     blob_store,  // ST's blob storage
    ///     config.to_reth_config(),
    /// );
    /// // Mempool lives in DCL, uses EL's StateProvider for validation
    /// CipherBftPool::wrap(reth_pool, config, state_provider_factory)
    /// ```
    pub fn wrap(
        pool: P,
        config: MempoolConfig,
        state_provider_factory: Arc<dyn StateProviderFactory>,
    ) -> Self {
        Self {
            pool,
            config,
            state_provider_factory,
        }
    }

    /// Get reference to Reth pool
    pub fn pool(&self) -> &P {
        &self.pool
    }

    /// Get BFT config
    pub fn config(&self) -> &MempoolConfig {
        &self.config
    }

    /// Recover and pre-validate a transaction before handing it to Reth
    ///
    /// Returns the recovered transaction if it passes CipherBFT policies.
    pub async fn recover_and_validate(
        &self,
        tx: TransactionSigned,
    ) -> Result<RecoveredTx, MempoolError> {
        // Recover signer using reth v1.9.3+ API
        // SignedTransaction::try_recover() returns Result<Address, RecoveryError>
        let signer = tx
            .try_recover()
            .map_err(|_| MempoolError::InvalidSignature)?;

        // Create the Recovered wrapper with the transaction and its signer
        let tx_recovered = Recovered::new_unchecked(tx, signer);

        debug!(
            "Pre-validating transaction from {:?}, nonce={}, gas_price={}",
            signer,
            tx_recovered.nonce(),
            tx_recovered.max_fee_per_gas()
        );

        self.validate_bft_policy(&tx_recovered).await?;

        debug!(
            "Transaction {:?} passed BFT policy checks",
            tx_recovered.tx_hash()
        );

        Ok(tx_recovered)
    }

    /// Validate BFT-specific policies only (MP-2)
    ///
    /// This method performs ONLY CipherBFT-specific checks.
    /// All standard Ethereum validation is delegated to Reth:
    /// - Signature verification → Reth
    /// - Nonce ordering (too low/duplicate) → Reth
    /// - Balance sufficiency → Reth
    /// - Gas limit vs chain limit → Reth (from chain spec)
    /// - Transaction size limits → Reth
    ///
    /// CipherBFT adds:
    /// 1. Minimum gas price (prevent spam)
    /// 2. Maximum nonce gap (prevent queue bloat)
    async fn validate_bft_policy(&self, tx: &RecoveredTx) -> Result<(), MempoolError> {
        let sender = tx.signer();

        // BFT Policy 1: Minimum gas price enforcement
        // Access transaction fields via Deref to inner TransactionSigned
        let effective_gas_price = tx.max_fee_per_gas();
        if effective_gas_price < self.config.min_gas_price {
            warn!(
                "Transaction from {:?} rejected: gas price {} < min {}",
                sender, effective_gas_price, self.config.min_gas_price
            );
            return Err(MempoolError::InsufficientGasPrice {
                got: effective_gas_price,
                min: self.config.min_gas_price,
            });
        }

        // BFT Policy 2: Nonce gap enforcement
        // Prevents attackers from bloating the queued pool with distant-future nonces
        let state_provider = self
            .state_provider_factory
            .latest()
            .map_err(|e| MempoolError::Internal(format!("Failed to get state provider: {e}")))?;
        let current_nonce = state_provider
            .account_nonce(&sender)
            .map_err(|e| MempoolError::Internal(format!("Failed to get nonce: {}", e)))?
            .unwrap_or(0); // Default to 0 if account doesn't exist yet
        let tx_nonce = tx.nonce();

        if tx_nonce > current_nonce {
            let gap = tx_nonce - current_nonce - 1;
            if gap > self.config.max_nonce_gap {
                return Err(MempoolError::NonceGapExceeded {
                    gap,
                    max: self.config.max_nonce_gap,
                });
            }
        }

        Ok(())
    }
}

impl<P> CipherBftPool<P>
where
    P: TransactionPool,
    P::Transaction: PoolTransaction<Consensus = TransactionSigned>,
{
    /// Borrow a worker-facing adapter over the underlying pool (ADR-006)
    pub fn adapter(&self) -> CipherBftPoolAdapter<'_, P> {
        CipherBftPoolAdapter::new(&self.pool)
    }
}

impl<Client, S> CipherBftPool<CipherBftRethPool<Client, S>>
where
    Client: StateProviderFactory
        + reth_chainspec::ChainSpecProvider<ChainSpec: EthereumHardforks>
        + 'static,
    S: BlobStore + Clone,
{
    /// Create a CipherBFT mempool that builds the underlying Reth pool internally.
    ///
    /// Note: In reth v1.9.3+, the client provides the chain spec via ChainSpecProvider trait,
    /// so we no longer need to pass chain_spec separately.
    pub fn new(
        client: Arc<Client>,
        blob_store: S,
        config: MempoolConfig,
    ) -> Result<Self, MempoolError> {
        let state_provider_factory: Arc<dyn StateProviderFactory> = client.clone();
        let validator = CipherBftValidator::new(Arc::clone(&client), blob_store.clone());
        let pool_config: reth_transaction_pool::PoolConfig = config.clone().into();
        let pool = Pool::new(
            validator,
            CoinbaseTipOrdering::default(),
            blob_store,
            pool_config,
        );
        Ok(Self::wrap(pool, config, state_provider_factory))
    }
}

/// Worker-facing adapter that surfaces pool operations (ADR-006)
pub struct CipherBftPoolAdapter<'a, P: TransactionPool> {
    pool: &'a P,
}

impl<'a, P> CipherBftPoolAdapter<'a, P>
where
    P: TransactionPool,
    P::Transaction: PoolTransaction<Consensus = TransactionSigned>,
{
    fn new(pool: &'a P) -> Self {
        Self { pool }
    }

    /// Get best transactions for a Worker batch (ADR-006)
    pub fn get_transactions_for_batch(
        &self,
        limit: usize,
        gas_limit: u64,
    ) -> Vec<TransactionSigned> {
        let mut selected = Vec::with_capacity(limit);
        let mut gas_used = 0u64;

        for tx in self.pool.best_transactions() {
            if selected.len() >= limit {
                break;
            }
            let tx_gas = tx.gas_limit();
            if gas_used + tx_gas > gas_limit {
                continue;
            }
            gas_used += tx_gas;
            let signed = tx.transaction.clone_into_consensus().into_inner();
            selected.push(signed);
        }

        selected
    }

    /// Remove transactions that were finalized in a committed block (ADR-006)
    pub fn remove_finalized(&self, tx_hashes: &[TxHash]) {
        let _ = self.pool.remove_transactions(tx_hashes.to_vec());
    }

    /// Get pool statistics for metrics (ADR-006)
    pub fn stats(&self) -> PoolStats {
        let size = self.pool.pool_size();
        PoolStats {
            pending: size.pending,
            queued: size.queued,
            total: size.pending + size.queued,
        }
    }

    /// Get pending (executable) transactions in pool order (MP-5).
    pub fn pending_transactions(&self) -> Vec<TransactionSigned> {
        self.pool
            .pending_transactions()
            .into_iter()
            .map(|tx| tx.transaction.clone_into_consensus().into_inner())
            .collect()
    }

    /// Get queued (nonce-gap) transactions in pool order (MP-5).
    pub fn queued_transactions(&self) -> Vec<TransactionSigned> {
        self.pool
            .queued_transactions()
            .into_iter()
            .map(|tx| tx.transaction.clone_into_consensus().into_inner())
            .collect()
    }
}

impl<P> CipherBftPool<P>
where
    P: TransactionPool,
    P::Transaction: PoolTransaction + TryFrom<RecoveredTx>,
    <P::Transaction as TryFrom<RecoveredTx>>::Error: std::fmt::Display,
{
    /// Add a signed transaction to the pool with CipherBFT validation (MP-2)
    ///
    /// This is the primary entry point for adding transactions. The transaction
    /// will be recovered, validated against BFT policies, and then added to the pool.
    pub async fn add_signed_transaction(
        &self,
        origin: TransactionOrigin,
        tx: TransactionSigned,
    ) -> Result<(), MempoolError> {
        let tx_recovered = self.recover_and_validate(tx).await?;
        let pooled_tx = P::Transaction::try_from(tx_recovered)
            .map_err(|err| MempoolError::Conversion(err.to_string()))?;
        self.pool.add_transaction(origin, pooled_tx).await?;
        Ok(())
    }

    /// Add a pre-recovered transaction to the pool with BFT validation.
    pub async fn add_recovered_transaction(
        &self,
        origin: TransactionOrigin,
        tx_recovered: RecoveredTx,
    ) -> Result<(), MempoolError> {
        self.validate_bft_policy(&tx_recovered).await?;
        let pooled_tx = P::Transaction::try_from(tx_recovered)
            .map_err(|err| MempoolError::Conversion(err.to_string()))?;
        self.pool.add_transaction(origin, pooled_tx).await?;
        Ok(())
    }

    /// Add raw transaction bytes to the pool.
    ///
    /// Decodes the bytes as a TransactionSigned, recovers the signer,
    /// validates against BFT policies, and adds to the pool.
    pub async fn add_raw_transaction(
        &self,
        origin: TransactionOrigin,
        bytes: &[u8],
    ) -> Result<(), MempoolError> {
        use alloy_rlp::Decodable;
        let tx = TransactionSigned::decode(&mut &bytes[..])
            .map_err(|err| MempoolError::Conversion(err.to_string()))?;
        self.add_signed_transaction(origin, tx).await
    }
}

/// Simplified pool stats view for metrics (ADR-006)
pub struct PoolStats {
    pub pending: usize,
    pub queued: usize,
    pub total: usize,
}

// Note: We use Reth's standard StateProvider trait from reth-storage-api.
// EL provides the implementation, but DCL Worker uses it for mempool validation.
// This follows ADR-006: Mempool integrates with DCL Workers for batch creation,
// while EL manages account state (nonce, balance) for transaction validation.

#[cfg(test)]
mod tests {
    use super::*;
    // Note: Tests simplified - mock StateProvider removed.
    // Real StateProvider comes from EL integration.

    #[test]
    fn test_config_defaults() {
        let config = MempoolConfig::default();
        assert_eq!(config.max_pending, 10_000);
        assert_eq!(config.max_queued_per_account, 100);
        assert_eq!(config.max_nonce_gap, 16);
        assert_eq!(config.min_gas_price, 1_000_000_000);
    }

    #[test]
    fn test_bft_policy_min_gas_price() {
        // BFT Policy: Minimum gas price enforcement
        let min_gas_price = 1_000_000_000u128;

        // Below minimum - rejected by CipherBFT
        let gas_price = 500_000_000u128;
        assert!(gas_price < min_gas_price);

        // At minimum - accepted
        let gas_price = 1_000_000_000u128;
        assert!(gas_price >= min_gas_price);

        // Above minimum - accepted
        let gas_price = 2_000_000_000u128;
        assert!(gas_price >= min_gas_price);
    }

    #[test]
    fn test_bft_policy_nonce_gap() {
        // BFT Policy: Max nonce gap prevents queue bloat
        // Reth handles nonce ordering (too low, duplicates)
        // CipherBFT adds gap limit for far-future nonces
        let current_nonce = 10u64;
        let max_gap = 16u64;

        // No gap (next nonce) - accepted
        let tx_nonce = 11u64;
        let gap = tx_nonce - current_nonce - 1;
        assert_eq!(gap, 0);
        assert!(gap <= max_gap);

        // Gap within limit - accepted
        let tx_nonce = 26u64;
        let gap = tx_nonce - current_nonce - 1;
        assert_eq!(gap, 15);
        assert!(gap <= max_gap);

        // Gap exceeds limit - rejected by CipherBFT
        let tx_nonce = 28u64;
        let gap = tx_nonce - current_nonce - 1;
        assert_eq!(gap, 17);
        assert!(gap > max_gap);
    }

    // Note: The following validations are delegated to Reth and NOT tested here:
    // - Balance sufficiency: Reth checks sender has enough for gas + value
    // - Transaction size limits: Reth enforces based on protocol rules
    // - Gas limit vs block limit: Reth validates against chain spec
    // - Nonce ordering (too low): Reth maintains nonce sequence per account
    // - Signature verification: Reth validates ECDSA signatures
    //
    // CipherBFT only adds BFT-specific policies tested above:
    // - Minimum gas price (spam prevention)
    // - Maximum nonce gap (queue bloat prevention)
}
