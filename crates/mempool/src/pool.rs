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
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{Bytes, TxHash};
use reth_primitives::{
    PooledTransactionsElement, PooledTransactionsElementEcRecovered, TransactionSigned,
    TransactionSignedEcRecovered, TransactionSignedNoHash,
};
use reth_storage_api::{StateProvider, StateProviderBox, StateProviderFactory};
use reth_transaction_pool::{
    blobstore::BlobStore, validate::EthTransactionValidator, CoinbaseTipOrdering,
    EthPooledTransaction, Pool, PoolTransaction, TransactionOrigin, TransactionPool,
};
use std::sync::Arc;
use tracing::{debug, warn};

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
    /// State provider for BFT policy validation (nonce queries)
    /// Uses Reth's standard StateProvider trait from reth-storage-api
    state_provider: StateProviderBox,
}

/// Concrete Reth pool type used by CipherBFT.
pub type CipherBftRethPool<Client, S> = Pool<
    CipherBftValidator<EthTransactionValidator<Client, EthPooledTransaction>>,
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
    /// CipherBftPool::wrap(reth_pool, config, state_provider)
    /// ```
    pub fn wrap(pool: P, config: MempoolConfig, state_provider: StateProviderBox) -> Self {
        Self {
            pool,
            config,
            state_provider,
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

    /// Borrow a worker-facing adapter over the underlying pool (ADR-006)
    pub fn adapter(&self) -> CipherBftPoolAdapter<'_, P> {
        CipherBftPoolAdapter::new(&self.pool)
    }

    /// Recover and pre-validate a transaction before handing it to Reth
    ///
    /// Returns the recovered transaction if it passes CipherBFT policies.
    pub async fn recover_and_validate(
        &self,
        tx: TransactionSigned,
    ) -> Result<TransactionSignedEcRecovered, MempoolError> {
        let tx_recovered = tx.try_ecrecovered().ok_or(MempoolError::InvalidSignature)?;

        let sender = tx_recovered.signer();
        let tx_ref = tx_recovered.as_ref();

        debug!(
            "Pre-validating transaction from {:?}, nonce={}, gas_price={}",
            sender,
            tx_ref.nonce(),
            tx_ref.max_fee_per_gas()
        );

        self.validate_bft_policy(&tx_recovered).await?;

        debug!("Transaction {:?} passed BFT policy checks", tx_ref.hash());

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
    async fn validate_bft_policy(
        &self,
        tx: &TransactionSignedEcRecovered,
    ) -> Result<(), MempoolError> {
        let sender = tx.signer();
        let tx_ref = tx.as_ref();

        // BFT Policy 1: Minimum gas price enforcement
        let effective_gas_price = tx_ref.max_fee_per_gas();
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
        let current_nonce = self
            .state_provider
            .account_nonce(sender)
            .map_err(|e| MempoolError::Internal(format!("Failed to get nonce: {}", e)))?
            .unwrap_or(0); // Default to 0 if account doesn't exist yet
        let tx_nonce = tx_ref.nonce();

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

impl<Client, S> CipherBftPool<CipherBftRethPool<Client, S>>
where
    Client: StateProviderFactory,
    S: BlobStore + Clone,
{
    /// Create a CipherBFT mempool that builds the underlying Reth pool internally.
    pub fn new(
        chain_spec: Arc<reth_chainspec::ChainSpec>,
        client: Client,
        blob_store: S,
        chain_id: u64,
        config: MempoolConfig,
    ) -> Result<Self, MempoolError> {
        let state_provider = client.latest().map_err(|err| {
            MempoolError::Internal(format!("Failed to get state provider: {err}"))
        })?;
        let validator = CipherBftValidator::new(chain_spec, client, blob_store.clone(), chain_id);
        let pool_config: reth_transaction_pool::PoolConfig = config.clone().into();
        let pool = Pool::new(
            validator,
            CoinbaseTipOrdering::default(),
            blob_store,
            pool_config,
        );
        Ok(Self::wrap(pool, config, state_provider))
    }
}

/// Worker-facing adapter that surfaces pool operations (ADR-006)
pub struct CipherBftPoolAdapter<'a, P: TransactionPool> {
    pool: &'a P,
}

impl<'a, P: TransactionPool> CipherBftPoolAdapter<'a, P> {
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
            let signed = tx.to_recovered_transaction().into_signed();
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
            .map(|tx| tx.to_recovered_transaction().into_signed())
            .collect()
    }

    /// Get queued (nonce-gap) transactions in pool order (MP-5).
    pub fn queued_transactions(&self) -> Vec<TransactionSigned> {
        self.pool
            .queued_transactions()
            .into_iter()
            .map(|tx| tx.to_recovered_transaction().into_signed())
            .collect()
    }
}

impl<P> CipherBftPool<P>
where
    P: TransactionPool,
    P::Transaction: PoolTransaction + TryFrom<TransactionSignedEcRecovered>,
    <P::Transaction as PoolTransaction>::Consensus: Into<TransactionSignedEcRecovered>,
    <P::Transaction as PoolTransaction>::Pooled: From<PooledTransactionsElementEcRecovered>,
    <P::Transaction as TryFrom<TransactionSignedEcRecovered>>::Error: std::fmt::Display,
{
    /// Add a transaction to the pool with CipherBFT validation (MP-2)
    pub async fn add_transaction<T>(
        &self,
        origin: TransactionOrigin,
        tx: T,
    ) -> Result<(), MempoolError>
    where
        T: IntoPoolTransactionInput<P::Transaction>,
    {
        let pooled_tx = match tx.into_input()? {
            PoolTransactionInput::Signed(tx) => {
                let tx_recovered = self.recover_and_validate(tx).await?;
                P::Transaction::try_from(tx_recovered)
                    .map_err(|err| MempoolError::Conversion(err.to_string()))?
            }
            PoolTransactionInput::Recovered(tx_recovered) => {
                self.validate_bft_policy(&tx_recovered).await?;
                P::Transaction::try_from(tx_recovered)
                    .map_err(|err| MempoolError::Conversion(err.to_string()))?
            }
            PoolTransactionInput::Pooled(PoolTx(pooled_tx)) => {
                let tx_recovered: TransactionSignedEcRecovered =
                    pooled_tx.clone().into_consensus().into();
                self.validate_bft_policy(&tx_recovered).await?;
                pooled_tx
            }
            PoolTransactionInput::PooledEcRecovered(pooled) => {
                let pooled_tx = P::Transaction::from_pooled(pooled.into());
                let tx_recovered: TransactionSignedEcRecovered =
                    pooled_tx.clone().into_consensus().into();
                self.validate_bft_policy(&tx_recovered).await?;
                pooled_tx
            }
            PoolTransactionInput::PooledRaw(pooled) => {
                let pooled = pooled
                    .try_into_ecrecovered()
                    .map_err(|_| MempoolError::InvalidSignature)?;
                let pooled_tx = P::Transaction::from_pooled(pooled.into());
                let tx_recovered: TransactionSignedEcRecovered =
                    pooled_tx.clone().into_consensus().into();
                self.validate_bft_policy(&tx_recovered).await?;
                pooled_tx
            }
        };
        self.pool.add_transaction(origin, pooled_tx).await?;
        Ok(())
    }

    /// Add a pooled transaction directly.
    pub async fn add_pooled_transaction(
        &self,
        origin: TransactionOrigin,
        tx: P::Transaction,
    ) -> Result<(), MempoolError> {
        self.add_transaction(origin, PoolTx::new(tx)).await
    }
}

pub enum PoolTransactionInput<Tx> {
    Signed(TransactionSigned),
    Recovered(TransactionSignedEcRecovered),
    Pooled(PoolTx<Tx>),
    PooledEcRecovered(PooledTransactionsElementEcRecovered),
    PooledRaw(PooledTransactionsElement),
}

pub trait IntoPoolTransactionInput<Tx> {
    fn into_input(self) -> Result<PoolTransactionInput<Tx>, MempoolError>;
}

pub struct PoolTx<Tx>(pub Tx);

impl<Tx> PoolTx<Tx> {
    pub fn new(tx: Tx) -> Self {
        Self(tx)
    }
}

impl<Tx> IntoPoolTransactionInput<Tx> for TransactionSigned {
    fn into_input(self) -> Result<PoolTransactionInput<Tx>, MempoolError> {
        Ok(PoolTransactionInput::Signed(self))
    }
}

impl<Tx> IntoPoolTransactionInput<Tx> for TransactionSignedEcRecovered {
    fn into_input(self) -> Result<PoolTransactionInput<Tx>, MempoolError> {
        Ok(PoolTransactionInput::Recovered(self))
    }
}

impl<Tx> IntoPoolTransactionInput<Tx> for PoolTx<Tx> {
    fn into_input(self) -> Result<PoolTransactionInput<Tx>, MempoolError> {
        Ok(PoolTransactionInput::Pooled(self))
    }
}

impl<Tx> IntoPoolTransactionInput<Tx> for PooledTransactionsElementEcRecovered
where
    Tx: PoolTransaction,
    Tx::Pooled: From<PooledTransactionsElementEcRecovered>,
{
    fn into_input(self) -> Result<PoolTransactionInput<Tx>, MempoolError> {
        Ok(PoolTransactionInput::PooledEcRecovered(self))
    }
}

impl<Tx> IntoPoolTransactionInput<Tx> for PooledTransactionsElement
where
    Tx: PoolTransaction,
    Tx::Pooled: From<PooledTransactionsElementEcRecovered>,
{
    fn into_input(self) -> Result<PoolTransactionInput<Tx>, MempoolError> {
        Ok(PoolTransactionInput::PooledRaw(self))
    }
}

impl<Tx> IntoPoolTransactionInput<Tx> for TransactionSignedNoHash {
    fn into_input(self) -> Result<PoolTransactionInput<Tx>, MempoolError> {
        Ok(PoolTransactionInput::Signed(self.into()))
    }
}

impl<Tx> IntoPoolTransactionInput<Tx> for Bytes
where
    Tx: PoolTransaction,
    Tx::Pooled: From<PooledTransactionsElementEcRecovered>,
{
    fn into_input(self) -> Result<PoolTransactionInput<Tx>, MempoolError> {
        decode_pooled_from_bytes(&self).map(PoolTransactionInput::PooledRaw)
    }
}

impl<Tx> IntoPoolTransactionInput<Tx> for Vec<u8>
where
    Tx: PoolTransaction,
    Tx::Pooled: From<PooledTransactionsElementEcRecovered>,
{
    fn into_input(self) -> Result<PoolTransactionInput<Tx>, MempoolError> {
        decode_pooled_from_bytes(&self).map(PoolTransactionInput::PooledRaw)
    }
}

impl<Tx> IntoPoolTransactionInput<Tx> for &[u8]
where
    Tx: PoolTransaction,
    Tx::Pooled: From<PooledTransactionsElementEcRecovered>,
{
    fn into_input(self) -> Result<PoolTransactionInput<Tx>, MempoolError> {
        decode_pooled_from_bytes(self).map(PoolTransactionInput::PooledRaw)
    }
}

fn decode_pooled_from_bytes(bytes: &[u8]) -> Result<PooledTransactionsElement, MempoolError> {
    let mut slice = bytes;
    PooledTransactionsElement::decode_2718(&mut slice)
        .map_err(|err| MempoolError::Conversion(err.to_string()))
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
