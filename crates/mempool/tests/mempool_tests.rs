//! Integration tests for CipherBftPool
//!
//! These tests verify the pool adapter methods work correctly with reth's TestPool.
//! They test basic pool operations (ordering, replacement, eviction) which are handled
//! by reth's Pool implementation. CipherBFT-specific validation (min gas price, nonce gap)
//! is tested in the unit tests in pool.rs.

use alloy_primitives::address;
use cipherbft_mempool::{CipherBftPool, MempoolConfig};
use reth_provider::test_utils::NoopProvider;
use reth_transaction_pool::test_utils::{MockTransaction, TestPool, TestPoolBuilder};
use reth_transaction_pool::{
    PoolConfig, PoolTransaction, SubPoolLimit, TransactionOrigin, TransactionPool,
};
use std::sync::Arc;

fn noop_state_provider() -> Arc<NoopProvider> {
    Arc::new(NoopProvider::default())
}

fn mock_tx(sender: alloy_primitives::Address, nonce: u64, gas_price: u128) -> MockTransaction {
    MockTransaction::legacy()
        .with_sender(sender)
        .with_nonce(nonce)
        .with_gas_price(gas_price)
}

#[tokio::test]
async fn test_transaction_insertion_and_retrieval() {
    let pool: TestPool = TestPoolBuilder::default().into();

    let tx = mock_tx(
        address!("1000000000000000000000000000000000000001"),
        0,
        2_000_000_000,
    );
    let tx_hash = *tx.hash();

    // Add transaction directly to the pool
    pool.add_transaction(TransactionOrigin::External, tx)
        .await
        .unwrap();

    // Verify transaction is in pending pool
    let pending = pool.pending_transactions();
    assert_eq!(pending.len(), 1);
    assert_eq!(*pending[0].hash(), tx_hash);
}

#[tokio::test]
async fn test_priority_ordering_by_gas_price() {
    let pool: TestPool = TestPoolBuilder::default().into();

    let low = mock_tx(
        address!("1000000000000000000000000000000000000002"),
        0,
        1_500_000_000,
    );
    let high = mock_tx(
        address!("1000000000000000000000000000000000000003"),
        0,
        3_000_000_000,
    );
    let high_hash = *high.hash();

    pool.add_transaction(TransactionOrigin::External, low)
        .await
        .unwrap();
    pool.add_transaction(TransactionOrigin::External, high)
        .await
        .unwrap();

    // Best transactions should be ordered by gas price (highest first)
    let best: Vec<_> = pool.best_transactions().take(2).collect();
    assert_eq!(best.len(), 2);
    // First transaction should be the high gas price one
    assert_eq!(*best[0].hash(), high_hash);
}

#[tokio::test]
async fn test_replacement_logic() {
    let pool: TestPool = TestPoolBuilder::default().into();

    let sender = address!("1000000000000000000000000000000000000004");
    let low = mock_tx(sender, 0, 1_000_000_000);
    let high = mock_tx(sender, 0, 2_000_000_000);
    let high_hash = *high.hash();

    pool.add_transaction(TransactionOrigin::External, low)
        .await
        .unwrap();
    pool.add_transaction(TransactionOrigin::External, high)
        .await
        .unwrap();

    // Only the higher gas price tx should remain (replacement)
    let pending = pool.pending_transactions();
    assert_eq!(pending.len(), 1);
    assert_eq!(*pending[0].hash(), high_hash);
}

#[tokio::test]
async fn test_pending_queued_promotion() {
    let pool: TestPool = TestPoolBuilder::default().into();

    let sender = address!("1000000000000000000000000000000000000005");
    let nonce_one = mock_tx(sender, 1, 2_000_000_000);
    let nonce_zero = mock_tx(sender, 0, 2_000_000_000);

    // Add nonce=1 first - should go to queued (not executable yet)
    pool.add_transaction(TransactionOrigin::External, nonce_one)
        .await
        .unwrap();
    assert_eq!(pool.pending_transactions().len(), 0);
    assert_eq!(pool.queued_transactions().len(), 1);

    // Add nonce=0 - should promote both to pending
    pool.add_transaction(TransactionOrigin::External, nonce_zero)
        .await
        .unwrap();
    assert_eq!(pool.queued_transactions().len(), 0);
    assert_eq!(pool.pending_transactions().len(), 2);
}

#[tokio::test]
async fn test_eviction_under_pressure() {
    let config = PoolConfig {
        pending_limit: SubPoolLimit::new(1, usize::MAX),
        basefee_limit: SubPoolLimit::new(0, usize::MAX),
        queued_limit: SubPoolLimit::new(0, usize::MAX),
        blob_limit: SubPoolLimit::new(0, usize::MAX),
        max_account_slots: 1,
        ..Default::default()
    };

    let pool: TestPool = TestPoolBuilder::default().with_config(config).into();

    let low = mock_tx(
        address!("1000000000000000000000000000000000000010"),
        0,
        1_000_000_000,
    );
    let high = mock_tx(
        address!("1000000000000000000000000000000000000011"),
        0,
        2_000_000_000,
    );

    pool.add_transaction(TransactionOrigin::External, low)
        .await
        .unwrap();
    pool.add_transaction(TransactionOrigin::External, high)
        .await
        .unwrap();

    // Pool limit is 1, so only highest priority tx should remain
    let pending = pool.pending_transactions();
    assert_eq!(pending.len(), 1);
}

#[tokio::test]
async fn test_cipherbft_pool_wrapper_config() {
    // Test that CipherBftPool wrapper correctly stores config
    let pool: TestPool = TestPoolBuilder::default().into();
    let config = MempoolConfig {
        min_gas_price: 5_000_000_000,
        max_nonce_gap: 8,
        ..Default::default()
    };

    let mempool = CipherBftPool::wrap(pool, config.clone(), noop_state_provider());

    assert_eq!(mempool.config().min_gas_price, 5_000_000_000);
    assert_eq!(mempool.config().max_nonce_gap, 8);
}

#[tokio::test]
async fn test_cipherbft_pool_exposes_underlying_pool() {
    let pool: TestPool = TestPoolBuilder::default().into();
    let mempool = CipherBftPool::wrap(pool, MempoolConfig::default(), noop_state_provider());

    // Can access underlying pool directly
    let tx = mock_tx(
        address!("1000000000000000000000000000000000000001"),
        0,
        2_000_000_000,
    );

    mempool
        .pool()
        .add_transaction(TransactionOrigin::External, tx)
        .await
        .unwrap();

    assert_eq!(mempool.pool().pending_transactions().len(), 1);
}
