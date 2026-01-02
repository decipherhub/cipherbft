use alloy_primitives::address;
use mempool::{CipherBftPool, MempoolConfig};
use reth_primitives::TransactionSignedEcRecovered;
use reth_provider::test_utils::NoopProvider;
use reth_storage_api::StateProviderBox;
use reth_transaction_pool::test_utils::{MockTransaction, TestPoolBuilder};
use reth_transaction_pool::{PoolConfig, SubPoolLimit, TransactionOrigin};

fn noop_state_provider() -> StateProviderBox {
    Box::new(NoopProvider::default())
}

fn recovered_tx(
    sender: alloy_primitives::Address,
    nonce: u64,
    gas_price: u128,
) -> TransactionSignedEcRecovered {
    let mock = MockTransaction::legacy()
        .with_sender(sender)
        .with_nonce(nonce)
        .with_gas_price(gas_price);
    TransactionSignedEcRecovered::from(mock)
}

#[tokio::test]
async fn test_transaction_insertion_and_retrieval() {
    let pool: reth_transaction_pool::test_utils::TestPool = TestPoolBuilder::default().into();
    let mempool: CipherBftPool<reth_transaction_pool::test_utils::TestPool> =
        CipherBftPool::new(pool, MempoolConfig::default(), noop_state_provider());

    let tx = recovered_tx(
        address!("1000000000000000000000000000000000000001"),
        0,
        2_000_000_000,
    );
    let tx_hash = *tx.clone().into_signed().hash();

    mempool
        .add_transaction(TransactionOrigin::External, tx)
        .await
        .unwrap();

    let pending = mempool.adapter().pending_transactions();
    assert_eq!(pending.len(), 1);
    assert_eq!(*pending[0].hash(), tx_hash);
}

#[tokio::test]
async fn test_priority_ordering_by_gas_price() {
    let pool: reth_transaction_pool::test_utils::TestPool = TestPoolBuilder::default().into();
    let mempool: CipherBftPool<reth_transaction_pool::test_utils::TestPool> =
        CipherBftPool::new(pool, MempoolConfig::default(), noop_state_provider());

    let low = recovered_tx(
        address!("1000000000000000000000000000000000000002"),
        0,
        1_500_000_000,
    );
    let high = recovered_tx(
        address!("1000000000000000000000000000000000000003"),
        0,
        3_000_000_000,
    );
    let high_hash = *high.clone().into_signed().hash();

    mempool
        .add_transaction(TransactionOrigin::External, low)
        .await
        .unwrap();
    mempool
        .add_transaction(TransactionOrigin::External, high)
        .await
        .unwrap();

    let batch = mempool
        .adapter()
        .get_transactions_for_batch(2, 1_000_000_000);
    assert_eq!(batch.len(), 2);
    assert_eq!(*batch[0].hash(), high_hash);
}

#[tokio::test]
async fn test_replacement_logic() {
    let pool: reth_transaction_pool::test_utils::TestPool = TestPoolBuilder::default().into();
    let mempool: CipherBftPool<reth_transaction_pool::test_utils::TestPool> =
        CipherBftPool::new(pool, MempoolConfig::default(), noop_state_provider());

    let sender = address!("1000000000000000000000000000000000000004");
    let low = recovered_tx(sender, 0, 1_000_000_000);
    let high = recovered_tx(sender, 0, 2_000_000_000);
    let high_hash = *high.clone().into_signed().hash();

    mempool
        .add_transaction(TransactionOrigin::External, low)
        .await
        .unwrap();
    mempool
        .add_transaction(TransactionOrigin::External, high)
        .await
        .unwrap();

    let pending = mempool.adapter().pending_transactions();
    assert_eq!(pending.len(), 1);
    assert_eq!(*pending[0].hash(), high_hash);
}

#[tokio::test]
async fn test_pending_queued_promotion() {
    let pool: reth_transaction_pool::test_utils::TestPool = TestPoolBuilder::default().into();
    let mempool: CipherBftPool<reth_transaction_pool::test_utils::TestPool> =
        CipherBftPool::new(pool, MempoolConfig::default(), noop_state_provider());

    let sender = address!("1000000000000000000000000000000000000005");
    let nonce_one = recovered_tx(sender, 1, 2_000_000_000);
    let nonce_zero = recovered_tx(sender, 0, 2_000_000_000);

    mempool
        .add_transaction(TransactionOrigin::External, nonce_one)
        .await
        .unwrap();
    assert_eq!(mempool.adapter().pending_transactions().len(), 0);
    assert_eq!(mempool.adapter().queued_transactions().len(), 1);

    mempool
        .add_transaction(TransactionOrigin::External, nonce_zero)
        .await
        .unwrap();
    assert_eq!(mempool.adapter().queued_transactions().len(), 0);
    assert_eq!(mempool.adapter().pending_transactions().len(), 2);
}

#[tokio::test]
async fn test_eviction_under_pressure() {
    let mut config = PoolConfig::default();
    config.pending_limit = SubPoolLimit::new(1, usize::MAX);
    config.basefee_limit = SubPoolLimit::new(0, usize::MAX);
    config.queued_limit = SubPoolLimit::new(0, usize::MAX);
    config.blob_limit = SubPoolLimit::new(0, usize::MAX);
    config.max_account_slots = 1;

    let pool: reth_transaction_pool::test_utils::TestPool =
        TestPoolBuilder::default().with_config(config).into();
    let mempool: CipherBftPool<reth_transaction_pool::test_utils::TestPool> =
        CipherBftPool::new(pool, MempoolConfig::default(), noop_state_provider());

    let low = recovered_tx(
        address!("1000000000000000000000000000000000000010"),
        0,
        1_000_000_000,
    );
    let high = recovered_tx(
        address!("1000000000000000000000000000000000000011"),
        0,
        2_000_000_000,
    );

    mempool
        .add_transaction(TransactionOrigin::External, low)
        .await
        .unwrap();
    mempool
        .add_transaction(TransactionOrigin::External, high)
        .await
        .unwrap();

    let pending = mempool.adapter().pending_transactions();
    assert_eq!(pending.len(), 1);
}
