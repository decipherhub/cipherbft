# Mempool integration notes

This crate wraps Reth's transaction pool and adds CipherBFT-specific validation.
Use these notes when wiring the pool in the EL/worker initialization.

## MP-1 / MP-2 behavior

- MP-1: `CipherBftPool` is a thin wrapper over Reth's pool, delegating pool behavior/config.
- MP-2: `add_transaction` performs BFT policy checks (min gas price, nonce gap) and then hands
  validated transactions to Reth for standard validation.

## Pool creation (required for MP-3 / MP-4)

MP-3 (priority ordering) and MP-4 (replacement logic) are enforced by the Reth pool.
To enable them, you must pass a Reth `PoolConfig` and an ordering implementation
when instantiating the pool.

Example (shape only; actual validator/blob store wiring depends on your node setup):

```rust
use reth_transaction_pool::{
    Pool, CoinbaseTipOrdering, TransactionValidationTaskExecutor,
};

let pool_config = mempool_config.into(); // or mempool_config.to_reth_config()
let ordering = CoinbaseTipOrdering::default();

let pool = Pool::new(
    tx_validator,
    ordering,
    blob_store,
    pool_config,
);
```

Notes:
- MP-3 relies on the built-in ordering (`CoinbaseTipOrdering`) and `best_transactions()`.
- MP-4 relies on `PoolConfig.price_bumps` (set via `MempoolConfig` mapping).
- MP-5 relies on Reth's pending/queued pools and promotion logic.

## MempoolConfig mapping

`MempoolConfig` maps into Reth's `PoolConfig`, including price bump settings:

```rust
let pool_config: PoolConfig = mempool_config.into();
```

Relevant fields:
- `default_price_bump` (percent)
- `replace_blob_tx_price_bump` (percent)

## Inserting transactions

`CipherBftPool::add_transaction` accepts several input types:
- `TransactionSigned`
- `TransactionSignedEcRecovered`
- `PooledTransactionsElement`
- `PooledTransactionsElementEcRecovered`
- `TransactionSignedNoHash`
- raw bytes (`Bytes`, `Vec<u8>`, `&[u8]`) decoded as EIP-2718

If you already have the pool's transaction type, use:

```rust
pool.add_pooled_transaction(origin, pooled_tx).await?;
```

## Batch selection

`CipherBftPoolAdapter::get_transactions_for_batch` uses
`pool.best_transactions()` and returns `TransactionSigned` values in the
order determined by the pool's ordering.

## Pending / queued access (MP-5)

Use the adapter helpers:

```rust
let pending = pool.adapter().pending_transactions();
let queued = pool.adapter().queued_transactions();
```
