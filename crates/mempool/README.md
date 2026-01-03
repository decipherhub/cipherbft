# Mempool integration notes

This crate wraps Reth's transaction pool and adds CipherBFT-specific validation.
Use these notes when wiring the pool in node/worker initialization.

## MP-1 / MP-2 behavior

- MP-1: `CipherBftPool` is a thin wrapper over Reth's pool, delegating pool behavior/config.
- MP-2: `add_transaction` performs BFT policy checks (min gas price, nonce gap) and then hands
  validated transactions to Reth for standard validation.

## Validator creation (optional)

You do not need to create a validator directly if you use `CipherBftPool::new(...)`.
This section is only for cases where you want to build or wrap a validator manually.

`CipherBftValidator::new` builds and wraps a Reth `EthTransactionValidator`.
It requires:
- `ChainSpec` (for chain ID and fork rules)
- `StateProviderFactory` (EL/Storage-backed)
- `BlobStore` (in-memory or persistent)

Example (shape only; actual types depend on your node setup):

```rust
use reth_transaction_pool::blobstore::InMemoryBlobStore;

let validator = CipherBftValidator::new(
    chain_spec,
    state_provider_factory,
    InMemoryBlobStore::default(),
    chain_id,
);
```

If you already have a validator instance, use `CipherBftValidator::wrap`.

## Pool creation (required for MP-3 / MP-4)

MP-3 (priority ordering) and MP-4 (replacement logic) are enforced by the Reth pool.
To enable them, you must pass a Reth `PoolConfig` and an ordering implementation
when instantiating the pool.

Preferred: build the pool through `CipherBftPool::new` (it creates the Reth pool internally).

```rust
let mempool = CipherBftPool::new(
    chain_spec,
    state_provider_factory,
    blob_store,
    chain_id,
    mempool_config,
)?;
```

If you already have a Reth pool instance, use `CipherBftPool::wrap(pool, config, state_provider)`.

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
