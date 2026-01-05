# CipherBFT Mempool

This crate wraps Reth's transaction pool and adds CipherBFT-specific validation.

## What is implemented

- `CipherBftPool<P>`: thin wrapper over Reth's pool (`pool.rs`)
- `CipherBftValidator<V>`: wrapper for Reth validator (`validator.rs`)
- BFT policy checks: min gas price + nonce gap (inside `validate_bft_policy`)
- `MempoolConfig -> PoolConfig` mapping (`config.rs`)
- Worker adapter: pending/queued/batch helpers (`CipherBftPoolAdapter`)

## Pool creation

### Recommended (build internally)

`CipherBftPool::new(...)` builds the Reth pool and validator internally.

```rust
use cipherbft_mempool::{CipherBftPool, MempoolConfig};
use reth_chainspec::ChainSpec;
use reth_provider::StateProviderFactory;
use reth_transaction_pool::blobstore::InMemoryBlobStore;
use std::sync::Arc;

let chain_spec: Arc<ChainSpec> = Arc::new(/* ... */);
let client: impl StateProviderFactory = /* ... */;
let blob_store = InMemoryBlobStore::default();
let chain_id = 1;
let config = MempoolConfig::default();

let pool = CipherBftPool::new(chain_spec, client, blob_store, chain_id, config)?;
```

### Wrap an existing Reth pool

Use this when you already constructed a `Pool`.

```rust
use cipherbft_mempool::{CipherBftPool, CipherBftValidator, MempoolConfig};
use reth_transaction_pool::{Pool, CoinbaseTipOrdering, PoolConfig};

let state_provider = client.latest()?;
let validator = CipherBftValidator::new(chain_spec, client, blob_store.clone(), chain_id);
let pool_config: PoolConfig = mempool_config.clone().into();
let reth_pool = Pool::new(
    validator,
    CoinbaseTipOrdering::default(),
    blob_store,
    pool_config,
);

let pool = CipherBftPool::wrap(reth_pool, mempool_config, state_provider);
```

## Transaction insertion

`add_transaction` accepts several input types (`TransactionSigned`, recovered, pooled, raw bytes):

```rust
use reth_transaction_pool::TransactionOrigin;

pool.add_transaction(TransactionOrigin::External, tx_signed).await?;
pool.add_transaction(TransactionOrigin::External, tx_recovered).await?;
pool.add_transaction(TransactionOrigin::External, pooled).await?;
```

Or insert pooled transactions directly:

```rust
pool.add_pooled_transaction(TransactionOrigin::Local, pooled_tx).await?;
```

## Adapter helpers (worker-facing)

```rust
let adapter = pool.adapter();
let pending = adapter.pending_transactions();
let queued = adapter.queued_transactions();
let batch = adapter.get_transactions_for_batch(100, 30_000_000);
let stats = adapter.stats();
adapter.remove_finalized(&tx_hashes);
```

## Notes

- BFT policy checks are enforced before handing transactions to Reth.
- Standard Ethereum validation is delegated to Reth.
- Worker integration is not yet wired in the node.
