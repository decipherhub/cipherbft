# ADR 006: Mempool Integration with Reth Transaction Pool

## Changelog

* 2026-02-01: Added implementation status
* 2025-12-07: Initial draft

## Status

ACCEPTED Implemented

## Implementation Status

| Component | Status | Location |
|-----------|--------|----------|
| Reth Transaction Pool | Implemented | `crates/mempool/` |
| Pool Adapter | Implemented | `crates/mempool/src/adapter.rs` |
| Transaction Validation | Implemented | `crates/mempool/src/validator.rs` |
| Worker Integration | Implemented | `crates/data-chain/src/worker/` |
| Post-Finalization Cleanup | Implemented | `crates/mempool/src/cleanup.rs` |

### Implementation Notes

- **Pool Size**: Default 10,000 transactions, configurable
- **Gas Price Ordering**: Uses `CoinbaseTipOrdering` for EIP-1559
- **Nonce Gap**: Maximum 16 nonce gap before rejection
- **Memory Usage**: Bounded by pool config limits

## Abstract

CipherBFT uses Reth's `reth-transaction-pool` crate for mempool management instead of implementing a custom mempool. This decision reduces implementation cost while leveraging a battle-tested, Ethereum-compatible transaction pool that already handles EIP-1559 gas pricing, nonce gaps, transaction replacement, and all standard mempool semantics.

## Context

CipherBFT needs a mempool to:
1. Receive transactions via `eth_sendRawTransaction` and P2P gossip
2. Validate transactions (signature, nonce, balance)
3. Order transactions by effective gas price (EIP-1559)
4. Provide transactions to Workers for batch creation
5. Remove finalized transactions after block commitment

### Build vs Buy Analysis

| Aspect | Native Implementation | Reth Transaction Pool |
|--------|----------------------|----------------------|
| Development effort | High (weeks) | Low (days) |
| EIP-1559 support | Must implement | Built-in |
| Nonce gap handling | Must implement | Built-in |
| Transaction replacement | Must implement | Built-in |
| Edge case coverage | Unknown unknowns | Battle-tested |
| Maintenance burden | High | Low (upstream updates) |
| Customization | Full control | Via traits |

### Reth Crate Consistency

CipherBFT already uses 9 Reth crates (ADR-002):
- reth-evm, reth-revm, reth-db, reth-provider, reth-trie
- reth-primitives, reth-execution-types, reth-chainspec, reth-rpc-types

Adding `reth-transaction-pool` maintains consistency and reduces integration friction.

## Alternatives

### Alternative 1: Native Priority Mempool

Implement full mempool from scratch with gas price ordering.

**Pros:**
- Maximum flexibility for Worker integration
- No external dependencies for core component

**Cons:**
- High development cost (2-4 weeks)
- Must handle all edge cases manually
- Risk of subtle bugs in critical path
- Duplicates existing Reth functionality

### Alternative 2: Minimal FIFO Queue

Simple queue without gas price ordering.

**Pros:**
- Very simple implementation

**Cons:**
- Not Ethereum-compatible
- No MEV protection
- Unfair to users

### Alternative 3: Reth Transaction Pool (Chosen)

Use `reth-transaction-pool` with thin integration layer.

**Pros:**
- Battle-tested in Reth production
- Full Ethereum semantics out of the box
- Consistent with other Reth crate usage
- Low maintenance burden

**Cons:**
- Less flexibility (must work within Reth's abstractions)
- Dependency on Reth release cycle

## Decision

Use `reth-transaction-pool` crate with a thin wrapper for Worker integration.

### Reth Crate Addition

```toml
[dependencies]
reth-transaction-pool = { git = "https://github.com/paradigmxyz/reth", rev = "v1.1.0" }
```

Total Reth crates: 10 (added `reth-transaction-pool`)

### Integration Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      MEMPOOL INTEGRATION                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   eth_sendRawTransaction ─┐                                      │
│                           ├─→ [reth-transaction-pool]            │
│   P2P Gossip ────────────┘    │                                  │
│                               │  - EIP-1559 ordering             │
│                               │  - Nonce gap handling            │
│                               │  - Transaction replacement       │
│                               │  - Validation (sig, balance)     │
│                               ↓                                  │
│                        [CipherBftPoolAdapter]                    │
│                               │                                  │
│                               ├─→ Worker 0: get_best_txs()       │
│                               ├─→ Worker 1: get_best_txs()       │
│                               ├─→ Worker 2: get_best_txs()       │
│                               └─→ Worker 3: get_best_txs()       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Pool Configuration

```rust
use reth_transaction_pool::{
    Pool, TransactionPool, PoolConfig, TransactionValidationTaskExecutor,
    CoinbaseTipOrdering, EthPooledTransaction,
};

pub struct CipherBftPoolConfig {
    /// Maximum transactions in pool (default: 10,000)
    pub max_pending: usize,

    /// Maximum queued transactions per sender (default: 100)
    pub max_queued_per_account: usize,

    /// Maximum nonce gap (default: 16)
    pub max_nonce_gap: u64,

    /// Minimum gas price (default: 1 gwei)
    pub min_gas_price: u128,
}

impl Default for CipherBftPoolConfig {
    fn default() -> Self {
        Self {
            max_pending: 10_000,
            max_queued_per_account: 100,
            max_nonce_gap: 16,
            min_gas_price: 1_000_000_000, // 1 gwei
        }
    }
}

impl From<CipherBftPoolConfig> for PoolConfig {
    fn from(cfg: CipherBftPoolConfig) -> Self {
        PoolConfig {
            pending_limit: cfg.max_pending,
            queued_limit: cfg.max_pending,
            max_account_slots: cfg.max_queued_per_account,
            ..Default::default()
        }
    }
}
```

### Pool Adapter for Workers

```rust
use reth_transaction_pool::{TransactionPool, BestTransactions};

/// Adapter between Reth pool and CipherBFT Workers
pub struct CipherBftPoolAdapter<P: TransactionPool> {
    pool: P,
}

impl<P: TransactionPool> CipherBftPoolAdapter<P> {
    pub fn new(pool: P) -> Self {
        Self { pool }
    }

    /// Get best transactions for a Worker batch
    /// Returns up to `limit` transactions within `gas_limit`
    pub fn get_transactions_for_batch(
        &self,
        limit: usize,
        gas_limit: u64,
    ) -> Vec<TransactionSigned> {
        let mut txs = Vec::with_capacity(limit);
        let mut gas_used = 0u64;

        // BestTransactions iterator yields txs in effective gas price order
        for tx in self.pool.best_transactions() {
            if txs.len() >= limit {
                break;
            }

            let tx_gas = tx.gas_limit();
            if gas_used + tx_gas > gas_limit {
                continue; // Skip tx that would exceed gas limit
            }

            gas_used += tx_gas;
            txs.push(tx.to_recovered_transaction().into_signed());
        }

        txs
    }

    /// Remove transactions after block finalization
    pub fn remove_finalized(&self, tx_hashes: &[TxHash]) {
        for hash in tx_hashes {
            self.pool.remove_transaction(*hash);
        }
    }

    /// Get pool statistics for metrics
    pub fn stats(&self) -> PoolStats {
        let size = self.pool.pool_size();
        PoolStats {
            pending: size.pending,
            queued: size.queued,
            total: size.pending + size.queued,
        }
    }
}

pub struct PoolStats {
    pub pending: usize,
    pub queued: usize,
    pub total: usize,
}
```

### Worker Integration

```rust
impl Worker {
    async fn create_batch(&mut self) {
        // Get transactions from pool via adapter
        let txs = self.pool_adapter.get_transactions_for_batch(
            self.config.max_batch_txs,
            self.block_gas_limit,
        );

        if txs.is_empty() {
            return;
        }

        let batch = Batch {
            worker_id: self.worker_id,
            transactions: txs,
            timestamp: now(),
        };

        // Broadcast to peer workers
        self.broadcast_batch(&batch).await;

        // Report to Primary
        self.primary_tx.send(batch.digest()).await;
    }
}
```

### Post-Finalization Cleanup

```rust
impl ConsensusEngine {
    async fn on_block_finalized(&mut self, block: &Block) {
        // Extract all transaction hashes from finalized Cut
        let tx_hashes: Vec<TxHash> = block.cut
            .cars
            .values()
            .flat_map(|car| car.transactions.iter())
            .cloned()
            .collect();

        // Remove from pool
        self.pool_adapter.remove_finalized(&tx_hashes);
    }
}
```

### Transaction Validation

Reth's pool handles validation automatically via `TransactionValidator`:

```rust
use reth_transaction_pool::{TransactionValidator, TransactionValidationOutcome};

/// CipherBFT-specific validation (wraps Reth's validator)
pub struct CipherBftValidator<V: TransactionValidator> {
    inner: V,
    chain_id: u64,
}

impl<V: TransactionValidator> TransactionValidator for CipherBftValidator<V> {
    type Transaction = V::Transaction;

    fn validate_transaction(
        &self,
        origin: TransactionOrigin,
        transaction: Self::Transaction,
    ) -> TransactionValidationOutcome<Self::Transaction> {
        // Check chain ID
        if transaction.chain_id() != Some(self.chain_id) {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidTransactionError::ChainIdMismatch,
            );
        }

        // Delegate to Reth's validator for standard checks:
        // - Signature verification
        // - Nonce validation
        // - Balance check
        // - Gas limit check
        // - EIP-1559 base fee check
        self.inner.validate_transaction(origin, transaction)
    }
}
```

## Consequences

### Backwards Compatibility

N/A - greenfield implementation.

### Positive

1. **Reduced development cost**: Weeks → days
2. **Battle-tested**: Reth pool is production-ready
3. **Full Ethereum semantics**: EIP-1559, nonce gaps, replacement all handled
4. **Consistency**: Same crate ecosystem as storage/execution
5. **Maintenance**: Upstream handles edge cases and updates

### Negative

1. **Less flexibility**: Must work within Reth's abstractions
2. **Dependency**: Tied to Reth release cycle
3. **Learning curve**: Understanding Reth's pool traits

### Neutral

1. **Performance**: Reth pool is optimized, likely similar to custom
2. **Memory usage**: Configurable via PoolConfig
3. **API surface**: Different from hypothetical native API

## Test Cases

1. **Pool initialization**: Create pool with CipherBFT config
2. **Transaction insertion**: Insert via adapter, verify in pool
3. **Gas price ordering**: Higher price txs returned first
4. **Worker batch creation**: get_transactions_for_batch returns correct txs
5. **Post-finalization removal**: Finalized txs removed from pool
6. **Nonce gap**: Queued txs promoted when gap fills
7. **Replacement**: Higher gas price replaces existing
8. **Pool limits**: Reject when max_pending reached
9. **Chain ID validation**: Reject wrong chain ID
10. **Metrics exposure**: Pool stats available

## References

* [reth-transaction-pool](https://github.com/paradigmxyz/reth/tree/main/crates/transaction-pool)
* [Reth TransactionPool trait](https://docs.rs/reth-transaction-pool/latest/reth_transaction_pool/trait.TransactionPool.html)
* [EIP-1559: Fee market change](https://eips.ethereum.org/EIPS/eip-1559)
* [EIP-2718: Typed Transaction Envelope](https://eips.ethereum.org/EIPS/eip-2718)
