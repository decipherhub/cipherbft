# Parallel Signature Verification

CipherBFT parallelizes ECDSA signature recovery during block execution using [rayon](https://docs.rs/rayon).

## Overview

ECDSA signature recovery (`secp256k1` curve) is CPU-intensive. By recovering signatures in parallel before sequential EVM execution, we reduce block processing latency.

```
Before: [Decode+Recover+Execute] → [Decode+Recover+Execute] → ...  (sequential)
After:  [Decode+Recover ∥ Decode+Recover ∥ ...] → [Execute] → [Execute] → ...
```

## API

### RecoveredTx

```rust
pub struct RecoveredTx {
    pub tx_bytes: Bytes,      // Original RLP bytes
    pub tx_env: TxEnv,        // Parsed for EVM
    pub tx_hash: B256,        // Transaction hash
    pub sender: Address,      // Recovered signer
    pub to: Option<Address>,  // Recipient (None = create)
}
```

### recover_transactions_parallel

```rust
impl CipherBftEvmConfig {
    pub fn recover_transactions_parallel(&self, txs: &[Bytes]) -> Vec<RecoveredTx>;
}
```

Recovers sender addresses from all transactions in parallel. Invalid transactions are filtered with debug logging.

## Execution Flow

1. Consensus delivers ordered transactions via `BlockInput`
2. `recover_transactions_parallel()` decodes and recovers all signatures in parallel
3. Transactions sorted by `(sender, nonce)` to prevent nonce errors
4. Sequential EVM execution using pre-recovered `TxEnv`
5. State committed after all transactions complete

## Performance

Parallelization benefits scale with:
- Number of CPU cores
- Transactions per block
- Signature recovery cost (~100μs per tx)

For blocks with 100+ transactions, expect 2-4x speedup on multi-core systems.

## Configuration

No configuration required. Rayon automatically uses available CPU cores.

To limit parallelism (e.g., for testing):

```rust
rayon::ThreadPoolBuilder::new()
    .num_threads(4)
    .build_global()
    .unwrap();
```
