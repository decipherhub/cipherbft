# ADR 012: State Root Handling and Delayed Commitment

## Changelog

* 2026-02-01: Added implementation status
* 2025-12-29: Initial draft

## Status

ACCEPTED Implemented

## Implementation Status

| Component | Status | Location |
|-----------|--------|----------|
| Delayed Commitment (N-K) | Implemented | `crates/execution/src/pipeline.rs` |
| Periodic State Root | Implemented | Every 100 blocks (configurable) |
| SealedBlock Structure | Implemented | `crates/types/src/block.rs` |
| ExecutionBlock Structure | Implemented | `crates/types/src/block.rs` |
| Snap Sync | Implemented | `crates/node/src/sync/snap.rs` |
| Full Sync | Planned | Sequential block validation for archive nodes |

### Implementation Notes

- **Pipeline Depth (K)**: Default 2 blocks delay for execution finalization
- **State Root Interval**: Every 100 blocks for full state root calculation
- **Intermediate Roots**: Incremental trie updates between snapshot blocks
- **Block Structure**: `delayed_block_hash` field added for execution verification

## Abstract

CipherBFT adopts a delayed commitment mechanism for execution results and periodic state root calculation. This design decouples consensus from execution through pipelining, and reduces computational overhead by calculating expensive state roots only at fixed intervals rather than every block.

## Context

### Autobahn BFT Scope

The Autobahn paper defines consensus only up to transaction ordering:

> "Once a replica has fully synchronized the cut committed in slot s... it tries to establish a total order across all 'new' data proposals"
> — [Autobahn BFT Paper, Section 5.2.2](https://arxiv.org/pdf/2401.10369)

The consensus target is the `Cut` (certified tip snapshot from each validator lane). Execution results and state roots are explicitly out of scope in the paper.

### Ethereum Block Header Roots

The [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf) defines the following root fields in block headers:

| Field | Definition | Computation Cost |
|-------|------------|------------------|
| `stateRoot` | Keccak 256-bit hash of the root node of the state trie (Section 4.1) | **High** |
| `transactionsRoot` | Keccak 256-bit hash of the root node of the transaction trie (Section 4.3.2) | Low |
| `receiptsRoot` | Keccak 256-bit hash of the root node of the receipts trie (Section 4.3.1) | Low |
| `logsBloom` | Bloom filter composed from logs of transactions (Section 4.3.1) | Low |

### State Root Computation Cost

Computing `stateRoot` requires:

1. Updating trie nodes for changed accounts
2. Updating storage trie nodes for changed contract slots
3. Recomputing all intermediate node hashes up to the root
4. Multiple disk I/O operations for trie node reads/writes

The [reth-trie](https://github.com/paradigmxyz/reth/tree/main/crates/trie) implementation shows this complexity:

```rust
// reth: crates/trie/trie/src/state.rs
// https://reth.rs/docs/src/reth_trie/trie.rs.html

impl<T, H> StateRoot<T, H> {
    pub fn root(&mut self) -> Result<B256, StateRootError> {
        // Full state trie traversal and hash computation
    }
}
```

In contrast, `transactionsRoot`, `receiptsRoot`, and `logsBloom` only require hashing block-local data, making them significantly cheaper.

### Traditional BFT Bottleneck

In traditional BFT protocols, execution must complete before consensus voting:

```
Propose → Execute → Calculate state_root → Vote
```

This creates a bottleneck where consensus cannot proceed until execution finishes.

## Problem Statement

CipherBFT must address two problems:

1. **Consensus-Execution Coupling**: Traditional BFT requires execution before voting, limiting throughput
2. **State Root Cost**: Computing `stateRoot` every block is expensive and unnecessary for execution verification

## Decision

### 1. Delayed Commitment (N-K Structure)

Consensus and execution are separated into a pipeline. When committing Block N, the consensus includes the hash of Block N-K (where K is the pipeline depth).

```
Block N-K:  [Consensus] → [Execute] → SealedBlock(N-K) complete
Block N-K+1:              [Consensus] → [Execute] → ...
...
Block N:                               [Consensus] ← delayed_block_hash = SealedBlock(N-K).hash
```

A validator can only vote on Block N if Block N-K execution has completed:

```rust
fn can_vote_for_block(n: Height) -> bool {
    let target_height = n.saturating_sub(K);
    is_executed(target_height)
}
```

### 2. Periodic State Root Calculation

`state_root` is calculated only at fixed intervals (every N blocks). Non-snapshot blocks copy the previous snapshot's `state_root` value.

```
Block 1~99:    state_root = snapshot_0 (copy from genesis)
Block 100:     state_root = snapshot_100 (CALCULATE)
Block 101~199: state_root = snapshot_100 (copy)
Block 200:     state_root = snapshot_200 (CALCULATE)
...
```

Execution correctness is verified every block using `receipts_root`, which is cheap to compute.

### 3. Block Structure

```rust
/// Consensus result
pub struct ConsensusBlock {
    pub height: Height,
    pub cut: Cut,                        // Consensus target: transaction ordering
    pub delayed_block_hash: B256,        // Hash of SealedBlock at height N-K
    pub commit_qc: CommitQC,             // 2f+1 signatures
}

/// Execution result
pub struct ExecutionBlock {
    pub transactions_root: B256,         // Every block (cheap)
    pub receipts_root: B256,             // Every block (cheap)
    pub logs_bloom: Bloom,               // Every block (cheap)
    pub gas_used: u64,                   // Every block
    pub state_root: B256,                // Periodic calculation, otherwise copied
    pub state_root_height: Height,       // Height at which state_root was calculated
}

/// Final block combining consensus and execution
pub struct SealedBlock {
    pub consensus: ConsensusBlock,
    pub execution: ExecutionBlock,
    pub block_hash: B256,                // Hash(consensus, execution)
}
```

### 4. Calculation Frequency

| Field | Frequency | Purpose |
|-------|-----------|---------|
| `transactions_root` | Every block | Transaction inclusion proof |
| `receipts_root` | Every block | Execution result verification |
| `logs_bloom` | Every block | Log search optimization |
| `state_root` | Every N blocks | State consistency verification |
| `delayed_block_hash` | Every block | N-K block commitment |

### 5. Ethereum RPC Compatibility

For [`eth_getBlockByNumber`](https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_getblockbynumber) responses:

- Snapshot blocks: Return newly calculated `state_root`
- Non-snapshot blocks: Return most recent snapshot's `state_root`
- `state_root_height` field indicates which block the `state_root` was calculated at

RPC responses are constructed by converting `SealedBlock` execution results to the Ethereum block format as defined in [alloy-consensus](https://docs.rs/alloy-consensus/latest/alloy_consensus/struct.Header.html):

```rust
impl From<&SealedBlock> for alloy_consensus::Header {
    fn from(block: &SealedBlock) -> Self {
        Header {
            state_root: block.execution.state_root,
            transactions_root: block.execution.transactions_root,
            receipts_root: block.execution.receipts_root,
            logs_bloom: block.execution.logs_bloom,
            // ... other fields
        }
    }
}
```

## Consequences

### Positive

1. **Pipelined Consensus**: Consensus proceeds without waiting for execution
2. **Reduced Computation**: Expensive `state_root` calculation only at intervals
3. **Execution Verification**: `receipts_root` ensures execution correctness every block
4. **RPC Compatibility**: `stateRoot` field always returns valid value

### Negative

1. **Delayed Finality**: State commitment is delayed by K blocks
2. **Non-Standard State Root**: `stateRoot` in non-snapshot blocks refers to a previous block's state
3. **Recovery Complexity**: Must handle state root recalculation during recovery

### Neutral

1. **Parameter Tuning**: K (pipeline depth) and N (snapshot interval) require empirical tuning
2. **Client Compatibility**: Some clients may expect per-block state roots; documentation required

## Alternatives Considered

### Alternative 1: Per-Block State Root Calculation

Calculate `state_root` for every block like Ethereum.

**Rejected because:**
- High computational cost per block
- Unnecessary for execution verification when `receipts_root` suffices
- Conflicts with high-throughput design goals

### Alternative 2: No State Root at All

Omit `state_root` entirely, rely only on `receipts_root`.

**Rejected because:**
- Cannot verify full state consistency
- Breaks Ethereum RPC compatibility
- Makes state sync more difficult

### Alternative 3: Lazy State Root Calculation

Calculate `state_root` on-demand when requested via RPC.

**Rejected because:**
- Unpredictable latency for RPC responses
- Computational spike during queries
- Complicates caching and node operations

## References

* [Autobahn BFT Paper](https://arxiv.org/pdf/2401.10369) - Section 5.2.2, Consensus scope
* [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf) - Block header field definitions
* [reth-trie](https://github.com/paradigmxyz/reth/tree/main/crates/trie) - State root calculation implementation
* [alloy-consensus](https://docs.rs/alloy-consensus/latest/alloy_consensus/) - Ethereum consensus types
* [Ethereum JSON-RPC Specification](https://ethereum.org/en/developers/docs/apis/json-rpc/) - RPC API specification
