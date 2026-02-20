# ADR 013: Commonware Aggregation for Fast Consensus Sync

## Changelog

* 2026-02-01: Initial draft

## Status

PROPOSED Not Implemented

## Abstract

Adopt Commonware Aggregation to generate State Root Certificates for O(1) consensus sync. Reduces sync time from ~20 minutes to ~2.5 minutes for 2,300 blocks.

## Context

Current consensus sync validates blocks sequentially (~500ms × 2,300 blocks = ~20 min). The bottleneck is per-block cryptographic verification. Snap sync downloads state efficiently but lacks a trust anchor without full block validation.

## Alternatives

| Alternative | Pros | Cons |
|-------------|------|------|
| Parallel validation | No dependencies | O(n), limited by sequential state |
| Hardcoded checkpoints | Simple | Centralized, stale between releases |
| Light client proofs | Trustless | Complex, high bandwidth |
| **Aggregation** | **O(1), consensus-agnostic** | **New dependency** |

## Decision

Adopt Commonware Aggregation to create quorum certificates over state roots.

### Core Mechanism

```rust
// Validators sign state roots after each block
struct Item { height: u64, payload: B256 }  // state root
struct Certificate { item: Item, signers: BitVec, signature: Signature }
```

### Sync Flow

| Current | With Aggregation |
|---------|------------------|
| Validate 2,300 blocks sequentially | Verify single certificate |
| ~20 minutes | ~2.5 minutes |

### Implementation

1. **Broadcast**: After block finalization, broadcast state root
2. **Acknowledge**: Validators sign and return acks
3. **Aggregate**: Engine produces certificate at 2/3+ quorum
4. **Sync**: New nodes verify certificate, then snap sync state

### Consensus Agnosticism

Aggregation only requires validator set + BLS keys. Works with Malachite now, Simplex later.

## Consequences

### Positive

- 10x sync speedup
- O(1) verification
- Consensus-agnostic
- Reuses existing snap sync and BLS

### Negative

- Protocol complexity (new message types)
- Requires 2/3+ online validators
- New Commonware dependency

## References

* [Commonware Aggregation](https://github.com/commonwarexyz/monorepo/tree/main/consensus/src/aggregation)
