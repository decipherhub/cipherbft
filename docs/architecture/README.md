# CipherBFT Architecture Decision Records

Architecture Decision Records (ADRs) for CipherBFT - a high-performance BFT consensus engine implementing the Autobahn BFT algorithm with native EVM execution.

## Why Not Engine API?

> **The Engine API's "execute-then-consensus" model is fundamentally incompatible with Autobahn BFT's "consensus-then-execute" model.**

This is not a performance optimization - it's a **causality inversion** that cannot be bridged:

```
Engine API:     Proposer executes → state_root in proposal → Consensus on result
Autobahn BFT:   All validators create Cars → Consensus on Cut → Execute → state_root in commit
```

See [ADR-002](./adr-002-evm-native-execution.md) for the complete analysis.

## ADR Index

### Core Architecture

| ADR | Title | Status |
|-----|-------|--------|
| [ADR-001](./adr-001-three-layer-architecture.md) | Three-Layer Architecture (DCL/CL/EL) | PROPOSED |
| [ADR-002](./adr-002-evm-native-execution.md) | EVM-Native Execution with Embedded revm | PROPOSED |
| [ADR-003](./adr-003-malachite-consensus.md) | Malachite Consensus Integration | PROPOSED |
| [ADR-004](./adr-004-primary-worker-architecture.md) | Autobahn BFT with Worker Scaling | PROPOSED |

### Cryptography & Networking

| ADR | Title | Status |
|-----|-------|--------|
| [ADR-005](./adr-005-dual-signatures.md) | Dual Signature Scheme (Ed25519 + BLS12-381) | PROPOSED |
| [ADR-007](./adr-007-p2p-networking.md) | P2P Networking with Malachite | PROPOSED |

### EVM & Storage

| ADR | Title | Status |
|-----|-------|--------|
| [ADR-006](./adr-006-mempool-design.md) | Mempool Integration with Reth Transaction Pool | PROPOSED |
| [ADR-008](./adr-008-json-rpc-interface.md) | JSON-RPC Interface | PROPOSED |
| [ADR-009](./adr-009-staking-precompile.md) | Staking Precompile | PROPOSED |
| [ADR-010](./adr-010-storage-design.md) | Storage Design | PROPOSED |

### Operations

| ADR | Title | Status |
|-----|-------|--------|
| [ADR-011](./adr-011-configuration-operations.md) | Configuration and Operations | PROPOSED |

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           CipherBFT Validator Node                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │                      PRIMARY PROCESS (1-2 cores)                    │    │
│  │                                                                      │    │
│  │   ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐    │    │
│  │   │     DCL     │    │     CL      │    │         EL          │    │    │
│  │   │             │    │             │    │                     │    │    │
│  │   │ Car/Cut     │───▶│  Malachite  │───▶│   Embedded revm     │    │    │
│  │   │ BLS Attestn │    │  PBFT       │    │   Reth Storage      │    │    │
│  │   │             │    │  Ed25519    │    │   Staking Precomp   │    │    │
│  │   │ (ADR-001)   │    │  (ADR-003)  │    │   (ADR-002,009)     │    │    │
│  │   └─────────────┘    └─────────────┘    └─────────────────────┘    │    │
│  │                                                                      │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                    │                                        │
│                          tokio mpsc channels                                │
│                                    │                                        │
│  ┌────────────────────────────────▼───────────────────────────────────┐    │
│  │                     WORKER PROCESSES (4-8 cores)                    │    │
│  │                           (ADR-004)                                 │    │
│  │                                                                      │    │
│  │   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐          │    │
│  │   │ Worker 0 │  │ Worker 1 │  │ Worker 2 │  │ Worker 3 │          │    │
│  │   │ Batch TX │  │ Batch TX │  │ Batch TX │  │ Batch TX │          │    │
│  │   │ Broadcast│  │ Broadcast│  │ Broadcast│  │ Broadcast│          │    │
│  │   └──────────┘  └──────────┘  └──────────┘  └──────────┘          │    │
│  │                                                                      │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Transaction Flow: Consensus-then-Execute

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              Transaction Flow                                 │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. USER                    2. MEMPOOL                 3. DCL                │
│  ┌─────────┐               ┌─────────────┐            ┌─────────────┐       │
│  │ eth_    │──────────────▶│  Validate   │───────────▶│ Create Car  │       │
│  │ sendRaw │               │  Queue by   │            │ Broadcast   │       │
│  │ Tx      │               │  Gas Price  │            │ to Peers    │       │
│  └─────────┘               └─────────────┘            └──────┬──────┘       │
│                                                               │              │
│  6. EL                      5. CL                      4. DCL │              │
│  ┌─────────────┐           ┌─────────────┐            ┌──────▼──────┐       │
│  │ Execute     │◀──────────│ PBFT on Cut │◀───────────│ Collect f+1 │       │
│  │ Compute     │           │ (Malachite) │            │ Attestations│       │
│  │ state_root  │           │             │            │ Form Cut    │       │
│  └──────┬──────┘           └─────────────┘            └─────────────┘       │
│         │                                                                    │
│         ▼                                                                    │
│  7. COMMIT                                                                   │
│  ┌─────────────┐                                                            │
│  │ state_root  │   Key insight: state_root computed AFTER consensus,       │
│  │ in commit   │   not before. This is why Engine API doesn't work.        │
│  │ certificate │                                                            │
│  └─────────────┘                                                            │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Key Design Decisions

### 1. Consensus-then-Execute (ADR-002)

| Aspect | Engine API | CipherBFT |
|--------|------------|-----------|
| Execution timing | Before consensus | After consensus |
| state_root | In proposal | In commit certificate |
| Transaction set | Known at proposal | Unknown until Cut finalized |
| Proposer model | Single proposer | All validators create Cars |

### 2. Three-Layer Separation (ADR-001)

- **DCL**: Car creation, BLS attestations, Cut formation
- **CL**: PBFT consensus via Malachite (Ed25519)
- **EL**: Transaction execution via embedded revm

Pipelining: Collect attestations for height N+1 while consensus runs for height N.

### 3. Dual Signature Scheme (ADR-005)

| Layer | Scheme | Purpose |
|-------|--------|---------|
| CL (Consensus) | Ed25519 | Malachite native, fast verification |
| DCL (Data) | BLS12-381 | Attestation aggregation (f+1 → 1 sig) |

### 4. Horizontal Scaling (ADR-004)

- **Primary** (1-2 cores): Consensus logic, attestation aggregation
- **Workers** (4-8 cores): Parallel transaction batching, data dissemination

## Performance Targets

| Metric | Target | Conditions |
|--------|--------|------------|
| Throughput | >100K TPS | n=21, 4 workers |
| Latency (p50) | <500ms | geo-distributed (3 regions) |
| Latency (p99) | <1s | geo-distributed |
| vs Bullshark | 2x latency improvement | identical conditions |
| Blip recovery | No hangover | vs HotStuff 30% longer |

## ADR Lifecycle

```
DRAFT ──▶ PROPOSED ──▶ ACCEPTED ──▶ IMPLEMENTED
                              │
                              └──▶ SUPERSEDED
```

| Status | Description |
|--------|-------------|
| DRAFT | ADR is being written |
| PROPOSED | Ready for review |
| ACCEPTED | Approved, implementation starting |
| IMPLEMENTED | Fully implemented and tested |
| SUPERSEDED | Replaced by newer ADR |
