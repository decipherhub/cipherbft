# CipherBFT Architecture Decision Records

This directory contains Architecture Decision Records (ADRs) for CipherBFT, a high-performance BFT consensus engine implementing the Autobahn BFT algorithm with native EVM execution.

## ADR Index

| ADR | Title | Status | Summary |
|-----|-------|--------|---------|
| [ADR-001](./adr-001-three-layer-architecture.md) | Three-Layer Architecture (DCL/CL/EL) | PROPOSED | Separates concerns into Data Chain Layer, Consensus Layer, and Execution Layer following Autobahn BFT design |
| [ADR-002](./adr-002-evm-native-execution.md) | EVM-Native Execution with revm | PROPOSED | Embeds revm directly instead of using Engine API with external EL |
| [ADR-003](./adr-003-malachite-consensus.md) | Malachite Consensus Integration | PROPOSED | Uses Malachite's effect-based, formally verified Tendermint BFT implementation |
| [ADR-004](./adr-004-primary-worker-architecture.md) | Primary-Worker Architecture | PROPOSED | Horizontal scaling through Primary (consensus) + Workers (data dissemination) separation |
| [ADR-005](./adr-005-ed25519-signatures.md) | Dual Signature Scheme | PROPOSED | Ed25519 for CL (Malachite), BLS12-381 for DCL (attestation aggregation) |
| [ADR-006](./adr-006-mempool-design.md) | Mempool Design | PROPOSED | Native priority mempool with gas price ordering and Ethereum semantics |

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           CipherBFT Validator Node                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │                      PRIMARY PROCESS (1-2 cores)                    │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐   │    │
│  │  │     DCL      │  │      CL      │  │          EL            │   │    │
│  │  │              │  │              │  │                        │   │    │
│  │  │ Car Creation │  │  Malachite   │  │   Embedded revm        │   │    │
│  │  │ Attestation  │──│  Consensus   │──│   Reth Storage         │   │    │
│  │  │ Cut Formation│  │  (ADR-003)   │  │   (ADR-002)            │   │    │
│  │  │              │  │              │  │                        │   │    │
│  │  │ (ADR-001)    │  │  Ed25519     │  │   Staking Precompile   │   │    │
│  │  │              │  │  (ADR-005)   │  │                        │   │    │
│  │  └──────────────┘  └──────────────┘  └────────────────────────┘   │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                    │                                        │
│                         tokio mpsc channels                                 │
│                                    │                                        │
│  ┌────────────────────────────────┴───────────────────────────────────┐    │
│  │                     WORKER PROCESSES (4-8 cores)                    │    │
│  │                           (ADR-004)                                 │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐           │    │
│  │  │ Worker 0 │  │ Worker 1 │  │ Worker 2 │  │ Worker 3 │           │    │
│  │  │  Batch   │  │  Batch   │  │  Batch   │  │  Batch   │           │    │
│  │  │ Broadcast│  │ Broadcast│  │ Broadcast│  │ Broadcast│           │    │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘           │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Key Design Decisions

### 1. Three-Layer Separation (ADR-001)

- **DCL (Data Chain Layer)**: Handles data availability through Car/Attestation/Cut
- **CL (Consensus Layer)**: Runs PBFT-style consensus over Cuts via Malachite
- **EL (Execution Layer)**: Executes finalized transactions via embedded revm

This separation enables **pipelined operation** where attestation collection for height N+1 occurs during consensus for height N.

### 2. EVM-Native Execution (ADR-002)

Instead of using the Engine API to communicate with an external execution client:
- Embed revm directly in the consensus node
- Use Reth crates for storage (reth-db) and EVM configuration (reth-evm)
- Zero network latency between CL and EL

### 3. Malachite Consensus (ADR-003)

- Formally verified Tendermint BFT implementation
- Effect-based architecture for clean integration
- Custom Context trait implementation for CipherBFT types

### 4. Primary-Worker Architecture (ADR-004)

- **Primary**: Handles consensus logic (1-2 cores)
- **Workers**: Handle parallel transaction batching and data dissemination (4-8 cores)
- Enables >100K TPS through horizontal scaling

### 5. Ed25519 Signatures (ADR-005)

- All consensus messages and attestations use Ed25519
- Native Malachite support via `malachitebft-signing-ed25519`
- Simpler than BLS aggregation for initial implementation

## Performance Targets

| Metric | Target | Conditions |
|--------|--------|------------|
| Throughput | >100K TPS | n=21, 4 workers |
| Latency (p50) | <500ms | geo-distributed |
| Latency (p99) | <1s | geo-distributed |
| vs Bullshark | 2x latency improvement | identical conditions |

## ADR Process

1. **DRAFT**: ADR is being written (draft PR)
2. **PROPOSED**: ADR is ready for review
3. **ACCEPTED**: ADR has been approved and is being implemented
4. **IMPLEMENTED**: ADR has been fully implemented
5. **SUPERSEDED**: ADR has been replaced by a newer ADR

To propose a new ADR, copy the template and follow the structure defined in each section.
