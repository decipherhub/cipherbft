# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CipherBFT is a high-performance BFT consensus engine implementing **Autobahn BFT** with native EVM execution. It uses a "consensus-then-execute" model (unlike Ethereum's Engine API) where consensus runs first on transaction sets, then execution computes state roots.

**Performance Targets**: >100K TPS, <500ms p50 latency (21 validators, 4 workers, geo-distributed)

## Build Commands

```bash
cargo build                                    # Development build
cargo build --release                          # Optimized release build
cargo check --all-targets --all-features       # Check without building
cargo clippy --all-targets --all-features -- -D warnings  # Lint (zero warnings policy)
cargo fmt --all                                # Format code
```

## Testing

```bash
cargo test                                     # Run all tests
cargo test -p <crate-name>                     # Test specific crate
cargo test <test-name>                         # Run specific test
cargo test --test <integration-test-name>      # Run integration test
cargo bench                                    # Run benchmarks
```

**Testing Requirements**: TDD workflow, 80%+ coverage, no `unwrap()` in production (use `expect()` only in tests).

## Architecture

Three-layer architecture with Primary-Worker separation:

```
┌─────────────────────────────────────────────────────────────┐
│  PRIMARY (1-2 cores)                                        │
│  ┌──────────┐    ┌──────────┐    ┌──────────────┐          │
│  │   DCL    │ →  │    CL    │ →  │      EL      │          │
│  │ Car/Cut/ │    │ Malachite│    │  revm/Reth   │          │
│  │BLS Attn  │    │PBFT/Ed25 │    │   Storage    │          │
│  └──────────┘    └──────────┘    └──────────────┘          │
│                       ↑ tokio mpsc channels                 │
│  WORKERS (4-8 cores): Parallel TX batching                  │
└─────────────────────────────────────────────────────────────┘
```

### Crate Responsibilities

| Crate | Layer | Purpose |
|-------|-------|---------|
| `types` | Foundation | Core types: Hash, Height, ValidatorId, Car, Cut, Attestation |
| `crypto` | Security | Dual signatures (Ed25519 for CL, BLS12-381 for DCL), key management |
| `data-chain` | DCL | Car creation, attestation collection, Cut formation |
| `consensus` | CL | Malachite PBFT integration, proposal/vote handling |
| `execution` | EL | revm integration, state root computation |
| `storage` | Persistence | MDBX backend, WAL, batch/block stores |
| `mempool` | Tx Pool | Reth TxPool integration |
| `rpc` | API | JSON-RPC 2.0, Ethereum-compatible methods |
| `node` | Binary | CLI (`cipherd`), key management, orchestration |

### Key Design Patterns

1. **Consensus-then-Execute**: Consensus on Cut first, then execute and compute state_root
2. **Dual Signatures**: Ed25519 (consensus, fast) + BLS12-381 (data chain, aggregatable)
3. **Trait-Based Storage**: `DclStore`, `BatchStore` traits with InMemory/MDBX implementations
4. **Pipelining**: Collect attestations for height N+1 while consensus runs on N

## Code Standards

- **Line width**: 100 characters
- **Indent**: 4 spaces
- **Error handling**: Use `Result<T, E>`, define errors with `thiserror`
- **Async**: Tokio for all I/O, never block async contexts
- **Crypto**: Zeroize sensitive data, constant-time operations
- **Commits**: Conventional commits (`feat:`, `fix:`, `refactor:`, etc.), max 30 chars

## Key Dependencies

- **Consensus**: Malachite BFT 0.5.x (informalsystems)
- **EVM**: revm 33.1.0, alloy-primitives 1.x
- **Crypto**: blst (BLS), ed25519-consensus
- **Storage**: reth-db (MDBX backend)
- **RPC**: jsonrpsee 0.24

## Documentation

Architecture Decision Records in `docs/architecture/`:
- ADR-001: Three-Layer Architecture
- ADR-002: EVM-Native Execution
- ADR-003: Malachite Consensus
- ADR-004: Primary-Worker Architecture
- ADR-005: Dual Signature Scheme
- ADR-010: Storage Design (MDBX/WAL)
