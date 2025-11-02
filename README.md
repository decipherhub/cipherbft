# Cipher BFT

![Cipher BFT](assets/cipherbft.png)

> A high-performance BFT consensus research project exploring next-generation consensus mechanisms

**⚠️ Note: This project is currently under active development with a target completion date of Q1 2026.**

## Project Overview

**Cipher BFT** is a research initiative by [Decipher](#about-decipher) in collaboration with [B-Harvest](#about-b-harvest) to explore performance improvements in BFT consensus engines. This project serves as an academic exploration to analyze core functionalities and investigate how various algorithms and protocols could theoretically improve performance.

**Project Nature**: Pure research and exploratory project aimed at understanding performance bottlenecks in BFT consensus systems and evaluating potential optimization approaches.

**Status**: Currently under active development with a target completion date of Q1 2026. Decipher and B-Harvest are collaborating on this research initiative, combining Decipher's academic research capabilities with B-Harvest's deep technical expertise in validator operations and blockchain infrastructure.

## Research Motivation

This research explores areas that can be further optimized in BFT consensus systems:

- Consensus layer architecture for higher throughput and better resilience
- P2P communication efficiency and message propagation patterns
- Transaction processing throughput and execution layer optimization
- Recovery mechanisms after network disruptions

By exploring alternative consensus algorithms like **Autobahn BFT** and optimizing P2P communication protocols, this research investigates how a BFT Consensus Engine could provide extreme performance while fully leveraging Rust's advantages.

## Implementation Approach

### 1. Bottleneck Analysis
- Broadcasting layer performance metrics
- Consensus layer latency and throughput
- Execution layer processing capacity

### 2. Technology Selection

#### **Consensus Algorithm: Autobahn BFT**
Autobahn is a next-generation BFT consensus protocol with a two-layer architecture that decouples data dissemination from consensus ordering:

- **Layer 1**: Parallel data dissemination through validator "lanes" (Cars)
- **Layer 2**: Consensus on snapshots (Cuts) using PBFT-style protocol

**Key Advantages**:
- Seamless recovery without performance hangovers
- 3 message delays on fast path (vs 12+ for DAG protocols)
- Linear bandwidth utilization with validator count
- 250k+ TPS potential in geo-distributed settings

#### **P2P Communication Protocols**

**Option 1: RaptorCast**
- UDP-based communication with Raptor codes for error correction
- Structured broadcast with predefined peer groups
- Transaction forwarding to upcoming block proposers

**Option 2: OptimumP2P**
- RLNC (Random Linear Network Coding) for adaptive error correction
- Dynamic network condition handling

### 3. Modular Implementation
- Implement selected technologies in Rust
- Maintain compatibility with ABCI 2.0 protocol
- Enable comparative testing of different approaches

### 4. Benchmarking
- Comparative performance analysis
- Latency and throughput measurements (<4s finality, >15K TPS target)
- Recovery time evaluation

## Getting Started

### Prerequisites

- **Rust**: 1.75+ (install via [rustup](https://rustup.rs/))
- **Processor**: x86_64 architecture recommended
- **Cores**: 4+ physical cores recommended
- **RAM**: 8GB minimum, 16GB recommended
- **Storage**: 20+ GB available space
- **OS**: Linux (Ubuntu 22.04+ recommended) or macOS (12+)

### System Dependencies

**Ubuntu/Debian**:
```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev clang cmake
```

**macOS**:
```bash
brew install cmake openssl
```

### Build from Source

```bash
# Clone repository
git clone https://github.com/decipherhub/cipherbft.git
cd cipherbft

# Build in release mode
cargo build --release

# Run tests
cargo test
```

### Quick Start - Single Node

```bash
# Initialize node
./target/release/cipherbft init --home ./testnet/node0

# Start node (requires ABCI app like kvstore)
./target/release/cipherbft start --home ./testnet/node0
```

### Testing with kvstore

```bash
# Download kvstore ABCI application
mkdir -p tests/fixtures/kvstore
cd tests/fixtures/kvstore
# Follow instructions in specs/001-cipherbft-implementation/quickstart.md

# Start kvstore
./kvstore &

# Start CipherBFT
cargo run --bin cipherbft -- start --home ./testnet/node0
```

## Architecture

The CipherBFT architecture follows a modular design with clear separation of concerns:

```
┌─────────────────────────────────────────────────┐
│                  RPC Layer                      │
│         (JSON-RPC 2.0, WebSocket)              │
└─────────────────┬───────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────┐
│              Consensus Engine                    │
│         (Autobahn BFT State Machine)            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐     │
│  │   Car    │  │   Cut    │  │   PBFT   │     │
│  │ Creation │→ │ Creation │→ │  Voting  │     │
│  └──────────┘  └──────────┘  └──────────┘     │
└─────────────────┬───────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────┐
│              Mempool Layer                       │
│     (Priority Queue, CheckTx Integration)       │
└─────────────────┬───────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────┐
│               P2P Network                        │
│  (Peer Discovery, Gossip, Block Sync)          │
└─────────────────┬───────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────┐
│            Storage Layer                         │
│      (RocksDB, WAL, Crash Recovery)            │
└─────────────────┬───────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────┐
│              ABCI Client                         │
│    (Application Communication Interface)        │
└──────────────────────────────────────────────────┘
```

## Key Components

- **cipherbft**: Main binary with CLI commands (init, start, version)
- **types**: Core data structures (Block, Vote, ValidatorSet)
- **crypto**: Ed25519 signatures and hashing utilities
- **abci-client**: ABCI 2.0 protocol client (TCP/Unix sockets)
- **consensus**: Autobahn BFT consensus engine with Car/Cut
- **mempool**: Priority-based transaction pool
- **p2p**: Custom P2P networking with gossip protocol
- **storage**: RocksDB persistence with WAL
- **rpc**: JSON-RPC 2.0 server with WebSocket support

## Performance Targets

Target metrics (4-validator network):

- **Finality**: <4 seconds from proposal to commit
- **Throughput**: >15,000 TPS (1KB transactions)
- **Memory**: <500MB during normal operation
- **CPU**: <50% at target throughput
- **Scalability**: 100+ validators support

## Documentation

- [Developer Quickstart](specs/001-cipherbft-implementation/quickstart.md)
- [Technical Architecture](specs/001-cipherbft-implementation/plan.md)
- [Data Model](specs/001-cipherbft-implementation/data-model.md)
- [API Contracts](specs/001-cipherbft-implementation/contracts/)
- [Implementation Tasks](specs/001-cipherbft-implementation/tasks.md)
- [Contributing Guidelines](CONTRIBUTING.md)

## About B-Harvest

![B-Harvest Logo](assets/bharvest.png)

B-Harvest is a leading blockchain infrastructure company and validator operator founded in 2018, with deep roots in the Cosmos ecosystem.

**Core Expertise**:
- Operating validators across 20+ blockchain networks
- Managing $300M+ in staked assets with 16,000+ delegators
- Core development on Tendermint/CometBFT-based blockchains
- DeFi protocol development (Crescent, Gravity DEX, etc.)

Website: [bharvest.io](https://bharvest.io/)

## About Decipher

![Decipher Logo](assets/decipher.png)

Decipher is the leading blockchain research group at Seoul National University and one of Korea's premier blockchain academic communities.

**Mission**:
- Advancing blockchain technology through cutting-edge research
- Education and knowledge dissemination in Korean
- Building Korea's blockchain ecosystem

**Activities**:
- Core protocol research and development
- Industry collaboration and partnerships
- Community building through conferences and events

Website: [decipher.ac](https://decipher.ac/)

## Research Goals

- Document theoretical and practical implications of consensus algorithm replacements
- Measure performance improvements in real-world conditions
- Contribute to academic understanding of BFT consensus optimization
- Provide open-source implementations for community evaluation
- Explore ABCI 2.0 compatibility with next-generation consensus

## Roadmap

- [x] Phase 0: Research & Technology Selection
- [x] Phase 1: Project Setup & Foundation
- [ ] Phase 2: ABCI Client Implementation (Weeks 1-2)
- [ ] Phase 3: Autobahn BFT Consensus Core (Weeks 3-5)
- [ ] Phase 4: Mempool Integration (Week 6)
- [ ] Phase 5: P2P Networking (Weeks 7-8)
- [ ] Phase 6: Storage & Persistence (Week 9)
- [ ] Phase 7: RPC & Tooling (Weeks 10-11)
- [ ] Phase 8: Integration Testing & Byzantine Fault Tests (Week 12)
- [ ] Phase 9: Performance Optimization (Weeks 13-14)

**Target Completion**: Q1 2026

## Contributing

This is an academic research project. We welcome:
- Performance analysis and benchmarking contributions
- Algorithm implementation improvements
- Documentation and educational content
- Bug reports and security findings

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

## References

- [Autobahn: Seamless high speed BFT](https://arxiv.org/abs/2401.10369)
- [RaptorCast: Designing a Messaging Layer](https://www.category.xyz/blogs/raptorcast-designing-a-messaging-layer)
- [CometBFT (Tendermint) Specification](https://github.com/cometbft/cometbft)
- [ABCI 2.0 Protocol](https://github.com/cometbft/cometbft/tree/main/spec/abci)

---

*Cipher BFT is a research collaboration between Decipher and B-Harvest, exploring the frontiers of high-performance consensus mechanisms.*

**Status**: 🚧 Under Active Development | **Progress**: Phase 1 Complete (3/107 tasks)
