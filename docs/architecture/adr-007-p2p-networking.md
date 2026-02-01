# ADR 007: P2P Networking with Malachite

## Changelog

* 2026-02-01: Added implementation status
* 2025-12-21: Added Malachite internal architecture analysis and channel extensibility
* 2025-12-07: Initial draft

## Status

ACCEPTED Implemented

## Implementation Status

| Component | Status | Location |
|-----------|--------|----------|
| Consensus Message Broadcast | Implemented | `crates/consensus/src/network.rs` |
| DCL Message Handler | Implemented | `crates/data-chain/src/network.rs` |
| Worker Batch Dissemination | Implemented | `crates/data-chain/src/worker/network.rs` |
| Transaction Gossip | Implemented | `crates/mempool/src/gossip.rs` |
| Malachite P2P Crates | Implemented | Via Malachite network layer |
| Channel Extensibility | Implemented | Custom channels for DCL |

### Implementation Notes

- **Network Stack**: Malachite P2P crates with GossipSub
- **Rate Limiting**: 100 msg/sec per peer, 10 MB/sec bandwidth limit
- **Peer Discovery**: Seed nodes + PEX protocol

## Abstract

CipherBFT uses Malachite's P2P networking crates for peer-to-peer communication instead of implementing custom networking or using libp2p directly. This decision maintains consistency with the Malachite consensus engine (ADR-003) and leverages battle-tested networking components designed specifically for BFT consensus.

## Context

CipherBFT requires P2P networking for:
1. **Consensus messages**: Broadcast proposals, votes to all validators
2. **DCL messages**: Disseminate Cars, collect attestations
3. **Worker data**: Batch propagation between Workers
4. **Sync**: Block catchup for validators rejoining after downtime
5. **Transaction gossip**: Propagate pending transactions

### Malachite Ecosystem Consistency

CipherBFT already uses Malachite for consensus (ADR-003):
- `malachitebft-core-consensus` - Consensus state machine
- `malachitebft-core-types` - Core types
- `malachitebft-signing-ed25519` - Ed25519 signatures

Using Malachite's networking crates maintains ecosystem consistency.

## Alternatives

### Alternative 1: libp2p

Use rust-libp2p with GossipSub and Kademlia.

**Pros:**
- Battle-tested in blockchain (Ethereum, Polkadot)
- Feature-rich (NAT traversal, multiplexing)

**Cons:**
- Large dependency tree
- Not designed specifically for BFT consensus
- Requires custom integration with Malachite

### Alternative 2: Custom TCP Implementation

Build networking from scratch.

**Pros:**
- Maximum control
- Minimal dependencies

**Cons:**
- High development cost
- Must implement discovery, encryption, multiplexing
- Security risks

### Alternative 3: Malachite P2P Crates (Chosen)

Use Malachite's native networking implementation.

**Pros:**
- Designed for BFT consensus
- Seamless integration with Malachite consensus engine
- Consistent ecosystem (same maintainers)
- Already handles consensus message types
- Uses libp2p internally (battle-tested transport layer)
- Production validated (Arc/Circle blockchain uses Malachite)

**Cons:**
- Tied to Malachite release cycle
- Must extend Channel enum for custom message types

## Malachite Internal Architecture

Investigation of the Malachite codebase reveals that it uses libp2p internally, providing the benefits of a battle-tested networking stack while offering a BFT-optimized API.

### Transport Layer

Malachite's network layer (`malachitebft-network`) is built on top of libp2p:

```
┌─────────────────────────────────────────────────────────────┐
│                    Malachite Network API                     │
│              (BFT-optimized, channel-based)                  │
├─────────────────────────────────────────────────────────────┤
│                       libp2p Stack                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  GossipSub  │  │  Kademlia   │  │  Identify/Ping      │  │
│  │  (pubsub)   │  │  (DHT)      │  │  (peer discovery)   │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                     Transport Layer                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  TCP/QUIC   │  │    Noise    │  │       Yamux         │  │
│  │ (transport) │  │ (encryption)│  │   (multiplexing)    │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Channel System

Malachite uses a channel-based message routing system. Each channel maps to a separate GossipSub topic:

```rust
// From malachite/code/crates/network/src/channel.rs
pub enum Channel {
    /// Consensus messages (Proposal, Vote, Timeout)
    Consensus,
    /// Liveness messages (protocol-specific)
    Liveness,
    /// Proposal parts (for large proposals)
    ProposalParts,
    /// State synchronization
    Sync,
}
```

### Channel Extensibility for DCL

The Channel enum can be extended to support CipherBFT's DCL messages. This enables independent communication channels for different message types:

```rust
/// Extended channel enum for CipherBFT (conceptual)
pub enum CipherBftChannel {
    // Malachite built-in channels
    Consensus,
    Liveness,
    ProposalParts,
    Sync,

    // CipherBFT DCL extensions
    DclCars,           // Car broadcast and propagation
    DclAttestations,   // Attestation collection
    WorkerBatches,     // Worker-to-Worker batch sync
    TransactionGossip, // Transaction mempool gossip
}
```

Each custom channel operates as an independent GossipSub topic, ensuring:
- **Isolation**: DCL traffic doesn't interfere with consensus messages
- **Priority**: Different channels can have different QoS settings
- **Scalability**: Channels can be subscribed/unsubscribed independently

### Message Format

Messages in Malachite are opaque byte buffers. Serialization/deserialization (codec) is handled at the application layer:

```rust
// Network layer deals with raw bytes
pub struct NetworkMessage {
    pub channel: Channel,
    pub data: Bytes,  // Opaque payload
}

// Application layer handles encoding
impl DclMessage {
    pub fn encode(&self) -> Bytes {
        bincode::serialize(self).unwrap().into()
    }

    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        bincode::deserialize(data)
    }
}
```

### Production Validation

Malachite is used in production by [Arc](https://www.circle.com/arc), Circle's blockchain platform. This provides real-world validation of:
- Network stability under load
- Peer discovery and management
- Message propagation reliability
- Integration with BFT consensus

## Decision

Use Malachite P2P crates for all networking needs.

### Malachite Networking Crates

```toml
[dependencies]
# Core networking
malachitebft-network = { git = "https://github.com/informalsystems/malachite" }
malachitebft-peer = { git = "https://github.com/informalsystems/malachite" }
malachitebft-discovery = { git = "https://github.com/informalsystems/malachite" }
malachitebft-sync = { git = "https://github.com/informalsystems/malachite" }

# Supporting crates
malachitebft-proto = { git = "https://github.com/informalsystems/malachite" }
malachitebft-config = { git = "https://github.com/informalsystems/malachite" }
malachitebft-metrics = { git = "https://github.com/informalsystems/malachite" }
```

| Crate | Purpose |
|-------|---------|
| `malachitebft-network` | Consensus message distribution |
| `malachitebft-peer` | Peer connection management |
| `malachitebft-discovery` | Peer discovery (seed nodes, PEX) |
| `malachitebft-sync` | State synchronization |
| `malachitebft-proto` | Protocol buffer definitions |
| `malachitebft-config` | Network configuration |
| `malachitebft-metrics` | Network observability |

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     MALACHITE NETWORKING                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    malachitebft-network                      ││
│  │  - Consensus message broadcast (Proposal, Vote)              ││
│  │  - Message serialization/deserialization (protobuf)          ││
│  │  - Connection multiplexing                                   ││
│  └─────────────────────────────────────────────────────────────┘│
│                              │                                   │
│  ┌──────────────┐  ┌────────┴────────┐  ┌────────────────────┐ │
│  │ malachitebft │  │  malachitebft   │  │   malachitebft     │ │
│  │   -peer      │  │   -discovery    │  │     -sync          │ │
│  │              │  │                 │  │                    │ │
│  │ - Connection │  │ - Seed nodes    │  │ - Block catchup    │ │
│  │   lifecycle  │  │ - PEX protocol  │  │ - State sync       │ │
│  │ - Peer state │  │ - Peer routing  │  │ - Checkpoint sync  │ │
│  └──────────────┘  └─────────────────┘  └────────────────────┘ │
│                                                                  │
├─────────────────────────────────────────────────────────────────┤
│                        CIPHERBFT EXTENSIONS                      │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    DCL Message Handler                       ││
│  │  - Car broadcast                                             ││
│  │  - Attestation collection                                    ││
│  │  - Car request/response                                      ││
│  └─────────────────────────────────────────────────────────────┘│
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                   Worker Message Handler                     ││
│  │  - Batch dissemination                                       ││
│  │  - Batch request/response                                    ││
│  └─────────────────────────────────────────────────────────────┘│
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                   Transaction Gossip                         ││
│  │  - New transaction propagation                               ││
│  │  - Transaction request/response                              ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

### Network Configuration

```rust
use malachitebft_config::NetworkConfig;

/// CipherBFT network configuration
pub struct CipherBftNetworkConfig {
    /// Malachite base network config
    pub base: NetworkConfig,

    /// Seed nodes for bootstrap
    pub seed_nodes: Vec<PeerAddress>,

    /// Maximum peer connections
    pub max_peers: usize,  // Default: 50

    /// Enable PEX (Peer Exchange)
    pub enable_pex: bool,  // Default: true

    /// Rate limiting
    pub rate_limit: RateLimitConfig,
}

pub struct RateLimitConfig {
    /// Max messages per second per peer
    pub msg_per_sec: u32,  // Default: 100

    /// Max bytes per second per peer
    pub bytes_per_sec: u64,  // Default: 10 MB/s
}

impl Default for CipherBftNetworkConfig {
    fn default() -> Self {
        Self {
            base: NetworkConfig::default(),
            seed_nodes: vec![],
            max_peers: 50,
            enable_pex: true,
            rate_limit: RateLimitConfig {
                msg_per_sec: 100,
                bytes_per_sec: 10 * 1024 * 1024,
            },
        }
    }
}
```

### CipherBFT Message Extensions

Malachite handles consensus messages natively. CipherBFT extends with additional message types:

```rust
/// DCL-specific messages (CipherBFT extension)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DclMessage {
    /// New Car created
    Car(Car),
    /// Attestation for a Car
    Attestation(Attestation),
    /// Request missing Car
    CarRequest { validator: ValidatorId, sequence: u64 },
    /// Response with Car data
    CarResponse(Option<Car>),
}

/// Worker messages (CipherBFT extension)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WorkerMessage {
    /// New batch available
    Batch(Batch),
    /// Request batch by digest
    BatchRequest { digest: Hash },
    /// Response with batch data
    BatchResponse { digest: Hash, data: Option<Vec<Transaction>> },
}

/// Transaction gossip (CipherBFT extension)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TxMessage {
    /// New transaction
    NewTransaction(TransactionSigned),
    /// Request transaction by hash
    GetTransaction(TxHash),
}
```

### Integration with Malachite Consensus

```rust
use malachitebft_network::Network;
use malachitebft_peer::PeerManager;
use malachitebft_discovery::Discovery;
use malachitebft_sync::Sync;

pub struct CipherBftNetwork {
    /// Malachite network layer
    network: Network,
    /// Peer management
    peer_manager: PeerManager,
    /// Peer discovery
    discovery: Discovery,
    /// State sync
    sync: Sync,

    /// CipherBFT-specific handlers
    dcl_handler: DclMessageHandler,
    worker_handler: WorkerMessageHandler,
    tx_handler: TxMessageHandler,
}

impl CipherBftNetwork {
    pub async fn new(config: CipherBftNetworkConfig) -> Result<Self, NetworkError> {
        let network = Network::new(config.base)?;
        let peer_manager = PeerManager::new(config.max_peers)?;
        let discovery = Discovery::new(config.seed_nodes, config.enable_pex)?;
        let sync = Sync::new()?;

        Ok(Self {
            network,
            peer_manager,
            discovery,
            sync,
            dcl_handler: DclMessageHandler::new(),
            worker_handler: WorkerMessageHandler::new(),
            tx_handler: TxMessageHandler::new(),
        })
    }

    /// Start network services
    pub async fn start(&mut self) -> Result<(), NetworkError> {
        // Start Malachite network
        self.network.start().await?;

        // Bootstrap from seed nodes
        self.discovery.bootstrap(&self.peer_manager).await?;

        // Start PEX if enabled
        self.discovery.start_pex().await?;

        Ok(())
    }

    /// Broadcast consensus message (delegates to Malachite)
    pub async fn broadcast_consensus(&self, msg: ConsensusMessage) {
        self.network.broadcast(msg).await;
    }

    /// Broadcast DCL message (CipherBFT extension)
    pub async fn broadcast_dcl(&self, msg: DclMessage) {
        self.dcl_handler.broadcast(&self.network, msg).await;
    }

    /// Broadcast to Workers (CipherBFT extension)
    pub async fn broadcast_worker(&self, msg: WorkerMessage) {
        self.worker_handler.broadcast(&self.network, msg).await;
    }
}
```

### Peer Discovery

```rust
impl CipherBftNetwork {
    /// Bootstrap from seed nodes
    pub async fn bootstrap(&mut self) -> Result<(), NetworkError> {
        for seed in &self.config.seed_nodes {
            self.peer_manager.connect(seed).await?;
        }

        // Request peers from connected nodes (PEX)
        if self.config.enable_pex {
            self.discovery.request_peers().await?;
        }

        Ok(())
    }

    /// Handle PEX response
    fn on_peers_received(&mut self, peers: Vec<PeerAddress>) {
        for peer in peers {
            if self.peer_manager.peer_count() < self.config.max_peers {
                self.peer_manager.connect(&peer).ok();
            }
        }
    }
}
```

### Rate Limiting

```rust
impl CipherBftNetwork {
    fn check_rate_limit(&mut self, peer: &PeerId, msg_size: usize) -> bool {
        let limiter = self.rate_limiters.entry(*peer).or_insert_with(|| {
            RateLimiter::new(
                self.config.rate_limit.msg_per_sec,
                self.config.rate_limit.bytes_per_sec,
            )
        });

        limiter.check(msg_size)
    }

    fn handle_inbound(&mut self, peer: &PeerId, data: &[u8]) -> Result<(), NetworkError> {
        if !self.check_rate_limit(peer, data.len()) {
            // Rate limit exceeded
            return Err(NetworkError::RateLimitExceeded);
        }

        // Process message...
        Ok(())
    }
}
```

## Consequences

### Backwards Compatibility

N/A - greenfield implementation.

### Positive

1. **Ecosystem consistency**: Same maintainers as consensus engine
2. **Designed for BFT**: Native support for consensus message types
3. **Seamless integration**: Works naturally with Malachite consensus
4. **Reduced complexity**: No need to bridge libp2p with Malachite
5. **Maintained together**: Networking and consensus evolve together
6. **Battle-tested transport**: Uses libp2p internally (TCP/QUIC, Noise, Yamux)
7. **Production validated**: Arc/Circle blockchain uses Malachite in production
8. **Channel extensibility**: Custom channels can be added for DCL messages

### Negative

1. **Coupled release**: Must update with Malachite versions
2. **Smaller community**: Less documentation than raw libp2p
3. **Channel extension effort**: Requires forking or contributing to Malachite for custom channels

### Neutral

1. **Learning curve**: Must understand Malachite's channel-based networking model
2. **Abstraction trade-off**: Higher-level API than raw libp2p (less control, more convenience)

## Test Cases

1. **Bootstrap**: Node connects to seed nodes
2. **PEX**: Node discovers additional peers via exchange
3. **Consensus broadcast**: Proposal reaches all validators
4. **DCL broadcast**: Car and attestation propagation
5. **Rate limiting**: Excessive messages dropped
6. **Reconnection**: Node reconnects after disconnect
7. **Sync**: New node catches up via block requests
8. **Worker batch**: Batch propagates to peer workers

## References

* [Malachite GitHub](https://github.com/informalsystems/malachite)
* [Malachite Documentation](https://malachite.informal.systems)
* [malachitebft-network crate](https://crates.io/crates/informalsystems-malachitebft-network)
* [Arc by Circle](https://www.circle.com/arc) - Production blockchain using Malachite
* [libp2p](https://libp2p.io/) - Underlying transport layer used by Malachite
* [Malachite Network Channel Source](https://github.com/informalsystems/malachite/blob/main/code/crates/network/src/channel.rs) - Channel enum definition
