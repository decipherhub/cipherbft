# ADR 001: Three-Layer Architecture (DCL/CL/EL)

## Changelog

* 2026-02-01: Added implementation status
* 2025-12-13: Enhanced with architecture diagram
* 2025-12-07: Initial draft

## Status

ACCEPTED Implemented

## Implementation Status

| Component | Status | Location |
|-----------|--------|----------|
| DCL (Data Chain Layer) | Implemented | `crates/data-chain/` |
| CL (Consensus Layer) | Implemented | `crates/consensus/` |
| EL (Execution Layer) | Implemented | `crates/execution/` |
| Pipeline Manager | Implemented | `crates/data-chain/src/pipeline.rs` |
| WAL (Write-Ahead Log) | Implemented | `crates/storage/src/wal.rs` |

### Implementation Notes

- **Layer Interfaces**: Trait-based boundaries implemented via `DataChainLayer`, `ConsensusLayer`, `ExecutionLayer` traits
- **Malachite Integration**: Context trait implemented in `crates/consensus/src/context.rs`
- **Error Handling**: Unified `CipherBftError` type with `is_critical()` method for halt conditions
- **Atomic Commit**: WAL-based atomic commit across consensus and EVM state

## Abstract
<img width="2320" height="1987" alt="image" src="https://github.com/user-attachments/assets/1be9339a-2375-4549-b699-77ad681d4552" />

CipherBFT implements a three-layer architecture separating concerns into Data Chain Layer (DCL), Consensus Layer (CL), and Execution Layer (EL). This design follows the Autobahn BFT paper's approach where DCL handles data availability through Car/Attestation/Cut mechanisms, CL runs PBFT-style consensus over Cuts, and EL executes finalized transactions via embedded revm. This separation enables pipelined operation where attestation collection for height N+1 occurs during consensus for height N, reducing latency.

## Context

Traditional BFT consensus implementations tightly couple data dissemination with consensus voting, creating sequential bottlenecks:

1. **Monolithic designs** (CometBFT) process proposals sequentially: receive → validate → vote → commit
2. **Data availability** is verified during consensus, adding latency to each round
3. **Execution** happens after commit, further delaying finality perception

Autobahn BFT (arxiv:2401.10369) introduces a separation that allows overlapping operations:
- Cars (certified transaction batches) can be created and attested independently
- Cuts (collection of highest attested Cars) are formed when consensus needs a proposal
- Consensus runs over Cuts, not raw transactions

This design targets:
- **>100K TPS** throughput with 4 workers per validator
- **<500ms p50 latency** in geo-distributed networks (21 validators, 3 regions)
- **2x latency improvement** over Bullshark

### Performance Target Analysis

| Configuration | Autobahn Paper | CipherBFT Target | Notes |
|---------------|----------------|------------------|-------|
| Validators | 4 | 21 | 5x more validators |
| Workers | 1 | 4 | 4x more workers |
| Throughput | 199K TPS | >100K TPS | Conservative due to validator scaling |
| Latency | 190ms | <500ms | Higher validator count increases rounds |

Scaling considerations:
- PBFT message complexity: O(n²) where n = validator count
- 21 validators ≈ 27x more messages than 4 validators
- Worker parallelism offsets some throughput loss
- Target is intentionally conservative pending benchmarks

## Alternatives

### Alternative 1: Monolithic Single-Layer Design

Traditional approach where consensus directly handles transactions.

**Pros:**
- Simpler implementation
- Fewer moving parts
- Well-understood model (CometBFT)

**Cons:**
- Sequential bottleneck limits throughput
- No overlap between data availability and consensus
- Harder to scale horizontally

### Alternative 2: Narwhal/Tusk DAG-based Separation

Use DAG structure for data availability (Narwhal) with separate ordering (Tusk/Bullshark).

**Pros:**
- High throughput proven in production (Sui)
- DAG provides natural parallelism

**Cons:**
- Complex garbage collection
- Higher memory requirements for DAG maintenance
- Longer time-to-finality due to DAG depth requirements

### Alternative 3: Autobahn Three-Layer (Chosen)

Car → Cut → PBFT with pipelined attestation collection.

**Pros:**
- Pipelining reduces effective latency
- Clean separation of concerns
- Maintains PBFT simplicity in consensus layer
- No DAG garbage collection complexity

**Cons:**
- Novel design, less battle-tested
- Pipeline state management complexity
- Requires careful error handling across layers

## Decision

We will implement the Autobahn BFT three-layer architecture:

---

## Layer Interface Definitions

### Data Chain Layer (DCL) Interface

```rust
/// Data Chain Layer - handles data availability
#[async_trait]
pub trait DataChainLayer: Send + Sync {
    /// Create a new CAR from pending batches
    fn create_car(&mut self, height: Height) -> Option<Car>;

    /// Process received CAR, return attestation if valid
    fn process_car(&mut self, car: &Car) -> Result<Option<Attestation>, DclError>;

    /// Add received attestation
    fn add_attestation(&mut self, att: Attestation) -> Result<bool, DclError>;

    /// Form Cut from highest attested CARs
    fn form_cut(&self, height: Height) -> Option<Cut>;

    /// Called when consensus finalizes a Cut
    fn on_consensus_decided(&mut self, height: Height, cut: &Cut);

    /// Called when consensus aborts (timeout/view change)
    fn on_consensus_abort(&mut self, height: Height);

    /// Get current pipeline state
    fn pipeline_state(&self) -> PipelineState;
}

#[derive(Debug)]
pub enum DclError {
    InvalidCar(String),
    InvalidAttestation(String),
    UnknownValidator(ValidatorId),
    InvalidSequence { expected: u64, got: u64 },
    SignatureVerificationFailed,
    BatchNotFound(Hash),
}
```

### Consensus Layer (CL) Interface

```rust
/// Consensus Layer - PBFT over Cuts via Malachite
#[async_trait]
pub trait ConsensusLayer: Send + Sync {
    /// Get value to propose (called when we are leader)
    fn get_proposal(&self, height: Height, round: Round) -> Option<Cut>;

    /// Validate proposed Cut
    fn validate_proposal(&self, cut: &Cut) -> Result<(), ClError>;

    /// Handle consensus decision
    fn on_decided(&mut self, height: Height, cut: Cut) -> Vec<Transaction>;

    /// Handle consensus timeout
    fn on_timeout(&mut self, height: Height, round: Round);

    /// Current consensus height
    fn current_height(&self) -> Height;
}

#[derive(Debug)]
pub enum ClError {
    InvalidCut(String),
    MissingCar { validator: ValidatorId },
    InsufficientAttestations { car_hash: Hash, have: usize, need: usize },
    StaleProposal { proposed: Height, current: Height },
}
```

### Execution Layer (EL) Interface

```rust
/// Execution Layer - EVM execution via revm
#[async_trait]
pub trait ExecutionLayer: Send + Sync {
    /// Execute block and return result
    fn execute_block(&mut self, block: BlockInput) -> Result<ExecutionResult, ElError>;

    /// Validate block without committing
    fn validate_block(&self, block: &BlockInput) -> Result<(), ElError>;

    /// Get current state root
    fn state_root(&self) -> Hash;

    /// Get account state
    fn get_account(&self, address: Address) -> Option<Account>;

    /// Commit pending state changes
    fn commit(&mut self) -> Result<Hash, ElError>;

    /// Revert to previous state
    fn revert(&mut self, state_root: Hash) -> Result<(), ElError>;
}

pub struct BlockInput {
    pub height: Height,
    pub timestamp: u64,
    pub transactions: Vec<Transaction>,
    pub parent_hash: Hash,
    pub proposer: ValidatorId,
}

pub struct ExecutionResult {
    pub state_root: Hash,
    pub receipts: Vec<Receipt>,
    pub logs: Vec<Log>,
    pub gas_used: u64,
    pub bloom: Bloom,
}

#[derive(Debug)]
pub enum ElError {
    InvalidTransaction { index: usize, reason: String },
    ExecutionFailed { index: usize, reason: String },
    StateRootMismatch { expected: Hash, got: Hash },
    OutOfGas { block_limit: u64, used: u64 },
    StorageError(String),
}
```

---

## Layer Responsibilities

### Data Chain Layer (DCL)
- **Car creation**: Batch transactions from mempool, sign with validator key
- **Attestation collection**: Broadcast Cars, collect f+1 attestations from validators
- **Cut formation**: Select highest attested Car from each validator (partial cuts allowed)
- **Pipeline manager**: Overlap attestation collection for N+1 during consensus on N
- **Batch storage**: Store batch data, serve to validators requesting missing batches

### Consensus Layer (CL)
- **Malachite integration**: Use Malachite's effect-based consensus engine
- **Value = Cut**: Malachite's Value type maps to our Cut
- **PBFT phases**: Propose → Prevote (2f+1) → Precommit (2f+1) → Decide
- **Anti-censorship**: Reject proposals if >f validators' available attested Cars are excluded (CipherBFT extension)
- **View change**: Handle leader failures with standard PBFT view change

### Execution Layer (EL)
- **Embedded revm**: Execute transactions in-process, no external EL
- **Reth integration**: Use reth-db for state storage, reth-evm for execution
- **Block building**: Order transactions from Cut, compute state root
- **Receipt generation**: Generate Ethereum-compatible receipts, logs, bloom filters
- **Gas accounting**: Enforce block gas limit (default: 30M gas)

---

## Malachite Integration

### Context Implementation

```rust
pub struct CipherBftContext {
    dcl: Arc<RwLock<dyn DataChainLayer>>,
    el: Arc<RwLock<dyn ExecutionLayer>>,
    validator_set: ValidatorSet,
    our_id: ValidatorId,
    secret_key: BlsSecretKey,
}

impl malachite_common::Context for CipherBftContext {
    type Value = Cut;
    type Address = ValidatorId;
    type Height = u64;
    type Round = u32;
    type Proposal = SignedProposal<Cut>;
    type Vote = SignedVote;
    type ValidatorSet = ValidatorSet;
    type Validator = Validator;
}
```

### Effect Handlers

```rust
impl CipherBftContext {
    /// Handle Malachite effects
    pub async fn handle_effect(&mut self, effect: Effect<Self>) -> Result<(), Error> {
        match effect {
            Effect::GetValue { height, round, reply } => {
                let cut = self.dcl.read().await.form_cut(height);
                reply.send(cut);
            }
            Effect::Decided { height, value, .. } => {
                // 1. Notify DCL
                self.dcl.write().await.on_consensus_decided(height, &value);

                // 2. Extract transactions from Cut
                let txs = self.extract_transactions(&value).await?;

                // 3. Execute via EL
                let result = self.el.write().await.execute_block(BlockInput {
                    height,
                    transactions: txs,
                    ..
                })?;

                // 4. Commit state
                self.el.write().await.commit()?;
            }
            // ... other effects
        }
    }
}
```

---

## Pipeline Operation

```
Height N:   [DCL: Create Car] → [DCL: Collect Attestations] → [CL: PBFT] → [EL: Execute]
Height N+1:                      [DCL: Create Car] → [DCL: Collect Attestations] → ...
                                 ↑ starts during N's PBFT phase
```

### Pipeline Abort Handling

When consensus at height N aborts (timeout, view change):
- **Attestations for N+1 are preserved** - they are bound to CAR positions, not consensus height
- DCL continues collecting attestations
- New proposal at N may include updated Cut with more recent CARs
- Only discard attestations if the referenced CAR becomes invalid (e.g., equivocation detected)

---

## Error Handling Strategy

### DCL Errors

| Error | Cause | Recovery |
|-------|-------|----------|
| InvalidCar | Bad signature, invalid sequence | Log, ignore Car |
| InvalidAttestation | Bad signature, unknown Car | Log, ignore attestation |
| BatchNotFound | Missing batch data | Request from peer workers |
| AttestationTimeout | f+1 not reached in time | Exponential backoff, retry |

### CL Errors

| Error | Cause | Recovery |
|-------|-------|----------|
| InvalidCut | Missing attestations, stale | Reject proposal, wait for valid |
| ConsensusTimeout | Leader failure | View change to next leader |
| EquivocationDetected | Byzantine behavior | Slash evidence, continue |

### EL Errors

| Error | Cause | Recovery |
|-------|-------|----------|
| InvalidTransaction | Bad signature, nonce | Skip transaction, continue block |
| ExecutionFailed | Contract revert | Include as failed tx with receipt |
| OutOfGas | Block limit exceeded | Stop including transactions |
| StateRootMismatch | Bug or Byzantine | **CRITICAL**: Halt and alert |

### Cross-Layer Error Propagation

```rust
/// Unified error type for cross-layer errors
#[derive(Debug)]
pub enum CipherBftError {
    Dcl(DclError),
    Cl(ClError),
    El(ElError),
    Storage(StorageError),
    Network(NetworkError),
}

/// Critical errors that should halt the node
impl CipherBftError {
    pub fn is_critical(&self) -> bool {
        matches!(self,
            CipherBftError::El(ElError::StateRootMismatch { .. }) |
            CipherBftError::Storage(StorageError::Corruption(_))
        )
    }
}
```

---

## Storage Architecture

### Storage Layers

```
┌─────────────────────────────────────────────────────────────────┐
│                        Storage Layer                             │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────┐│
│  │  Consensus State (consensus-db)                              ││
│  │  - Cars: car_hash → Car                                      ││
│  │  - Attestations: car_hash → Vec<Attestation>                 ││
│  │  - Cuts: height → Cut                                        ││
│  │  - Checkpoints: height → Checkpoint                          ││
│  └─────────────────────────────────────────────────────────────┘│
│  ┌─────────────────────────────────────────────────────────────┐│
│  │  EVM State (reth-db)                                         ││
│  │  - Accounts: address → Account                               ││
│  │  - Storage: (address, slot) → value                          ││
│  │  - Code: code_hash → bytecode                                ││
│  │  - Receipts: (block, tx_index) → Receipt                     ││
│  └─────────────────────────────────────────────────────────────┘│
│  ┌─────────────────────────────────────────────────────────────┐│
│  │  Write-Ahead Log (WAL)                                       ││
│  │  - Pending operations for crash recovery                     ││
│  │  - Atomic commit across consensus + EVM state               ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

### Atomic Commit Protocol

To ensure consistency between consensus state and EVM state:

```rust
pub struct AtomicCommit {
    wal: WriteAheadLog,
    consensus_db: ConsensusDb,
    evm_db: EvmDb,
}

impl AtomicCommit {
    pub fn commit(&mut self, height: Height, cut: &Cut, execution: &ExecutionResult) -> Result<()> {
        // 1. Write intent to WAL
        self.wal.write_intent(CommitIntent {
            height,
            cut_hash: cut.hash(),
            state_root: execution.state_root,
        })?;

        // 2. Write consensus state
        self.consensus_db.put_cut(height, cut)?;

        // 3. Write EVM state
        self.evm_db.commit(execution)?;

        // 4. Mark complete in WAL
        self.wal.mark_complete(height)?;

        Ok(())
    }

    pub fn recover(&mut self) -> Result<()> {
        // On startup, check WAL for incomplete commits
        if let Some(intent) = self.wal.get_incomplete()? {
            // Rollback to last complete state
            self.consensus_db.rollback_to(intent.height - 1)?;
            self.evm_db.rollback_to_state_root(self.get_state_root(intent.height - 1)?)?;
        }
        Ok(())
    }
}
```

---

## Networking Layer

### P2P Protocol

- **Library**: libp2p with QUIC transport
- **Discovery**: Kademlia DHT for peer discovery
- **Protocols**:
  - `/cipherbft/consensus/1.0.0` - Consensus messages (proposal, vote)
  - `/cipherbft/dcl/1.0.0` - DCL messages (Car, Attestation)
  - `/cipherbft/sync/1.0.0` - State sync (checkpoint, blocks)
  - `/cipherbft/worker/1.0.0` - Worker batch dissemination

### Message Types

```rust
pub enum ConsensusMessage {
    Proposal(SignedProposal),
    Prevote(SignedVote),
    Precommit(SignedVote),
    ViewChange(SignedViewChange),
}

pub enum DclMessage {
    Car(Car),
    Attestation(Attestation),
    CarRequest { validator: ValidatorId, sequence: u64 },
    CarResponse(Option<Car>),
    BatchRequest { digest: Hash },
    BatchResponse { digest: Hash, data: Option<Vec<Transaction>> },
}

pub enum SyncMessage {
    CheckpointRequest { height: Option<Height> },
    CheckpointResponse(Option<Checkpoint>),
    BlockRangeRequest { start: Height, end: Height },
    BlockRangeResponse { blocks: Vec<Block> },
}
```

### DoS Protection

- Rate limiting per peer: max 100 messages/sec
- Request quotas: max 10 pending requests per peer
- Bandwidth limits: max 10 MB/sec per peer
- Reputation system: track peer behavior, disconnect bad actors

---

## Crate Structure

```
crates/
├── types/          # Shared types: Hash, Height, ValidatorId, etc.
├── crypto/         # BLS signatures, hashing
├── data-chain/     # DCL: Car, Attestation, Cut, Pipeline
├── consensus/      # CL: Malachite Context, Effect handlers
├── execution/      # EL: revm integration, state management
├── worker/         # Data dissemination workers (Primary-Worker)
├── mempool/        # Transaction pool
├── storage/        # Storage abstraction, WAL
├── network/        # P2P networking, message routing
├── sync/           # State synchronization
├── node/           # Node orchestration, startup
└── rpc/            # JSON-RPC API
```

---

## Consequences

### Backwards Compatibility

This is a greenfield implementation with no backwards compatibility concerns. CipherBFT is a new consensus engine, not an upgrade to an existing system.

### Positive

1. **Reduced latency**: Pipelining overlaps attestation collection with consensus
2. **Higher throughput**: Workers parallelize data dissemination
3. **Clean separation**: Each layer can be tested and optimized independently
4. **Malachite benefits**: Effect-based consensus is formally verified
5. **EVM compatibility**: Embedded revm provides full Ethereum compatibility
6. **Clear interfaces**: Trait-based layer boundaries enable independent development

### Negative

1. **Implementation complexity**: Three layers plus pipeline state management
2. **Novel design risk**: Less production experience than CometBFT
3. **Cross-layer debugging**: Issues may span multiple layers
4. **Memory overhead**: Maintaining Cars/Attestations for pipeline requires memory

### Neutral

1. **Different mental model**: Developers familiar with CometBFT need to learn new concepts
2. **Testing strategy**: Requires integration tests across all three layers

---

## Further Discussions

1. **Pipeline depth**: Currently supporting 1-deep pipeline (N+1 during N). Should we support N+2?
2. **Car timeout tuning**: Base 500ms + exponential backoff - needs benchmarking
3. **Checkpoint interval**: 1000 blocks default - optimize based on state size growth
4. **Anti-censorship threshold**: Currently >50% available Cars excluded triggers reject

## Test Cases

1. **Single validator produces blocks**: DCL creates Cars, CL finalizes, EL executes
2. **4-validator consensus**: All three layers coordinate correctly
3. **Pipeline overlap**: Attestations for N+1 collected during N consensus
4. **Consensus timeout**: View change, attestations preserved
5. **Byzantine tolerance**: f < n/3 Byzantine validators, safety maintained
6. **State sync**: New node joins, syncs from checkpoint, catches up
7. **Crash recovery**: Node crashes mid-commit, recovers via WAL
8. **EL execution failure**: Invalid tx skipped, block continues

## References

* [Autobahn BFT Paper](https://arxiv.org/abs/2401.10369)
* [Malachite Consensus](https://github.com/informalsystems/malachite)
* [Reth Documentation](https://reth.rs)
* [Narwhal/Bullshark Paper](https://arxiv.org/abs/2201.05677)
