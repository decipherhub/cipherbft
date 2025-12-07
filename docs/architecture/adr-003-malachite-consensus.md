# ADR 003: Malachite Consensus Integration

## Changelog

* 2025-12-06: Initial draft

## Status

PROPOSED Not Implemented

## Abstract

CipherBFT integrates Malachite as the Consensus Layer (CL) engine. Malachite is a production-grade, formally verified implementation of Tendermint BFT consensus with an effect-based architecture. Rather than implementing PBFT from scratch, we implement Malachite's `Context` trait and effect handlers to integrate our Data Chain Layer (DCL) for value proposal and Execution Layer (EL) for finalization. This gives us a battle-tested consensus core while maintaining full control over CipherBFT-specific components.

## Context

Implementing BFT consensus correctly is notoriously difficult:

1. **Safety bugs** can cause chain forks and loss of funds
2. **Liveness bugs** can halt the network
3. **Subtle edge cases** in view change, equivocation detection, and vote aggregation

Existing options for BFT consensus:

| Option | Language | Maturity | Architecture |
|--------|----------|----------|--------------|
| CometBFT | Go | Production | Monolithic ABCI |
| Tendermint-rs | Rust | Mature | Library |
| Malachite | Rust | New (Formal) | Effect-based |
| Custom PBFT | Rust | None | Custom |

Malachite offers:
- **Formal verification**: TLA+ specs, model checking
- **Effect-based**: Side effects are explicit, testable
- **Rust-native**: Same ecosystem as our EL and DCL
- **Active development**: Informal Systems maintains it

## Alternatives

### Alternative 1: Custom PBFT Implementation

Write PBFT from scratch.

**Pros:**
- Full control over all code
- No external dependencies
- Can optimize for our specific use case

**Cons:**
- High risk of consensus bugs
- Significant development time
- No formal verification
- Must implement view change, equivocation detection, etc.

### Alternative 2: tendermint-rs Library

Use the tendermint-rs crate.

**Pros:**
- Mature, used in production (Penumbra)
- Well-documented

**Cons:**
- Designed for CometBFT compatibility
- ABCI-focused, not effect-based
- Less flexible for custom integration

### Alternative 3: Fork CometBFT

Port CometBFT Go code to Rust.

**Pros:**
- Battle-tested consensus
- Extensive documentation

**Cons:**
- Large codebase to port
- Go idioms don't translate well to Rust
- ABCI assumption throughout

### Alternative 4: Malachite Integration (Chosen)

Implement Malachite's Context trait, use effect handlers.

**Pros:**
- Formally verified consensus core
- Effect-based architecture matches our layered design
- Native Rust, active maintenance
- Clear integration points

**Cons:**
- Newer project, less production history
- Must learn effect-based paradigm
- API may evolve

## Decision

We will integrate Malachite as the consensus engine by implementing:

### 1. CipherBftContext (Context Trait)

```rust
// crates/consensus/src/context.rs
use malachitebft_core_types::Context;

pub struct CipherBftContext {
    chain_id: String,
}

impl Context for CipherBftContext {
    type Address = ValidatorAddress;      // [u8; 20] Ethereum address
    type Height = CipherBftHeight;        // u64 wrapper
    type Proposal = CipherBftProposal;    // Cut proposal
    type ProposalPart = CipherBftProposalPart;
    type Validator = CipherBftValidator;
    type ValidatorSet = CipherBftValidatorSet;
    type Value = Cut;                     // DCL Cut as consensus value
    type Vote = CipherBftVote;
    type Extension = CipherBftExtension;
    type SigningScheme = Ed25519;

    fn select_proposer(&self, validator_set: &Self::ValidatorSet, round: Round) -> &Self::Validator {
        // Round-robin proposer selection
    }
}
```

### 2. Type Implementations

| Malachite Type | CipherBFT Implementation |
|----------------|-------------------------|
| `Address` | `ValidatorAddress` ([u8; 20]) |
| `Height` | `CipherBftHeight` (u64 wrapper) |
| `Value` | `Cut` (DCL's Cut type) |
| `Proposal` | `CipherBftProposal` (Cut + metadata) |
| `Vote` | `CipherBftVote` (height, round, value_id, type) |
| `ValidatorSet` | `CipherBftValidatorSet` (validators + voting power) |

### 3. Effect Handlers

Malachite uses effects for side effects. We implement handlers:

```rust
// crates/consensus/src/effects/mod.rs

// Signing effects
pub fn handle_sign_vote(vote: &Vote, key: &PrivateKey) -> SignedMessage<Vote>;
pub fn handle_sign_proposal(proposal: &Proposal, key: &PrivateKey) -> SignedMessage<Proposal>;
pub fn handle_verify_signature(msg: &SignedMessage<T>) -> bool;

// Network effects
pub fn handle_publish_consensus_msg(msg: ConsensusMessage, network: &NetworkManager);
pub fn handle_publish_liveness_msg(msg: LivenessMessage, network: &NetworkManager);

// Value effects (DCL integration)
pub fn handle_get_value(dcl: &DataChainLayer) -> LocallyProposedValue<Cut>;

// Decision effects (EL integration)
pub fn handle_decide(certificate: CommitCertificate, el: &ExecutionEngine, storage: &Storage);

// WAL effects
pub fn handle_wal_append_message(msg: &ConsensusMessage, wal: &Wal);
pub fn handle_wal_append_timeout(timeout: &Timeout, wal: &Wal);
```

### 4. Consensus Engine

```rust
// crates/consensus/src/engine.rs
use malachitebft_core_consensus::process;

pub struct ConsensusEngine {
    ctx: CipherBftContext,
    state: ConsensusState,
    dcl: DataChainLayer,
    el: ExecutionEngine,
    network: NetworkManager,
    wal: Wal,
}

impl ConsensusEngine {
    pub async fn run_height(&mut self, height: Height) -> Result<Block, ConsensusError> {
        // Use Malachite's process! macro for state machine
        loop {
            let effect = process!(&mut self.state, input);
            match effect {
                Effect::SignVote(vote) => {
                    let signed = handle_sign_vote(&vote, &self.key);
                    // ...
                }
                Effect::GetValue => {
                    let cut = handle_get_value(&self.dcl);
                    // ...
                }
                Effect::Decide(certificate) => {
                    handle_decide(certificate, &self.el, &self.storage);
                    return Ok(block);
                }
                // ... other effects
            }
        }
    }
}
```

### 5. Integration Points

```
┌─────────────────────────────────────────────────────────────┐
│                     CipherBFT Node                          │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐     ┌─────────────────────────┐           │
│  │     DCL     │────→│  GetValue Effect        │           │
│  │ (Car, Cut)  │     │  Returns Cut for        │           │
│  └─────────────┘     │  proposal               │           │
│                      │                         │           │
│  ┌─────────────┐     │  ┌─────────────────┐   │           │
│  │  Malachite  │←────│  │ Effect Handlers │   │           │
│  │  Consensus  │     │  └─────────────────┘   │           │
│  │   Engine    │────→│                         │           │
│  └─────────────┘     │  Decide Effect          │           │
│                      │  Triggers EL execution  │           │
│  ┌─────────────┐     │                         │           │
│  │     EL      │←────│                         │           │
│  │   (revm)    │     └─────────────────────────┘           │
│  └─────────────┘                                            │
└─────────────────────────────────────────────────────────────┘
```

## Consequences

### Backwards Compatibility

N/A - greenfield implementation. No existing CipherBFT networks to maintain compatibility with.

### Positive

1. **Formal verification**: Malachite's TLA+ specs increase confidence in consensus correctness
2. **Effect isolation**: Side effects are explicit, making testing straightforward
3. **Rust ecosystem**: Same language as DCL and EL, no FFI
4. **Active maintenance**: Informal Systems actively develops Malachite
5. **Clean integration**: Context trait provides clear extension points

### Negative

1. **Learning curve**: Effect-based paradigm differs from traditional OOP
2. **Newer project**: Less production history than CometBFT
3. **API stability**: Malachite API may change as it matures
4. **Documentation**: Less extensive than CometBFT

### Neutral

1. **Ed25519 default**: Malachite uses Ed25519, aligning with our signature choice
2. **Different from CometBFT**: Cannot reuse CometBFT tooling directly
3. **Formal methods required**: Maintaining TLA+ specs as we extend

## Further Discussions

1. **Malachite version pinning**: Which version to target? Track main or stable?
2. **Custom effects**: Do we need CipherBFT-specific effects beyond Malachite's defaults?
3. **Vote extensions**: How to use Malachite's vote extension feature?
4. **Metrics integration**: How to expose Malachite internals to Prometheus?

## Test Cases

1. **Single validator consensus**: Process messages, reach decision
2. **4-validator happy path**: All honest, blocks finalized
3. **Round timeout**: Advance round on timeout
4. **Equivocation detection**: Detect and exclude double-voting validator
5. **Network partition**: Safety maintained, liveness stalls appropriately
6. **Crash recovery**: Resume from WAL after restart

## References

* [Malachite GitHub](https://github.com/informalsystems/malachite)
* [Malachite Documentation](https://malachite.informal.systems)
* [Tendermint BFT Paper](https://arxiv.org/abs/1807.04938)
* [TLA+ Specification](https://github.com/informalsystems/malachite/tree/main/specs)
