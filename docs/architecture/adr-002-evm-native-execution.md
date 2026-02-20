# ADR 002: EVM-Native Execution with Embedded revm

## Changelog

* 2026-02-01: Added implementation status
* 2025-12-07: Initial draft

## Status

ACCEPTED Implemented

## Implementation Status

| Component | Status | Location |
|-----------|--------|----------|
| Embedded revm | Implemented | `crates/execution/` |
| Reth crate integration | Implemented | See `Cargo.toml` dependencies |
| ExecutionEngine trait | Implemented | `crates/execution/src/engine.rs` |
| EVM Configuration | Implemented | `crates/execution/src/evm_config.rs` |
| Staking Precompile | Implemented | `crates/execution/src/precompiles/staking.rs` |
| State Root Calculation | Implemented | `crates/execution/src/state.rs` |
| Transaction Validation | Implemented | `crates/execution/src/validation.rs` |

### Implementation Notes

- **Reth Version**: Pinned to v1.1.0 for API stability
- **EVM Fork**: Supports Shanghai fork, Dencun activation configurable
- **Gas Limit**: Default 30M gas per block, configurable via genesis
- **State Sync**: Snap sync implemented for fast bootstrap

## Abstract

CipherBFT embeds revm directly in the consensus node for EVM execution rather than using the Engine API to communicate with an external execution client. This design is not merely a performance optimization—it is an architectural necessity because the Engine API's "execute-then-consensus" model is fundamentally incompatible with Autobahn BFT's "consensus-then-execute" model.

## Context

### Ethereum's CL/EL Separation Model

Ethereum 2.0 introduced the Engine API pattern where consensus and execution are separate processes:

```
Consensus Layer (CL) <--> Engine API (JSON-RPC) <--> Execution Layer (EL)
```

**Engine API Flow** (Execute-then-Consensus):
```
1. CL → EL: engine_forkchoiceUpdatedV3(payloadAttributes)  // Trigger build
2. EL: Execute transactions, compute state_root
3. CL ← EL: engine_getPayloadV3 → {transactions, state_root}  // Already executed
4. CL: Broadcast payload to validators, run consensus on pre-executed result
5. CL → EL: engine_newPayloadV3  // Other validators verify execution
6. CL → EL: engine_forkchoiceUpdatedV3  // Finalize head
```

Key characteristic: **The proposer executes transactions before consensus**, and `state_root` is included in the proposal.

### Autobahn BFT's Execution Model

**Autobahn BFT Flow** (Consensus-then-Execute):
```
1. All validators: Create Cars with transaction batches (no execution yet)
2. DCL: Collect f+1 attestations per Car
3. Leader: Form Cut from attested Cars
4. CL: Run PBFT consensus on Cut (transactions not yet executed)
5. After consensus: Execute Cut transactions, compute state_root
6. Include state_root in commit certificate
```

Key characteristic: **Consensus determines transaction ordering before execution**. The final transaction set is unknown until consensus completes.

## Problem Statement

The Engine API cannot support Autobahn BFT due to five fundamental incompatibilities:

### 1. Causality Inversion (Critical)

| Aspect | Engine API | Autobahn BFT |
|--------|------------|--------------|
| Execution timing | Before consensus | After consensus |
| state_root | In proposal | In commit certificate |
| Transaction set | Known at proposal | Unknown until consensus |

Engine API assumes `state_root` is known at proposal time. Autobahn BFT cannot know the final transaction set (which Cars are included in the Cut) until consensus completes. **This is not optimizable—it's a causality problem.**

### 2. Multi-Proposer Model Mismatch

```
Autobahn BFT:
  Validator A → Car_A (with f+1 attestations)
  Validator B → Car_B (with f+1 attestations)  → Cut = {Car_A, Car_B, Car_C} → Consensus
  Validator C → Car_C (with f+1 attestations)

Engine API:
  Single Proposer → engine_getPayloadV3 → Single Payload → Consensus
```

Engine API has no mechanism for:
- Multiple validators creating independent transaction batches
- Aggregating multiple payloads into a single execution unit
- f+1 attestation collection per Car

### 3. Transaction Ordering Control

- **Autobahn BFT**: CL enforces deterministic ordering (Cars by ValidatorId, deduplication by first occurrence)
- **Engine API**: EL controls ordering via its internal mempool

The CL cannot override the EL's transaction selection or ordering through Engine API.

### 4. Pipelined Attestation Collection

- **Autobahn BFT**: While consensus runs for height N, DCL collects attestations for height N+1
- **Engine API**: `payloadAttributes` triggers building only after fork choice is determined

No mechanism for speculative, pre-consensus transaction batching.

### 5. Latency Budget

| Operation | Latency | Notes |
|-----------|---------|-------|
| `engine_forkchoiceUpdatedV3` (trigger) | 1-5ms | |
| Payload building | 50-200ms | EL builds block |
| `engine_getPayloadV3` | 1-5ms | |
| `engine_newPayloadV3` | 10-50ms | Validate + execute |
| `engine_forkchoiceUpdatedV3` (finalize) | 1-5ms | |
| **Total** | **63-265ms** | 12-53% of 500ms budget |

With <500ms p50 finality target, Engine API overhead is unacceptable even if the causality problem didn't exist.

## Alternatives Considered

### Alternative 1: Engine API with External Reth

Use Reth as external EL via Engine API.

**Rejected because:**
- Causality inversion cannot be solved
- Multi-proposer model not supported
- CL cannot control transaction ordering

### Alternative 2: Fork Reth Entirely

Fork Reth and replace its consensus with CipherBFT.

**Rejected because:**
- Massive codebase (>500K LOC) to maintain
- Most Reth code unnecessary for our use case
- Difficult to track upstream security patches

### Alternative 3: Embedded revm with Reth Crates (Chosen)

Embed revm directly, use reth-db and reth-evm crates selectively.

**Chosen because:**
- Enables consensus-then-execute model
- Direct control over transaction ordering
- Minimal dependency footprint
- Use battle-tested Reth components for storage and EVM

## Decision

Embed revm directly in the CipherBFT consensus node using selective Reth crates.

### Reth Crate Integration

Pin to specific Reth commit for API stability:

```toml
[dependencies]
reth-evm = { git = "https://github.com/paradigmxyz/reth", rev = "v1.1.0" }
reth-revm = { git = "https://github.com/paradigmxyz/reth", rev = "v1.1.0" }
reth-db = { git = "https://github.com/paradigmxyz/reth", rev = "v1.1.0" }
reth-provider = { git = "https://github.com/paradigmxyz/reth", rev = "v1.1.0" }
reth-trie = { git = "https://github.com/paradigmxyz/reth", rev = "v1.1.0" }
reth-primitives = { git = "https://github.com/paradigmxyz/reth", rev = "v1.1.0" }
reth-execution-types = { git = "https://github.com/paradigmxyz/reth", rev = "v1.1.0" }
reth-chainspec = { git = "https://github.com/paradigmxyz/reth", rev = "v1.1.0" }
reth-rpc-types = { git = "https://github.com/paradigmxyz/reth", rev = "v1.1.0" }
```

| Crate | Purpose |
|-------|---------|
| `reth-evm` | ConfigureEvm, ConfigureEvmEnv traits |
| `reth-revm` | Transaction execution via EvmBuilder |
| `reth-db` | MDBX storage for blocks and state |
| `reth-provider` | StateProvider abstraction |
| `reth-trie` | Merkle Patricia Trie for state roots |
| `reth-primitives` | Block, Transaction, Receipt, Account types |
| `reth-execution-types` | BlockExecutionOutput, BundleState |
| `reth-chainspec` | ChainSpec, genesis configuration |
| `reth-rpc-types` | JSON-RPC type compatibility |

### Transaction Flow (Consensus-then-Execute)

```
1. eth_sendRawTransaction → Mempool
2. Mempool validates (signature, nonce, balance, gas)
3. DCL: Validators create Cars from mempool transactions
4. DCL: Collect f+1 attestations per Car
5. Leader: Form Cut from attested Cars
6. CL: PBFT consensus on Cut (no execution yet)
7. After consensus: ExecutionEngine::execute_transactions(cut)
   - Deterministic ordering: Cars by ValidatorId
   - Deduplication: first occurrence wins
   - Execute via revm, accumulate BundleState
8. Compute state_root via StateRoot::overlay_root()
9. Include state_root in commit certificate
10. Persist block and state to reth-db
```

## Consequences

### Positive

1. **Enables Autobahn BFT**: Consensus-then-execute model now possible
2. **Zero execution latency**: No network calls between CL and EL
3. **Single binary**: Simplified deployment and operations
4. **Direct ordering control**: CL enforces deterministic transaction order
5. **Reth compatibility**: Battle-tested storage and EVM code

### Negative

1. **No EL choice**: Cannot use Geth, Besu, or other clients
2. **Maintenance burden**: Must track Reth crate updates
3. **No EL diversity**: All validators run identical execution code
4. **State sync complexity**: Must implement own sync protocols (see Implementation Details)

### Neutral

1. **Different deployment model**: Single binary vs CL+EL pair
2. **Testing approach**: Unit test execution directly, no Engine API mocking

---

## Implementation Details

### Execution Engine Interface

```rust
// crates/execution/src/engine.rs
pub trait ExecutionEngine: Send + Sync {
    /// Execute transactions from a finalized Cut
    fn execute_transactions(
        &mut self,
        cut: &Cut,
        parent_state_root: B256,
    ) -> Result<ExecutionResult, ExecutionError>;

    /// Validate a transaction before mempool insertion
    fn validate_transaction(
        &self,
        tx: &TransactionSigned,
    ) -> Result<(), ValidationError>;

    /// Compute state root from hashed post-state
    fn compute_state_root(
        &self,
        hashed_state: &HashedPostState,
    ) -> Result<B256, TrieError>;

    /// Get current canonical state root
    fn state_root(&self) -> B256;
}

pub struct ExecutionResult {
    pub bundle_state: BundleState,
    pub receipts: Vec<Receipt>,
    pub gas_used: u64,
    pub hashed_state: HashedPostState,
    pub state_root: B256,
}
```

### EVM Configuration (Reth 1.x API)

```rust
// crates/execution/src/evm_config.rs
impl ConfigureEvm for CipherBftEvmConfig {
    type DefaultExternalContext<'a> = ();

    fn evm<DB: Database>(&self, db: DB) -> Evm<'_, (), DB> {
        EvmBuilder::default()
            .with_db(db)
            .append_handler_register(|handler| {
                install_staking_precompile(handler);
            })
            .build()
    }
}
```

### Staking Precompile

Address: `0x0000000000000000000000000000000000000100`

| Operation | Gas Cost | Notes |
|-----------|----------|-------|
| `registerValidator(bytes32)` | 50,000 | Storage write |
| `deregisterValidator()` | 25,000 | Storage update |
| `getValidatorSet()` | 2,100 + 100/validator | Read-only |
| `getStake(address)` | 2,100 | Single read |
| `slash(address, uint256)` | 30,000 | System-only |

### State Storage Schema

| Data Type | Table | Notes |
|-----------|-------|-------|
| Account state (plain) | `PlainAccountState` | Direct lookups |
| Account state (hashed) | `HashedAccounts` | For trie computation |
| Storage slots (plain) | `PlainStorageState` | Direct lookups |
| Storage slots (hashed) | `HashedStorages` | For trie computation |
| Block headers | `Headers` | Canonical chain |
| Block bodies | `BlockBodies` | Transactions |
| Receipts | `Receipts` | Transaction receipts |
| Cars | `Cars` | CipherBFT-specific |
| Attestations | `Attestations` | CipherBFT-specific |
| Consensus WAL | `ConsensusWal` | Recovery |
| Validator set | `ValidatorSets` | Per-epoch |

### State Sync (Deferred to Phase 2)

Without Engine API, CipherBFT implements own state synchronization:

| Mode | Use Case |
|------|----------|
| Full Sync | Archive nodes |
| Snap Sync | Regular validators |
| Checkpoint Sync | Fast bootstrap |

See separate design document for detailed protocol specification.

### Transaction Validation

```rust
pub enum ValidationError {
    InvalidChainId { expected: u64, got: u64 },
    NonceTooLow { expected: u64, got: u64 },
    NonceTooHigh { expected: u64, got: u64 },  // Gap > 16
    InsufficientBalance { required: U256, available: U256 },
    GasLimitTooHigh,
    IntrinsicGasTooLow,
    MaxFeeBelowBaseFee,
    InvalidSignature,
}
```

---

## Test Cases

1. **Simple transfer**: Execute ETH transfer, verify balance changes and state root
2. **Contract deployment**: Deploy contract, verify code storage
3. **Contract call**: Execute function, verify state changes
4. **EIP-1559 transaction**: Verify base fee burning and priority fee
5. **Gas limit enforcement**: Transaction exceeding limit fails
6. **Staking precompile**: Register/deregister validator
7. **State root computation**: Verify correctness after execution
8. **Transaction validation**: All error cases (nonce, balance, gas, signature)

## References

* [Reth Documentation](https://reth.rs)
* [Reth GitHub](https://github.com/paradigmxyz/reth)
* [revm GitHub](https://github.com/bluealloy/revm)
* [Ethereum Engine API Spec](https://github.com/ethereum/execution-apis)
* [Autobahn BFT Paper](https://arxiv.org/abs/2301.01306)
