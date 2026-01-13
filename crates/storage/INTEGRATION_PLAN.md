# Execution Layer + Storage Layer Integration Plan

## Overview

This document outlines the integration plan between the Execution Layer (`crates/execution`) and Storage Layer (`crates/storage`) for CipherBFT.

---

## Current State Analysis

### Execution Layer (feat/el-integration branch)

| Component                      | Status      | Description                          |
| ------------------------------ | ----------- | ------------------------------------ |
| `ExecutionEngine<P: Provider>` | Done        | Core execution engine with EVM       |
| `Provider` trait               | Done        | Storage abstraction interface        |
| `InMemoryProvider`             | Done        | In-memory implementation (for tests) |
| `StateManager<P>`              | Done        | State root computation & snapshots   |
| `CipherBftEvmConfig`           | Done        | EVM configuration (Cancun fork)      |
| `StakingPrecompile`            | Done        | Staking precompile at 0x100          |
| `ExecutionLayer` (lib.rs)      | Placeholder | Public API wrapper (Phase 2)         |

#### Provider Trait Interface

```rust
pub trait Provider: Send + Sync {
    fn get_account(&self, address: Address) -> Result<Option<Account>>;
    fn get_code(&self, code_hash: B256) -> Result<Option<Bytecode>>;
    fn get_storage(&self, address: Address, slot: U256) -> Result<U256>;
    fn get_block_hash(&self, number: u64) -> Result<Option<B256>>;
    fn set_account(&self, address: Address, account: Account) -> Result<()>;
    fn set_code(&self, code_hash: B256, bytecode: Bytecode) -> Result<()>;
    fn set_storage(&self, address: Address, slot: U256, value: U256) -> Result<()>;
    fn set_block_hash(&self, number: u64, hash: B256) -> Result<()>;
}
```

### Storage Layer (kyrie/storage-layer branch)

| Component             | Status | Description                      |
| --------------------- | ------ | -------------------------------- |
| `DclStore` trait      | Done   | Consensus data storage interface |
| `MdbxDclStore`        | Done   | MDBX-based implementation        |
| `DclStoreTx`          | Done   | Transaction support              |
| WAL (Write-Ahead Log) | Done   | Crash recovery                   |
| Pruning Service       | Done   | Garbage collection               |

#### Current Tables (Consensus Data Only)

- `Batches`, `Cars`, `CarsByHash` - Batch/CAR data
- `Attestations` - Attestations
- `PendingCuts`, `FinalizedCuts` - Cuts
- `ConsensusWal`, `ConsensusState` - Consensus state
- `ValidatorSets`, `Votes`, `Proposals` - Validator/voting data

---

## Known Issues

### 1. Dependency Conflict (c-kzg version)

```
execution layer: alloy 1.x + revm 33 + c-kzg 2.x
storage layer:   reth v1.1.0 -> alloy 0.4.x + c-kzg 1.x
```

**Solution:** Upgrade reth to a version that uses alloy 1.x and c-kzg 2.x

```toml
# Current (Cargo.toml workspace)
reth-db = { git = "https://github.com/paradigmxyz/reth", tag = "v1.1.0" }

# Required: Find reth version compatible with alloy 1.x
```

### 2. Missing MdbxProvider

Execution layer only has `InMemoryProvider`. Need to implement `MdbxProvider` that uses storage layer's MDBX backend for persistence.

---

## Integration Architecture

```
+-----------------------------------------------------------+
|                     crates/storage                         |
+--------------------------+--------------------------------+
|  [Existing] DclStore     |  [NEW] EvmStore                |
|  - Batches, Cars, Cuts   |  - Accounts                    |
|  - Attestations          |  - Code                        |
|  - ConsensusState        |  - Storage                     |
|                          |  - BlockHashes                 |
+--------------------------+--------------------------------+
                           |
                           v
+-----------------------------------------------------------+
|                    crates/execution                        |
|  MdbxProvider implements Provider trait                    |
|  (uses storage layer's EvmStore)                          |
+-----------------------------------------------------------+
                           |
                           v
+-----------------------------------------------------------+
|  ExecutionEngine<MdbxProvider>                            |
|  - execute_block()                                         |
|  - validate_block()                                        |
|  - seal_block()                                            |
+-----------------------------------------------------------+
```

---

## Implementation Steps

### Phase 1: Resolve Dependency Conflict ✅ COMPLETED

- [x] Research reth versions compatible with alloy 1.x
- [x] Update workspace Cargo.toml with new reth version (v1.9.3)
- [x] Verify storage layer builds with updated dependencies
- [x] Verify execution layer builds
- [x] Verify both crates build together

### Phase 2: Add EVM Tables to Storage Layer ✅ COMPLETED

**File:** `crates/storage/src/mdbx/tables.rs`

```rust
// New tables for EVM state
pub struct EvmAccounts;      // Address -> Account
pub struct EvmCode;          // CodeHash -> Bytecode
pub struct EvmStorage;       // (Address, Slot) -> Value
pub struct EvmBlockHashes;   // BlockNumber -> Hash

// New tables for Staking Precompile state
pub struct StakingValidators;   // Address -> ValidatorInfo
pub struct StakingMetadata;     // () -> StakingMetadata (total_stake, epoch)
```

### Phase 2.5: Staking Precompile Storage Integration ✅ COMPLETED

**Problem:** `StakingPrecompile` currently stores state in memory only:

```rust
// Current (in-memory, lost on restart)
pub struct StakingPrecompile {
    state: Arc<RwLock<StakingState>>,
}
```

**Solution:** Integrate with storage layer for persistence:

```rust
// New (persistent)
pub struct StakingPrecompile<S: StakingStore> {
    store: Arc<S>,
    cache: Arc<RwLock<StakingState>>,  // Optional: in-memory cache
}

pub trait StakingStore: Send + Sync {
    fn get_validator(&self, address: Address) -> Result<Option<ValidatorInfo>>;
    fn set_validator(&self, address: Address, info: ValidatorInfo) -> Result<()>;
    fn delete_validator(&self, address: Address) -> Result<()>;
    fn get_all_validators(&self) -> Result<Vec<ValidatorInfo>>;
    fn get_total_stake(&self) -> Result<U256>;
    fn set_total_stake(&self, stake: U256) -> Result<()>;
    fn get_epoch(&self) -> Result<u64>;
    fn set_epoch(&self, epoch: u64) -> Result<()>;
}
```

**Data to persist:**

- `ValidatorInfo` (address, bls_pubkey, stake, registered_at, pending_exit)
- `total_stake` (U256)
- `epoch` (u64)

### Phase 3: Implement EvmStore Trait ✅ COMPLETED

**File:** `crates/storage/src/evm.rs` (new)

```rust
pub trait EvmStore: Send + Sync {
    fn get_account(&self, address: Address) -> Result<Option<Account>>;
    fn set_account(&self, address: Address, account: Account) -> Result<()>;
    fn get_code(&self, code_hash: B256) -> Result<Option<Bytecode>>;
    fn set_code(&self, code_hash: B256, bytecode: Bytecode) -> Result<()>;
    fn get_storage(&self, address: Address, slot: U256) -> Result<U256>;
    fn set_storage(&self, address: Address, slot: U256, value: U256) -> Result<()>;
    fn get_block_hash(&self, number: u64) -> Result<Option<B256>>;
    fn set_block_hash(&self, number: u64, hash: B256) -> Result<()>;
}
```

### Phase 4: Implement MdbxEvmStore ✅ COMPLETED

**File:** `crates/storage/src/mdbx/evm.rs` (new)

```rust
pub struct MdbxEvmStore {
    db: Arc<DatabaseEnv>,
}

impl EvmStore for MdbxEvmStore {
    // MDBX-based implementation
}
```

### Phase 5: Implement MdbxProvider in Execution Layer ✅ COMPLETED

**File:** `crates/execution/src/database.rs` (add)

```rust
use cipherbft_storage::EvmStore;

pub struct MdbxProvider<S: EvmStore> {
    store: Arc<S>,
}

impl<S: EvmStore> Provider for MdbxProvider<S> {
    // Delegate to EvmStore
}
```

### Phase 6: Integration Testing ✅ COMPLETED

- [x] Unit tests for MdbxEvmStore
- [x] Unit tests for MdbxStakingStore
- [x] Unit tests for MdbxProvider (6 tests in execution layer)
- [x] TableSet trait implementation for custom table creation
- [x] All 47+ unit tests passing (storage + execution mdbx tests)
- [ ] End-to-end test: block execution with persistence (future work)

---

## File Changes Summary

### Storage Layer (crates/storage)

| File                  | Action | Description                     |
| --------------------- | ------ | ------------------------------- |
| `src/mdbx/tables.rs`  | Modify | Add EVM + Staking tables        |
| `src/evm.rs`          | Create | EvmStore trait                  |
| `src/staking.rs`      | Create | StakingStore trait              |
| `src/mdbx/evm.rs`     | Create | MdbxEvmStore implementation     |
| `src/mdbx/staking.rs` | Create | MdbxStakingStore implementation |
| `src/lib.rs`          | Modify | Export new modules              |

### Execution Layer (crates/execution)

| File                         | Action | Description                                    |
| ---------------------------- | ------ | ---------------------------------------------- |
| `Cargo.toml`                 | Modify | Add cipherbft-storage dependency               |
| `src/database.rs`            | Modify | Add MdbxProvider                               |
| `src/precompiles/staking.rs` | Modify | Add StakingStore generic, persistence          |
| `src/lib.rs`                 | Modify | Export MdbxProvider, updated StakingPrecompile |

### Workspace (root)

| File         | Action | Description         |
| ------------ | ------ | ------------------- |
| `Cargo.toml` | Modify | Update reth version |

---

## Testing Strategy

```
Unit Tests
    |
    +-- MdbxEvmStore (storage layer)
    |       +-- test_account_operations
    |       +-- test_code_operations
    |       +-- test_storage_operations
    |       +-- test_block_hash_operations
    |
    +-- MdbxStakingStore (storage layer)
    |       +-- test_validator_crud
    |       +-- test_total_stake_operations
    |       +-- test_epoch_operations
    |       +-- test_get_all_validators
    |
    +-- MdbxProvider (execution layer)
    |       +-- test_provider_get_account
    |       +-- test_provider_set_account
    |       +-- ...
    |
    +-- StakingPrecompile<MdbxStakingStore> (execution layer)
            +-- test_register_validator_persistent
            +-- test_deregister_validator_persistent
            +-- test_staking_state_recovery

Integration Tests
    |
    +-- ExecutionEngine<MdbxProvider>
            +-- test_execute_block_with_persistence
            +-- test_state_recovery_after_restart
            +-- test_rollback_with_persistence
            +-- test_staking_precompile_with_persistence
```

---

## Open Questions

1. **Transaction Boundaries:** Should EVM state changes be in the same MDBX transaction as consensus data?

2. **Snapshot Strategy:** How to handle state snapshots for rollbacks with MDBX?

3. **Migration:** How to migrate existing InMemoryProvider test data to MdbxProvider tests?

---

## References

- Execution Layer Design: `crates/execution/DESIGN.md` (in feat/el-integration branch)
- Storage Layer ADR: `docs/adr/adr-010-storage-design.md`
- reth-db documentation: https://github.com/paradigmxyz/reth
