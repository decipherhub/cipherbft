# MDBX Storage Layer Implementation

This document summarizes the current state of the MDBX storage backend implementation and outlines remaining work.

## Overview

The MDBX storage backend provides persistent storage for CipherBFT using [reth-db](https://github.com/paradigmxyz/reth), which wraps LMDB/MDBX. This implementation follows [ADR-010: Storage Design](../../docs/architecture/adr-010-storage-design.md).

## Architecture

```
crates/storage/src/mdbx/
├── mod.rs          # Module definition and re-exports
├── database.rs     # Database wrapper (DatabaseConfig, DatabaseEnv)
├── tables.rs       # Table key/value type definitions
├── provider.rs     # MdbxDclStore (DclStore trait implementation)
└── wal.rs          # MdbxWal (Wal trait implementation)
```

## Current Status

### Completed

| Component | Status | Description |
|-----------|--------|-------------|
| `DatabaseConfig` | Done | Configuration for DB path, size limits, read-only mode |
| `Database` | Done | Wrapper around reth-db MDBX environment |
| `MdbxDclStore` | **Done** | Full DclStore trait implementation with MDBX operations |
| `MdbxWal` | Skeleton | Wal trait implementation for crash recovery |
| Table Key Types | Done | `CarTableKey`, `HeightRoundKey`, `HashKey`, `HeightKey`, `UnitKey` with Encode/Decode |
| Stored Value Types | Done | `StoredBatch`, `StoredCar`, `StoredCut`, etc. with Serialize/Deserialize |
| **Table Definitions** | **Done** | All 11 tables defined with reth-db `Table` trait |
| **CRUD Operations** | **Done** | All put/get/delete/has methods implemented |
| **Range Queries** | **Done** | Cursor-based range scans for Cars and Cuts |
| **Secondary Indexes** | **Done** | CarsByHash index maintained on put/delete |

### Feature Flag

The MDBX backend requires the `mdbx` feature:

```toml
[dependencies]
cipherbft-storage = { version = "0.1", features = ["mdbx"] }
```

## Usage

```rust
use cipherbft_storage::mdbx::{Database, DatabaseConfig, MdbxDclStore};
use std::sync::Arc;

// Open database
let config = DatabaseConfig::new("/path/to/db");
let db = Arc::new(Database::open(config)?);

// Create store
let store = MdbxDclStore::new(db);

// Use DclStore trait methods
store.put_batch(batch).await?;
store.put_car(car).await?;
```

## Table Definitions

All 11 tables are now defined in `tables.rs` using the reth-db `Table` trait:

### DCL Tables

| Table | Key Type | Value Type | Description |
|-------|----------|------------|-------------|
| `Batches` | `HashKey` | `BincodeValue<StoredBatch>` | Transaction batches from Workers |
| `Cars` | `CarTableKey` | `BincodeValue<StoredCar>` | CARs indexed by (validator, position) |
| `CarsByHash` | `HashKey` | `CarTableKey` | Secondary index for Car lookup by hash |
| `Attestations` | `HashKey` | `BincodeValue<StoredAggregatedAttestation>` | Aggregated BLS attestations |
| `PendingCuts` | `HeightKey` | `BincodeValue<StoredCut>` | Cuts awaiting consensus |
| `FinalizedCuts` | `HeightKey` | `BincodeValue<StoredCut>` | Finalized Cuts |

### Consensus Tables

| Table | Key Type | Value Type | Description |
|-------|----------|------------|-------------|
| `ConsensusState` | `UnitKey` | `BincodeValue<StoredConsensusState>` | Singleton current state |
| `ConsensusWal` | `HeightKey` | `BincodeValue<StoredWalEntry>` | WAL entries |
| `ValidatorSets` | `HeightKey` | `BincodeValue<StoredValidatorSet>` | Validator sets by epoch |
| `Votes` | `HeightRoundKey` | `BincodeValue<StoredVotes>` | Votes by (height, round) |
| `Proposals` | `HeightRoundKey` | `BincodeValue<StoredProposal>` | Proposals by (height, round) |

### Key Types

| Key Type | Size | Description |
|----------|------|-------------|
| `HashKey` | 32 bytes | 32-byte hash, big-endian encoded |
| `CarTableKey` | 28 bytes | (validator_prefix[20] + position[8]) |
| `HeightKey` | 8 bytes | u64 height, big-endian for sorted iteration |
| `HeightRoundKey` | 12 bytes | (height[8] + round[4]) |
| `UnitKey` | 1 byte | Singleton key for single-row tables |

### Value Encoding

All values use `BincodeValue<T>` wrapper which:
- Implements `Compress` trait (serializes with bincode)
- Implements `Decompress` trait (deserializes with bincode)
- Provides compact binary representation

## TODO

### Phase 1: Core MDBX Operations ✅ COMPLETED

- [x] **Define tables using reth-db Table trait**
  - ~~Use `define_tables!` macro for type-safe table definitions~~
  - Implemented using direct `Table` trait implementation
  - All 11 tables defined: `Batches`, `Cars`, `CarsByHash`, `Attestations`, `PendingCuts`, `FinalizedCuts`, `ConsensusState`, `ConsensusWal`, `ValidatorSets`, `Votes`, `Proposals`

- [x] **Implement actual MDBX read/write in MdbxDclStore**
  - All CRUD operations implemented with proper transaction handling
  - Implemented `put_*`, `get_*`, `delete_*`, `has_*` for all data types
  - Secondary index `CarsByHash` maintained on put/delete operations

- [x] **Implement cursor-based queries**
  - `get_cars_range`: Range scan for Cars by validator ✅
  - `get_finalized_cuts_range`: Range scan for Cuts by height ✅
  - `get_highest_car_position`: Reverse scan to find max position ✅
  - `get_latest_finalized_cut`: Reverse scan for latest Cut ✅
  - `get_all_pending_cuts`: Full table scan ✅
  - `prune_before`: Cursor-based deletion with count tracking ✅
  - `stats`: Table entry counting ✅

### Phase 2: WAL and Recovery

- [ ] **Implement persistent WAL in MdbxWal**
  - Store WAL entries in `ConsensusWal` table
  - Implement `append`, `replay_from`, `truncate_before`
  - Ensure fsync/durability guarantees

- [ ] **Implement RecoveryManager**
  - Load last committed state from `ConsensusState` table
  - Replay WAL entries from checkpoint
  - Restore in-memory state

### Phase 3: Transactions

- [ ] **Implement DclStoreTx trait**
  - Wrap MDBX write transactions
  - Support atomic batch operations
  - Implement `commit` and `abort`

- [ ] **Implement DclStoreExt trait**
  - Factory method `begin_tx()` for creating transactions

### Phase 4: Garbage Collection

- [ ] **Implement prune_before()**
  - Delete finalized Cuts before threshold height
  - Delete unreferenced Cars (not in any retained Cut)
  - Delete unreferenced Attestations
  - Delete unreferenced Batches
  - Track and return pruned entry count

- [ ] **Background pruning task**
  - Periodic pruning based on `PruningConfig`
  - Default: retain 100,000 blocks, run every 1,000 blocks

### Phase 5: Testing and Integration

- [ ] **Integration tests**
  - Test with temporary databases
  - Verify data persistence across restarts
  - Test concurrent access patterns

- [ ] **Benchmarks**
  - Write throughput (batch inserts)
  - Read latency (point queries, range scans)
  - Storage efficiency (compression ratios)

- [ ] **Crash recovery tests**
  - Simulate crashes at various points
  - Verify WAL replay correctness

## Dependencies

```toml
[dependencies]
reth-db = { git = "https://github.com/paradigmxyz/reth", tag = "v1.1.0" }
reth-db-api = { git = "https://github.com/paradigmxyz/reth", tag = "v1.1.0" }
reth-codecs = { git = "https://github.com/paradigmxyz/reth", tag = "v1.1.0" }
```

## Design Decisions

1. **Reth Compatibility**: Reuse reth-db for MDBX wrapper to leverage battle-tested code and maintain ecosystem compatibility.

2. **Single Database**: All data stored in one MDBX environment for atomic cross-table operations.

3. **Bincode Serialization**: Values serialized with bincode for compact binary representation.

4. **Secondary Indexes**: `CarsByHash` table provides O(1) lookup by Car hash, maintained manually on writes.

5. **Optional Feature**: MDBX backend is opt-in via feature flag to keep default builds lightweight.

## References

- [ADR-010: Storage Design](../../docs/architecture/adr-010-storage-design.md)
- [reth-db documentation](https://github.com/paradigmxyz/reth/tree/main/crates/storage/db)
- [MDBX documentation](https://erthink.github.io/libmdbx/)
