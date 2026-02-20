# ADR 010: Storage Design

## Changelog

* 2026-02-01: Added implementation status
* 2025-12-07: Initial draft

## Status

ACCEPTED Implemented

## Implementation Status

| Component | Status | Location |
|-----------|--------|----------|
| MDBX Backend | Implemented | `crates/storage/` |
| EVM State Tables | Implemented | Reth-native tables |
| Block Tables | Implemented | Reth-native tables |
| Consensus Tables | Implemented | `crates/storage/src/tables/consensus.rs` |
| DCL Tables | Implemented | `crates/storage/src/tables/dcl.rs` |
| WAL | Implemented | `crates/storage/src/wal.rs` |
| Block Pruning | Implemented | `crates/storage/src/pruning.rs` |
| Recovery Manager | Implemented | `crates/storage/src/recovery.rs` |

### Implementation Notes

- **Database Path**: `<data-dir>/db/` (MDBX files)
- **WAL Path**: `<data-dir>/wal/` (separate for crash safety)
- **Retention**: Default 100,000 blocks before pruning
- **State Root**: Calculated via `reth-trie` integration

## Abstract

CipherBFT uses `reth-db` (MDBX) for persistent storage with a hybrid table schema: Reth-native tables for EVM state and custom tables for consensus-specific data. This includes Write-Ahead Log (WAL) for crash recovery and configurable block pruning.

## Context

CipherBFT requires persistent storage for:
1. **EVM state**: Account balances, contract storage, code
2. **Blocks and receipts**: Finalized blocks with execution results
3. **Consensus state**: Height, round, votes, proposals
4. **Data Chain Layer**: Cars, attestations, pending Cuts
5. **Crash recovery**: WAL for safe restart after failure
6. **Historical queries**: Block and transaction lookups

### Design Goals

- **Consistency with Reth**: Use same table structures for EVM data
- **Crash safety**: WAL ensures no data loss on unexpected shutdown
- **Query efficiency**: Indexed by height and hash
- **Configurable retention**: Pruning for storage management

## Alternatives

### Alternative 1: Full Custom Storage

Implement all storage from scratch with RocksDB or similar.

**Pros:**
- Maximum control over schema
- No external dependencies

**Cons:**
- High implementation cost
- Must implement state trie from scratch
- No Reth ecosystem compatibility

### Alternative 2: Reth Storage Only

Use only Reth's existing tables, no custom tables.

**Pros:**
- Full Reth compatibility
- Minimal custom code

**Cons:**
- Cannot store consensus-specific data
- Would need external consensus state storage

### Alternative 3: Hybrid Schema (Chosen)

Use Reth tables for EVM state, custom tables for consensus.

**Pros:**
- Reth compatibility for EVM data
- Flexible consensus storage
- Single database for all data
- Consistent with ADR-002 (EVM-native execution)

**Cons:**
- Must maintain custom table definitions
- Migration complexity if Reth schema changes

## Decision

Use `reth-db` with hybrid table schema and MDBX backend.

### Database Backend

```toml
[dependencies]
reth-db = { git = "https://github.com/paradigmxyz/reth", rev = "v1.1.0" }
```

MDBX (Lightning Memory-Mapped Database Extended) provides:
- ACID transactions
- Memory-mapped I/O for performance
- Copy-on-write for crash safety
- Minimal configuration

### Table Schema

#### EVM State Tables (Reth-native)

| Table | Key | Value | Description |
|-------|-----|-------|-------------|
| `PlainAccountState` | Address | Account | Account nonce, balance |
| `PlainStorageState` | (Address, StorageKey) | StorageValue | Contract storage |
| `HashedAccounts` | Keccak(Address) | Account | For state root |
| `HashedStorages` | Keccak(Address, Key) | StorageValue | For state root |
| `Bytecodes` | CodeHash | Bytes | Contract bytecode |

#### Block Tables (Reth-native)

| Table | Key | Value | Description |
|-------|-----|-------|-------------|
| `Headers` | BlockNumber | Header | Block headers |
| `HeaderNumbers` | BlockHash | BlockNumber | Hash to number index |
| `BlockBodies` | BlockNumber | Body | Transactions, ommers |
| `Receipts` | BlockNumber | Vec<Receipt> | Execution receipts |
| `TransactionLookup` | TxHash | BlockNumber | Tx to block index |

#### Consensus Tables (Custom)

| Table | Key | Value | Description |
|-------|-----|-------|-------------|
| `ConsensusState` | () | ConsensusState | Current height/round |
| `ConsensusWal` | WalIndex | WalEntry | Write-ahead log |
| `ValidatorSets` | Epoch | ValidatorSet | Historical validator sets |
| `Votes` | (Height, Round) | Vec<Vote> | Collected votes |
| `Proposals` | (Height, Round) | Proposal | Block proposals |

#### Data Chain Layer Tables (Custom)

| Table | Key | Value | Description |
|-------|-----|-------|-------------|
| `Cars` | (ValidatorId, Sequence) | Car | Data availability Cars |
| `Attestations` | CarHash | AggregatedAttestation | BLS aggregated attestations |
| `PendingCuts` | Height | Cut | Cuts awaiting consensus |
| `FinalizedCuts` | Height | Cut | Consensus-finalized Cuts |

### Table Definitions

```rust
// crates/storage/src/tables.rs
use reth_db::define_tables;

// Re-export Reth EVM tables
pub use reth_db::tables::{
    PlainAccountState,
    PlainStorageState,
    HashedAccounts,
    HashedStorages,
    Bytecodes,
    Headers,
    HeaderNumbers,
    BlockBodies,
    Receipts,
    TransactionLookup,
};

// Define custom consensus tables
define_tables! {
    /// Current consensus state (height, round, step)
    table ConsensusState<(), ConsensusStateValue>;

    /// Write-ahead log for crash recovery
    table ConsensusWal<u64, WalEntry>;

    /// Validator sets by epoch
    table ValidatorSets<u64, ValidatorSetValue>;

    /// Collected votes by (height, round)
    table Votes<(u64, u32), VotesValue>;

    /// Proposals by (height, round)
    table Proposals<(u64, u32), ProposalValue>;

    /// Cars by (validator, sequence)
    table Cars<(ValidatorId, u64), CarValue>;

    /// Aggregated attestations by Car hash
    table Attestations<Hash, AggregatedAttestationValue>;

    /// Pending Cuts awaiting consensus
    table PendingCuts<u64, CutValue>;

    /// Finalized Cuts after consensus
    table FinalizedCuts<u64, CutValue>;
}
```

### Write-Ahead Log (WAL)

```rust
// crates/storage/src/wal.rs

/// WAL entry types
#[derive(Encode, Decode)]
pub enum WalEntry {
    /// Received proposal
    Proposal(Proposal),
    /// Cast vote
    Vote(Vote),
    /// Received vote from peer
    ReceivedVote(Vote),
    /// Height committed
    Commit(Height),
    /// New round started
    NewRound(Height, Round),
}

pub struct ConsensusWal {
    db: Arc<Database>,
    next_index: AtomicU64,
}

impl ConsensusWal {
    /// Append entry to WAL
    pub fn append(&self, entry: WalEntry) -> Result<u64> {
        let index = self.next_index.fetch_add(1, Ordering::SeqCst);
        let tx = self.db.tx_mut()?;
        tx.put::<ConsensusWal>(index, entry)?;
        tx.commit()?;
        Ok(index)
    }

    /// Replay WAL from index
    pub fn replay_from(&self, start: u64) -> impl Iterator<Item = WalEntry> {
        self.db.cursor::<ConsensusWal>()
            .walk(Some(start))
            .map(|(_, entry)| entry)
    }

    /// Truncate WAL after commit
    pub fn truncate_before(&self, index: u64) -> Result<()> {
        let tx = self.db.tx_mut()?;
        let mut cursor = tx.cursor::<ConsensusWal>()?;
        while let Some((idx, _)) = cursor.next()? {
            if idx < index {
                cursor.delete()?;
            } else {
                break;
            }
        }
        tx.commit()
    }
}
```

### Crash Recovery

```rust
// crates/storage/src/recovery.rs

pub struct RecoveryManager {
    db: Arc<Database>,
    wal: Arc<ConsensusWal>,
}

impl RecoveryManager {
    /// Recover consensus state after crash
    pub fn recover(&self) -> Result<ConsensusState> {
        // Load last committed state
        let mut state = self.load_committed_state()?;

        // Replay WAL entries
        for entry in self.wal.replay_from(state.wal_index) {
            match entry {
                WalEntry::Proposal(p) => {
                    state.proposals.insert((p.height, p.round), p);
                }
                WalEntry::Vote(v) => {
                    state.votes.entry((v.height, v.round))
                        .or_default()
                        .push(v);
                }
                WalEntry::Commit(height) => {
                    state.height = height + 1;
                    state.round = 0;
                    state.proposals.clear();
                    state.votes.clear();
                }
                WalEntry::NewRound(height, round) => {
                    state.height = height;
                    state.round = round;
                }
                _ => {}
            }
        }

        Ok(state)
    }

    fn load_committed_state(&self) -> Result<ConsensusState> {
        let tx = self.db.tx()?;
        tx.get::<ConsensusState>(())?
            .ok_or(Error::NoCommittedState)
    }
}
```

### Block Pruning

```rust
// crates/storage/src/pruning.rs

pub struct PruningConfig {
    /// Blocks to retain (default: 100,000)
    pub retention: u64,
    /// Prune interval (blocks between prune runs)
    pub interval: u64,
}

impl Default for PruningConfig {
    fn default() -> Self {
        Self {
            retention: 100_000,
            interval: 1000,
        }
    }
}

pub struct Pruner {
    db: Arc<Database>,
    config: PruningConfig,
}

impl Pruner {
    /// Prune old blocks if needed
    pub fn maybe_prune(&self, current_height: u64) -> Result<u64> {
        if current_height % self.config.interval != 0 {
            return Ok(0);
        }

        if current_height <= self.config.retention {
            return Ok(0);
        }

        let prune_before = current_height - self.config.retention;
        self.prune_before(prune_before)
    }

    fn prune_before(&self, height: u64) -> Result<u64> {
        let tx = self.db.tx_mut()?;
        let mut pruned = 0u64;

        // Prune block bodies
        let mut cursor = tx.cursor::<BlockBodies>()?;
        while let Some((num, _)) = cursor.next()? {
            if num < height {
                cursor.delete()?;
                pruned += 1;
            } else {
                break;
            }
        }

        // Prune receipts
        let mut cursor = tx.cursor::<Receipts>()?;
        while let Some((num, _)) = cursor.next()? {
            if num < height {
                cursor.delete()?;
            } else {
                break;
            }
        }

        // Prune finalized Cuts
        let mut cursor = tx.cursor::<FinalizedCuts>()?;
        while let Some((num, _)) = cursor.next()? {
            if num < height {
                cursor.delete()?;
            } else {
                break;
            }
        }

        // Note: Headers and state are NOT pruned (needed for queries)

        tx.commit()?;
        Ok(pruned)
    }
}
```

### Storage Provider

```rust
// crates/storage/src/provider.rs
use reth_provider::{BlockReader, StateProvider, ReceiptProvider};

pub struct CipherBftStorage {
    db: Arc<Database>,
    wal: Arc<ConsensusWal>,
    pruner: Pruner,
}

impl CipherBftStorage {
    pub fn new(path: &Path, config: StorageConfig) -> Result<Self> {
        let db = Database::open(path)?;
        let wal = ConsensusWal::new(db.clone());
        let pruner = Pruner::new(db.clone(), config.pruning);

        Ok(Self { db, wal, pruner })
    }

    /// Get block by number
    pub fn block_by_number(&self, number: u64) -> Result<Option<Block>> {
        let tx = self.db.tx()?;
        let header = tx.get::<Headers>(number)?;
        let body = tx.get::<BlockBodies>(number)?;

        match (header, body) {
            (Some(h), Some(b)) => Ok(Some(Block { header: h, body: b })),
            _ => Ok(None),
        }
    }

    /// Get block by hash
    pub fn block_by_hash(&self, hash: B256) -> Result<Option<Block>> {
        let tx = self.db.tx()?;
        let number = tx.get::<HeaderNumbers>(hash)?;
        match number {
            Some(n) => self.block_by_number(n),
            None => Ok(None),
        }
    }

    /// Commit finalized block
    pub fn commit_block(&self, block: &Block, receipts: Vec<Receipt>) -> Result<()> {
        let tx = self.db.tx_mut()?;

        // Store header
        tx.put::<Headers>(block.number, &block.header)?;
        tx.put::<HeaderNumbers>(block.hash(), block.number)?;

        // Store body
        tx.put::<BlockBodies>(block.number, &block.body)?;

        // Store receipts
        tx.put::<Receipts>(block.number, receipts)?;

        // Index transactions
        for (idx, tx_signed) in block.body.transactions.iter().enumerate() {
            tx.put::<TransactionLookup>(tx_signed.hash(), block.number)?;
        }

        tx.commit()?;

        // Maybe prune old data
        self.pruner.maybe_prune(block.number)?;

        Ok(())
    }
}
```

### State Root Calculation

```rust
// crates/storage/src/state_root.rs
use reth_trie::StateRoot;

impl CipherBftStorage {
    /// Calculate state root from hashed tables
    pub fn calculate_state_root(&self) -> Result<B256> {
        let tx = self.db.tx()?;

        // Use Reth's state root calculation
        let root = StateRoot::new(&tx)
            .with_hashed_cursor_factory(&tx)
            .root()?;

        Ok(root)
    }

    /// Update state with execution changes
    pub fn apply_state_changes(&self, changes: &StateChangeset) -> Result<()> {
        let tx = self.db.tx_mut()?;

        for (address, account) in &changes.accounts {
            // Update plain state
            tx.put::<PlainAccountState>(*address, account)?;

            // Update hashed state (for state root)
            let hashed_addr = keccak256(address);
            tx.put::<HashedAccounts>(hashed_addr, account)?;
        }

        for ((address, slot), value) in &changes.storage {
            // Update plain storage
            tx.put::<PlainStorageState>((*address, *slot), *value)?;

            // Update hashed storage
            let hashed_addr = keccak256(address);
            let hashed_slot = keccak256(slot);
            tx.put::<HashedStorages>((hashed_addr, hashed_slot), *value)?;
        }

        tx.commit()
    }
}
```

## Consequences

### Backwards Compatibility

N/A - greenfield implementation.

### Positive

1. **Reth compatibility**: Same EVM state tables as Reth
2. **Crash safety**: WAL ensures recovery to consistent state
3. **Query efficiency**: Indexed by height and hash
4. **Storage management**: Configurable pruning
5. **Single database**: All data in one MDBX instance

### Negative

1. **Schema coupling**: Must update if Reth tables change
2. **MDBX limitations**: Maximum database size depends on address space
3. **Migration complexity**: Schema changes require migration logic

### Neutral

1. **Retention tradeoff**: Pruning saves space but loses history
2. **WAL overhead**: Extra writes for crash safety
3. **Hashed tables**: Duplicate data for state root calculation

## Test Cases

1. **Block storage**: Store and retrieve block by number and hash
2. **State persistence**: Account changes persist across restarts
3. **WAL replay**: Correct state after simulated crash
4. **Pruning**: Old blocks removed, headers retained
5. **State root**: Calculated root matches expected value
6. **Transaction lookup**: Find transaction by hash
7. **Consensus state**: Height/round persists correctly
8. **Car storage**: Store and retrieve Cars by validator/sequence
9. **Attestation aggregation**: Aggregated attestations stored correctly

## References

* [reth-db](https://github.com/paradigmxyz/reth/tree/main/crates/storage/db)
* [MDBX](https://github.com/erthink/libmdbx)
* [Reth State Management](https://github.com/paradigmxyz/reth/tree/main/crates/storage/provider)
* [Ethereum State Trie](https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/)
