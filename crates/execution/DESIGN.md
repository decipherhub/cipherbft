# Execution Layer Design Document

## Overview

CipherBFT's Execution Layer provides a revm-based EVM execution environment that executes transactions received from the Consensus Layer and manages state. Built on Revm 33 and Alloy 1.x, it provides validator management through a custom Staking Precompile at address 0x100.

## Related ADRs

- [ADR-002: EVM Native Execution](../../docs/architecture/adr-002-evm-native-execution.md) - EVM Execution Layer Architecture
- [ADR-009: Staking Precompile](../../docs/architecture/adr-009-staking-precompile.md) - Custom Precompile for Validator Management
- [ADR-012: State Root Handling](../../docs/architecture/adr-012-state-root-handling.md) - State Root Computation and Checkpoints

## Architecture

<p align="center">
  <img src="assets/el-architecture.png" alt="el architecture" width="1000">
</p>

## Data Flow

<p align="center">
  <img src="assets/data-flow.png" alt="data flow" width="300">
</p>

## Core Components

### 1. ExecutionLayer (`src/layer.rs`)

The main Execution Layer struct responsible for cut execution and state management.

**Key Functions:**
- Cut Execution: `execute_cut()` - Executes all transactions in a cut received from the Consensus Layer in order
- Transaction Validation: `validate_transaction()` - Validates transactions before execution
- State Commit: Persists state changes to permanent storage after cut execution

**Core Implementation:**
```rust
pub fn execute_cut(&mut self, cut: Cut) -> Result<ExecutionResult> {
    // 1. Configure EVM (Context API)
    let mut evm = self.evm_config.build_evm_with_precompiles(
        &mut self.state.db,
        block_number,
        timestamp,
        Arc::clone(&self.staking_precompile),
    );

    // 2. Execute transactions from each car
    for car in cut.cars {
        for tx_bytes in car.transactions {
            // CRITICAL: Use transact_one() - preserves journal state
            let result = self.evm_config.execute_transaction(&mut evm, &tx_bytes)?;
            receipts.push(result.receipt);
            gas_used += result.gas_used;
        }
    }

    // 3. Compute state root (every 100 blocks)
    let state_root = if self.state.should_compute_state_root(block_number) {
        self.state.compute_state_root(block_number)?
    } else {
        B256::ZERO
    };

    // 4. Commit state
    self.state.commit()?;

    Ok(ExecutionResult { state_root, receipts, gas_used })
}
```

### 2. EvmConfig (`src/evm.rs`)

Manages EVM instance creation and transaction execution.

**Key Features:**
- **Revm 33 Context API**: Uses `Context`-based API instead of `Env`
- **Custom Precompile Provider**: Integrates staking precompile (0x100) with standard precompiles
- **Journal State Preservation**: Uses `transact_one()` to preserve state changes like nonce increments

**Security:**
- Gas limit enforcement prevents infinite loops
- Nonce validation blocks replay attacks
- Signature verification prevents transaction forgery
- Revert handling rolls back failed transaction state changes

**Core Implementation:**
```rust
pub fn build_evm_with_precompiles<'a, DB>(
    &self,
    database: &'a mut DB,
    block_number: u64,
    timestamp: u64,
    staking_precompile: Arc<RwLock<StakingPrecompile>>,
) -> Evm<'a, (), &'a mut DB, CipherBftPrecompileProvider>
where
    DB: Database + DatabaseCommit,
{
    // Create context
    let mut ctx: Context<(), &mut DB> = Context::new(database, self.spec_id);

    // Configure block context
    ctx.block.number = alloy_primitives::U256::from(block_number);
    ctx.block.timestamp = alloy_primitives::U256::from(timestamp);
    ctx.cfg.chain_id = self.chain_id;

    // Create custom precompile provider
    let custom_precompiles = CipherBftPrecompileProvider::new(
        staking_precompile,
        self.spec_id,
    );

    Evm {
        ctx,
        inspector: (),
        instruction: EthInstructions::default(),
        handler: EvmHandler::new(custom_precompiles),
        db_tx: PhantomData,
    }
}

pub fn execute_transaction<EVM>(&self, evm: &mut EVM, tx_bytes: &Bytes)
    -> Result<TransactionResult>
where
    EVM: EvmTx<&mut dyn Database, CipherBftPrecompileProvider>,
{
    // Decode transaction
    let tx_env = self.decode_transaction(tx_bytes)?;

    // CRITICAL: Use transact_one()
    // - transact() resets journal on each call
    // - transact_one() preserves journal state (nonce increments, etc.)
    let result = evm.transact_one(tx_env)
        .map_err(|e| ExecutionError::EvmError(format!("EVM execution failed: {:?}", e)))?;

    self.process_execution_result(result, tx_hash, sender, to)
}
```

### 3. StateManager (`src/state.rs`)

Handles state management and state root computation.

**Key Functions:**
- State Root Computation: Calculates Merkle Patricia Trie every 100 blocks
- State Commit: Persists changes to RocksDB
- Account State Management: Manages balance, nonce, code, and storage
- Rollback Support: Snapshot-based state restoration

**Security:**
- Atomic commits ensure state consistency
- State root verification ensures state integrity
- Snapshot-based rollback supports fault recovery

**State Root Interval (Protocol Constant):**
```rust
/// State root computation interval - MUST NOT BE CHANGED
/// All validators must use the same interval for consensus
pub const STATE_ROOT_SNAPSHOT_INTERVAL: u64 = 100;

impl StateManager {
    pub fn should_compute_state_root(&self, block_number: u64) -> bool {
        block_number > 0 && block_number % STATE_ROOT_SNAPSHOT_INTERVAL == 0
    }

    pub fn compute_state_root(&self, block_number: u64) -> Result<B256> {
        tracing::debug!(
            block_number,
            "Computing state root (checkpoint interval: {})",
            STATE_ROOT_SNAPSHOT_INTERVAL
        );

        // Compute Merkle Patricia Trie
        let root = self.db.merkle_root()?;

        tracing::info!(
            block_number,
            state_root = %root,
            "State root computed"
        );

        Ok(root)
    }
}
```

**Important:** `STATE_ROOT_SNAPSHOT_INTERVAL` is part of the consensus protocol. **All validators must use the same value**. Changing this value will cause consensus mismatch.

### 4. Staking Precompile (`src/precompiles/staking.rs`)

Custom precompile for validator management at address 0x100.

**Function Selectors (Alloy 1.x):**
```rust
// registerValidator(bytes) - 0x607049d8
// deregisterValidator() - 0x6a911ccf
// getValidatorSet() - 0xcf331250
// getStake(address) - 0x08c36874
// slash(address,uint256) - 0xd8fe7642
```

**Core Features:**
- **registerValidator**: Register validator (minimum 1 ETH stake)
- **deregisterValidator**: Deregister validator
- **getValidatorSet**: Query active validator list
- **getStake**: Query specific validator's stake amount
- **slash**: Slash validator (only callable by system address)

**Security:**
```rust
pub const MIN_VALIDATOR_STAKE: u128 = 1_000_000_000_000_000_000; // 1 ETH
pub const SYSTEM_ADDRESS: Address = address!("0000000000000000000000000000000000000000");

fn slash(&mut self, validator: Address, amount: U256, caller: Address) -> Result<Bytes> {
    // Only system address can slash
    if caller != SYSTEM_ADDRESS {
        return Err(PrecompileError::Fatal(
            "Only system can slash".to_string()
        ));
    }

    // Deduct from current stake
    let remaining = current_stake.saturating_sub(amount);
    if remaining < MIN_VALIDATOR_STAKE {
        self.validators.remove(&validator);
    }
    // ...
}
```

- Minimum stake requirement (1 ETH) prevents Sybil attacks
- Slashing restricted to system address prevents malicious slashing
- Input validation and error handling blocks invalid data

### 5. CipherBftPrecompileProvider (`src/precompiles/provider.rs`)

Routes precompile calls.

**Operation:**
```rust
impl PrecompileProvider for CipherBftPrecompileProvider {
    fn get_precompile(&self, address: &Address, _context: &PrecompileContext)
        -> Option<Precompile>
    {
        if address == &STAKING_PRECOMPILE_ADDRESS {
            // 0x100: Custom Staking Precompile
            Some(Precompile::Stateful(Arc::new(
                move |input: &Bytes, gas_limit: u64, context: &PrecompileContext| {
                    let mut precompile = staking_precompile.blocking_write();
                    precompile.execute(input, gas_limit, context)
                }
            )))
        } else {
            // 0x01-0x0a: Standard Precompiles
            self.default_precompiles.get_precompile(address, _context)
        }
    }
}
```

## Consensus Layer Integration

### ExecutionBridge (`crates/node/src/execution_bridge.rs`)

Acts as a bridge between Consensus Layer and Execution Layer.

**Key Responsibilities:**
1. **Cut Conversion**: Consensus Cut → Execution Cut
2. **Transaction Validation**: Mempool CheckTx support
3. **Cut Execution**: Calls Execution Layer and returns results

**Usage Example:**
```rust
// Enable ExecutionBridge in node
let node = Node::new(config)?
    .with_execution_layer()?;

// Execute cut
match bridge.execute_cut(cut).await {
    Ok(result) => {
        info!(
            "Cut executed - state_root: {}, gas_used: {}",
            result.state_root,
            result.gas_used
        );
    }
    Err(e) => error!("Cut execution failed: {}", e),
}
```

## Performance Considerations

### State Root Computation

**Why 100-block interval:**
- **Performance**: Merkle Patricia Trie computation cost scales with state size
- **Checkpoints**: Periodic snapshots for rollback and state verification
- **Consensus**: All validators must compute state root at the same blocks

**Future Optimizations:**
- Measure computation cost for large state sizes
- Consider incremental MPT implementation
- Investigate parallel computation possibilities

### Transaction Execution

**Performance Characteristics:**
- `transact_one()` usage minimizes journal overhead
- Context API eliminates unnecessary copying
- Precompile call optimization (Arc<RwLock> usage)

## TODO

1. **Batch Lookup Integration:**
   - Implement actual batch data fetching in ExecutionBridge's `convert_cut()`
   - Integrate with worker storage

2. **Parent Hash Tracking:**
   - Manage parent hash for blockchain connectivity
   - Support verification during reorganization

3. **Performance Optimization:**
   - Optimize state root computation
   - Implement incremental MPT
   - Parallel transaction validation

4. **Enhanced Monitoring:**
   - Collect detailed metrics
   - Performance profiling

## References

- **Revm 33 Documentation**: https://docs.rs/revm/33.0.0
- **Alloy 1.x**: https://docs.rs/alloy/1.0.0
- **ADR-002**: EVM Native Execution
- **ADR-009**: Staking Precompile
- **ADR-012**: State Root Handling
