# ADR 009: Staking Precompile

## Changelog

* 2025-12-07: Initial draft

## Status

PROPOSED Not Implemented

## Abstract

CipherBFT implements validator staking through a precompiled contract at reserved address `0x0000...0100`. This precompile handles validator registration, deregistration, stake queries, and slashing. Validator set updates are applied at epoch boundaries (every 5000 blocks).

## Context

CipherBFT requires a mechanism for:
1. **Validator registration**: New validators join the network with stake
2. **Validator deregistration**: Validators exit gracefully
3. **Stake queries**: Query validator set and individual stakes
4. **Slashing**: Penalize Byzantine validators (system-only)
5. **Epoch transitions**: Apply validator set changes at boundaries

### Design Goals

- **Native integration**: Embedded in revm, no external contract deployment
- **Gas efficiency**: Minimal gas costs for staking operations
- **Epoch-based updates**: Changes applied at predictable intervals
- **Simple API**: Standard EVM function call interface

## Alternatives

### Alternative 1: External Smart Contract

Deploy staking logic as a standard Solidity contract.

**Pros:**
- Upgradeable without node updates
- Standard development workflow

**Cons:**
- Higher gas costs (SSTORE operations)
- Security surface (contract bugs)
- Complex state synchronization with consensus
- Must be deployed at genesis

### Alternative 2: Consensus-Only Staking

Handle staking entirely in consensus layer, no EVM interface.

**Pros:**
- Maximum efficiency
- No EVM overhead

**Cons:**
- Not queryable via standard RPC
- Different interface from other chains
- No composability with smart contracts

### Alternative 3: Precompiled Contract (Chosen)

Implement staking as a precompile with native consensus integration.

**Pros:**
- Native performance (no SSTORE)
- Standard EVM call interface
- Queryable via eth_call
- Direct consensus integration
- Predictable gas costs

**Cons:**
- Requires node update for changes
- Fixed address reservation

## Decision

Implement staking as a precompiled contract at address `0x0000000000000000000000000000000000000100`.

### Precompile Address

```
0x0000000000000000000000000000000000000100
```

Reserved in the precompile address range (0x01-0xFF are standard, 0x100+ for chain-specific).

### Function Signatures

| Function | Selector | Gas Cost |
|----------|----------|----------|
| `registerValidator(bytes32 blsPubkey)` | `0x6e7cf85a` | 50,000 |
| `deregisterValidator()` | `0x88a7ca5c` | 25,000 |
| `getValidatorSet()` | `0xe7b5c8a9` | 2,100 + 100/validator |
| `getStake(address)` | `0x7a766460` | 2,100 |
| `slash(address, uint256)` | `0x02fb4d85` | 30,000 (system-only) |

### Data Structures

```rust
// crates/staking/src/types.rs

/// Validator registration info
pub struct ValidatorInfo {
    /// Ethereum address (derived from Ed25519 pubkey)
    pub address: Address,
    /// BLS12-381 public key for DCL attestations
    pub bls_pubkey: BlsPublicKey,
    /// Staked amount in wei
    pub stake: U256,
    /// Registration block height
    pub registered_at: u64,
    /// Pending deregistration (epoch when it takes effect)
    pub pending_exit: Option<u64>,
}

/// Validator set at an epoch
pub struct ValidatorSet {
    /// Active validators
    pub validators: Vec<ValidatorInfo>,
    /// Total stake
    pub total_stake: U256,
    /// Epoch number
    pub epoch: u64,
}

/// Pending changes to apply at next epoch
pub struct PendingChanges {
    /// New registrations
    pub registrations: Vec<ValidatorInfo>,
    /// Deregistrations (addresses)
    pub exits: Vec<Address>,
    /// Slashing events
    pub slashes: Vec<(Address, U256)>,
}
```

### Precompile Implementation

```rust
// crates/staking/src/precompile.rs
use revm::precompile::{Precompile, PrecompileResult};

pub struct StakingPrecompile {
    state: Arc<RwLock<StakingState>>,
}

impl Precompile for StakingPrecompile {
    fn run(&self, input: &[u8], gas_limit: u64, context: &Context) -> PrecompileResult {
        if input.len() < 4 {
            return Err(PrecompileError::InvalidInput);
        }

        let selector = &input[0..4];
        let data = &input[4..];

        match selector {
            // registerValidator(bytes32 blsPubkey)
            [0x6e, 0x7c, 0xf8, 0x5a] => {
                self.register_validator(data, gas_limit, context)
            }
            // deregisterValidator()
            [0x88, 0xa7, 0xca, 0x5c] => {
                self.deregister_validator(gas_limit, context)
            }
            // getValidatorSet()
            [0xe7, 0xb5, 0xc8, 0xa9] => {
                self.get_validator_set(gas_limit)
            }
            // getStake(address)
            [0x7a, 0x76, 0x64, 0x60] => {
                self.get_stake(data, gas_limit)
            }
            // slash(address, uint256)
            [0x02, 0xfb, 0x4d, 0x85] => {
                self.slash(data, gas_limit, context)
            }
            _ => Err(PrecompileError::InvalidSelector),
        }
    }
}
```

### Function Implementations

```rust
impl StakingPrecompile {
    /// Register as a validator
    /// Requires: msg.value >= MIN_STAKE, caller not already registered
    fn register_validator(
        &self,
        data: &[u8],
        gas_limit: u64,
        context: &Context,
    ) -> PrecompileResult {
        const GAS_COST: u64 = 50_000;
        if gas_limit < GAS_COST {
            return Err(PrecompileError::OutOfGas);
        }

        // Decode BLS public key (48 bytes, padded to 64)
        if data.len() < 64 {
            return Err(PrecompileError::InvalidInput);
        }
        let bls_pubkey = BlsPublicKey::from_bytes(&data[16..64])?;

        // Check minimum stake
        if context.value < MIN_STAKE {
            return Err(PrecompileError::InsufficientStake);
        }

        // Check not already registered
        let mut state = self.state.write();
        if state.is_validator(&context.caller) {
            return Err(PrecompileError::AlreadyRegistered);
        }

        // Add to pending registrations (applied at epoch boundary)
        state.pending.registrations.push(ValidatorInfo {
            address: context.caller,
            bls_pubkey,
            stake: context.value,
            registered_at: context.block_number,
            pending_exit: None,
        });

        Ok(PrecompileOutput {
            gas_used: GAS_COST,
            output: vec![],
        })
    }

    /// Deregister as a validator
    /// Requires: caller is registered validator
    fn deregister_validator(
        &self,
        gas_limit: u64,
        context: &Context,
    ) -> PrecompileResult {
        const GAS_COST: u64 = 25_000;
        if gas_limit < GAS_COST {
            return Err(PrecompileError::OutOfGas);
        }

        let mut state = self.state.write();
        if !state.is_validator(&context.caller) {
            return Err(PrecompileError::NotValidator);
        }

        // Mark for exit at next epoch
        state.pending.exits.push(context.caller);

        Ok(PrecompileOutput {
            gas_used: GAS_COST,
            output: vec![],
        })
    }

    /// Get current validator set
    fn get_validator_set(&self, gas_limit: u64) -> PrecompileResult {
        let state = self.state.read();
        let validator_count = state.validators.len();

        let gas_cost = 2_100 + (100 * validator_count as u64);
        if gas_limit < gas_cost {
            return Err(PrecompileError::OutOfGas);
        }

        // Encode as ABI: address[], uint256[]
        let output = encode_validator_set(&state.validators);

        Ok(PrecompileOutput {
            gas_used: gas_cost,
            output,
        })
    }

    /// Get stake for an address
    fn get_stake(&self, data: &[u8], gas_limit: u64) -> PrecompileResult {
        const GAS_COST: u64 = 2_100;
        if gas_limit < GAS_COST {
            return Err(PrecompileError::OutOfGas);
        }

        if data.len() < 32 {
            return Err(PrecompileError::InvalidInput);
        }
        let address = Address::from_slice(&data[12..32]);

        let state = self.state.read();
        let stake = state.get_stake(&address).unwrap_or(U256::ZERO);

        Ok(PrecompileOutput {
            gas_used: GAS_COST,
            output: stake.to_be_bytes_vec(),
        })
    }

    /// Slash a validator (system-only)
    fn slash(
        &self,
        data: &[u8],
        gas_limit: u64,
        context: &Context,
    ) -> PrecompileResult {
        const GAS_COST: u64 = 30_000;
        if gas_limit < GAS_COST {
            return Err(PrecompileError::OutOfGas);
        }

        // Only callable by system (block.coinbase or special address)
        if context.caller != SYSTEM_ADDRESS {
            return Err(PrecompileError::Unauthorized);
        }

        if data.len() < 64 {
            return Err(PrecompileError::InvalidInput);
        }
        let validator = Address::from_slice(&data[12..32]);
        let amount = U256::from_be_slice(&data[32..64]);

        let mut state = self.state.write();
        state.pending.slashes.push((validator, amount));

        Ok(PrecompileOutput {
            gas_used: GAS_COST,
            output: vec![],
        })
    }
}
```

### Epoch Transitions

```rust
// crates/staking/src/epoch.rs

pub const EPOCH_LENGTH: u64 = 5000;

pub fn is_epoch_boundary(block_number: u64) -> bool {
    block_number % EPOCH_LENGTH == 0
}

pub fn apply_epoch_transition(state: &mut StakingState) {
    // Apply pending registrations
    for validator in state.pending.registrations.drain(..) {
        state.validators.push(validator);
    }

    // Apply pending exits
    for address in state.pending.exits.drain(..) {
        state.validators.retain(|v| v.address != address);
        // Note: Stake refund handled separately
    }

    // Apply slashes
    for (address, amount) in state.pending.slashes.drain(..) {
        if let Some(v) = state.validators.iter_mut().find(|v| v.address == address) {
            v.stake = v.stake.saturating_sub(amount);
            // Remove if stake below minimum
            if v.stake < MIN_STAKE {
                state.pending.exits.push(address);
            }
        }
    }

    state.epoch += 1;
    state.recalculate_total_stake();
}
```

### Integration with revm

```rust
// crates/execution/src/evm_config.rs
use reth_evm::ConfigureEvm;

pub struct CipherBftEvmConfig {
    staking: Arc<StakingPrecompile>,
}

impl ConfigureEvm for CipherBftEvmConfig {
    fn precompiles(&self) -> impl IntoIterator<Item = (Address, Precompile)> {
        let staking_addr = address!("0000000000000000000000000000000000000100");

        // Standard precompiles + staking
        standard_precompiles()
            .chain(std::iter::once((staking_addr, self.staking.clone())))
    }
}
```

### Consensus Integration

```rust
// crates/consensus/src/validator_set.rs

impl ConsensusEngine {
    /// Called at each block finalization
    pub fn on_block_finalized(&mut self, block: &Block) {
        if is_epoch_boundary(block.number) {
            // Apply pending validator set changes
            apply_epoch_transition(&mut self.staking_state);

            // Update Malachite validator set
            let new_validators = self.staking_state.to_malachite_validators();
            self.malachite.update_validator_set(new_validators);
        }
    }
}
```

## Consequences

### Backwards Compatibility

N/A - greenfield implementation.

### Positive

1. **Native performance**: No SSTORE overhead for staking operations
2. **Standard interface**: Callable via eth_call from any client
3. **Predictable gas**: Fixed costs for all operations
4. **Epoch safety**: Changes applied at boundaries, not mid-consensus
5. **Composability**: Other contracts can query validator set

### Negative

1. **Upgrade difficulty**: Changes require node software update
2. **Fixed address**: Cannot relocate precompile
3. **Limited flexibility**: Cannot add new staking features via contract

### Neutral

1. **Epoch latency**: Registration takes effect at next epoch (up to 5000 blocks)
2. **Simple slashing**: Only stake reduction, no jailing mechanism
3. **No delegation**: Direct staking only, no liquid staking

## Test Cases

1. **registerValidator**: Successfully registers with sufficient stake
2. **registerValidator**: Fails with insufficient stake
3. **registerValidator**: Fails if already registered
4. **deregisterValidator**: Successfully marks for exit
5. **deregisterValidator**: Fails if not a validator
6. **getValidatorSet**: Returns correct set after epoch transition
7. **getStake**: Returns correct stake for validator
8. **getStake**: Returns zero for non-validator
9. **slash**: Successfully reduces stake (system caller)
10. **slash**: Fails for non-system caller
11. **Epoch transition**: New validators active after boundary
12. **Epoch transition**: Exited validators removed after boundary
13. **Gas metering**: All functions consume expected gas

## References

* [EIP-2930: Access List Precompiles](https://eips.ethereum.org/EIPS/eip-2930)
* [revm Precompile Documentation](https://github.com/bluealloy/revm)
* [Reth EvmConfig trait](https://github.com/paradigmxyz/reth/blob/main/crates/evm/src/lib.rs)
* [Ethereum Precompiled Contracts](https://www.evm.codes/precompiled)
