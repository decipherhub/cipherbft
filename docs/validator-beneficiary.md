# Validator Beneficiary

This document explains how block rewards are attributed to validators in CipherBFT.

## Overview

When a block is produced, the block header's `beneficiary` field determines which address receives block rewards (transaction fees, MEV, etc.). In CipherBFT, this is set to the **proposer's Ethereum address** - the validator who built and proposed the Cut that became the block.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Validator Identity                            │
├─────────────────────────────────────────────────────────────────┤
│  Ed25519 KeyPair ──► ValidatorId (consensus identity)           │
│  secp256k1 addr  ──► ethereum_address (reward recipient)        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    ConsensusValidator                            │
├─────────────────────────────────────────────────────────────────┤
│  address: ConsensusAddress    (Ed25519-derived)                 │
│  public_key: ConsensusPublicKey                                 │
│  voting_power: u64                                              │
│  ethereum_address: Address    ◄── Block reward recipient        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                         Cut                                      │
├─────────────────────────────────────────────────────────────────┤
│  height: u64                                                    │
│  cars: HashMap<ValidatorId, Car>                                │
│  attestations: HashMap<Hash, AggregatedAttestation>             │
│  proposer_id: Option<ValidatorId>      ◄── Who built this Cut   │
│  proposer_address: Option<Address>     ◄── Their ETH address    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Block Header                                │
├─────────────────────────────────────────────────────────────────┤
│  beneficiary: Address   ◄── Set from Cut.proposer_address       │
│  ...                                                            │
└─────────────────────────────────────────────────────────────────┘
```

## Data Flow

### 1. Genesis Configuration

Validators are configured in genesis with their Ethereum addresses:

```json
{
  "validators": [
    {
      "public_key": "ed25519:...",
      "voting_power": 100,
      "ethereum_address": "0x1234..."
    }
  ]
}
```

### 2. Node Startup

When a node starts, it loads validator information from genesis:

```rust
// node.rs
let validators = genesis.validators.iter().map(|v| {
    ConsensusValidator::new_with_ethereum_address(
        validator_id,
        public_key,
        voting_power,
        v.ethereum_address,  // Loaded from genesis
    )
}).collect();
```

### 3. Cut Building

When a validator is selected as proposer, they build a Cut and set themselves as the beneficiary:

```rust
// host.rs - ChannelValueBuilder::build_value()
let mut cut = self.cut_builder.build_cut(height);

// Set proposer info for beneficiary attribution
if let (Some(validator_id), Some(ethereum_address)) =
    (&self.validator_id, &self.ethereum_address)
{
    cut.set_proposer(*validator_id, *ethereum_address);
}
```

### 4. Consensus

The Cut is proposed through Malachite consensus. The Cut's hash includes `proposer_id` and `proposer_address`, making the beneficiary tamper-proof once consensus decides.

### 5. Block Sealing

After consensus finalizes a Cut, the execution layer seals it into a block:

```rust
// engine.rs - seal_block()
let header = BlockHeader {
    beneficiary: consensus_block.beneficiary,  // From Cut.proposer_address
    // ...
};
```

## Hash Integrity

The `Cut.hash()` includes proposer fields to ensure beneficiary attribution cannot be tampered with after consensus:

```rust
pub fn hash(&self) -> Hash {
    let mut data = Vec::new();

    // ... height, cars ...

    // Include proposer info in hash
    if let Some(proposer_id) = &self.proposer_id {
        data.extend_from_slice(proposer_id.as_bytes());
    }
    if let Some(proposer_address) = &self.proposer_address {
        data.extend_from_slice(proposer_address.as_slice());
    }

    Hash::compute(&data)
}
```

## CutPart Streaming

When Cuts are streamed over the network via `CutPart`, both the consensus proposer and beneficiary proposer are transmitted:

```rust
pub enum CutPart {
    Init {
        height: u64,
        round: u32,
        proposer: ValidatorId,           // Malachite consensus proposer
        car_count: u32,
        proposer_id: Option<ValidatorId>,    // Beneficiary proposer
        proposer_address: Option<Address>,   // Beneficiary ETH address
    },
    // ...
}
```

### Why Two Proposer Fields?

In normal operation, these are the same validator. The distinction exists for protocol edge cases:

| Field | Purpose | Set When |
|-------|---------|----------|
| `proposer` | Malachite consensus identity | Streaming the proposal |
| `proposer_id` | Beneficiary attribution | Building the Cut |

**Scenario**: If validator A builds a Cut but consensus doesn't finalize in round 0, validator B (round 1 proposer) might re-propose the same Cut value. In this case:
- `proposer` = B (who streamed the proposal)
- `proposer_id` = A (who built the Cut and deserves the reward)

The hash includes `proposer_id`, ensuring A gets the reward regardless of who re-proposed it.

## Backward Compatibility

### Serde (JSON)

New fields use `#[serde(default, skip_serializing_if = "Option::is_none")]`:
- Old nodes can deserialize new data (missing fields default to `None`)
- New nodes can deserialize old data (missing fields are `None`)

### Borsh (Binary)

The `ConsensusValidator` Borsh deserializer handles missing `ethereum_address`:

```rust
impl BorshDeserialize for ConsensusValidator {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        // ... read other fields ...

        // Backward compatibility: fall back to ZERO if EOF
        let ethereum_address = match reader.read_exact(&mut eth_bytes) {
            Ok(()) => Address::from(eth_bytes),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Address::ZERO,
            Err(e) => return Err(e),
        };

        // ...
    }
}
```

## Fallback Behavior

If a Cut has no `proposer_address` (e.g., from an old node), the beneficiary falls back to `Address::ZERO` with a warning:

```rust
let beneficiary = match consensus_cut.proposer_address {
    Some(addr) => addr,
    None => {
        warn!(
            height = consensus_cut.height,
            "Cut has no proposer_address, using Address::ZERO as beneficiary. \
             Block rewards will be unclaimable."
        );
        Address::ZERO
    }
};
```

