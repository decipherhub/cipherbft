# CipherBFT Consensus

Consensus layer scaffold for integrating Malachite BFT.

- Default build keeps Malachite crates disabled; enable with `--features malachite`.
- Malachite crates currently require Rust 1.85+ per their `rust-version`.

## Modules

- **`config`**: Consensus configuration (chain ID, timeouts).
- **`types`**: Core consensus types with Malachite trait implementations.
- **`context`**: `malachitebft_core_types::Context` implementation (round-robin proposer selection).
- **`proposal`**: Cut-as-proposal wrapper implementing Malachite `Proposal` and `ProposalPart` traits.
- **`validator_set`**: Validator set management with voting power and deterministic ordering.
- **`signing`**: Ed25519 signing scheme implementation for Malachite.
- **`vote`**: Vote types implementing Malachite `Vote` trait with optional extensions.
- **`engine`**: Wiring helper that spawns Malachite consensus/host/network/WAL actors when provided with the external handles.

## Malachite Trait Implementations

This crate implements the following Malachite core types traits (all gated behind the `malachite` feature):

### Core Type Traits (`types.rs` - `malachite_impls` module)

The `malachite_impls` module in `types.rs` contains:

- **`Height` for `ConsensusHeight`**: Implements height arithmetic (increment/decrement), zero and initial height constants (`ZERO = 0`, `INITIAL = 1`), and conversion to/from `u64`.
- **`Value` for `ConsensusValue`**: Wraps DCL `Cut` as a consensus value, with `ConsensusValueId` (Cut hash) as the associated `Id` type. The `id()` method returns the hash of the underlying `Cut`.
- **`From<Cut> for ConsensusValue`**: Enables direct conversion from DCL cuts to consensus values.
- **`From<ConsensusValueId> for Hash`**: Conversion from value IDs back to hash types for compatibility with other parts of the codebase.
- **`ConsensusRound` type alias**: Re-exports Malachite's `Round` type when the feature is enabled (falls back to `i64` when disabled).

### Context and Protocol Traits (`context.rs`, `proposal.rs`, `vote.rs`)

- **`Context` for `CipherBftContext`** (`context.rs`): Main context implementation providing proposer selection (round-robin based on validator set ordering), proposal/vote creation helpers, and validator set access. Defines all associated types for the consensus protocol.

- **`Proposal` for `CutProposal`** (`proposal.rs`): Proposal type carrying height, round, value (ConsensusValue), POL round, and proposer address. Implements methods for accessing proposal metadata and extracting the consensus value.

- **`ProposalPart` for `CutProposalPart`** (`proposal.rs`): Single-part proposal chunks with `is_first()` and `is_last()` flags. Currently supports single-chunk proposals via `CutProposalPart::single()`, but structured to support multi-part streaming in the future.

- **`Vote` for `ConsensusVote`** (`vote.rs`): Prevote and precommit vote types with height, round, value ID (`NilOrVal<ConsensusValueId>`), vote type, validator address, and optional signed extensions. Supports vote extension through the `extend()` method.

### Validator Traits (`validator_set.rs`)

- **`Address` for `ConsensusAddress`**: Validator address type implemented as a marker trait, wrapping Ed25519-derived validator ID (`ValidatorId`).

- **`Validator` for `ConsensusValidator`**: Individual validator entry providing access to address, public key (as Malachite `PublicKey`), and voting power. Each validator is uniquely identified by its `ConsensusAddress`.

- **`ValidatorSet` for `ConsensusValidatorSet`**: Deterministically ordered validator set that implements voting power bookkeeping. Validators are sorted by power (descending), then by address (ascending) to ensure deterministic ordering required by Malachite. Provides methods for lookup by address or index, total voting power calculation, and validator count.

### Signing Traits (`signing.rs`)

- **`SigningScheme` for `Ed25519SigningScheme`**: Ed25519 signature scheme with 64-byte signature encoding/decoding, integrated with `cipherbft-crypto` Ed25519 types.

## Engine Wiring (`engine.rs`)

The `engine` module provides a builder pattern for wiring CipherBFT context and types into Malachite's actor-based consensus engine:

- **`MalachiteEngineBuilder`**: Builder that assembles all required components (context, consensus parameters, signing provider, network/host/WAL/sync actors, metrics, and event channels) and spawns the Malachite consensus and node supervisors. Expects callers to provide pre-instantiated network, host, and WAL actors that already satisfy Malachite's message contracts.

- **`EngineHandles`**: Bundles all actor references returned after spawning: node, consensus, network, WAL, host, optional sync actor, event channel, and metrics registry. These handles allow external code to interact with the running consensus engine.

The builder pattern allows optional configuration via:
  - `with_sync()`: Attach the sync actor for state synchronization
  - `with_metrics()`: Override the default metrics registry
  - `with_events()`: Override the default event channel

The `spawn()` method creates and starts the consensus and node actors, returning handles that can be used to send messages and monitor the consensus process.

## How it fits together (workflow)

1) Configuration and types  
   - `ConsensusConfig` carries chain id and timeouts.  
   - `ConsensusHeight` implements Malachite `Height`; `ConsensusValue` wraps a DCL `Cut`; `ConsensusValueId` is the Cut hash.  
   - `ConsensusRound` reuses Malachite `Round` when the feature is on.

2) Validator set and proposer selection  
   - `ConsensusValidatorSet` sorts validators by (power desc, address asc) to meet Malachite ordering requirements.  
   - `CipherBftContext::select_proposer` uses round-robin over that ordered list (nil round maps to index 0).

3) Proposal path  
   - `ConsensusValue::id()` returns the Cut hash; Malachite binds votes to this `ValueId`.  
   - `context.new_proposal` builds a `CutProposal` with height/round/POL round and proposer address.  
   - Proposal parts are currently single-chunk (`CutProposalPart::single`); streaming hooks are in place if we need to split large payloads later.

4) Vote path  
   - `context.new_prevote` / `new_precommit` emit `ConsensusVote` with `NilOrVal<ValueId>` per Malachite’s API.  
   - Vote extensions are typed as `Vec<u8>` for now; they are carried through the trait methods but not populated yet.

5) Signing scheme  
   - `Ed25519SigningScheme` wraps existing `cipherbft-crypto` Ed25519 types to satisfy Malachite `SigningScheme`.  
   - `ConsensusSignature` stores the raw 64-byte Ed25519 signature; encode/decode helpers plug directly into Malachite’s signature handling.

6) Feature gating  
   - All Malachite-dependent code sits behind the `malachite` feature; default builds stay unaffected.  
   - Run `cargo check -p cipherbft-consensus --features malachite` after enabling Rust 1.85+.
