# Malachite Integration Notes (with malaketh-layered reference)

This note captures how Malachite’s actor/channel API is meant to be driven, and how the `malaketh-layered` project wires it to an execution client. Use this as a blueprint for CipherBFT’s Malachite integration.

## Malachite channel/actor surface (v0.5.x)

- The Malachite engine exposes a channels-based app API (via `AppMsg`/`ConsensusMsg`/`NetworkMsg` in `malachitebft-app-channel`).
- Core messages the host must handle:
  - `ConsensusReady { reply }`: Malachite is initialized; reply with `StartHeight(height, validator_set)`.
  - `StartedRound { height, round, proposer }`: informational hook for internal bookkeeping/metrics.
  - `GetValue { height, round, timeout, reply }`: build and return a proposal value; also stream proposal parts to peers.
  - `ReceivedProposalPart { from, part, reply }`: ingest streamed proposal parts; reply with `ProposedValue` once complete (or `None` if incomplete/invalid).
  - `Decided { certificate, extensions, reply }`: commit the decided value (execute/persist), then reply `Next::Start(next_height, validator_set)` or `Next::Restart(height, validator_set)`.
  - `GetValidatorSet { height, reply }`: provide validator set for verification at arbitrary heights.
  - Sync helpers: `ProcessSyncedValue`, `GetDecidedValue`, `GetHistoryMinHeight`, `RestreamProposal` (for catch-up and restreaming).
  - Vote extensions: `ExtendVote` / `VerifyVoteExtension` (can be `None`/`Ok(())` if unused).
  - Network topology: `PeerJoined` / `PeerLeft` (optional tracking).
- Malachite engine wiring requires:
  - `Context` implementation (done in `cipherbft-consensus`).
  - `SigningProvider` (Ed25519) to sign consensus messages.
  - Network actor implementing publish/subscribe for proposals, proposal parts, and votes.
  - WAL actor for persistence/replay.
  - Optional sync actor for catch-up.

## What malaketh-layered does (Reth + Engine API)

Source: `app/src/app.rs` and `app/src/state.rs` in the `malaketh-layered` repo.

### Event handling loop
- `ConsensusReady`:
  - Checks execution client capabilities (`engine.check_capabilities()`).
  - Fetches latest block from EL (`eth_getBlockByNumber`) and stores it.
  - Replies `StartHeight(current_height, validator_set)`.
- `StartedRound`:
  - Updates local tracking of height/round/proposer.
- `GetValue` (proposer path):
  - Calls `forkchoiceUpdated` with `PayloadAttributes` to ask EL to build a block, then `getPayload` to retrieve it.
  - Stores block bytes; builds `LocallyProposedValue` and replies.
  - Streams proposal parts over network (`PublishProposalPart`).
- `ReceivedProposalPart` (non-proposer path):
  - Stores incoming parts; reassembles when complete, verifies signature, persists undecided proposal + data; replies with `ProposedValue` when ready.
- `GetValidatorSet`:
  - Returns genesis validator set (static in the PoC).
- `Decided`:
  - Fetches stored block bytes for the decided height/round.
  - Decodes execution payload; notifies EL (`newPayload`/`forkchoiceUpdated` equivalent via `notify_new_block` + `set_latest_forkchoice_state`).
  - Updates latest block metadata, commits certificate/value to store.
  - Replies `StartHeight(next_height, validator_set)`.
- Sync helpers:
  - `ProcessSyncedValue`: decode bytes and reply with `ProposedValue`.
  - `GetDecidedValue`: return stored decided value bytes + certificate.
  - `GetHistoryMinHeight`: return earliest stored height.
- Extensions/restream:
  - `RestreamProposal` unimplemented; `ExtendVote`/`VerifyVoteExtension` are no-ops (`None`/`Ok(())`).

### State management highlights (`state.rs`)
- Stores undecided/decided proposals and block data; prunes history.
- Proposal streaming:
  - Splits payload into chunks (`CHUNK_SIZE = 128 KiB`), wraps in `ProposalPart::Data`, framed by `Init` and `Fin` (Fin carries a signature over height, round, and data hash).
  - `StreamMessage` carries `sequence` and `StreamId`; final message is `StreamContent::Fin`.
- Proposal assembly/verification:
  - Reassembles by concatenating `Data` parts; recomputes hash; verifies `Fin` signature against proposer public key from validator set.
- Commit flow:
  - On `Decided`, moves proposal and block data from “undecided” to “decided”, updates height/round, prunes older heights (keeps last N).
- Validator set:
  - Static set loaded from genesis; `get_validator_set` used for verification and gossip.

### Deeper malaketh-layered specifics (for replication)
- Context/proposer selection: `select_proposer = (height-1 + round) % validator_count`, round must be non-nil; validator set order matters.
- Proposal part structure:
  - `Init(height, round, proposer)` -> multiple `Data(Bytes)` chunks (128 KiB each) -> `Fin(signature)`.
  - Hash for `Fin` signature: Keccak(height || round || all data chunks). `Fin` is signed by Ed25519 proposer key.
  - `StreamId = height || round || stream_nonce`; `sequence` increments per part; final message is `StreamContent::Fin`.
- Signing provider (`types/src/signing.rs`):
  - Implements Malachite `SigningProvider` for votes/proposals/proposal parts; verifies commit signatures by reconstructing the precommit vote (height/round/value_id, address).
  - Exposes helpers to sign arbitrary hashes for the `Fin` chunk.
- Engine RPC wrapper (`engine/src/engine.rs`):
  - `check_capabilities` ensures `forkchoice_updated_v3/get_payload_v3/new_payload_v3`.
  - `generate_block`: `forkchoice_updated(head, PayloadAttributes)` → `get_payload(payload_id)` to fetch block.
  - `notify_new_block`: calls `new_payload` with block + versioned hashes.
  - `set_latest_forkchoice_state`: `forkchoice_updated` with decided head to advance/finalize.
- State/store behavior (`app/src/state.rs`):
  - Persists undecided proposals and block bytes; verifies incoming proposals via `Fin` signature; prunes decided history beyond last 5 heights.
  - On `Decided`: fetch undecided proposal + stored block data, persist as decided, prune, increment height/round.
  - Sync helpers: `ProcessSyncedValue` decodes via `ProtobufCodec`; `GetDecidedValue` returns cert + protobuf-encoded value bytes; `GetHistoryMinHeight` from store floor.
- Genesis/validator set:
  - Loaded once, static across heights in the PoC; validator pubkeys used for proposal verification and commit sig checking.

## What is already implemented in this repo (CipherBFT)

Paths below are workspace-relative.

- Crate scaffold and feature gating
  - `crates/consensus/Cargo.toml`: Malachite deps behind `malachite` feature; all pinned to `0.5.x` (core-types/consensus/engine/codec/metrics/etc.).
  - Default build unaffected; enable with `--features malachite`.

- Core types and context
  - `crates/consensus/src/types.rs`:
    - `ConsensusHeight` implements Malachite `Height` (ZERO=0, INITIAL=1, increment/decrement/as_u64).
    - `ConsensusValue` wraps DCL `Cut`; `ConsensusValue::id()` uses `Cut::hash()`; `ConsensusValueId` wraps `Hash`.
    - `ConsensusRound` aliases Malachite `Round` when feature is on (falls back to `i64` otherwise).
  - `crates/consensus/src/context.rs`:
    - `CipherBftContext` implements Malachite `Context` with round-robin proposer (`round % validators.len()`; nil → index 0).
    - Provides constructors for proposals and votes; vote extensions are `Vec<u8>` (no-op).
    - Aliases exported for address/validator/set/proposal/part/vote/signing scheme to keep trait signatures concise.
  - `crates/types/src/hash.rs`: `Hash` derives `Ord`/`PartialOrd` for Malachite’s trait bounds.

- Proposal / vote / validator set
  - `crates/consensus/src/proposal.rs`:
    - `CutProposal` (height/round/value/POL round/proposer) implements Malachite `Proposal`.
    - `CutProposalPart` implements `ProposalPart` with `is_first`/`is_last`; equality via Cut hash; currently single-part helper `CutProposalPart::single`.
  - `crates/consensus/src/vote.rs`: `ConsensusVote` (height/round/`NilOrVal<ConsensusValueId>`/vote type/address/optional extension) implements Malachite `Vote`; derives `Ord` to satisfy trait bounds.
  - `crates/consensus/src/validator_set.rs`: `ConsensusAddress` (ValidatorId), `ConsensusValidator` (address/pubkey/power), `ConsensusValidatorSet` (sorted by power desc, address asc) implementing Malachite `Validator`/`ValidatorSet`.

- Signing scheme
  - `crates/consensus/src/signing.rs`: Ed25519 signing scheme wrapper implementing Malachite `SigningScheme` (encode/decode 64-byte sigs, PK/SK wrappers); `ConsensusSigner` convenience around `cipherbft-crypto` Ed25519 keypair. `ConsensusSigningProvider` implements Malachite `SigningProvider` with deterministic byte encoding for votes/proposals/parts/extensions and verify helpers.

- Engine wiring
  - `crates/consensus/src/engine.rs`:
    - `MalachiteEngineBuilder` glue that spawns Malachite engine actors (`Consensus`, supervising `Node`) when given network/host/WAL/sync actor refs, consensus params/config, metrics/events, and a `SigningProvider`.
    - Returns `EngineHandles` (actor refs + metrics/events). This assumes external actors exist; none are implemented here yet.
    - Helpers: `create_context`, `default_consensus_params` (ProposalOnly payload, default thresholds), `default_engine_config_single_part` (ProposalOnly engine value payload).

- Docs
  - `crates/consensus/README.md`: module overview and workflow summary.
  - This note: high-level plan + malaketh-layered patterns.

What is **not** done yet
- Host actor that maps `AppMsg` events to DCL/EL/storage (the malaketh-layered-equivalent loop).
- SigningProvider adapter (tying `cipherbft-crypto` keys into Malachite’s SigningProvider trait).
- Network/WAL actor instantiation and codecs for proposals/votes (currently only the builder expects them).
- Sync/restream logic and any chunked proposal streaming (currently single-part Cut).
- Node binary integration to swap Primary runner for Malachite engine.

## How to apply this to CipherBFT

1) **Host actor (CipherBFT) mirroring `app.rs`:**
   - Map `ConsensusReady` → load latest executed state/Cut height from storage; reply `StartHeight(height, validator_set)`.
   - `GetValue` → ask DCL Primary for highest attested `Cut` (or block until ready); persist Cut bytes and stream parts; reply `LocallyProposedValue`.
   - `ReceivedProposalPart` → store incoming Cut parts (single-part today), validate hash/signature if present; reply `ProposedValue` when complete.
   - `Decided` → execute Cut in EL, persist commit cert + state root, update height, reply `StartHeight(next_height, validator_set)` or `RestartHeight`.
   - Implement `GetValidatorSet`, `ProcessSyncedValue`, `GetDecidedValue`, `GetHistoryMinHeight` analogs using CipherBFT storage.
   - Keep `ExtendVote`/`VerifyVoteExtension` as no-ops until you define extensions.
2) **Streaming strategy:**
   - Short term: single-part proposals (already supported by `CutProposalPart`).
   - Long term: follow malaketh-layered pattern—`Init`/`Data` chunks/`Fin` with signature over height/round/data hash; chunk Cuts if they become large.
3) **Signing provider:**
   - Implement Malachite `SigningProvider` using `cipherbft-crypto` Ed25519 keys (similar to `malaketh-layered`’s `Ed25519Provider`).
4) **Network/WAL:**
   - Use Malachite’s built-in network actor initially; adapt to CipherBFT P2P later if needed.
   - Point WAL to per-height log directory; ensure `StartHeight`/`Reset` calls align with height transitions.
5) **Execution bridge:**
   - Replace Engine API calls with EL interface: execute Cut → compute state root → persist, then signal `forkchoice` equivalent inside EL/storage.
6) **Sync/re-stream:**
   - Implement `ProcessSyncedValue`/`GetDecidedValue`/`RestreamProposal` using stored Cuts and block data for catch-up.
7) **Version alignment:**
   - Keep all Malachite crates on `0.5.x` to match the engine, avoiding mixed `0.6.0-pre` dependencies.

## Suggested reading (already inspected)

- `malaketh-layered/README.md`: high-level mapping of Malachite events to Engine API calls.
- `app/src/app.rs`: full host loop handling all Malachite `AppMsg` variants and driving Reth via Engine API.
- `app/src/state.rs`: proposal chunking/assembly, signature verification, storage of undecided/decided values, pruning strategy.

Use this doc as the implementation checklist before wiring CipherBFT’s host/network/storage to Malachite. Once host and signing provider are in place, plug them into `MalachiteEngineBuilder` and start exercising consensus with single-part Cuts, then iterate toward chunked proposals and full sync support.
