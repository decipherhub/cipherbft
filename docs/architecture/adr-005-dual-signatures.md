# ADR 005: Dual Signature Scheme (Ed25519 + BLS12-381)

## Changelog

* 2026-02-01: Added implementation status
* 2025-12-07: Initial draft

## Status

ACCEPTED Implemented

## Implementation Status

| Component | Status | Location |
|-----------|--------|----------|
| Ed25519 (CL) | Implemented | Via Malachite `malachitebft-signing-ed25519` |
| BLS12-381 (DCL) | Implemented | `crates/crypto/src/bls.rs` |
| Key Management | Implemented | `crates/crypto/src/keys.rs` |
| Attestation Aggregation | Implemented | `crates/data-chain/src/attestation.rs` |
| Domain Separation Tags | Implemented | `DST_CAR`, `DST_ATTESTATION` in `crates/crypto/` |

### Implementation Notes

- **BLS Library**: Uses `blst` crate for BLS12-381 operations
- **Key Files**: Separate files for Ed25519 (`consensus.key`) and BLS (`dcl.key`)
- **Aggregation**: f+1 attestations aggregated into single BLS signature
- **Verification**: Batch verification for aggregated attestations

## Abstract

CipherBFT uses a dual signature scheme: **Ed25519 for Consensus Layer** (Malachite compatibility) and **BLS12-381 for Data Chain Layer** (attestation aggregation). This decision balances Malachite's native Ed25519 support with BLS's aggregation benefits for data availability attestations.

## Context

Cryptographic signatures in CipherBFT serve different purposes across layers:

**Consensus Layer (CL)** - via Malachite:
1. **Vote authentication**: Validators sign Prevote/Precommit messages
2. **Proposal authentication**: Leaders sign proposals

**Data Chain Layer (DCL)** - custom implementation:
3. **Car signing**: Validators sign their Car (transaction batch)
4. **Attestation signing**: Validators attest to receiving other validators' Cars

The key insight is that these two layers have different requirements:

| Layer | Signature Count | Aggregation Benefit | Malachite Constraint |
|-------|-----------------|---------------------|---------------------|
| CL (votes) | 2f+1 per round | Moderate | Must use Ed25519 |
| DCL (attestations) | f+1 per Car × n Cars | High | No constraint |

**Malachite constraint**: Malachite provides `malachitebft-signing-ed25519` as the native signing scheme. Using BLS would require implementing a custom signing provider.

**DCL aggregation benefit**: With n=21 validators, each creating Cars that need f+1=8 attestations:
- Without aggregation: 21 × 8 × 96 bytes = 16,128 bytes per Cut
- With aggregation: 21 × 96 bytes = 2,016 bytes per Cut (8x reduction)

## Alternatives

### Alternative 1: Ed25519 Only

Use Ed25519 for all signatures via Malachite.

**Pros:**
- Single cryptographic scheme
- Malachite native support for both layers
- Simpler key management (one key pair)
- Faster individual verification (~8,000/sec)

**Cons:**
- No signature aggregation for attestations
- Larger Cut overhead (16KB vs 2KB per Cut with n=21)
- Higher bandwidth for data availability layer

### Alternative 2: BLS12-381 Only

Use BLS for all signatures.

**Pros:**
- Signature aggregation everywhere
- Ethereum 2.0 standard
- Smallest possible message sizes

**Cons:**
- Malachite doesn't provide native BLS support
- Must implement custom Malachite signing scheme
- Slower individual verification (~2,000/sec)
- Higher implementation complexity

### Alternative 3: Dual Scheme (Chosen)

Ed25519 for Consensus Layer, BLS12-381 for Data Chain Layer.

**Pros:**
- Malachite compatibility (Ed25519 for CL)
- Attestation aggregation (BLS for DCL)
- Best fit for each layer's requirements
- Proven approach (similar to Ethereum's validator keys)

**Cons:**
- Two cryptographic schemes to maintain
- Two key pairs per validator
- Mixed security assumptions

### Alternative 4: Configurable Scheme

Support both via trait abstraction, configurable at runtime.

**Pros:**
- Maximum flexibility

**Cons:**
- Unnecessary complexity
- Testing burden doubles
- No clear benefit over fixed dual scheme

## Decision

We will use a **dual signature scheme**:

- **Consensus Layer**: Ed25519 via Malachite (`malachitebft-signing-ed25519`)
- **Data Chain Layer**: BLS12-381 via `blst` crate

### Signature Usage by Layer

| Layer | Component | Purpose | Scheme |
|-------|-----------|---------|--------|
| CL | Votes | Prevote, Precommit | Ed25519 |
| CL | Proposals | Leader proposal signing | Ed25519 |
| DCL | Cars | Transaction batch signing | BLS12-381 |
| DCL | Attestations | Data availability attestation | BLS12-381 (aggregatable) |

### Key Management

Each validator maintains **two key pairs**:

```rust
// crates/crypto/src/keys.rs

/// Ed25519 key pair for Consensus Layer (Malachite)
pub struct ConsensusKeys {
    /// Ed25519 private key (via Malachite)
    pub secret_key: malachitebft_signing_ed25519::PrivateKey,
    /// Ed25519 public key
    pub public_key: malachitebft_signing_ed25519::PublicKey,
}

/// BLS12-381 key pair for Data Chain Layer
pub struct DataChainKeys {
    /// BLS secret key (via blst)
    pub secret_key: blst::min_pk::SecretKey,
    /// BLS public key
    pub public_key: blst::min_pk::PublicKey,
}

/// Complete validator key set
pub struct ValidatorKeys {
    /// Ed25519 keys for consensus votes/proposals
    pub consensus: ConsensusKeys,
    /// BLS12-381 keys for Car signing and attestations
    pub data_chain: DataChainKeys,
    /// Derived Ethereum address (from Ed25519 pubkey)
    pub address: ValidatorAddress,
}

impl ValidatorKeys {
    /// Generate new validator key pairs
    pub fn generate() -> Self { ... }

    /// Load from key files
    pub fn load(consensus_key_path: &Path, dcl_key_path: &Path) -> Result<Self> { ... }
}
```

### Consensus Layer Implementation (Ed25519)

```rust
// crates/consensus/src/context.rs
use malachitebft_signing_ed25519::Ed25519;

impl Context for CipherBftContext {
    type SigningScheme = Ed25519;  // Malachite's native Ed25519
    // ...
}

// Malachite handles all CL signing/verification internally
```

### Data Chain Layer Implementation (BLS12-381)

```rust
// crates/data-chain/src/signing.rs
use blst::min_pk::{SecretKey, PublicKey, Signature, AggregateSignature};

pub struct BlsCrypto;

impl BlsCrypto {
    /// Sign a Car
    pub fn sign_car(key: &SecretKey, car: &Car) -> Signature {
        let msg = car.signing_bytes();
        key.sign(&msg, DST_CAR, &[])
    }

    /// Sign an attestation
    pub fn sign_attestation(key: &SecretKey, car_hash: &Hash) -> Signature {
        key.sign(car_hash.as_bytes(), DST_ATTESTATION, &[])
    }

    /// Aggregate attestation signatures
    pub fn aggregate_attestations(sigs: &[Signature]) -> AggregateSignature {
        AggregateSignature::aggregate(sigs, true).unwrap()
    }

    /// Verify aggregated attestation
    pub fn verify_aggregated(
        agg_sig: &AggregateSignature,
        pubkeys: &[PublicKey],
        car_hash: &Hash,
    ) -> bool {
        let msgs: Vec<&[u8]> = vec![car_hash.as_bytes(); pubkeys.len()];
        agg_sig.aggregate_verify(true, &msgs, DST_ATTESTATION, pubkeys, true)
            .is_ok()
    }
}

// Domain Separation Tags
const DST_CAR: &[u8] = b"CIPHERBFT_CAR_V1";
const DST_ATTESTATION: &[u8] = b"CIPHERBFT_ATTESTATION_V1";
```

### Attestation Aggregation

```rust
// crates/data-chain/src/attestation.rs

/// Individual attestation (before aggregation)
pub struct Attestation {
    pub car_hash: Hash,
    pub validator: ValidatorId,
    pub signature: blst::min_pk::Signature,
}

/// Aggregated attestations for a Car (f+1 combined)
pub struct AggregatedAttestation {
    pub car_hash: Hash,
    /// Bitmap of validators who attested
    pub validators: BitVec,
    /// Single aggregated BLS signature
    pub aggregated_signature: blst::min_pk::AggregateSignature,
}

impl AggregatedAttestation {
    /// Create from f+1 individual attestations
    pub fn aggregate(attestations: Vec<Attestation>) -> Self {
        let sigs: Vec<_> = attestations.iter().map(|a| &a.signature).collect();
        let agg_sig = AggregateSignature::aggregate(&sigs, true).unwrap();

        let mut validators = BitVec::repeat(false, MAX_VALIDATORS);
        for att in &attestations {
            validators.set(att.validator.index(), true);
        }

        AggregatedAttestation {
            car_hash: attestations[0].car_hash,
            validators,
            aggregated_signature: agg_sig,
        }
    }

    /// Verify aggregated attestation against validator set
    pub fn verify(&self, validator_set: &ValidatorSet) -> bool {
        let pubkeys: Vec<_> = self.validators
            .iter()
            .enumerate()
            .filter(|(_, set)| *set)
            .map(|(i, _)| validator_set.get_bls_pubkey(i))
            .collect();

        BlsCrypto::verify_aggregated(
            &self.aggregated_signature,
            &pubkeys,
            &self.car_hash,
        )
    }
}
```

### Cut Structure with Aggregated Attestations

```rust
/// Cut containing highest attested Cars from each validator
pub struct Cut {
    pub height: Height,
    /// Map of validator → their highest attested Car
    pub cars: HashMap<ValidatorId, Car>,
    /// Aggregated attestations for each Car (BLS aggregated)
    pub attestations: HashMap<Hash, AggregatedAttestation>,
}

// Size analysis for n=21 validators:
// - Cars: ~21 × 1KB = 21KB (transaction hashes)
// - Attestations: 21 × (32 + 32 + 96) bytes = 3.36KB (aggregated)
// Total: ~25KB per Cut (vs ~40KB without aggregation)
```

### Bandwidth Analysis

For n=21 validators (benchmark configuration):

| Component | Size (Dual Scheme) | Size (Ed25519 Only) |
|-----------|-------------------|---------------------|
| CL Vote | 64 bytes | 64 bytes |
| CL Proposal | ~1KB + 64 sig | ~1KB + 64 sig |
| DCL Car signature | 96 bytes | 64 bytes |
| DCL Attestation (single) | 96 bytes | 64 bytes |
| DCL Attestation (f+1 agg) | 96 bytes | 512 bytes (8×64) |
| Cut attestations total | 2,016 bytes | 16,128 bytes |

**Per-block bandwidth savings**: ~14KB/block with BLS aggregation in DCL.

At 100ms blocks (10 TPS): ~140KB/s bandwidth savings.

### Security Considerations

**Ed25519 (CL)**:
- Based on Curve25519
- 128-bit security level
- Well-analyzed, widely deployed
- Deterministic signatures

**BLS12-381 (DCL)**:
- Pairing-based cryptography
- 128-bit security level
- Ethereum 2.0 standard
- Supports aggregation

**Key isolation**: Using separate key pairs for CL and DCL provides:
- Compromise of one key doesn't affect the other layer
- Different signing contexts prevent cross-protocol attacks
- Clear separation of responsibilities

## Consequences

### Backwards Compatibility

N/A - greenfield implementation.

### Positive

1. **Malachite alignment**: Native Ed25519 support for Consensus Layer
2. **Attestation efficiency**: BLS aggregation reduces DCL bandwidth by 8x
3. **Layer separation**: Clear cryptographic boundaries between CL and DCL
4. **Ethereum compatibility**: BLS12-381 matches Ethereum 2.0 standard
5. **Security isolation**: Separate keys for separate purposes

### Negative

1. **Two key pairs**: Validators must manage Ed25519 + BLS keys
2. **Two crypto libraries**: Malachite Ed25519 + blst BLS
3. **Mixed assumptions**: EdDSA and pairing-based crypto
4. **Key ceremony complexity**: Two key generation/rotation processes

### Neutral

1. **Implementation complexity**: Moderate - each layer uses its native scheme
2. **Verification performance**: CL fast (Ed25519), DCL moderate (BLS verify)
3. **Key storage**: Two key files per validator

## Test Cases

### Ed25519 (Consensus Layer)
1. **Malachite integration**: CipherBftContext uses Ed25519 signing scheme
2. **Vote signing**: Prevote/Precommit signatures verify correctly
3. **Proposal signing**: Leader proposals verify correctly

### BLS12-381 (Data Chain Layer)
1. **Car signing**: Car signatures verify with proposer's BLS key
2. **Attestation signing**: Individual attestations verify correctly
3. **Aggregation**: f+1 attestations aggregate into single signature
4. **Aggregated verification**: Aggregated signature verifies against pubkey set
5. **Domain separation**: Different DSTs prevent cross-context attacks

### Key Management
1. **Key generation**: Both key pairs generated correctly
2. **Key loading**: Keys load from separate files
3. **Key isolation**: CL keys cannot be used for DCL and vice versa

### Integration
1. **Full flow**: Transaction → Car → Attestation → Cut → Consensus → Finalize
2. **Mixed verification**: CL votes (Ed25519) and DCL attestations (BLS) in same block

## References

* [Malachite Ed25519 Crate](https://github.com/informalsystems/malachite/tree/main/code/crates/signing/ed25519)
* [Ed25519 Paper](https://ed25519.cr.yp.to/ed25519-20110926.pdf)
* [BLS12-381 Spec](https://hackmd.io/@benjaminion/bls12-381)
* [blst Crate](https://github.com/supranational/blst)
* [RFC 8032 - Edwards-Curve DSA](https://datatracker.ietf.org/doc/html/rfc8032)
* [Ethereum 2.0 BLS Signature Spec](https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#bls-signatures)
