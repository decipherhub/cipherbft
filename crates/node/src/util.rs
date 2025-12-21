//! Utility functions

use cipherbft_crypto::BlsPublicKey;
use cipherbft_types::{ValidatorId, VALIDATOR_ID_SIZE};

/// Derive ValidatorId from BLS public key (last 20 bytes of hash)
pub fn validator_id_from_bls(pubkey: &BlsPublicKey) -> ValidatorId {
    let hash = pubkey.hash();
    let mut bytes = [0u8; VALIDATOR_ID_SIZE];
    bytes.copy_from_slice(&hash[12..32]); // last 20 bytes
    ValidatorId::from_bytes(bytes)
}
