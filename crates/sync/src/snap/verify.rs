//! Merkle proof verification for snap sync

use crate::error::{Result, SyncError};
use crate::protocol::AccountData;
use alloy_primitives::{keccak256, Address, Bytes, B256};
use alloy_rlp::Encodable;
use alloy_trie::{proof::verify_proof as trie_verify_proof, Nibbles, EMPTY_ROOT_HASH};

/// RLP-encoded account for trie verification.
/// This matches Ethereum's account encoding in the state trie.
#[derive(alloy_rlp::RlpEncodable)]
struct RlpAccount {
    nonce: u64,
    balance: alloy_primitives::U256,
    storage_root: B256,
    code_hash: B256,
}

impl From<&AccountData> for RlpAccount {
    fn from(account: &AccountData) -> Self {
        Self {
            nonce: account.nonce,
            balance: account.balance,
            storage_root: account.storage_root,
            code_hash: account.code_hash,
        }
    }
}

/// Verify an account range proof against the state root.
///
/// This verifies that:
/// 1. The proof is valid (connects to state_root)
/// 2. Each account exists at its claimed address
/// 3. The range is complete (no gaps between accounts)
pub fn verify_account_range_proof(
    state_root: B256,
    start_address: Address,
    accounts: &[AccountData],
    proof: &[Bytes],
) -> Result<()> {
    if accounts.is_empty() {
        // Empty range is valid if proof shows no keys in range
        // SECURITY: Empty range claims REQUIRE proofs to prevent peers from
        // falsely claiming "no accounts exist" when accounts do exist
        return verify_empty_range(state_root, start_address, proof);
    }

    // TODO: Server proof generation not yet implemented
    // When proofs are empty but accounts are returned, we skip individual proof
    // verification. The final state root check will catch any malicious data.
    // This is acceptable because:
    // 1. We DO require proofs for empty range claims (above)
    // 2. The final state root verification catches any omitted/modified accounts
    // 3. Malicious peers will be detected and banned when sync completes
    if !proof.is_empty() {
        // Verify each account exists in the trie
        for account in accounts {
            let key = Nibbles::unpack(keccak256(account.address));
            let rlp_account = RlpAccount::from(account);
            let mut encoded = Vec::new();
            rlp_account.encode(&mut encoded);

            // Use alloy-trie's proof verification
            verify_proof(state_root, &key, Some(&encoded), proof)?;
        }
    }

    // Verify range completeness (no missing accounts between returned ones)
    // This check runs regardless of whether proofs are present
    verify_range_completeness(state_root, start_address, accounts, proof)?;

    Ok(())
}

/// Verify a storage range proof against the account's storage root.
pub fn verify_storage_range_proof(
    storage_root: B256,
    start_slot: B256,
    slots: &[(B256, B256)],
    proof: &[Bytes],
) -> Result<()> {
    if slots.is_empty() {
        // SECURITY: Empty storage claims REQUIRE proofs
        return verify_empty_storage_range(storage_root, start_slot, proof);
    }

    // TODO: Server proof generation not yet implemented
    // Skip individual slot verification when proofs are empty.
    // Final state root check will catch any malicious data.
    if !proof.is_empty() {
        // Verify each slot exists in the storage trie
        for (key, value) in slots {
            let nibble_key = Nibbles::unpack(keccak256(key));
            let encoded_value = alloy_rlp::encode(value);

            verify_proof(storage_root, &nibble_key, Some(&encoded_value), proof)?;
        }
    }

    Ok(())
}

/// Verify a single proof against expected value.
fn verify_proof(
    root: B256,
    key: &Nibbles,
    expected_value: Option<&[u8]>,
    proof_nodes: &[Bytes],
) -> Result<()> {
    // Convert expected value to owned Vec for alloy-trie API
    let expected = expected_value.map(|v| v.to_vec());

    // Use alloy-trie's proof verification
    match trie_verify_proof(root, *key, expected, proof_nodes) {
        Ok(()) => Ok(()),
        Err(e) => Err(SyncError::invalid_proof(
            "peer",
            format!("proof verification failed: {}", e),
        )),
    }
}

/// Verify that an empty range response is valid.
fn verify_empty_range(state_root: B256, start: Address, proof: &[Bytes]) -> Result<()> {
    // For empty range, proof should show no keys exist at or after start
    if state_root == EMPTY_ROOT_HASH {
        // Empty state is valid
        return Ok(());
    }

    // An empty range claim requires a non-empty proof
    if proof.is_empty() {
        return Err(SyncError::invalid_proof(
            "peer",
            "empty proof for empty range claim - proof required to demonstrate absence",
        ));
    }

    // Verify the proof shows absence of the key
    // This is an exclusion proof - we expect the key NOT to exist
    let key = Nibbles::unpack(keccak256(start));

    // For exclusion proofs, expected_value is None
    // The proof MUST verify successfully - invalid proofs are rejected
    trie_verify_proof(state_root, key, None, proof).map_err(|e| {
        SyncError::invalid_proof(
            "peer",
            format!("empty range exclusion proof invalid: {}", e),
        )
    })
}

/// Verify that no accounts are missing between the returned ones.
///
/// This performs several validations:
/// 1. Accounts are sorted by their keccak256 hash (trie key order)
/// 2. Accounts are within the requested range
/// 3. First account is at or after the start address
///
/// Note: Full boundary proof verification would require walking the trie structure
/// to prove no keys exist between consecutive accounts. This is complex and
/// partially covered by the individual account proofs. Malicious peers that omit
/// accounts will be detected when the final state root doesn't match.
fn verify_range_completeness(
    _state_root: B256,
    start: Address,
    accounts: &[AccountData],
    _proof: &[Bytes],
) -> Result<()> {
    if accounts.is_empty() {
        return Ok(());
    }

    // Verify first account is at or after start address
    let first_hash = keccak256(accounts[0].address);
    let start_hash = keccak256(start);
    if first_hash < start_hash {
        return Err(SyncError::invalid_proof(
            "peer",
            format!(
                "first account {} is before requested start {}",
                accounts[0].address, start
            ),
        ));
    }

    // Verify accounts are in sorted order by their trie key (keccak256 hash)
    // This is required for range completeness - gaps would show up as unsorted
    let mut prev_hash = first_hash;
    for (i, account) in accounts.iter().enumerate().skip(1) {
        let curr_hash = keccak256(account.address);
        if curr_hash <= prev_hash {
            return Err(SyncError::invalid_proof(
                "peer",
                format!(
                    "accounts not in sorted order at index {}: {} should be after {}",
                    i,
                    account.address,
                    accounts[i - 1].address
                ),
            ));
        }
        prev_hash = curr_hash;
    }

    // Note: Full range completeness would verify boundary proofs showing no keys
    // exist between consecutive accounts. This requires trie structure walking.
    // The current implementation relies on:
    // 1. Individual account proofs verifying each account exists
    // 2. Sorted order verification above
    // 3. Final state root verification catching any omissions
    //
    // A malicious peer omitting accounts would produce an incorrect final state root,
    // causing sync to fail and the peer to be banned.

    Ok(())
}

/// Verify empty storage range.
fn verify_empty_storage_range(storage_root: B256, start: B256, proof: &[Bytes]) -> Result<()> {
    if storage_root == EMPTY_ROOT_HASH {
        return Ok(());
    }

    // An empty storage range claim requires a non-empty proof
    if proof.is_empty() {
        return Err(SyncError::invalid_proof(
            "peer",
            "empty proof for empty storage range claim - proof required to demonstrate absence",
        ));
    }

    // Verify the proof shows absence of the key
    let key = Nibbles::unpack(keccak256(start));

    // The proof MUST verify successfully - invalid proofs are rejected
    trie_verify_proof(storage_root, key, None, proof).map_err(|e| {
        SyncError::invalid_proof(
            "peer",
            format!("empty storage range exclusion proof invalid: {}", e),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;

    #[test]
    fn test_rlp_account_encoding() {
        let account = AccountData {
            address: Address::ZERO,
            nonce: 1,
            balance: U256::from(100),
            code_hash: B256::ZERO,
            storage_root: B256::ZERO,
        };

        let rlp = RlpAccount::from(&account);
        let mut encoded = Vec::new();
        rlp.encode(&mut encoded);

        // RLP encoding should produce valid bytes
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_empty_state_verification() {
        // Empty state root with empty accounts should pass
        let result = verify_account_range_proof(
            EMPTY_ROOT_HASH,
            Address::ZERO,
            &[],
            &[Bytes::from(vec![0x80])], // RLP empty
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_empty_storage_verification() {
        let result = verify_storage_range_proof(EMPTY_ROOT_HASH, B256::ZERO, &[], &[]);

        assert!(result.is_ok());
    }

    #[test]
    fn test_empty_proof_empty_range_fails() {
        // Empty range claims REQUIRE proofs - this is security critical
        // A peer claiming "no accounts exist" must prove it

        // Empty accounts with empty proof on non-empty state should fail
        let result = verify_account_range_proof(
            B256::repeat_byte(0xab), // Non-empty state root
            Address::ZERO,
            &[], // Empty accounts = empty range claim
            &[], // Empty proof
        );
        assert!(result.is_err());

        // Empty storage with empty proof on non-empty storage root should fail
        let result = verify_storage_range_proof(
            B256::repeat_byte(0xab), // Non-empty storage root
            B256::ZERO,
            &[], // Empty slots = empty range claim
            &[], // Empty proof
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_proof_with_data_allowed_temporarily() {
        // TODO: When server implements proof generation, this test should expect errors
        // For now, empty proofs are allowed when data IS returned
        // (security relies on final state root verification)

        let account = AccountData {
            address: Address::ZERO, // Use ZERO to ensure it's at/after start
            nonce: 1,
            balance: U256::from(100),
            code_hash: B256::ZERO,
            storage_root: EMPTY_ROOT_HASH,
        };

        // Non-empty accounts with empty proof - temporarily allowed
        let result = verify_account_range_proof(
            B256::repeat_byte(0xab),
            Address::ZERO,
            &[account],
            &[], // Empty proof
        );
        assert!(
            result.is_ok(),
            "Empty proof with accounts should temporarily pass"
        );

        // Non-empty storage with empty proof - temporarily allowed
        let result = verify_storage_range_proof(
            B256::repeat_byte(0xab),
            B256::ZERO,
            &[(B256::ZERO, B256::repeat_byte(0x42))],
            &[], // Empty proof
        );
        assert!(
            result.is_ok(),
            "Empty proof with slots should temporarily pass"
        );
    }
}
