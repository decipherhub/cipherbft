//! Property-based tests for mnemonic and key derivation
//!
//! Uses proptest to verify key invariants across many randomly generated inputs.

use cipherbft_crypto::mnemonic::{derive_validator_keys, Mnemonic};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))] // Reduced cases due to slow scrypt

    /// Property: Mnemonic phrase roundtrip
    ///
    /// A mnemonic phrase converted to words and back should be identical.
    #[test]
    fn prop_mnemonic_phrase_roundtrip(_seed in any::<[u8; 32]>()) {
        // Generate a mnemonic from entropy (we can't use random words as they might be invalid)
        // Instead, we just verify that valid mnemonics roundtrip correctly
        let mnemonic = Mnemonic::generate().expect("should generate mnemonic");
        let phrase = mnemonic.phrase();

        // Parse the phrase back
        let restored = Mnemonic::from_phrase(phrase).expect("should parse phrase");

        // Verify they produce the same seed (using to_seed method)
        let seed1 = mnemonic.to_seed(None);
        let seed2 = restored.to_seed(None);
        prop_assert_eq!(seed1, seed2);
    }

    /// Property: Key derivation determinism
    ///
    /// The same mnemonic and account index should always produce identical keys.
    #[test]
    fn prop_key_derivation_determinism(account in 0u32..100) {
        let mnemonic = Mnemonic::generate().expect("should generate mnemonic");
        let phrase = mnemonic.phrase().to_string();

        // Derive keys twice from the same phrase and account
        let mnemonic1 = Mnemonic::from_phrase(&phrase).unwrap();
        let mnemonic2 = Mnemonic::from_phrase(&phrase).unwrap();

        let keys1 = derive_validator_keys(&mnemonic1, account, None).expect("derive keys 1");
        let keys2 = derive_validator_keys(&mnemonic2, account, None).expect("derive keys 2");

        // Same mnemonic + account should produce same validator ID
        prop_assert_eq!(keys1.validator_id(), keys2.validator_id());

        // Same public keys
        prop_assert_eq!(
            keys1.consensus_pubkey().to_bytes(),
            keys2.consensus_pubkey().to_bytes()
        );
        prop_assert_eq!(
            keys1.data_chain_pubkey().to_bytes(),
            keys2.data_chain_pubkey().to_bytes()
        );
    }

    /// Property: Different accounts produce different keys
    ///
    /// Different account indices from the same mnemonic should produce different keys.
    #[test]
    fn prop_different_accounts_different_keys(
        account1 in 0u32..50,
        account2 in 50u32..100
    ) {
        // Ensure accounts are different (they're from non-overlapping ranges)
        prop_assume!(account1 != account2);

        let mnemonic = Mnemonic::generate().expect("should generate mnemonic");

        let keys1 = derive_validator_keys(&mnemonic, account1, None).expect("derive keys 1");
        let keys2 = derive_validator_keys(&mnemonic, account2, None).expect("derive keys 2");

        // Different accounts should produce different validator IDs
        prop_assert_ne!(keys1.validator_id(), keys2.validator_id());

        // Different public keys
        prop_assert_ne!(
            keys1.consensus_pubkey().to_bytes(),
            keys2.consensus_pubkey().to_bytes()
        );
    }

    /// Property: Different mnemonics produce different keys
    ///
    /// Different mnemonics should produce different keys for the same account.
    #[test]
    fn prop_different_mnemonics_different_keys(account in 0u32..100) {
        let mnemonic1 = Mnemonic::generate().expect("generate mnemonic 1");
        let mnemonic2 = Mnemonic::generate().expect("generate mnemonic 2");

        // Very low probability of collision but check anyway
        if mnemonic1.phrase() == mnemonic2.phrase() {
            return Ok(()); // Skip this case
        }

        let keys1 = derive_validator_keys(&mnemonic1, account, None).expect("derive keys 1");
        let keys2 = derive_validator_keys(&mnemonic2, account, None).expect("derive keys 2");

        // Different mnemonics should produce different keys
        prop_assert_ne!(keys1.validator_id(), keys2.validator_id());
    }
}

/// Property: Keystore encryption roundtrip
///
/// Encryption followed by decryption should return the original secret.
/// Using a smaller test count since scrypt is slow.
#[cfg(test)]
mod keystore_proptest {
    use super::*;
    use cipherbft_crypto::EncryptedKeystore;
    use secrecy::ExposeSecret;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))] // Very slow due to scrypt

        #[test]
        fn prop_keystore_roundtrip(
            secret in prop::array::uniform32(any::<u8>()),
            passphrase in "[a-zA-Z0-9!@#$%^&*]{8,32}"
        ) {
            let pubkey = "test-pubkey";

            // Encrypt
            let keystore = EncryptedKeystore::encrypt(&secret, &passphrase, pubkey)
                .expect("encryption should succeed");

            // Decrypt
            let decrypted = keystore.decrypt(&passphrase)
                .expect("decryption should succeed");

            // Verify roundtrip
            prop_assert_eq!(decrypted.expose_secret().as_slice(), &secret[..]);
        }

        #[test]
        fn prop_wrong_passphrase_fails(
            secret in prop::array::uniform32(any::<u8>()),
            passphrase1 in "[a-zA-Z]{8,16}",
            passphrase2 in "[0-9]{8,16}"
        ) {
            // Ensure passphrases are different
            prop_assume!(passphrase1 != passphrase2);

            let pubkey = "test-pubkey";

            // Encrypt with passphrase1
            let keystore = EncryptedKeystore::encrypt(&secret, &passphrase1, pubkey)
                .expect("encryption should succeed");

            // Try to decrypt with passphrase2 - should fail
            let result = keystore.decrypt(&passphrase2);
            prop_assert!(result.is_err(), "decryption with wrong passphrase should fail");
        }
    }
}
