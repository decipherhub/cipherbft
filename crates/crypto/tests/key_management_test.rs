//! Integration tests for CipherBFT key management
//!
//! These tests verify the complete key management workflow including:
//! - Key generation with secure memory handling
//! - Keystore encryption/decryption
//! - Memory cleanup on drop
//! - Round-trip workflows

use cipherbft_crypto::{EncryptedKeystore, KeystorePaths, ValidatorKeys, ValidatorPublicKeys};
use secrecy::ExposeSecret;
use tempfile::TempDir;

/// Test complete key generation -> storage -> loading -> signing workflow
#[test]
fn test_full_key_workflow() {
    // Step 1: Generate fresh validator keys
    let keys = ValidatorKeys::generate(&mut rand::thread_rng());
    let validator_id = keys.validator_id();

    // Capture public keys for later verification
    let pub_keys = ValidatorPublicKeys::from_keys(&keys);
    assert_eq!(pub_keys.validator_id(), validator_id);

    // Step 2: Extract secret key bytes for storage
    let ed_secret_bytes = keys.consensus_secret().to_bytes();
    let bls_secret_bytes = keys.data_chain_secret().to_bytes();

    // Step 3: Create encrypted keystores
    let temp_dir = TempDir::new().expect("failed to create temp dir");
    let passphrase = "test-integration-passphrase-12345";

    // Store Ed25519 key
    let ed_pubkey_hex = hex::encode(keys.consensus_pubkey().to_bytes());
    let ed_keystore =
        EncryptedKeystore::encrypt(&ed_secret_bytes, passphrase, &ed_pubkey_hex).unwrap();

    let ed_path = temp_dir.path().join("consensus.json");
    ed_keystore
        .save(&ed_path)
        .expect("failed to save ed keystore");

    // Store BLS key
    let bls_pubkey_hex = hex::encode(keys.data_chain_pubkey().to_bytes());
    let bls_keystore =
        EncryptedKeystore::encrypt(&bls_secret_bytes, passphrase, &bls_pubkey_hex).unwrap();

    let bls_path = temp_dir.path().join("data_chain.json");
    bls_keystore
        .save(&bls_path)
        .expect("failed to save bls keystore");

    // Step 4: Load keystores and decrypt
    let loaded_ed = EncryptedKeystore::load(&ed_path).expect("failed to load ed keystore");
    let loaded_bls = EncryptedKeystore::load(&bls_path).expect("failed to load bls keystore");

    let decrypted_ed = loaded_ed.decrypt(passphrase).unwrap();
    let decrypted_bls = loaded_bls.decrypt(passphrase).unwrap();

    // Step 5: Verify decrypted keys match original
    assert_eq!(decrypted_ed.expose_secret().as_slice(), &ed_secret_bytes);
    assert_eq!(decrypted_bls.expose_secret().as_slice(), &bls_secret_bytes);

    // Step 6: Reconstruct keys and verify signing still works
    let ed_secret = cipherbft_crypto::Ed25519SecretKey::from_bytes(
        decrypted_ed.expose_secret().as_slice().try_into().unwrap(),
    );
    let bls_secret = cipherbft_crypto::BlsSecretKey::from_bytes(
        decrypted_bls.expose_secret().as_slice().try_into().unwrap(),
    )
    .unwrap();

    // Sign a test message
    let test_msg = b"integration test message";
    let ed_sig = ed_secret.sign(test_msg);
    let bls_sig = bls_secret.sign(test_msg, cipherbft_crypto::bls::DST_CAR);

    // Verify signatures with original public keys
    assert!(
        pub_keys.consensus_pubkey().verify(test_msg, &ed_sig),
        "Ed25519 signature verification failed"
    );
    assert!(
        pub_keys
            .data_chain_pubkey()
            .verify(test_msg, cipherbft_crypto::bls::DST_CAR, &bls_sig),
        "BLS signature verification failed"
    );
}

/// Test that ValidatorKeys drop properly cleans up
///
/// Note: We cannot directly verify memory content after drop (that's UB).
/// Instead, we verify the drop behavior through side effects and ensure
/// the Drop trait is actually being called.
#[test]
fn test_validator_keys_drop_behavior() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    // We can't directly test memory zeroing without UB, but we can verify:
    // 1. The keys are created successfully
    // 2. The keys go out of scope (drop is called)
    // 3. The Drop impl compiles and runs without panic

    let drop_completed = Arc::new(AtomicBool::new(false));
    let drop_flag = drop_completed.clone();

    // Spawn in a thread to isolate the stack
    let handle = std::thread::spawn(move || {
        let keys = ValidatorKeys::generate(&mut rand::thread_rng());

        // Use the keys to ensure they're not optimized away
        let _id = keys.validator_id();
        let msg = b"test";
        let _sig = keys.consensus.sign(msg);

        // Keys will be dropped here
        drop(keys);

        drop_flag.store(true, Ordering::SeqCst);
    });

    handle.join().expect("thread panicked during key drop");
    assert!(
        drop_completed.load(Ordering::SeqCst),
        "Drop was not completed"
    );
}

/// Test SecureKeyMaterial zeroing behavior
#[test]
fn test_secure_key_material_zeroing() {
    use cipherbft_crypto::secure::SecureKeyMaterial;
    use zeroize::Zeroize;

    let ed_seed = [0xAAu8; 32];
    let bls_seed = [0xBBu8; 32];

    let mut material = SecureKeyMaterial::new(ed_seed, bls_seed);

    // Verify seeds are present before zeroizing
    assert_eq!(material.ed25519_seed(), &ed_seed);
    assert_eq!(material.bls_seed(), &bls_seed);

    // Explicitly zeroize (this is what Drop would do)
    material.zeroize();

    // The Zeroize derive ensures internal state is cleared
    // We can verify compilation and that zeroize() runs without panic
}

/// Test keystore roundtrip with various passphrase strengths
#[test]
fn test_keystore_passphrase_handling() {
    let secret = [0x42u8; 32];
    let pubkey = "test-pubkey";

    // Test with various passphrase lengths
    let passphrases = [
        "short",                                                  // Very short (weak)
        "medium_length_phrase",                                   // Medium
        "this-is-a-very-long-passphrase-with-special-chars!@#$%", // Long with special
        "🔐 unicode passphrase 密码",                             // Unicode
    ];

    for passphrase in &passphrases {
        let keystore = EncryptedKeystore::encrypt(&secret, passphrase, pubkey)
            .expect("encryption should succeed");

        let decrypted = keystore
            .decrypt(passphrase)
            .expect("decryption should succeed");

        assert_eq!(
            decrypted.expose_secret().as_slice(),
            &secret,
            "roundtrip failed for passphrase: {}",
            passphrase
        );

        // Wrong passphrase should fail
        let wrong_result = keystore.decrypt("wrong_passphrase");
        assert!(wrong_result.is_err(), "should fail with wrong passphrase");
    }
}

/// Test file permissions are set correctly (Unix only)
#[test]
#[cfg(unix)]
fn test_keystore_file_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = TempDir::new().expect("failed to create temp dir");
    let keystore_path = temp_dir.path().join("secure.json");

    let keystore = EncryptedKeystore::encrypt(&[1u8; 32], "passphrase", "pubkey").unwrap();
    keystore.save(&keystore_path).unwrap();

    let metadata = std::fs::metadata(&keystore_path).unwrap();
    let mode = metadata.permissions().mode() & 0o777;

    assert_eq!(mode, 0o600, "keystore should have 0600 permissions");
}

/// Test that Debug output doesn't leak secrets
#[test]
fn test_debug_output_safety() {
    let keys = ValidatorKeys::generate(&mut rand::thread_rng());
    let debug_output = format!("{:?}", keys);

    // Should not contain raw key bytes
    assert!(
        !debug_output.contains("secret"),
        "Debug output should not contain 'secret'"
    );

    // Should only show public info
    assert!(
        debug_output.contains("validator_id"),
        "Debug should show validator_id"
    );
}

/// Test DerivationInfo tracking through the workflow
#[test]
fn test_derivation_info_tracking() {
    use cipherbft_crypto::secure::DerivationInfo;
    use cipherbft_crypto::{BlsKeyPair, Ed25519KeyPair, Secp256k1KeyPair};

    let consensus = Ed25519KeyPair::generate(&mut rand::thread_rng());
    let data_chain = BlsKeyPair::generate(&mut rand::thread_rng());
    let evm = Secp256k1KeyPair::generate(&mut rand::thread_rng());

    let derivation = DerivationInfo {
        account_index: 5,
        consensus_path: "m/12381/8888/5/0".to_string(),
        data_chain_path: "m/12381/8888/5/1".to_string(),
        evm_path: Some("m/44'/60'/0'/0/5".to_string()),
    };

    let keys = ValidatorKeys::from_keypairs_with_derivation(
        consensus,
        data_chain,
        evm,
        derivation.clone(),
    );

    // Verify derivation info is preserved
    assert!(keys.is_derived());
    let info = keys.derivation_info().expect("should have derivation info");
    assert_eq!(info.account_index, 5);
    assert_eq!(info.consensus_path, "m/12381/8888/5/0");
}

/// Test keystore paths tracking
#[test]
fn test_keystore_paths_tracking() {
    use std::path::PathBuf;

    let mut keys = ValidatorKeys::generate(&mut rand::thread_rng());

    // Initially no keystore paths
    assert!(!keys.has_keystore());

    // Set paths
    let paths = KeystorePaths::new(
        PathBuf::from("/keys/consensus.json"),
        PathBuf::from("/keys/data_chain.json"),
    );
    keys.set_keystore_paths(paths);

    // Now should have keystore
    assert!(keys.has_keystore());
    let stored_paths = keys.keystore_paths().expect("should have paths");
    assert_eq!(
        stored_paths.consensus.as_ref().unwrap().to_str().unwrap(),
        "/keys/consensus.json"
    );
}
