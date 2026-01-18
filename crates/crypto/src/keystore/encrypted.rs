//! EIP-2335 EncryptedKeystore implementation
//!
//! This module provides the main keystore struct that combines KDF, cipher,
//! and checksum modules into a complete encrypted key storage solution.

use std::fs;
use std::path::Path;

use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::checksum::{compute_checksum, ChecksumModule};
use super::cipher::{encrypt_secret, generate_iv, CipherModule};
use super::error::{KeystoreError, KeystoreResult};
use super::kdf::{generate_salt, KdfModule};
use crate::secure::SecretBytes;

/// Version number for EIP-2335 keystores
pub const KEYSTORE_VERSION: u32 = 4;

/// EIP-2335 compatible encrypted keystore
///
/// This struct represents a complete keystore file containing an encrypted
/// private key along with all parameters needed for decryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedKeystore {
    /// Crypto parameters (KDF + cipher + checksum)
    pub crypto: CryptoModule,
    /// Optional description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Public key as hex string (for identification)
    pub pubkey: String,
    /// Derivation path (if derived from mnemonic)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Unique identifier
    pub uuid: String,
    /// Schema version
    pub version: u32,
}

/// Combined crypto parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoModule {
    /// Key derivation function parameters
    pub kdf: KdfModule,
    /// Checksum for integrity verification
    pub checksum: ChecksumModule,
    /// Cipher parameters and encrypted data
    pub cipher: CipherModule,
}

impl EncryptedKeystore {
    /// Create a new keystore by encrypting a secret
    ///
    /// # Arguments
    ///
    /// * `secret` - The secret bytes to encrypt (typically a private key)
    /// * `passphrase` - The passphrase to derive encryption key from
    /// * `pubkey` - The public key (hex encoded) for identification
    ///
    /// # Returns
    ///
    /// New EncryptedKeystore ready to be saved
    pub fn encrypt(
        secret: &[u8],
        passphrase: &str,
        pubkey: &str,
    ) -> KeystoreResult<Self> {
        KeystoreBuilder::new()
            .secret(secret)
            .passphrase(passphrase)
            .pubkey(pubkey)
            .build()
    }

    /// Decrypt the keystore and return the secret
    ///
    /// # Arguments
    ///
    /// * `passphrase` - The passphrase used during encryption
    ///
    /// # Returns
    ///
    /// Decrypted secret as SecretBytes
    pub fn decrypt(&self, passphrase: &str) -> KeystoreResult<SecretBytes> {
        // Derive key from passphrase
        let derived_key = self.crypto.kdf.derive_key(passphrase)?;
        let dk_bytes = derived_key.expose_secret();

        // Get ciphertext
        let ciphertext = self.crypto.cipher.ciphertext()?;

        // Verify checksum before decrypting
        if !self.crypto.checksum.verify(dk_bytes, &ciphertext)? {
            return Err(KeystoreError::InvalidPassphrase);
        }

        // Decrypt
        let iv = self.crypto.cipher.iv()?;
        let decrypted = super::cipher::decrypt_secret(&ciphertext, dk_bytes, &iv)?;

        Ok(decrypted)
    }

    /// Save keystore to a file
    ///
    /// Creates the file with restricted permissions (0600).
    ///
    /// # Arguments
    ///
    /// * `path` - File path to save to
    pub fn save<P: AsRef<Path>>(&self, path: P) -> KeystoreResult<()> {
        let path = path.as_ref();

        // Create parent directories if needed
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Serialize to JSON with pretty formatting
        let json = serde_json::to_string_pretty(self)?;

        // Write file
        fs::write(path, &json)?;

        // Set restrictive permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = fs::Permissions::from_mode(0o600);
            fs::set_permissions(path, permissions)?;
        }

        Ok(())
    }

    /// Load keystore from a file
    ///
    /// # Arguments
    ///
    /// * `path` - File path to load from
    pub fn load<P: AsRef<Path>>(path: P) -> KeystoreResult<Self> {
        let contents = fs::read_to_string(path)?;
        let keystore: Self = serde_json::from_str(&contents)?;
        Ok(keystore)
    }

    /// Get the UUID
    pub fn uuid(&self) -> &str {
        &self.uuid
    }

    /// Get the public key
    pub fn pubkey(&self) -> &str {
        &self.pubkey
    }

    /// Get the description if present
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Get the derivation path if present
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }
}

/// Builder for creating EncryptedKeystore instances
#[derive(Default)]
pub struct KeystoreBuilder {
    secret: Option<Vec<u8>>,
    passphrase: Option<String>,
    pubkey: Option<String>,
    description: Option<String>,
    path: Option<String>,
    uuid: Option<String>,
}

impl KeystoreBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the secret to encrypt
    pub fn secret(mut self, secret: &[u8]) -> Self {
        self.secret = Some(secret.to_vec());
        self
    }

    /// Set the passphrase for key derivation
    pub fn passphrase(mut self, passphrase: &str) -> Self {
        self.passphrase = Some(passphrase.to_string());
        self
    }

    /// Set the public key (hex encoded)
    pub fn pubkey(mut self, pubkey: &str) -> Self {
        self.pubkey = Some(pubkey.to_string());
        self
    }

    /// Set an optional description
    pub fn description(mut self, description: &str) -> Self {
        self.description = Some(description.to_string());
        self
    }

    /// Set the derivation path (if derived from mnemonic)
    pub fn path(mut self, path: &str) -> Self {
        self.path = Some(path.to_string());
        self
    }

    /// Set a custom UUID (normally auto-generated)
    pub fn uuid(mut self, uuid: &str) -> Self {
        self.uuid = Some(uuid.to_string());
        self
    }

    /// Build the keystore
    ///
    /// # Returns
    ///
    /// EncryptedKeystore ready to be saved
    pub fn build(self) -> KeystoreResult<EncryptedKeystore> {
        let secret = self.secret.ok_or(KeystoreError::InvalidSecretLength {
            expected: 32,
            actual: 0,
        })?;

        let passphrase = self.passphrase.ok_or_else(|| {
            KeystoreError::WeakPassphrase("passphrase is required".to_string())
        })?;

        let pubkey = self.pubkey.unwrap_or_default();

        // Generate random salt and IV
        let salt = generate_salt();
        let iv = generate_iv();

        // Create KDF module and derive key
        let kdf = KdfModule::new_scrypt(salt);
        let derived_key = kdf.derive_key(&passphrase)?;
        let dk_bytes = derived_key.expose_secret();

        // Encrypt the secret (using first 16 bytes of derived key)
        let ciphertext = encrypt_secret(&secret, dk_bytes, &iv)?;

        // Compute checksum (using bytes 16-32 of derived key)
        let checksum_bytes = compute_checksum(dk_bytes, &ciphertext)?;

        // Create modules
        let cipher = CipherModule::new(iv, ciphertext);
        let checksum = ChecksumModule::new(checksum_bytes);

        let crypto = CryptoModule {
            kdf,
            checksum,
            cipher,
        };

        let uuid = self.uuid.unwrap_or_else(|| Uuid::new_v4().to_string());

        Ok(EncryptedKeystore {
            crypto,
            description: self.description,
            pubkey,
            path: self.path,
            uuid,
            version: KEYSTORE_VERSION,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let secret = [0xAB; 32];
        let passphrase = "test-passphrase-123";
        let pubkey = "0x1234567890abcdef";

        let keystore = EncryptedKeystore::encrypt(&secret, passphrase, pubkey).unwrap();

        assert_eq!(keystore.version, KEYSTORE_VERSION);
        assert_eq!(keystore.pubkey, pubkey);

        let decrypted = keystore.decrypt(passphrase).unwrap();
        assert_eq!(decrypted.expose_secret(), &secret);
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let secret = [0xCD; 32];
        let passphrase = "correct-passphrase";
        let wrong_passphrase = "wrong-passphrase";
        let pubkey = "0xdeadbeef";

        let keystore = EncryptedKeystore::encrypt(&secret, passphrase, pubkey).unwrap();

        let result = keystore.decrypt(wrong_passphrase);
        assert!(matches!(result, Err(KeystoreError::InvalidPassphrase)));
    }

    #[test]
    fn test_keystore_builder() {
        let secret = [0xEF; 32];

        let keystore = KeystoreBuilder::new()
            .secret(&secret)
            .passphrase("my-passphrase")
            .pubkey("0x1111")
            .description("Test keystore")
            .path("m/12381/8888/0/0")
            .build()
            .unwrap();

        assert_eq!(keystore.description(), Some("Test keystore"));
        assert_eq!(keystore.path(), Some("m/12381/8888/0/0"));
        assert_eq!(keystore.pubkey(), "0x1111");
    }

    #[test]
    fn test_keystore_serialization() {
        let secret = [0x11; 32];
        let passphrase = "serialize-test";

        let keystore = EncryptedKeystore::encrypt(&secret, passphrase, "0x2222").unwrap();

        // Serialize to JSON
        let json = serde_json::to_string_pretty(&keystore).unwrap();

        // Parse back
        let parsed: EncryptedKeystore = serde_json::from_str(&json).unwrap();

        // Should still decrypt correctly
        let decrypted = parsed.decrypt(passphrase).unwrap();
        assert_eq!(decrypted.expose_secret(), &secret);
    }

    #[test]
    fn test_save_and_load() {
        let secret = [0x33; 32];
        let passphrase = "file-test";

        let keystore = EncryptedKeystore::encrypt(&secret, passphrase, "0x3333").unwrap();

        // Create temp directory
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("test_keystore.json");

        // Save
        keystore.save(&file_path).unwrap();

        // Verify file exists
        assert!(file_path.exists());

        // Load
        let loaded = EncryptedKeystore::load(&file_path).unwrap();

        // Decrypt
        let decrypted = loaded.decrypt(passphrase).unwrap();
        assert_eq!(decrypted.expose_secret(), &secret);
    }

    #[test]
    #[cfg(unix)]
    fn test_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let secret = [0x44; 32];
        let passphrase = "permissions-test";

        let keystore = EncryptedKeystore::encrypt(&secret, passphrase, "0x4444").unwrap();

        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("permissions_test.json");

        keystore.save(&file_path).unwrap();

        let metadata = fs::metadata(&file_path).unwrap();
        let permissions = metadata.permissions().mode();

        // Check that permissions are 0600 (rw-------)
        assert_eq!(permissions & 0o777, 0o600);
    }

    #[test]
    fn test_different_secret_sizes() {
        // EIP-2335 supports any secret size, not just 32 bytes
        for size in [16, 32, 48, 64, 96] {
            let secret = vec![0x55; size];
            let passphrase = "size-test";

            let keystore = EncryptedKeystore::encrypt(&secret, passphrase, "0x5555").unwrap();
            let decrypted = keystore.decrypt(passphrase).unwrap();

            assert_eq!(decrypted.expose_secret(), &secret);
        }
    }

    #[test]
    fn test_uuid_uniqueness() {
        let keystore1 = KeystoreBuilder::new()
            .secret(&[1; 32])
            .passphrase("test")
            .build()
            .unwrap();

        let keystore2 = KeystoreBuilder::new()
            .secret(&[1; 32])
            .passphrase("test")
            .build()
            .unwrap();

        // Each keystore should have a unique UUID
        assert_ne!(keystore1.uuid(), keystore2.uuid());
    }

    #[test]
    fn test_custom_uuid() {
        let custom_uuid = "12345678-1234-5678-1234-567812345678";

        let keystore = KeystoreBuilder::new()
            .secret(&[1; 32])
            .passphrase("test")
            .uuid(custom_uuid)
            .build()
            .unwrap();

        assert_eq!(keystore.uuid(), custom_uuid);
    }
}
