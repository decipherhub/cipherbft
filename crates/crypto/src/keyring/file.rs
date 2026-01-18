//! File-based keyring backend using EIP-2335 encrypted keystores
//!
//! This backend stores keys as JSON files using the EIP-2335 standard format.
//! Keys are encrypted using scrypt KDF + AES-128-CTR cipher.

use std::fs;
use std::path::{Path, PathBuf};

use super::error::{KeyringError, KeyringResult};
use super::{KeyMetadata, KeyringBackend, KeyringBackendTrait};
use crate::keystore::{EncryptedKeystore, KeystoreBuilder};
use crate::secure::SecretBytes;

/// File-based keyring using EIP-2335 encrypted keystores
pub struct FileKeyring {
    /// Base directory for storing keystores
    base_path: PathBuf,
}

impl FileKeyring {
    /// Create a new file-based keyring
    ///
    /// # Arguments
    ///
    /// * `base_path` - Directory where keystores will be stored
    pub fn new(base_path: &Path) -> KeyringResult<Self> {
        // Create directory if it doesn't exist
        if !base_path.exists() {
            fs::create_dir_all(base_path)?;

            // Set directory permissions to 0700 (owner only)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = fs::Permissions::from_mode(0o700);
                fs::set_permissions(base_path, perms)?;
            }
        }

        Ok(Self {
            base_path: base_path.to_path_buf(),
        })
    }

    /// Get the keystore file path for a key name
    fn keystore_path(&self, name: &str) -> PathBuf {
        self.base_path.join(format!("{}.json", name))
    }
}

impl KeyringBackendTrait for FileKeyring {
    fn store_key(
        &self,
        metadata: &KeyMetadata,
        secret: &[u8],
        passphrase: Option<&str>,
    ) -> KeyringResult<()> {
        let passphrase = passphrase.ok_or(KeyringError::PassphraseRequired)?;
        let path = self.keystore_path(&metadata.name);

        // Build the keystore
        let mut builder = KeystoreBuilder::new()
            .secret(secret)
            .passphrase(passphrase)
            .pubkey(&metadata.pubkey);

        if let Some(desc) = &metadata.description {
            builder = builder.description(desc);
        }

        if let Some(derivation_path) = &metadata.path {
            builder = builder.path(derivation_path);
        }

        let keystore = builder.build()?;
        keystore.save(&path)?;

        Ok(())
    }

    fn get_key(&self, name: &str, passphrase: Option<&str>) -> KeyringResult<SecretBytes> {
        let passphrase = passphrase.ok_or(KeyringError::PassphraseRequired)?;
        let path = self.keystore_path(name);

        if !path.exists() {
            return Err(KeyringError::KeyNotFound(name.to_string()));
        }

        let keystore = EncryptedKeystore::load(&path)?;
        let secret = keystore.decrypt(passphrase)?;

        Ok(secret)
    }

    fn delete_key(&self, name: &str) -> KeyringResult<()> {
        let path = self.keystore_path(name);

        if !path.exists() {
            return Err(KeyringError::KeyNotFound(name.to_string()));
        }

        fs::remove_file(&path)?;
        Ok(())
    }

    fn list_keys(&self) -> KeyringResult<Vec<String>> {
        let mut keys = Vec::new();

        if !self.base_path.exists() {
            return Ok(keys);
        }

        for entry in fs::read_dir(&self.base_path)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() && path.extension().is_some_and(|ext| ext == "json") {
                // Try to load as keystore to verify it's valid
                if let Ok(_keystore) = EncryptedKeystore::load(&path) {
                    if let Some(stem) = path.file_stem() {
                        if let Some(name) = stem.to_str() {
                            keys.push(name.to_string());
                        }
                    }
                }
            }
        }

        keys.sort();
        Ok(keys)
    }

    fn get_metadata(&self, name: &str) -> KeyringResult<KeyMetadata> {
        let path = self.keystore_path(name);

        if !path.exists() {
            return Err(KeyringError::KeyNotFound(name.to_string()));
        }

        let keystore = EncryptedKeystore::load(&path)?;

        Ok(KeyMetadata {
            name: name.to_string(),
            key_type: "encrypted".to_string(), // We don't store key type in EIP-2335
            pubkey: keystore.pubkey().to_string(),
            description: keystore.description().map(|s| s.to_string()),
            path: keystore.path().map(|s| s.to_string()),
        })
    }

    fn key_exists(&self, name: &str) -> bool {
        self.keystore_path(name).exists()
    }

    fn backend_type(&self) -> KeyringBackend {
        KeyringBackend::File
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use tempfile::TempDir;

    #[test]
    fn test_file_keyring_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let keyring = FileKeyring::new(temp_dir.path()).unwrap();

        let metadata = KeyMetadata::new("test_key", "ed25519", "0xabc123")
            .with_description("Test key")
            .with_path("m/12381/8888/0/0");

        let secret = vec![0xAB; 32];
        let passphrase = "test-passphrase-123";

        // Store
        keyring
            .store_key(&metadata, &secret, Some(passphrase))
            .unwrap();

        // Verify file exists
        assert!(keyring.key_exists("test_key"));

        // Retrieve
        let retrieved = keyring.get_key("test_key", Some(passphrase)).unwrap();
        assert_eq!(retrieved.expose_secret(), &secret);

        // Get metadata
        let loaded_metadata = keyring.get_metadata("test_key").unwrap();
        assert_eq!(loaded_metadata.pubkey, "0xabc123");
        assert_eq!(loaded_metadata.description, Some("Test key".to_string()));

        // List keys
        let keys = keyring.list_keys().unwrap();
        assert!(keys.contains(&"test_key".to_string()));

        // Delete
        keyring.delete_key("test_key").unwrap();
        assert!(!keyring.key_exists("test_key"));
    }

    #[test]
    fn test_file_keyring_wrong_passphrase() {
        let temp_dir = TempDir::new().unwrap();
        let keyring = FileKeyring::new(temp_dir.path()).unwrap();

        let metadata = KeyMetadata::new("test_key", "ed25519", "0xabc123");
        let secret = vec![0xAB; 32];

        keyring
            .store_key(&metadata, &secret, Some("correct-passphrase"))
            .unwrap();

        let result = keyring.get_key("test_key", Some("wrong-passphrase"));
        assert!(result.is_err());
    }

    #[test]
    fn test_file_keyring_key_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let keyring = FileKeyring::new(temp_dir.path()).unwrap();

        let result = keyring.get_key("nonexistent", Some("passphrase"));
        assert!(matches!(result, Err(KeyringError::KeyNotFound(_))));
    }

    #[test]
    fn test_file_keyring_requires_passphrase() {
        let temp_dir = TempDir::new().unwrap();
        let keyring = FileKeyring::new(temp_dir.path()).unwrap();

        let metadata = KeyMetadata::new("test_key", "ed25519", "0xabc123");
        let secret = vec![0xAB; 32];

        let result = keyring.store_key(&metadata, &secret, None);
        assert!(matches!(result, Err(KeyringError::PassphraseRequired)));
    }

    #[test]
    #[cfg(unix)]
    fn test_file_keyring_directory_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().unwrap();
        let keyring_path = temp_dir.path().join("new_keyring");

        let _keyring = FileKeyring::new(&keyring_path).unwrap();

        let metadata = fs::metadata(&keyring_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "directory should have 0700 permissions");
    }
}
