//! Test keyring backend - UNENCRYPTED storage for development only
//!
//! **WARNING**: This backend stores keys in PLAINTEXT. Never use in production!
//!
//! Keys are stored as simple JSON files without encryption. This is useful for:
//! - Local development
//! - CI/CD testing
//! - Quick debugging
//!
//! The backend will print a warning every time it's used.

use std::fs;
use std::path::{Path, PathBuf};

use secrecy::SecretBox;
use serde::{Deserialize, Serialize};

use super::error::{KeyringError, KeyringResult};
use super::{KeyMetadata, KeyringBackend, KeyringBackendTrait};
use crate::secure::SecretBytes;

/// Plaintext key storage format
#[derive(Debug, Serialize, Deserialize)]
struct PlaintextKeystore {
    /// Key name
    name: String,
    /// Key type (e.g., "ed25519", "bls12-381")
    key_type: String,
    /// Public key in hex
    pubkey: String,
    /// Secret key in hex (PLAINTEXT!)
    secret_hex: String,
    /// Optional description
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    /// Optional derivation path
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    /// Warning marker
    #[serde(default)]
    warning: String,
}

/// Test keyring backend - stores keys in PLAINTEXT
///
/// **WARNING**: This backend provides NO encryption. Keys are stored as
/// plain hex strings in JSON files. Only use for development and testing!
pub struct TestKeyring {
    /// Base directory for storing keystores
    base_path: PathBuf,
}

impl TestKeyring {
    /// Create a new test keyring
    ///
    /// Prints a warning about the insecure nature of this backend.
    pub fn new(base_path: &Path) -> KeyringResult<Self> {
        eprintln!();
        eprintln!("╔════════════════════════════════════════════════════════════╗");
        eprintln!("║  WARNING: Using 'test' keyring backend - KEYS NOT ENCRYPTED ║");
        eprintln!("║  This is NOT safe for production use!                       ║");
        eprintln!("╚════════════════════════════════════════════════════════════╝");
        eprintln!();

        if !base_path.exists() {
            fs::create_dir_all(base_path)?;
        }

        Ok(Self {
            base_path: base_path.to_path_buf(),
        })
    }

    /// Get the keystore file path for a key name
    fn keystore_path(&self, name: &str) -> PathBuf {
        self.base_path.join(format!("{}.test.json", name))
    }
}

impl KeyringBackendTrait for TestKeyring {
    fn store_key(
        &self,
        metadata: &KeyMetadata,
        secret: &[u8],
        _passphrase: Option<&str>,
    ) -> KeyringResult<()> {
        let path = self.keystore_path(&metadata.name);

        let keystore = PlaintextKeystore {
            name: metadata.name.clone(),
            key_type: metadata.key_type.clone(),
            pubkey: metadata.pubkey.clone(),
            secret_hex: hex::encode(secret),
            description: metadata.description.clone(),
            path: metadata.path.clone(),
            warning: "PLAINTEXT KEY - NOT ENCRYPTED - FOR TESTING ONLY".to_string(),
        };

        let json = serde_json::to_string_pretty(&keystore)?;
        fs::write(&path, json)?;

        Ok(())
    }

    fn get_key(&self, name: &str, _passphrase: Option<&str>) -> KeyringResult<SecretBytes> {
        let path = self.keystore_path(name);

        if !path.exists() {
            return Err(KeyringError::KeyNotFound(name.to_string()));
        }

        let contents = fs::read_to_string(&path)?;
        let keystore: PlaintextKeystore = serde_json::from_str(&contents)?;

        let secret_bytes =
            hex::decode(&keystore.secret_hex).map_err(|e| KeyringError::HexError(e.to_string()))?;

        Ok(SecretBox::new(Box::new(secret_bytes)))
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

            if path.is_file() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.ends_with(".test.json") {
                        let key_name = name.trim_end_matches(".test.json");
                        keys.push(key_name.to_string());
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

        let contents = fs::read_to_string(&path)?;
        let keystore: PlaintextKeystore = serde_json::from_str(&contents)?;

        Ok(KeyMetadata {
            name: keystore.name,
            key_type: keystore.key_type,
            pubkey: keystore.pubkey,
            description: keystore.description,
            path: keystore.path,
        })
    }

    fn key_exists(&self, name: &str) -> bool {
        self.keystore_path(name).exists()
    }

    fn backend_type(&self) -> KeyringBackend {
        KeyringBackend::Test
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use tempfile::TempDir;

    #[test]
    fn test_test_keyring_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let keyring = TestKeyring::new(temp_dir.path()).unwrap();

        let metadata = KeyMetadata::new("test_key", "ed25519", "0xabc123")
            .with_description("Test key")
            .with_path("m/12381/8888/0/0");

        let secret = vec![0xAB; 32];

        // Store (no passphrase needed)
        keyring.store_key(&metadata, &secret, None).unwrap();

        // Verify file exists
        assert!(keyring.key_exists("test_key"));

        // Retrieve
        let retrieved = keyring.get_key("test_key", None).unwrap();
        assert_eq!(retrieved.expose_secret(), &secret);

        // Get metadata
        let loaded_metadata = keyring.get_metadata("test_key").unwrap();
        assert_eq!(loaded_metadata.pubkey, "0xabc123");
        assert_eq!(loaded_metadata.key_type, "ed25519");

        // List keys
        let keys = keyring.list_keys().unwrap();
        assert!(keys.contains(&"test_key".to_string()));

        // Delete
        keyring.delete_key("test_key").unwrap();
        assert!(!keyring.key_exists("test_key"));
    }

    #[test]
    fn test_test_keyring_stores_plaintext() {
        let temp_dir = TempDir::new().unwrap();
        let keyring = TestKeyring::new(temp_dir.path()).unwrap();

        let metadata = KeyMetadata::new("test_key", "ed25519", "0xabc123");
        let secret = vec![0xDE, 0xAD, 0xBE, 0xEF];

        keyring.store_key(&metadata, &secret, None).unwrap();

        // Read the file directly and verify it contains the hex-encoded secret
        let file_path = temp_dir.path().join("test_key.test.json");
        let contents = fs::read_to_string(file_path).unwrap();

        // Should contain the hex-encoded secret in plaintext
        assert!(contents.contains("deadbeef"));
        // Should contain the warning
        assert!(contents.contains("PLAINTEXT"));
    }

    #[test]
    fn test_test_keyring_key_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let keyring = TestKeyring::new(temp_dir.path()).unwrap();

        let result = keyring.get_key("nonexistent", None);
        assert!(matches!(result, Err(KeyringError::KeyNotFound(_))));
    }
}
