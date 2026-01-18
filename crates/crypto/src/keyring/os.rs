//! OS Native Keyring Backend
//!
//! This backend uses the operating system's native credential storage:
//! - macOS: Keychain
//! - Windows: Credential Manager
//! - Linux: Secret Service (GNOME Keyring, KWallet, etc.)
//!
//! Requires the `keychain` feature to be enabled.

use std::collections::HashMap;
use std::sync::RwLock;

use keyring::Entry;
use secrecy::SecretBox;
use serde::{Deserialize, Serialize};

use super::error::{KeyringError, KeyringResult};
use super::{KeyMetadata, KeyringBackend, KeyringBackendTrait};
use crate::secure::SecretBytes;

/// Service name used for OS keyring entries
const SERVICE_NAME: &str = "cipherbft-validator";

/// Metadata stored alongside the secret in OS keyring
#[derive(Debug, Serialize, Deserialize)]
struct StoredMetadata {
    key_type: String,
    pubkey: String,
    description: Option<String>,
    path: Option<String>,
}

/// OS native keyring backend
///
/// Uses the operating system's credential store for secure key storage.
/// The OS handles authentication (biometrics, password prompt, etc.).
pub struct OsKeyring {
    /// In-memory cache of known key names (OS keyring doesn't support listing)
    known_keys: RwLock<HashMap<String, StoredMetadata>>,
}

impl OsKeyring {
    /// Create a new OS keyring backend
    pub fn new() -> KeyringResult<Self> {
        // Try to access the keyring to verify it's available
        let test_entry = Entry::new(SERVICE_NAME, "__cipherbft_test__")
            .map_err(|e| KeyringError::OsKeyringError(e.to_string()))?;

        // Try to delete any stale test entry (ignore errors)
        let _ = test_entry.delete_credential();

        Ok(Self {
            known_keys: RwLock::new(HashMap::new()),
        })
    }

    /// Get keyring entry for a key name
    fn get_entry(&self, name: &str) -> KeyringResult<Entry> {
        Entry::new(SERVICE_NAME, name).map_err(|e| KeyringError::OsKeyringError(e.to_string()))
    }

    /// Get metadata entry for a key name
    fn get_metadata_entry(&self, name: &str) -> KeyringResult<Entry> {
        Entry::new(SERVICE_NAME, &format!("{}_metadata", name))
            .map_err(|e| KeyringError::OsKeyringError(e.to_string()))
    }
}

impl KeyringBackendTrait for OsKeyring {
    fn store_key(
        &self,
        metadata: &KeyMetadata,
        secret: &[u8],
        _passphrase: Option<&str>,
    ) -> KeyringResult<()> {
        // Store the secret
        let entry = self.get_entry(&metadata.name)?;
        let secret_hex = hex::encode(secret);
        entry
            .set_password(&secret_hex)
            .map_err(|e| KeyringError::OsKeyringError(e.to_string()))?;

        // Store metadata separately
        let stored_metadata = StoredMetadata {
            key_type: metadata.key_type.clone(),
            pubkey: metadata.pubkey.clone(),
            description: metadata.description.clone(),
            path: metadata.path.clone(),
        };

        let metadata_entry = self.get_metadata_entry(&metadata.name)?;
        let metadata_json = serde_json::to_string(&stored_metadata)?;
        metadata_entry
            .set_password(&metadata_json)
            .map_err(|e| KeyringError::OsKeyringError(e.to_string()))?;

        // Update known keys cache
        if let Ok(mut known_keys) = self.known_keys.write() {
            known_keys.insert(metadata.name.clone(), stored_metadata);
        }

        Ok(())
    }

    fn get_key(&self, name: &str, _passphrase: Option<&str>) -> KeyringResult<SecretBytes> {
        let entry = self.get_entry(name)?;

        let secret_hex = entry.get_password().map_err(|e| match e {
            keyring::Error::NoEntry => KeyringError::KeyNotFound(name.to_string()),
            _ => KeyringError::OsKeyringError(e.to_string()),
        })?;

        let secret_bytes =
            hex::decode(&secret_hex).map_err(|e| KeyringError::HexError(e.to_string()))?;

        Ok(SecretBox::new(Box::new(secret_bytes)))
    }

    fn delete_key(&self, name: &str) -> KeyringResult<()> {
        // Delete the secret
        let entry = self.get_entry(name)?;
        entry.delete_credential().map_err(|e| match e {
            keyring::Error::NoEntry => KeyringError::KeyNotFound(name.to_string()),
            _ => KeyringError::OsKeyringError(e.to_string()),
        })?;

        // Delete metadata (ignore errors if it doesn't exist)
        let metadata_entry = self.get_metadata_entry(name)?;
        let _ = metadata_entry.delete_credential();

        // Update known keys cache
        if let Ok(mut known_keys) = self.known_keys.write() {
            known_keys.remove(name);
        }

        Ok(())
    }

    fn list_keys(&self) -> KeyringResult<Vec<String>> {
        // OS keyrings don't support listing, so we return cached keys
        // This is a limitation - keys stored by other processes won't be listed
        let known_keys = self
            .known_keys
            .read()
            .map_err(|e| KeyringError::OsKeyringError(e.to_string()))?;

        let mut keys: Vec<String> = known_keys.keys().cloned().collect();
        keys.sort();
        Ok(keys)
    }

    fn get_metadata(&self, name: &str) -> KeyringResult<KeyMetadata> {
        let metadata_entry = self.get_metadata_entry(name)?;

        let metadata_json = metadata_entry.get_password().map_err(|e| match e {
            keyring::Error::NoEntry => KeyringError::KeyNotFound(name.to_string()),
            _ => KeyringError::OsKeyringError(e.to_string()),
        })?;

        let stored: StoredMetadata = serde_json::from_str(&metadata_json)?;

        Ok(KeyMetadata {
            name: name.to_string(),
            key_type: stored.key_type,
            pubkey: stored.pubkey,
            description: stored.description,
            path: stored.path,
        })
    }

    fn key_exists(&self, name: &str) -> bool {
        if let Ok(entry) = self.get_entry(name) {
            entry.get_password().is_ok()
        } else {
            false
        }
    }

    fn backend_type(&self) -> KeyringBackend {
        KeyringBackend::Os
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests require a working OS keyring
    // They may fail in CI environments without proper setup

    #[test]
    #[ignore = "requires OS keyring access"]
    fn test_os_keyring_roundtrip() {
        let keyring = OsKeyring::new().unwrap();

        let metadata = KeyMetadata::new("cipherbft_test_key", "ed25519", "0xabc123")
            .with_description("Test key for CI");

        let secret = vec![0xAB; 32];

        // Clean up any existing test key
        let _ = keyring.delete_key("cipherbft_test_key");

        // Store
        keyring.store_key(&metadata, &secret, None).unwrap();

        // Verify exists
        assert!(keyring.key_exists("cipherbft_test_key"));

        // Retrieve
        let retrieved = keyring.get_key("cipherbft_test_key", None).unwrap();
        use secrecy::ExposeSecret;
        assert_eq!(retrieved.expose_secret(), &secret);

        // Get metadata
        let loaded_metadata = keyring.get_metadata("cipherbft_test_key").unwrap();
        assert_eq!(loaded_metadata.pubkey, "0xabc123");

        // Clean up
        keyring.delete_key("cipherbft_test_key").unwrap();
        assert!(!keyring.key_exists("cipherbft_test_key"));
    }
}
