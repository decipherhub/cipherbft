//! Keyring Backend Abstraction for CipherBFT
//!
//! This module provides a unified interface for storing and retrieving validator keys
//! across different storage backends, similar to Cosmos SDK's keyring system.
//!
//! # Available Backends
//!
//! - **file**: EIP-2335 encrypted keystores (default, most secure for production)
//! - **os**: Operating system's native keyring (macOS Keychain, Windows Credential Manager, Linux Secret Service)
//! - **test**: Unencrypted storage for development/testing (NOT for production)
//!
//! # Example
//!
//! ```rust,ignore
//! use cipherbft_crypto::keyring::{KeyringBackend, Keyring};
//!
//! // Create a file-based keyring (production)
//! let keyring = Keyring::new(KeyringBackend::File, "/path/to/keys")?;
//!
//! // Store a key
//! keyring.store_key("validator_0", &secret_bytes, "passphrase")?;
//!
//! // Retrieve a key
//! let secret = keyring.get_key("validator_0", "passphrase")?;
//! ```

pub mod error;
pub mod file;
#[cfg(feature = "keychain")]
pub mod os;
pub mod test;

use std::fmt;
use std::path::Path;
use std::str::FromStr;

pub use error::{KeyringError, KeyringResult};
pub use file::FileKeyring;
#[cfg(feature = "keychain")]
pub use os::OsKeyring;
pub use test::TestKeyring;

use crate::secure::SecretBytes;

/// Keyring backend type
///
/// Determines where and how validator keys are stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyringBackend {
    /// File-based encrypted keystore (EIP-2335 format)
    ///
    /// This is the most secure option for production use. Keys are encrypted
    /// using scrypt KDF + AES-128-CTR and stored as JSON files with restricted
    /// permissions (0600).
    #[default]
    File,

    /// Operating system's native keyring
    ///
    /// Uses the OS credential store:
    /// - macOS: Keychain
    /// - Windows: Credential Manager
    /// - Linux: Secret Service (GNOME Keyring, KWallet)
    ///
    /// Requires the `keychain` feature.
    Os,

    /// Unencrypted storage for testing
    ///
    /// **WARNING**: Keys are stored in plaintext. Only use for development
    /// and testing. Never use in production!
    Test,
}

impl KeyringBackend {
    /// Get all available backend names
    pub fn variants() -> &'static [&'static str] {
        &["file", "os", "test"]
    }

    /// Check if this backend requires a passphrase
    pub fn requires_passphrase(&self) -> bool {
        match self {
            KeyringBackend::File => true,
            KeyringBackend::Os => false, // OS keyring handles its own auth
            KeyringBackend::Test => false,
        }
    }

    /// Check if this backend is safe for production use
    pub fn is_production_safe(&self) -> bool {
        match self {
            KeyringBackend::File => true,
            KeyringBackend::Os => true,
            KeyringBackend::Test => false,
        }
    }
}

impl fmt::Display for KeyringBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyringBackend::File => write!(f, "file"),
            KeyringBackend::Os => write!(f, "os"),
            KeyringBackend::Test => write!(f, "test"),
        }
    }
}

impl FromStr for KeyringBackend {
    type Err = KeyringError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "file" => Ok(KeyringBackend::File),
            "os" => Ok(KeyringBackend::Os),
            "test" => Ok(KeyringBackend::Test),
            _ => Err(KeyringError::InvalidBackend(s.to_string())),
        }
    }
}

/// Key metadata stored alongside the secret
#[derive(Debug, Clone)]
pub struct KeyMetadata {
    /// Unique identifier for the key (e.g., "validator_0_consensus")
    pub name: String,
    /// Key type (e.g., "ed25519", "bls12-381")
    pub key_type: String,
    /// Public key in hex format
    pub pubkey: String,
    /// Optional description
    pub description: Option<String>,
    /// Optional derivation path
    pub path: Option<String>,
}

impl KeyMetadata {
    /// Create new key metadata
    pub fn new(name: &str, key_type: &str, pubkey: &str) -> Self {
        Self {
            name: name.to_string(),
            key_type: key_type.to_string(),
            pubkey: pubkey.to_string(),
            description: None,
            path: None,
        }
    }

    /// Set description
    pub fn with_description(mut self, description: &str) -> Self {
        self.description = Some(description.to_string());
        self
    }

    /// Set derivation path
    pub fn with_path(mut self, path: &str) -> Self {
        self.path = Some(path.to_string());
        self
    }
}

/// Trait for keyring backend implementations
pub trait KeyringBackendTrait: Send + Sync {
    /// Store a secret key with metadata
    ///
    /// # Arguments
    ///
    /// * `metadata` - Key metadata including name, type, and public key
    /// * `secret` - The secret key bytes to store
    /// * `passphrase` - Optional passphrase for encryption (required for some backends)
    fn store_key(
        &self,
        metadata: &KeyMetadata,
        secret: &[u8],
        passphrase: Option<&str>,
    ) -> KeyringResult<()>;

    /// Retrieve a secret key by name
    ///
    /// # Arguments
    ///
    /// * `name` - The key name to retrieve
    /// * `passphrase` - Optional passphrase for decryption
    fn get_key(&self, name: &str, passphrase: Option<&str>) -> KeyringResult<SecretBytes>;

    /// Delete a key by name
    fn delete_key(&self, name: &str) -> KeyringResult<()>;

    /// List all stored key names
    fn list_keys(&self) -> KeyringResult<Vec<String>>;

    /// Get metadata for a key (without decrypting)
    fn get_metadata(&self, name: &str) -> KeyringResult<KeyMetadata>;

    /// Check if a key exists
    fn key_exists(&self, name: &str) -> bool;

    /// Get the backend type
    fn backend_type(&self) -> KeyringBackend;
}

/// Unified keyring interface
///
/// This struct provides a unified interface for all keyring backends.
pub struct Keyring {
    inner: Box<dyn KeyringBackendTrait>,
}

impl Keyring {
    /// Create a new keyring with the specified backend
    ///
    /// # Arguments
    ///
    /// * `backend` - The backend type to use
    /// * `base_path` - Base path for file-based backends
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot be initialized.
    pub fn new(backend: KeyringBackend, base_path: &Path) -> KeyringResult<Self> {
        let inner: Box<dyn KeyringBackendTrait> = match backend {
            KeyringBackend::File => Box::new(FileKeyring::new(base_path)?),
            #[cfg(feature = "keychain")]
            KeyringBackend::Os => Box::new(OsKeyring::new()?),
            #[cfg(not(feature = "keychain"))]
            KeyringBackend::Os => {
                return Err(KeyringError::BackendNotAvailable(
                    "OS keyring requires the 'keychain' feature".to_string(),
                ))
            }
            KeyringBackend::Test => Box::new(TestKeyring::new(base_path)?),
        };

        Ok(Self { inner })
    }

    /// Get the backend type
    pub fn backend(&self) -> KeyringBackend {
        self.inner.backend_type()
    }

    /// Store a secret key with metadata
    pub fn store_key(
        &self,
        metadata: &KeyMetadata,
        secret: &[u8],
        passphrase: Option<&str>,
    ) -> KeyringResult<()> {
        // Validate passphrase requirement
        if self.inner.backend_type().requires_passphrase() && passphrase.is_none() {
            return Err(KeyringError::PassphraseRequired);
        }

        self.inner.store_key(metadata, secret, passphrase)
    }

    /// Retrieve a secret key by name
    pub fn get_key(&self, name: &str, passphrase: Option<&str>) -> KeyringResult<SecretBytes> {
        if self.inner.backend_type().requires_passphrase() && passphrase.is_none() {
            return Err(KeyringError::PassphraseRequired);
        }

        self.inner.get_key(name, passphrase)
    }

    /// Delete a key by name
    pub fn delete_key(&self, name: &str) -> KeyringResult<()> {
        self.inner.delete_key(name)
    }

    /// List all stored key names
    pub fn list_keys(&self) -> KeyringResult<Vec<String>> {
        self.inner.list_keys()
    }

    /// Get metadata for a key (without decrypting)
    pub fn get_metadata(&self, name: &str) -> KeyringResult<KeyMetadata> {
        self.inner.get_metadata(name)
    }

    /// Check if a key exists
    pub fn key_exists(&self, name: &str) -> bool {
        self.inner.key_exists(name)
    }

    /// Check if the current backend is safe for production
    pub fn is_production_safe(&self) -> bool {
        self.inner.backend_type().is_production_safe()
    }
}

impl fmt::Debug for Keyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keyring")
            .field("backend", &self.inner.backend_type())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_from_str() {
        assert_eq!(
            KeyringBackend::from_str("file").unwrap(),
            KeyringBackend::File
        );
        assert_eq!(KeyringBackend::from_str("os").unwrap(), KeyringBackend::Os);
        assert_eq!(
            KeyringBackend::from_str("test").unwrap(),
            KeyringBackend::Test
        );
        assert_eq!(
            KeyringBackend::from_str("FILE").unwrap(),
            KeyringBackend::File
        ); // case insensitive

        assert!(KeyringBackend::from_str("invalid").is_err());
    }

    #[test]
    fn test_backend_display() {
        assert_eq!(KeyringBackend::File.to_string(), "file");
        assert_eq!(KeyringBackend::Os.to_string(), "os");
        assert_eq!(KeyringBackend::Test.to_string(), "test");
    }

    #[test]
    fn test_backend_requires_passphrase() {
        assert!(KeyringBackend::File.requires_passphrase());
        assert!(!KeyringBackend::Os.requires_passphrase());
        assert!(!KeyringBackend::Test.requires_passphrase());
    }

    #[test]
    fn test_backend_production_safe() {
        assert!(KeyringBackend::File.is_production_safe());
        assert!(KeyringBackend::Os.is_production_safe());
        assert!(!KeyringBackend::Test.is_production_safe());
    }

    #[test]
    fn test_key_metadata() {
        let metadata = KeyMetadata::new("my_key", "ed25519", "0xabc123")
            .with_description("Test key")
            .with_path("m/12381/8888/0/0");

        assert_eq!(metadata.name, "my_key");
        assert_eq!(metadata.key_type, "ed25519");
        assert_eq!(metadata.pubkey, "0xabc123");
        assert_eq!(metadata.description, Some("Test key".to_string()));
        assert_eq!(metadata.path, Some("m/12381/8888/0/0".to_string()));
    }
}
