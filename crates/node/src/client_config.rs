//! Client configuration (Cosmos SDK style)
//!
//! This module provides a `client.toml` configuration file for storing
//! user preferences and defaults for CLI commands. It follows the Cosmos SDK
//! pattern where client-side settings are separate from node configuration.
//!
//! # Configuration File Location
//!
//! The client configuration is stored at `{home}/config/client.toml`.
//!
//! # Example client.toml
//!
//! ```toml
//! # The network chain ID
//! chain-id = "cipherbft-1"
//!
//! # The keyring's backend (file|os|test)
//! keyring-backend = "file"
//!
//! # Directory for keyring storage
//! keyring-dir = ""
//!
//! # Default key name for signing transactions
//! keyring-default-keyname = "default"
//!
//! # CLI output format (text|json)
//! output = "text"
//!
//! # <host>:<port> to node RPC interface
//! node = "tcp://localhost:26657"
//!
//! # Transaction broadcasting mode (sync|async)
//! broadcast-mode = "sync"
//! ```

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Default client configuration filename.
pub const CLIENT_CONFIG_FILENAME: &str = "client.toml";

/// Client configuration for CLI commands (Cosmos SDK style).
///
/// This configuration stores user preferences that persist across CLI invocations,
/// reducing the need to specify common flags repeatedly.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClientConfig {
    /// The network chain ID.
    #[serde(default)]
    pub chain_id: String,

    /// The keyring backend for key storage (file|os|test).
    ///
    /// - `file`: EIP-2335 encrypted keystores (default, most secure)
    /// - `os`: Operating system's native keyring
    /// - `test`: Unencrypted storage (development only!)
    #[serde(default = "default_keyring_backend")]
    pub keyring_backend: String,

    /// Directory for keyring storage.
    ///
    /// If empty, uses the default: `{home}/keys`
    #[serde(default)]
    pub keyring_dir: String,

    /// Default key name for signing transactions.
    ///
    /// When the `--from` flag is not specified, this key is used.
    #[serde(default = "default_keyring_default_keyname")]
    pub keyring_default_keyname: String,

    /// CLI output format (text|json).
    #[serde(default = "default_output")]
    pub output: String,

    /// Node RPC endpoint (`<host>:<port>`).
    #[serde(default = "default_node")]
    pub node: String,

    /// Transaction broadcasting mode (sync|async).
    #[serde(default = "default_broadcast_mode")]
    pub broadcast_mode: String,
}

fn default_keyring_backend() -> String {
    "file".to_string()
}

fn default_keyring_default_keyname() -> String {
    "default".to_string()
}

fn default_output() -> String {
    "text".to_string()
}

fn default_node() -> String {
    "tcp://localhost:26657".to_string()
}

fn default_broadcast_mode() -> String {
    "sync".to_string()
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            chain_id: String::new(),
            keyring_backend: default_keyring_backend(),
            keyring_dir: String::new(),
            keyring_default_keyname: default_keyring_default_keyname(),
            output: default_output(),
            node: default_node(),
            broadcast_mode: default_broadcast_mode(),
        }
    }
}

impl ClientConfig {
    /// Create a new client configuration with the given chain ID.
    pub fn new(chain_id: &str) -> Self {
        Self {
            chain_id: chain_id.to_string(),
            ..Default::default()
        }
    }

    /// Get the path to the client config file.
    pub fn config_path(home: &Path) -> PathBuf {
        home.join("config").join(CLIENT_CONFIG_FILENAME)
    }

    /// Load client configuration from file.
    ///
    /// If the file doesn't exist, returns default configuration.
    pub fn load(home: &Path) -> Result<Self> {
        let config_path = Self::config_path(home);

        if !config_path.exists() {
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(&config_path)
            .with_context(|| format!("Failed to read client config: {}", config_path.display()))?;

        toml::from_str(&content)
            .with_context(|| format!("Failed to parse client config: {}", config_path.display()))
    }

    /// Save client configuration to file.
    pub fn save(&self, home: &Path) -> Result<()> {
        let config_path = Self::config_path(home);

        // Ensure config directory exists
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create config directory: {}", parent.display())
            })?;
        }

        let content = toml::to_string_pretty(self).context("Failed to serialize client config")?;

        std::fs::write(&config_path, content)
            .with_context(|| format!("Failed to write client config: {}", config_path.display()))?;

        Ok(())
    }

    /// Resolve the effective keyring directory.
    ///
    /// Returns in order of precedence:
    /// 1. `keyring_dir` from config (if non-empty)
    /// 2. Default: `{home}/keys`
    pub fn effective_keyring_dir(&self, home: &Path) -> PathBuf {
        if self.keyring_dir.is_empty() {
            home.join("keys")
        } else {
            PathBuf::from(&self.keyring_dir)
        }
    }

    /// Resolve the effective key name.
    ///
    /// Returns the default key name from config, or "default" if not set.
    pub fn effective_key_name(&self) -> &str {
        if self.keyring_default_keyname.is_empty() {
            "default"
        } else {
            &self.keyring_default_keyname
        }
    }

    /// Resolve the effective keyring backend.
    pub fn effective_keyring_backend(&self) -> &str {
        if self.keyring_backend.is_empty() {
            "file"
        } else {
            &self.keyring_backend
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_default_config() {
        let config = ClientConfig::default();
        assert_eq!(config.keyring_backend, "file");
        assert_eq!(config.keyring_default_keyname, "default");
        assert_eq!(config.output, "text");
        assert_eq!(config.broadcast_mode, "sync");
    }

    #[test]
    fn test_save_and_load() {
        let temp_dir = tempdir().unwrap();
        let home = temp_dir.path();

        let config = ClientConfig {
            chain_id: "test-chain-1".to_string(),
            keyring_backend: "test".to_string(),
            keyring_dir: "/custom/keys".to_string(),
            keyring_default_keyname: "mykey".to_string(),
            output: "json".to_string(),
            node: "tcp://localhost:9000".to_string(),
            broadcast_mode: "async".to_string(),
        };

        config.save(home).unwrap();

        let loaded = ClientConfig::load(home).unwrap();
        assert_eq!(loaded.chain_id, "test-chain-1");
        assert_eq!(loaded.keyring_backend, "test");
        assert_eq!(loaded.keyring_dir, "/custom/keys");
        assert_eq!(loaded.keyring_default_keyname, "mykey");
    }

    #[test]
    fn test_load_missing_file_returns_default() {
        let temp_dir = tempdir().unwrap();
        let home = temp_dir.path();

        let config = ClientConfig::load(home).unwrap();
        assert_eq!(config.keyring_backend, "file");
    }

    #[test]
    fn test_effective_keyring_dir() {
        let config = ClientConfig::default();
        let home = PathBuf::from("/home/user/.cipherd");

        // Default: uses home/keys
        assert_eq!(
            config.effective_keyring_dir(&home),
            PathBuf::from("/home/user/.cipherd/keys")
        );

        // Custom: uses specified path
        let config_custom = ClientConfig {
            keyring_dir: "/custom/keys".to_string(),
            ..Default::default()
        };
        assert_eq!(
            config_custom.effective_keyring_dir(&home),
            PathBuf::from("/custom/keys")
        );
    }

    #[test]
    fn test_toml_format() {
        let config = ClientConfig::new("cipherbft-1");
        let toml_str = toml::to_string_pretty(&config).unwrap();

        // Verify kebab-case keys
        assert!(toml_str.contains("chain-id"));
        assert!(toml_str.contains("keyring-backend"));
        assert!(toml_str.contains("keyring-default-keyname"));
        assert!(toml_str.contains("broadcast-mode"));
    }
}
