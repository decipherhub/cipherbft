//! Node configuration
//!
//! Supports two modes of key storage:
//! - **Keystore mode** (recommended): Keys stored in EIP-2335 encrypted keystores
//! - **Plaintext mode** (deprecated): Keys stored directly in config (migration required)

use cipherbft_crypto::{BlsKeyPair, Ed25519KeyPair};
use cipherbft_types::ValidatorId;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

/// Environment variable for genesis file path override.
///
/// When set, this environment variable takes precedence over the config file's
/// `genesis_path` field. This enables container-friendly deployments where
/// paths are injected at runtime.
///
/// # Example
///
/// ```bash
/// CIPHERD_GENESIS_PATH=/etc/cipherd/genesis.json cipherd start
/// ```
pub const CIPHERD_GENESIS_PATH_ENV: &str = "CIPHERD_GENESIS_PATH";

/// Environment variable for home directory override.
///
/// When set, this environment variable takes precedence over the default
/// home directory (`~/.cipherd`). This follows the Cosmos SDK convention
/// where each daemon supports a `{DAEMON}_HOME` environment variable.
///
/// # Example
///
/// ```bash
/// export CIPHERD_HOME=/custom/path/cipherd
/// cipherd start
/// ```
pub const CIPHERD_HOME_ENV: &str = "CIPHERD_HOME";

/// Default home directory name (relative to user's home directory).
///
/// The full default path is `~/.cipherd`.
pub const DEFAULT_HOME_DIR: &str = ".cipherd";

/// Default genesis filename.
///
/// The full default path is `{home_dir}/config/genesis.json`.
pub const DEFAULT_GENESIS_FILENAME: &str = "genesis.json";

/// Default keys directory relative to the home directory.
///
/// The full default path is `~/.cipherd/keys`.
pub const DEFAULT_KEYS_DIR: &str = "keys";

/// Default keyring backend.
pub const DEFAULT_KEYRING_BACKEND: &str = "file";

/// Default key name.
pub const DEFAULT_KEY_NAME: &str = "default";

/// Serde default function for keyring_backend
fn default_keyring_backend() -> String {
    DEFAULT_KEYRING_BACKEND.to_string()
}

/// Serde default function for key_name
fn default_key_name() -> String {
    DEFAULT_KEY_NAME.to_string()
}

/// Default RPC HTTP port (Ethereum standard)
pub const DEFAULT_RPC_HTTP_PORT: u16 = 8545;

/// Default RPC WebSocket port (Ethereum standard)
pub const DEFAULT_RPC_WS_PORT: u16 = 8546;

/// Default metrics port (Prometheus standard)
pub const DEFAULT_METRICS_PORT: u16 = 9100;

/// Serde default function for rpc_http_port
fn default_rpc_http_port() -> u16 {
    DEFAULT_RPC_HTTP_PORT
}

/// Serde default function for rpc_ws_port
fn default_rpc_ws_port() -> u16 {
    DEFAULT_RPC_WS_PORT
}

/// Serde default function for metrics_port
fn default_metrics_port() -> u16 {
    DEFAULT_METRICS_PORT
}

/// Default timeout for waiting for cuts after consensus decisions (50ms)
pub const DEFAULT_WAIT_FOR_CUT_TIMEOUT_MS: u64 = 50;

/// Serde default function for wait_for_cut_timeout_ms
fn default_wait_for_cut_timeout_ms() -> u64 {
    DEFAULT_WAIT_FOR_CUT_TIMEOUT_MS
}

/// Peer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    /// Validator ID (20 bytes hex)
    pub validator_id: String,
    /// BLS public key (hex encoded) for DCL layer signatures
    pub bls_public_key_hex: String,
    /// Ed25519 public key (hex encoded) for consensus layer signatures
    pub ed25519_public_key_hex: String,
    /// Primary address for P2P
    pub primary_addr: SocketAddr,
    /// Consensus address for Malachite p2p
    pub consensus_addr: SocketAddr,
    /// Worker addresses for batch sync
    pub worker_addrs: Vec<SocketAddr>,
}

/// Node configuration
///
/// Keys are loaded from the keyring backend specified by `keyring_backend`.
/// For local testing, use `for_local_test()` which returns keypairs separately.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// This node's validator ID (derived from BLS key at runtime for validators).
    ///
    /// This field is optional and will be derived from the BLS key when starting
    /// a validator node. For non-validator nodes, this can remain None.
    #[serde(default)]
    pub validator_id: Option<ValidatorId>,

    /// Keyring backend for key storage.
    ///
    /// - "file": EIP-2335 encrypted keystores (default, recommended)
    /// - "os": OS native keyring (macOS Keychain, Windows Credential Manager)
    /// - "test": Unencrypted storage (development only!)
    #[serde(default = "default_keyring_backend")]
    pub keyring_backend: String,

    /// Name of the key to use for this node.
    ///
    /// This corresponds to the key name used in `cipherd keys add <name>`.
    /// If not set, defaults to "default".
    #[serde(default = "default_key_name")]
    pub key_name: String,

    /// Directory containing keystore files (for file backend).
    ///
    /// Expected structure:
    /// ```text
    /// {keystore_dir}/
    ///   <key_name>/
    ///     ed25519.json       # Ed25519 keystore (consensus/p2p)
    ///     bls.json           # BLS keystore (optional, validators only)
    ///     key_info.json      # Public key info
    /// ```
    ///
    /// If not set, defaults to `{data_dir}/keys` or `~/.cipherd/keys`.
    #[serde(default)]
    pub keystore_dir: Option<PathBuf>,

    /// Account index for HD key derivation (default: 0).
    ///
    /// Used when deriving keys from a mnemonic phrase.
    #[serde(default)]
    pub keystore_account: Option<u32>,

    /// Primary listen address (DCL layer)
    pub primary_listen: SocketAddr,
    /// Consensus listen address (Malachite p2p layer)
    pub consensus_listen: SocketAddr,
    /// Worker listen addresses
    pub worker_listens: Vec<SocketAddr>,
    /// Known peers
    pub peers: Vec<PeerConfig>,
    /// Number of workers
    pub num_workers: usize,
    /// Home directory (e.g., ~/.cipherd)
    ///
    /// This is the root directory containing `config/` and `data/` subdirectories.
    #[serde(default)]
    pub home_dir: Option<PathBuf>,
    /// Data directory
    pub data_dir: PathBuf,
    /// Path to the genesis file.
    ///
    /// Defaults to `{home_dir}/config/genesis.json`. Can be overridden by
    /// the `CIPHERD_GENESIS_PATH` environment variable.
    #[serde(default)]
    pub genesis_path: Option<PathBuf>,
    /// Car creation interval (ms)
    pub car_interval_ms: u64,
    /// Maximum transactions per batch
    pub max_batch_txs: usize,
    /// Maximum batch size in bytes
    pub max_batch_bytes: usize,
    /// Whether to enable the JSON-RPC server
    #[serde(default)]
    pub rpc_enabled: bool,
    /// HTTP JSON-RPC port (default: 8545)
    #[serde(default = "default_rpc_http_port")]
    pub rpc_http_port: u16,
    /// WebSocket JSON-RPC port (default: 8546)
    #[serde(default = "default_rpc_ws_port")]
    pub rpc_ws_port: u16,
    /// Port for Prometheus metrics endpoint (default: 9100)
    #[serde(default = "default_metrics_port")]
    pub metrics_port: u16,

    /// Timeout in milliseconds to wait for the next cut after a consensus decision (default: 50ms).
    ///
    /// After consensus decides on a block, the host waits for the next cut to be
    /// available before starting the next consensus round. This prevents a race
    /// condition where consensus requests a value before DCL has produced the cut.
    ///
    /// Lower values improve block throughput but may cause NIL votes if cuts
    /// aren't ready. Higher values reduce throughput but give DCL more time.
    /// Set to 0 to disable waiting entirely.
    #[serde(default = "default_wait_for_cut_timeout_ms")]
    pub wait_for_cut_timeout_ms: u64,
}

/// Test configuration with keypairs for local testing
#[derive(Debug, Clone)]
pub struct LocalTestConfig {
    /// Node configuration
    pub config: NodeConfig,
    /// BLS keypair for DCL layer
    pub bls_keypair: BlsKeyPair,
    /// Ed25519 keypair for consensus layer
    pub ed25519_keypair: Ed25519KeyPair,
}

impl NodeConfig {
    /// Create a test configuration for local testing
    ///
    /// Returns a `LocalTestConfig` containing the node config along with
    /// the generated keypairs. This is the recommended way to create test
    /// configurations as keys are never stored in plaintext.
    pub fn for_local_test(index: usize, _total: usize) -> LocalTestConfig {
        let bls_keypair = BlsKeyPair::generate(&mut rand::thread_rng());
        let ed25519_keypair = Ed25519KeyPair::generate(&mut rand::thread_rng());
        let validator_id = ed25519_keypair.public_key.validator_id();

        let base_port = 9000 + (index * 10) as u16;

        let home_dir = PathBuf::from(format!("/tmp/cipherd-{}", index));
        let config = Self {
            validator_id: Some(validator_id),
            keyring_backend: "test".to_string(),
            key_name: format!("validator_{}", index),
            keystore_dir: None,
            keystore_account: None,
            primary_listen: format!("127.0.0.1:{}", base_port)
                .parse()
                .expect("test address format is always valid"),
            consensus_listen: format!("127.0.0.1:{}", base_port + 5)
                .parse()
                .expect("test address format is always valid"),
            worker_listens: vec![format!("127.0.0.1:{}", base_port + 1)
                .parse()
                .expect("test address format is always valid")],
            peers: Vec::new(), // Will be populated after all nodes are created
            num_workers: 1,
            home_dir: Some(home_dir.clone()),
            data_dir: home_dir.join("data"),
            genesis_path: None, // Uses default: {home_dir}/config/genesis.json
            car_interval_ms: 100,
            max_batch_txs: 100,
            max_batch_bytes: 1024 * 1024, // 1MB
            rpc_enabled: false,
            rpc_http_port: DEFAULT_RPC_HTTP_PORT + (index as u16),
            rpc_ws_port: DEFAULT_RPC_WS_PORT + (index as u16),
            metrics_port: DEFAULT_METRICS_PORT + (index as u16),
            wait_for_cut_timeout_ms: DEFAULT_WAIT_FOR_CUT_TIMEOUT_MS,
        };

        LocalTestConfig {
            config,
            bls_keypair,
            ed25519_keypair,
        }
    }

    /// Resolve the effective genesis file path.
    ///
    /// Resolution order (highest priority first):
    /// 1. `CIPHERD_GENESIS_PATH` environment variable
    /// 2. `genesis_path` field in config (if set)
    /// 3. Default: `{home_dir}/config/genesis.json`
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let config = NodeConfig::load(&path)?;
    /// let genesis_path = config.effective_genesis_path();
    /// println!("Loading genesis from: {}", genesis_path.display());
    /// ```
    pub fn effective_genesis_path(&self) -> PathBuf {
        // 1. Check environment variable first
        if let Ok(env_path) = std::env::var(CIPHERD_GENESIS_PATH_ENV) {
            return PathBuf::from(env_path);
        }

        // 2. Use configured path if set
        if let Some(ref configured_path) = self.genesis_path {
            return configured_path.clone();
        }

        // 3. Fall back to default: {home_dir}/config/genesis.json
        //    If home_dir is not set, derive it from data_dir's parent
        let home = self.home_dir.clone().unwrap_or_else(|| {
            self.data_dir
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| self.data_dir.clone())
        });
        home.join("config").join(DEFAULT_GENESIS_FILENAME)
    }

    /// Check if key storage is properly configured.
    ///
    /// Returns true if either:
    /// - keystore_dir is set (file backend)
    /// - keyring_backend is "os" or "test" (doesn't require explicit keystore_dir)
    pub fn has_key_config(&self) -> bool {
        self.keystore_dir.is_some()
            || self.keyring_backend == "os"
            || self.keyring_backend == "test"
    }

    /// Get the effective key name.
    pub fn effective_key_name(&self) -> &str {
        &self.key_name
    }

    /// Get the keyring backend string.
    pub fn effective_keyring_backend(&self) -> &str {
        &self.keyring_backend
    }

    /// Resolve the effective keystore directory path.
    ///
    /// Resolution order (highest priority first):
    /// 1. `keystore_dir` field in config (if set)
    /// 2. Default: `{data_dir}/keys`
    pub fn effective_keystore_dir(&self) -> PathBuf {
        if let Some(ref keystore_dir) = self.keystore_dir {
            return keystore_dir.clone();
        }
        self.data_dir.join(DEFAULT_KEYS_DIR)
    }

    /// Get the account index for keystore loading (default: 0).
    pub fn effective_keystore_account(&self) -> u32 {
        self.keystore_account.unwrap_or(0)
    }

    /// Save config to file
    pub fn save(&self, path: &std::path::Path) -> Result<(), anyhow::Error> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Load config from file
    pub fn load(path: &std::path::Path) -> Result<Self, anyhow::Error> {
        let json = std::fs::read_to_string(path)?;
        let config: Self = serde_json::from_str(&json)?;
        Ok(config)
    }
}

/// Generate a new BLS keypair for key management
pub fn generate_keypair() -> BlsKeyPair {
    BlsKeyPair::generate(&mut rand::thread_rng())
}

/// Generate configs for N validators for local testing
///
/// Returns a vector of `LocalTestConfig` containing both the node configurations
/// and their associated keypairs. Peer lists are automatically populated.
pub fn generate_local_configs(n: usize) -> Vec<LocalTestConfig> {
    let mut test_configs: Vec<LocalTestConfig> =
        (0..n).map(|i| NodeConfig::for_local_test(i, n)).collect();

    // Populate peer lists with full public key information
    // Keys are directly available from LocalTestConfig
    let peer_infos: Vec<_> = test_configs
        .iter()
        .map(|tc| {
            let bls_pubkey_hex = hex::encode(tc.bls_keypair.public_key.to_bytes());
            let ed25519_pubkey_hex = hex::encode(tc.ed25519_keypair.public_key.to_bytes());

            PeerConfig {
                validator_id: hex::encode(
                    tc.config
                        .validator_id
                        .expect("validator_id should be set in test config")
                        .as_bytes(),
                ),
                bls_public_key_hex: bls_pubkey_hex,
                ed25519_public_key_hex: ed25519_pubkey_hex,
                primary_addr: tc.config.primary_listen,
                consensus_addr: tc.config.consensus_listen,
                worker_addrs: tc.config.worker_listens.clone(),
            }
        })
        .collect();

    for (i, test_config) in test_configs.iter_mut().enumerate() {
        // Add all other validators as peers
        test_config.config.peers = peer_infos
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, p)| p.clone())
            .collect();
    }

    test_configs
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::Mutex;

    // Mutex to serialize tests that modify environment variables
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn test_effective_genesis_path_default() {
        let _guard = ENV_MUTEX.lock().unwrap();
        // Ensure env var is not set
        env::remove_var(CIPHERD_GENESIS_PATH_ENV);

        let test_config = NodeConfig::for_local_test(0, 1);
        // Default path is {home_dir}/config/genesis.json
        let expected = test_config
            .config
            .home_dir
            .as_ref()
            .unwrap()
            .join("config")
            .join(DEFAULT_GENESIS_FILENAME);
        assert_eq!(test_config.config.effective_genesis_path(), expected);
    }

    #[test]
    fn test_effective_genesis_path_configured() {
        let _guard = ENV_MUTEX.lock().unwrap();
        // Ensure env var is not set
        env::remove_var(CIPHERD_GENESIS_PATH_ENV);

        let mut test_config = NodeConfig::for_local_test(0, 1);
        let custom_path = PathBuf::from("/custom/genesis.json");
        test_config.config.genesis_path = Some(custom_path.clone());

        assert_eq!(test_config.config.effective_genesis_path(), custom_path);
    }

    #[test]
    fn test_effective_genesis_path_env_override() {
        let _guard = ENV_MUTEX.lock().unwrap();

        let env_path = "/env/override/genesis.json";
        env::set_var(CIPHERD_GENESIS_PATH_ENV, env_path);

        let mut test_config = NodeConfig::for_local_test(0, 1);
        // Even with configured path, env var takes precedence
        test_config.config.genesis_path = Some(PathBuf::from("/custom/genesis.json"));

        let result = test_config.config.effective_genesis_path();

        // Clean up env var before assertion (so it's cleaned even if assertion fails)
        env::remove_var(CIPHERD_GENESIS_PATH_ENV);

        assert_eq!(result, PathBuf::from(env_path));
    }

    #[test]
    fn test_genesis_path_field_optional_in_serde() {
        // Test that genesis_path is optional in JSON
        let json = r#"{
            "validator_id": "0000000000000000000000000000000000000000",
            "keystore_dir": "/path/to/keys",
            "primary_listen": "127.0.0.1:9000",
            "consensus_listen": "127.0.0.1:9005",
            "worker_listens": ["127.0.0.1:9001"],
            "peers": [],
            "num_workers": 1,
            "data_dir": "/tmp/cipherd-0",
            "car_interval_ms": 100,
            "max_batch_txs": 100,
            "max_batch_bytes": 1048576
        }"#;

        let config: NodeConfig = serde_json::from_str(json).unwrap();
        assert!(config.genesis_path.is_none());
        assert!(config.has_key_config());
    }

    #[test]
    fn test_genesis_path_serialization() {
        let mut test_config = NodeConfig::for_local_test(0, 1);
        test_config.config.genesis_path = Some(PathBuf::from("/custom/genesis.json"));

        let json = serde_json::to_string(&test_config.config).unwrap();
        assert!(json.contains("genesis_path"));
        assert!(json.contains("/custom/genesis.json"));
    }

    #[test]
    fn test_keystore_config() {
        // Test with "file" backend - no keystore_dir means no key config
        let mut test_config = NodeConfig::for_local_test(0, 1);
        test_config.config.keyring_backend = "file".to_string();
        test_config.config.keystore_dir = None;
        assert!(!test_config.config.has_key_config());

        // File backend with keystore_dir has key config
        test_config.config.keystore_dir = Some(PathBuf::from("/path/to/keys"));
        assert!(test_config.config.has_key_config());

        // Test backend always has key config (uses system keyring, no file path needed)
        test_config.config.keyring_backend = "test".to_string();
        test_config.config.keystore_dir = None;
        assert!(test_config.config.has_key_config());

        // OS backend always has key config (uses system keyring, no file path needed)
        test_config.config.keyring_backend = "os".to_string();
        assert!(test_config.config.has_key_config());
    }

    #[test]
    fn test_effective_keystore_dir_default() {
        let test_config = NodeConfig::for_local_test(0, 1);
        let expected = test_config.config.data_dir.join(DEFAULT_KEYS_DIR);
        assert_eq!(test_config.config.effective_keystore_dir(), expected);
    }

    #[test]
    fn test_effective_keystore_dir_configured() {
        let mut test_config = NodeConfig::for_local_test(0, 1);
        let custom_path = PathBuf::from("/custom/keys");
        test_config.config.keystore_dir = Some(custom_path.clone());
        assert_eq!(test_config.config.effective_keystore_dir(), custom_path);
    }

    #[test]
    fn test_keystore_account_default() {
        let test_config = NodeConfig::for_local_test(0, 1);
        assert_eq!(test_config.config.effective_keystore_account(), 0);
    }

    #[test]
    fn test_keystore_account_configured() {
        let mut test_config = NodeConfig::for_local_test(0, 1);
        test_config.config.keystore_account = Some(5);
        assert_eq!(test_config.config.effective_keystore_account(), 5);
    }

    #[test]
    fn test_config_with_keystore() {
        // Config with keystore_dir
        let json = r#"{
            "validator_id": "0000000000000000000000000000000000000000",
            "keystore_dir": "/path/to/keys",
            "keystore_account": 0,
            "primary_listen": "127.0.0.1:9000",
            "consensus_listen": "127.0.0.1:9005",
            "worker_listens": ["127.0.0.1:9001"],
            "peers": [],
            "num_workers": 1,
            "data_dir": "/tmp/cipherd-0",
            "car_interval_ms": 100,
            "max_batch_txs": 100,
            "max_batch_bytes": 1048576
        }"#;

        let config: NodeConfig = serde_json::from_str(json).unwrap();
        assert!(config.has_key_config());
        assert_eq!(
            config.effective_keystore_dir(),
            PathBuf::from("/path/to/keys")
        );
    }

    #[test]
    fn test_local_test_config_has_keypairs() {
        let test_config = NodeConfig::for_local_test(0, 1);
        // Verify keypairs are generated
        assert_eq!(test_config.bls_keypair.public_key.to_bytes().len(), 48);
        assert_eq!(test_config.ed25519_keypair.public_key.to_bytes().len(), 32);
        // Verify validator ID matches Ed25519 public key
        let expected_validator_id = test_config.ed25519_keypair.public_key.validator_id();
        assert_eq!(test_config.config.validator_id, Some(expected_validator_id));
    }

    #[test]
    fn test_generate_local_configs() {
        let configs = generate_local_configs(3);
        assert_eq!(configs.len(), 3);

        // Each config should have 2 peers (all others)
        for tc in &configs {
            assert_eq!(tc.config.peers.len(), 2);
        }

        // All validator IDs should be unique
        let validator_ids: Vec<_> = configs.iter().map(|tc| tc.config.validator_id).collect();
        for (i, id) in validator_ids.iter().enumerate() {
            for (j, other_id) in validator_ids.iter().enumerate() {
                if i != j {
                    assert_ne!(id, other_id);
                }
            }
        }
    }
}
