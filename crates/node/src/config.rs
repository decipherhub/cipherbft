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

/// Exit code for configuration errors requiring user action.
///
/// This follows the sysexits.h convention where 78 = EX_CONFIG.
/// Used when plaintext keys are detected and migration is required.
pub const EXIT_CONFIG_ERROR: i32 = 78;

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
/// Keys can be provided either via:
/// - `keystore_dir`: Path to directory containing EIP-2335 encrypted keystores (recommended)
/// - `bls_secret_key_hex` + `ed25519_secret_key_hex`: Plaintext keys (deprecated, migration required)
///
/// If both are present, `keystore_dir` takes precedence and a warning is logged.
/// If plaintext keys are detected and `keystore_dir` is not set, the node will exit
/// with code 78 (EX_CONFIG) and print migration instructions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// This node's validator ID
    pub validator_id: ValidatorId,

    /// Directory containing EIP-2335 encrypted keystores (recommended).
    ///
    /// Expected structure:
    /// ```text
    /// {keystore_dir}/
    ///   validator_0/
    ///     consensus.json     # Ed25519 keystore
    ///     data_chain.json    # BLS keystore
    ///     validator_info.json
    /// ```
    ///
    /// If not set, defaults to `{data_dir}/keys` or `~/.cipherd/keys`.
    #[serde(default)]
    pub keystore_dir: Option<PathBuf>,

    /// Account index within the keystore directory (default: 0).
    ///
    /// Used to select which validator's keys to load when multiple
    /// validators exist in the keystore directory.
    #[serde(default)]
    pub keystore_account: Option<u32>,

    /// BLS secret key (hex encoded) - **DEPRECATED**
    ///
    /// Use `keystore_dir` instead. This field is only for backwards compatibility
    /// and migration. The node will refuse to start if this field is present
    /// without `keystore_dir` being set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bls_secret_key_hex: Option<String>,

    /// Ed25519 secret key (hex encoded) for Consensus Layer - **DEPRECATED**
    ///
    /// Use `keystore_dir` instead. This field is only for backwards compatibility
    /// and migration. The node will refuse to start if this field is present
    /// without `keystore_dir` being set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ed25519_secret_key_hex: Option<String>,

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
}

impl NodeConfig {
    /// Create a test configuration for local testing
    ///
    /// NOTE: This uses plaintext keys for testing convenience. Production
    /// deployments should use `keystore_dir` with encrypted keystores.
    pub fn for_local_test(index: usize, _total: usize) -> Self {
        let bls_keypair = BlsKeyPair::generate(&mut rand::thread_rng());
        let ed25519_keypair = Ed25519KeyPair::generate(&mut rand::thread_rng());
        let validator_id = crate::util::validator_id_from_bls(&bls_keypair.public_key);

        let base_port = 9000 + (index * 10) as u16;

        let home_dir = PathBuf::from(format!("/tmp/cipherd-{}", index));
        Self {
            validator_id,
            keystore_dir: None,
            keystore_account: None,
            // Use plaintext keys for testing (not recommended for production)
            bls_secret_key_hex: Some(hex::encode(bls_keypair.secret_key.to_bytes())),
            ed25519_secret_key_hex: Some(hex::encode(ed25519_keypair.secret_key.to_bytes())),
            primary_listen: format!("127.0.0.1:{}", base_port).parse().unwrap(),
            consensus_listen: format!("127.0.0.1:{}", base_port + 5).parse().unwrap(),
            worker_listens: vec![format!("127.0.0.1:{}", base_port + 1).parse().unwrap()],
            peers: Vec::new(), // Will be populated after all nodes are created
            num_workers: 1,
            home_dir: Some(home_dir.clone()),
            data_dir: home_dir.join("data"),
            genesis_path: None, // Uses default: {home_dir}/config/genesis.json
            car_interval_ms: 100,
            max_batch_txs: 100,
            max_batch_bytes: 1024 * 1024, // 1MB
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

    /// Check if plaintext keys are present in the configuration.
    ///
    /// Returns `true` if either `bls_secret_key_hex` or `ed25519_secret_key_hex`
    /// is set in the configuration. This is used to detect configurations that
    /// need migration to keystore-based storage.
    pub fn has_plaintext_keys(&self) -> bool {
        self.bls_secret_key_hex.is_some() || self.ed25519_secret_key_hex.is_some()
    }

    /// Check if keystore-based key storage is configured.
    pub fn has_keystore_config(&self) -> bool {
        self.keystore_dir.is_some()
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

    /// Generate BLS keypair from config (plaintext mode).
    ///
    /// # Errors
    ///
    /// Returns an error if `bls_secret_key_hex` is not set or is invalid.
    ///
    /// # Deprecated
    ///
    /// Use keystore-based key loading instead of plaintext keys.
    pub fn keypair(&self) -> Result<BlsKeyPair, anyhow::Error> {
        let secret_hex = self
            .bls_secret_key_hex
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("bls_secret_key_hex not set in config"))?;
        let secret_bytes = hex::decode(secret_hex)?;
        if secret_bytes.len() != 32 {
            anyhow::bail!(
                "BLS secret key must be 32 bytes, got {}",
                secret_bytes.len()
            );
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&secret_bytes);
        let secret_key = cipherbft_crypto::BlsSecretKey::from_bytes(&arr)
            .map_err(|e| anyhow::anyhow!("Invalid BLS secret key: {:?}", e))?;
        Ok(BlsKeyPair::from_secret_key(secret_key))
    }

    /// Generate Ed25519 keypair from config (plaintext mode).
    ///
    /// # Errors
    ///
    /// Returns an error if `ed25519_secret_key_hex` is not set or is invalid.
    ///
    /// # Deprecated
    ///
    /// Use keystore-based key loading instead of plaintext keys.
    pub fn ed25519_keypair(&self) -> Result<Ed25519KeyPair, anyhow::Error> {
        let secret_hex = self
            .ed25519_secret_key_hex
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("ed25519_secret_key_hex not set in config"))?;
        let secret_bytes = hex::decode(secret_hex)?;
        if secret_bytes.len() != 32 {
            anyhow::bail!(
                "Ed25519 secret key must be 32 bytes, got {}",
                secret_bytes.len()
            );
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&secret_bytes);
        // Ed25519SecretKey::from_bytes returns Self, not Result
        let secret_key = cipherbft_crypto::Ed25519SecretKey::from_bytes(&arr);
        Ok(Ed25519KeyPair::from_secret_key(secret_key))
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
pub fn generate_local_configs(n: usize) -> Vec<NodeConfig> {
    let mut configs: Vec<NodeConfig> = (0..n).map(|i| NodeConfig::for_local_test(i, n)).collect();

    // Populate peer lists with full public key information
    // We need to derive public keys from each config's secret keys
    let peer_infos: Vec<_> = configs
        .iter()
        .map(|c| {
            // Derive BLS public key from secret key
            let bls_keypair = c.keypair().expect("valid BLS keypair in config");
            let bls_pubkey_hex = hex::encode(bls_keypair.public_key.to_bytes());

            // Derive Ed25519 public key from secret key
            let ed25519_keypair = c
                .ed25519_keypair()
                .expect("valid Ed25519 keypair in config");
            let ed25519_pubkey_hex = hex::encode(ed25519_keypair.public_key.to_bytes());

            PeerConfig {
                validator_id: hex::encode(c.validator_id.as_bytes()),
                bls_public_key_hex: bls_pubkey_hex,
                ed25519_public_key_hex: ed25519_pubkey_hex,
                primary_addr: c.primary_listen,
                consensus_addr: c.consensus_listen,
                worker_addrs: c.worker_listens.clone(),
            }
        })
        .collect();

    for (i, config) in configs.iter_mut().enumerate() {
        // Add all other validators as peers
        config.peers = peer_infos
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, p)| p.clone())
            .collect();
    }

    configs
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

        let config = NodeConfig::for_local_test(0, 1);
        // Default path is {home_dir}/config/genesis.json
        let expected = config
            .home_dir
            .as_ref()
            .unwrap()
            .join("config")
            .join(DEFAULT_GENESIS_FILENAME);
        assert_eq!(config.effective_genesis_path(), expected);
    }

    #[test]
    fn test_effective_genesis_path_configured() {
        let _guard = ENV_MUTEX.lock().unwrap();
        // Ensure env var is not set
        env::remove_var(CIPHERD_GENESIS_PATH_ENV);

        let mut config = NodeConfig::for_local_test(0, 1);
        let custom_path = PathBuf::from("/custom/genesis.json");
        config.genesis_path = Some(custom_path.clone());

        assert_eq!(config.effective_genesis_path(), custom_path);
    }

    #[test]
    fn test_effective_genesis_path_env_override() {
        let _guard = ENV_MUTEX.lock().unwrap();

        let env_path = "/env/override/genesis.json";
        env::set_var(CIPHERD_GENESIS_PATH_ENV, env_path);

        let mut config = NodeConfig::for_local_test(0, 1);
        // Even with configured path, env var takes precedence
        config.genesis_path = Some(PathBuf::from("/custom/genesis.json"));

        let result = config.effective_genesis_path();

        // Clean up env var before assertion (so it's cleaned even if assertion fails)
        env::remove_var(CIPHERD_GENESIS_PATH_ENV);

        assert_eq!(result, PathBuf::from(env_path));
    }

    #[test]
    fn test_genesis_path_field_optional_in_serde() {
        // Test that genesis_path is optional in JSON (backwards compatibility)
        // Also test backwards compatibility with old plaintext key format
        let json = r#"{
            "validator_id": "0000000000000000000000000000000000000000",
            "bls_secret_key_hex": "0000000000000000000000000000000000000000000000000000000000000001",
            "ed25519_secret_key_hex": "0000000000000000000000000000000000000000000000000000000000000001",
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
        assert!(config.keystore_dir.is_none());
        // Plaintext keys should be parsed
        assert!(config.has_plaintext_keys());
    }

    #[test]
    fn test_genesis_path_serialization() {
        let mut config = NodeConfig::for_local_test(0, 1);
        config.genesis_path = Some(PathBuf::from("/custom/genesis.json"));

        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("genesis_path"));
        assert!(json.contains("/custom/genesis.json"));
    }

    #[test]
    fn test_has_plaintext_keys() {
        let config = NodeConfig::for_local_test(0, 1);
        // for_local_test creates plaintext keys
        assert!(config.has_plaintext_keys());
        assert!(!config.has_keystore_config());
    }

    #[test]
    fn test_keystore_config() {
        let mut config = NodeConfig::for_local_test(0, 1);
        assert!(!config.has_keystore_config());

        config.keystore_dir = Some(PathBuf::from("/path/to/keys"));
        assert!(config.has_keystore_config());
    }

    #[test]
    fn test_effective_keystore_dir_default() {
        let config = NodeConfig::for_local_test(0, 1);
        let expected = config.data_dir.join(DEFAULT_KEYS_DIR);
        assert_eq!(config.effective_keystore_dir(), expected);
    }

    #[test]
    fn test_effective_keystore_dir_configured() {
        let mut config = NodeConfig::for_local_test(0, 1);
        let custom_path = PathBuf::from("/custom/keys");
        config.keystore_dir = Some(custom_path.clone());
        assert_eq!(config.effective_keystore_dir(), custom_path);
    }

    #[test]
    fn test_keystore_account_default() {
        let config = NodeConfig::for_local_test(0, 1);
        assert_eq!(config.effective_keystore_account(), 0);
    }

    #[test]
    fn test_keystore_account_configured() {
        let mut config = NodeConfig::for_local_test(0, 1);
        config.keystore_account = Some(5);
        assert_eq!(config.effective_keystore_account(), 5);
    }

    #[test]
    fn test_config_without_plaintext_keys() {
        // Config with keystore_dir but no plaintext keys
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
        assert!(!config.has_plaintext_keys());
        assert!(config.has_keystore_config());
        assert_eq!(
            config.effective_keystore_dir(),
            PathBuf::from("/path/to/keys")
        );
    }

    #[test]
    fn test_plaintext_keys_not_serialized_when_none() {
        let mut config = NodeConfig::for_local_test(0, 1);
        // Clear plaintext keys
        config.bls_secret_key_hex = None;
        config.ed25519_secret_key_hex = None;
        config.keystore_dir = Some(PathBuf::from("/path/to/keys"));

        let json = serde_json::to_string(&config).unwrap();
        // Plaintext key fields should not be present
        assert!(!json.contains("bls_secret_key_hex"));
        assert!(!json.contains("ed25519_secret_key_hex"));
        // Keystore dir should be present
        assert!(json.contains("keystore_dir"));
    }
}
