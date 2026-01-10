//! Node configuration

use cipherbft_crypto::{BlsKeyPair, Ed25519KeyPair};
use cipherbft_types::ValidatorId;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

/// Peer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    /// Validator ID (20 bytes hex)
    pub validator_id: String,
    /// Primary address for P2P
    pub primary_addr: SocketAddr,
    /// Worker addresses for batch sync
    pub worker_addrs: Vec<SocketAddr>,
}

/// Node configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// This node's validator ID
    pub validator_id: ValidatorId,
    /// BLS secret key (hex encoded)
    pub bls_secret_key_hex: String,
    /// Ed25519 secret key (hex encoded) for Consensus Layer
    pub ed25519_secret_key_hex: String,
    /// Primary listen address
    pub primary_listen: SocketAddr,
    /// Worker listen addresses
    pub worker_listens: Vec<SocketAddr>,
    /// Known peers
    pub peers: Vec<PeerConfig>,
    /// Number of workers
    pub num_workers: usize,
    /// Data directory
    pub data_dir: PathBuf,
    /// Car creation interval (ms)
    pub car_interval_ms: u64,
    /// Maximum transactions per batch
    pub max_batch_txs: usize,
    /// Maximum batch size in bytes
    pub max_batch_bytes: usize,
}

impl NodeConfig {
    /// Create a test configuration for local testing
    pub fn for_local_test(index: usize, _total: usize) -> Self {
        let bls_keypair = BlsKeyPair::generate(&mut rand::thread_rng());
        let ed25519_keypair = Ed25519KeyPair::generate(&mut rand::thread_rng());
        let validator_id = crate::util::validator_id_from_bls(&bls_keypair.public_key);

        let base_port = 9000 + (index * 10) as u16;

        Self {
            validator_id,
            bls_secret_key_hex: hex::encode(bls_keypair.secret_key.to_bytes()),
            ed25519_secret_key_hex: hex::encode(ed25519_keypair.secret_key.to_bytes()),
            primary_listen: format!("127.0.0.1:{}", base_port).parse().unwrap(),
            worker_listens: vec![format!("127.0.0.1:{}", base_port + 1).parse().unwrap()],
            peers: Vec::new(), // Will be populated after all nodes are created
            num_workers: 1,
            data_dir: PathBuf::from(format!("/tmp/cipherbft-node-{}", index)),
            car_interval_ms: 100,
            max_batch_txs: 100,
            max_batch_bytes: 1024 * 1024, // 1MB
        }
    }

    /// Generate BLS keypair from config
    pub fn keypair(&self) -> Result<BlsKeyPair, anyhow::Error> {
        let secret_bytes = hex::decode(&self.bls_secret_key_hex)?;
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

    /// Generate Ed25519 keypair from config
    pub fn ed25519_keypair(&self) -> Result<Ed25519KeyPair, anyhow::Error> {
        let secret_bytes = hex::decode(&self.ed25519_secret_key_hex)?;
        if secret_bytes.len() != 32 {
            anyhow::bail!(
                "Ed25519 secret key must be 32 bytes, got {}",
                secret_bytes.len()
            );
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&secret_bytes);
        let secret_key = cipherbft_crypto::Ed25519SecretKey::from_bytes(&arr)
            .map_err(|e| anyhow::anyhow!("Invalid Ed25519 secret key: {:?}", e))?;
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

/// Generate configs for N validators for local testing
pub fn generate_local_configs(n: usize) -> Vec<NodeConfig> {
    let mut configs: Vec<NodeConfig> = (0..n).map(|i| NodeConfig::for_local_test(i, n)).collect();

    // Populate peer lists
    let peer_infos: Vec<_> = configs
        .iter()
        .map(|c| PeerConfig {
            validator_id: hex::encode(c.validator_id.as_bytes()),
            primary_addr: c.primary_listen,
            worker_addrs: c.worker_listens.clone(),
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
