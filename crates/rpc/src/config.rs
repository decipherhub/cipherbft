//! RPC server configuration.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};

/// RPC namespace enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RpcNamespace {
    /// Ethereum namespace (eth_*)
    #[default]
    Eth,
    /// Web3 namespace (web3_*)
    Web3,
    /// Network namespace (net_*)
    Net,
}

/// RPC server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RpcConfig {
    /// HTTP server port (default: 8545).
    pub http_port: u16,

    /// WebSocket server port (default: 8546).
    pub ws_port: u16,

    /// Bind address (default: 0.0.0.0).
    pub bind_addr: IpAddr,

    /// Maximum concurrent connections (default: 100).
    pub max_connections: u32,

    /// Rate limit: requests per second per IP (default: 1000).
    pub rate_limit_per_ip: u32,

    /// Rate limit burst size (default: 100).
    pub rate_limit_burst: u32,

    /// Optional IP allowlist. If None, all IPs are allowed.
    pub ip_allowlist: Option<Vec<IpAddr>>,

    /// Enabled RPC namespaces.
    pub enabled_namespaces: Vec<RpcNamespace>,

    /// Maximum block range for eth_getLogs queries (default: 10000).
    pub max_logs_block_range: u64,

    /// Chain ID for eth_chainId responses.
    pub chain_id: u64,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            http_port: 8545,
            ws_port: 8546,
            bind_addr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            max_connections: 100,
            rate_limit_per_ip: 1000,
            rate_limit_burst: 100,
            ip_allowlist: None,
            enabled_namespaces: vec![RpcNamespace::Eth, RpcNamespace::Web3, RpcNamespace::Net],
            max_logs_block_range: 10_000,
            chain_id: 85300, // CipherBFT testnet chain ID
        }
    }
}

impl RpcConfig {
    /// Create a new RpcConfig with the given chain ID.
    pub fn with_chain_id(chain_id: u64) -> Self {
        Self {
            chain_id,
            ..Default::default()
        }
    }

    /// Get the HTTP server socket address.
    pub fn http_addr(&self) -> std::net::SocketAddr {
        std::net::SocketAddr::new(self.bind_addr, self.http_port)
    }

    /// Get the WebSocket server socket address.
    pub fn ws_addr(&self) -> std::net::SocketAddr {
        std::net::SocketAddr::new(self.bind_addr, self.ws_port)
    }

    /// Check if a namespace is enabled.
    pub fn is_namespace_enabled(&self, ns: RpcNamespace) -> bool {
        self.enabled_namespaces.contains(&ns)
    }

    /// Check if an IP is allowed (returns true if no allowlist is configured).
    pub fn is_ip_allowed(&self, ip: &IpAddr) -> bool {
        match &self.ip_allowlist {
            Some(allowlist) => allowlist.contains(ip),
            None => true,
        }
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.http_port == 0 {
            return Err("HTTP port must be > 0".to_string());
        }
        if self.ws_port == 0 {
            return Err("WebSocket port must be > 0".to_string());
        }
        if self.http_port == self.ws_port {
            return Err("HTTP and WebSocket ports must be different".to_string());
        }
        if self.max_connections == 0 {
            return Err("max_connections must be > 0".to_string());
        }
        if self.rate_limit_per_ip == 0 {
            return Err("rate_limit_per_ip must be > 0".to_string());
        }
        if self.enabled_namespaces.is_empty() {
            return Err("At least one namespace must be enabled".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = RpcConfig::default();
        assert_eq!(config.http_port, 8545);
        assert_eq!(config.ws_port, 8546);
        assert_eq!(config.rate_limit_per_ip, 1000);
        assert_eq!(config.max_logs_block_range, 10_000);
        assert!(config.ip_allowlist.is_none());
    }

    #[test]
    fn test_config_validation() {
        let mut config = RpcConfig::default();
        assert!(config.validate().is_ok());

        config.http_port = 0;
        assert!(config.validate().is_err());

        config.http_port = 8545;
        config.ws_port = 8545;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_ip_allowlist() {
        let mut config = RpcConfig::default();
        let test_ip: IpAddr = "192.168.1.1".parse().unwrap();

        // No allowlist = all allowed
        assert!(config.is_ip_allowed(&test_ip));

        // With allowlist
        config.ip_allowlist = Some(vec!["10.0.0.1".parse().unwrap()]);
        assert!(!config.is_ip_allowed(&test_ip));
        assert!(config.is_ip_allowed(&"10.0.0.1".parse().unwrap()));
    }
}
