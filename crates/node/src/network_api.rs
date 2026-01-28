//! Real NetworkApi implementation backed by TcpPrimaryNetwork.

use std::sync::Arc;

use async_trait::async_trait;
use cipherbft_rpc::{NetworkApi, RpcResult, StubNetworkApi};

use crate::network::TcpPrimaryNetwork;

/// Real NetworkApi backed by TcpPrimaryNetwork.
pub struct TcpNetworkApi {
    network: Arc<TcpPrimaryNetwork>,
}

impl TcpNetworkApi {
    /// Create a new TcpNetworkApi wrapping the given network.
    pub fn new(network: Arc<TcpPrimaryNetwork>) -> Self {
        Self { network }
    }
}

#[async_trait]
impl NetworkApi for TcpNetworkApi {
    async fn peer_count(&self) -> RpcResult<u64> {
        Ok(self.network.connected_peer_count().await as u64)
    }

    async fn is_listening(&self) -> RpcResult<bool> {
        Ok(self.network.is_listening())
    }
}

/// Unified NetworkApi that can be either real (TcpNetworkApi) or stub.
///
/// This enum allows the RpcServer to use a single concrete type while
/// supporting both DCL-enabled and DCL-disabled configurations.
pub enum NodeNetworkApi {
    /// Real implementation backed by TcpPrimaryNetwork (DCL enabled)
    Tcp(TcpNetworkApi),
    /// Stub implementation (DCL disabled)
    Stub(StubNetworkApi),
}

impl NodeNetworkApi {
    /// Create a real NetworkApi backed by TcpPrimaryNetwork.
    pub fn tcp(network: Arc<TcpPrimaryNetwork>) -> Self {
        Self::Tcp(TcpNetworkApi::new(network))
    }

    /// Create a stub NetworkApi.
    pub fn stub() -> Self {
        Self::Stub(StubNetworkApi::new())
    }
}

#[async_trait]
impl NetworkApi for NodeNetworkApi {
    async fn peer_count(&self) -> RpcResult<u64> {
        match self {
            Self::Tcp(api) => api.peer_count().await,
            Self::Stub(api) => api.peer_count().await,
        }
    }

    async fn is_listening(&self) -> RpcResult<bool> {
        match self {
            Self::Tcp(api) => api.is_listening().await,
            Self::Stub(api) => api.is_listening().await,
        }
    }
}
