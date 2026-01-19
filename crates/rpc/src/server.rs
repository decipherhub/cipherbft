//! RPC server implementation managing HTTP and WebSocket transports.

use std::net::SocketAddr;
use std::sync::Arc;

use jsonrpsee::server::{ServerBuilder, ServerHandle};
use jsonrpsee::RpcModule;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::config::RpcConfig;
use crate::error::RpcResult;
use crate::eth::{EthApi, EthRpcServer};
use crate::net::{NetApi, NetRpcServer};
use crate::pubsub::{EthPubSubApi, EthPubSubRpcServer, SubscriptionManager};
use crate::traits::{ExecutionApi, MempoolApi, NetworkApi, RpcStorage};
use crate::web3::{Web3Api, Web3RpcServer};

/// RPC server state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerState {
    /// Server is stopped.
    Stopped,
    /// Server is starting.
    Starting,
    /// Server is running.
    Running,
    /// Server is stopping.
    Stopping,
}

/// RPC server managing HTTP and WebSocket endpoints.
pub struct RpcServer<S, M, E, N>
where
    S: RpcStorage + 'static,
    M: MempoolApi + 'static,
    E: ExecutionApi + 'static,
    N: NetworkApi + 'static,
{
    /// Server configuration.
    config: Arc<RpcConfig>,
    /// Storage interface.
    storage: Arc<S>,
    /// Mempool interface.
    mempool: Arc<M>,
    /// Execution interface.
    executor: Arc<E>,
    /// Network interface.
    network: Arc<N>,
    /// Subscription manager.
    subscription_manager: Arc<SubscriptionManager>,
    /// Current server state.
    state: Arc<RwLock<ServerState>>,
    /// HTTP server handle.
    http_handle: Arc<RwLock<Option<ServerHandle>>>,
    /// WebSocket server handle.
    ws_handle: Arc<RwLock<Option<ServerHandle>>>,
}

impl<S, M, E, N> RpcServer<S, M, E, N>
where
    S: RpcStorage + 'static,
    M: MempoolApi + 'static,
    E: ExecutionApi + 'static,
    N: NetworkApi + 'static,
{
    /// Create a new RPC server.
    pub fn new(
        config: RpcConfig,
        storage: Arc<S>,
        mempool: Arc<M>,
        executor: Arc<E>,
        network: Arc<N>,
    ) -> Self {
        Self {
            config: Arc::new(config),
            storage,
            mempool,
            executor,
            network,
            subscription_manager: Arc::new(SubscriptionManager::default()),
            state: Arc::new(RwLock::new(ServerState::Stopped)),
            http_handle: Arc::new(RwLock::new(None)),
            ws_handle: Arc::new(RwLock::new(None)),
        }
    }

    /// Get the server configuration.
    pub fn config(&self) -> &RpcConfig {
        &self.config
    }

    /// Get the subscription manager.
    pub fn subscription_manager(&self) -> &SubscriptionManager {
        &self.subscription_manager
    }

    /// Get the current server state.
    pub async fn state(&self) -> ServerState {
        *self.state.read().await
    }

    /// Build the RPC module with all registered methods.
    fn build_rpc_module(&self) -> RpcResult<RpcModule<()>> {
        let mut module = RpcModule::new(());

        // Register eth_* namespace
        let eth_api = EthApi::new(
            Arc::clone(&self.storage),
            Arc::clone(&self.mempool),
            Arc::clone(&self.executor),
            Arc::clone(&self.config),
        );
        module.merge(eth_api.into_rpc()).map_err(|e| {
            crate::error::RpcError::Internal(format!("Failed to merge eth module: {}", e))
        })?;
        info!("Registered eth_* namespace");

        // Register net_* namespace
        let net_api = NetApi::new(Arc::clone(&self.network), self.config.chain_id);
        module.merge(net_api.into_rpc()).map_err(|e| {
            crate::error::RpcError::Internal(format!("Failed to merge net module: {}", e))
        })?;
        info!("Registered net_* namespace");

        // Register web3_* namespace
        let web3_api = Web3Api::new();
        module.merge(web3_api.into_rpc()).map_err(|e| {
            crate::error::RpcError::Internal(format!("Failed to merge web3 module: {}", e))
        })?;
        info!("Registered web3_* namespace");

        // Register eth pubsub (WebSocket subscriptions)
        let pubsub_api = EthPubSubApi::new(Arc::clone(&self.subscription_manager));
        module.merge(pubsub_api.into_rpc()).map_err(|e| {
            crate::error::RpcError::Internal(format!("Failed to merge pubsub module: {}", e))
        })?;
        info!("Registered eth pubsub (eth_subscribe, eth_unsubscribe)");

        Ok(module)
    }

    /// Start the RPC server.
    pub async fn start(&self) -> RpcResult<()> {
        // Validate config first
        self.config
            .validate()
            .map_err(crate::error::RpcError::Internal)?;

        // Update state
        {
            let mut state = self.state.write().await;
            if *state != ServerState::Stopped {
                return Err(crate::error::RpcError::Internal(
                    "Server is not in stopped state".to_string(),
                ));
            }
            *state = ServerState::Starting;
        }

        // Build the RPC module with all handlers
        let module = self.build_rpc_module()?;

        // Start HTTP server
        let http_addr = self.config.http_addr();
        match self.start_http_server(http_addr, module.clone()).await {
            Ok(handle) => {
                info!("HTTP RPC server started on {}", http_addr);
                *self.http_handle.write().await = Some(handle);
            }
            Err(e) => {
                warn!("Failed to start HTTP server: {}", e);
                *self.state.write().await = ServerState::Stopped;
                return Err(crate::error::RpcError::Internal(format!(
                    "Failed to start HTTP server: {}",
                    e
                )));
            }
        }

        // Start WebSocket server
        let ws_addr = self.config.ws_addr();
        match self.start_ws_server(ws_addr, module).await {
            Ok(handle) => {
                info!("WebSocket RPC server started on {}", ws_addr);
                *self.ws_handle.write().await = Some(handle);
            }
            Err(e) => {
                warn!("Failed to start WebSocket server: {}", e);
                // Don't fail startup if WS fails - HTTP is still running
            }
        }

        // Update state to running
        *self.state.write().await = ServerState::Running;
        Ok(())
    }

    /// Start the HTTP server.
    async fn start_http_server(
        &self,
        addr: SocketAddr,
        module: RpcModule<()>,
    ) -> Result<ServerHandle, String> {
        let server = ServerBuilder::default()
            .max_connections(self.config.max_connections)
            .build(addr)
            .await
            .map_err(|e| {
                format!(
                    "Failed to bind HTTP RPC server to {}. \
                     Port {} may already be in use. \
                     Check with: lsof -i :{} (error: {})",
                    addr,
                    addr.port(),
                    addr.port(),
                    e
                )
            })?;

        let handle = server.start(module);
        Ok(handle)
    }

    /// Start the WebSocket server.
    async fn start_ws_server(
        &self,
        addr: SocketAddr,
        module: RpcModule<()>,
    ) -> Result<ServerHandle, String> {
        let server = ServerBuilder::default()
            .max_connections(self.config.max_connections)
            .ws_only()
            .build(addr)
            .await
            .map_err(|e| {
                format!(
                    "Failed to bind WebSocket RPC server to {}. \
                     Port {} may already be in use. \
                     Check with: lsof -i :{} (error: {})",
                    addr,
                    addr.port(),
                    addr.port(),
                    e
                )
            })?;

        let handle = server.start(module);
        Ok(handle)
    }

    /// Stop the RPC server.
    pub async fn stop(&self) -> RpcResult<()> {
        {
            let mut state = self.state.write().await;
            if *state != ServerState::Running {
                return Ok(());
            }
            *state = ServerState::Stopping;
        }

        // Stop HTTP server
        if let Some(handle) = self.http_handle.write().await.take() {
            handle.stop().map_err(|e| {
                crate::error::RpcError::Internal(format!("Failed to stop HTTP server: {:?}", e))
            })?;
            info!("HTTP RPC server stopped");
        }

        // Stop WebSocket server
        if let Some(handle) = self.ws_handle.write().await.take() {
            handle.stop().map_err(|e| {
                crate::error::RpcError::Internal(format!("Failed to stop WS server: {:?}", e))
            })?;
            info!("WebSocket RPC server stopped");
        }

        *self.state.write().await = ServerState::Stopped;
        Ok(())
    }
}
