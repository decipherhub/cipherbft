//! ABCI client implementation.
//!
//! Provides async client for communicating with ABCI applications
//! using the ABCI 2.0 protocol.

use tendermint_proto::v0_38::abci::{
    RequestCheckTx, RequestCommit, RequestFinalizeBlock, RequestInfo, RequestInitChain,
    RequestPrepareProposal, RequestProcessProposal, RequestQuery, ResponseCheckTx,
    ResponseCommit, ResponseFinalizeBlock, ResponseInfo, ResponseInitChain,
    ResponsePrepareProposal, ResponseProcessProposal, ResponseQuery,
};

/// ABCI client error types.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// IO error during transport.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// Codec error during message encoding/decoding.
    #[error("Codec error: {0}")]
    Codec(String),
    /// Connection error.
    #[error("Connection error: {0}")]
    Connection(String),
    /// Request timeout.
    #[error("Request timeout")]
    Timeout,
    /// Application error.
    #[error("Application error: {0}")]
    Application(String),
}

/// Result type for ABCI client operations.
pub type ClientResult<T> = Result<T, ClientError>;

/// ABCI client trait for consensus connection.
///
/// This trait defines the ABCI 2.0 interface for consensus-related
/// operations between the blockchain engine and the application.
#[async_trait::async_trait]
pub trait ABCIClient: Send + Sync {
    /// Get information about the application state.
    ///
    /// Used on startup to sync the consensus engine with the application.
    async fn info(&mut self, request: RequestInfo) -> ClientResult<ResponseInfo>;

    /// Initialize the blockchain with validators and app state.
    ///
    /// Called once when the blockchain starts from genesis.
    async fn init_chain(&mut self, request: RequestInitChain) -> ClientResult<ResponseInitChain>;

    /// Prepare a proposal for a new block.
    ///
    /// Allows the application to modify transactions before proposing.
    async fn prepare_proposal(
        &mut self,
        request: RequestPrepareProposal,
    ) -> ClientResult<ResponsePrepareProposal>;

    /// Process a proposed block.
    ///
    /// Validates a block proposal from another validator.
    async fn process_proposal(
        &mut self,
        request: RequestProcessProposal,
    ) -> ClientResult<ResponseProcessProposal>;

    /// Finalize a block that has been committed.
    ///
    /// Executes transactions and updates application state.
    async fn finalize_block(
        &mut self,
        request: RequestFinalizeBlock,
    ) -> ClientResult<ResponseFinalizeBlock>;

    /// Commit the current state.
    ///
    /// Persists the application state and returns app hash.
    async fn commit(&mut self, request: RequestCommit) -> ClientResult<ResponseCommit>;

    /// Check a transaction for validity.
    ///
    /// Used by mempool to validate transactions before broadcasting.
    async fn check_tx(&mut self, request: RequestCheckTx) -> ClientResult<ResponseCheckTx>;

    /// Query the application state.
    ///
    /// Allows querying application data without modifying state.
    async fn query(&mut self, request: RequestQuery) -> ClientResult<ResponseQuery>;
}

use crate::codec::ABCICodec;
use crate::transport::{ConnectionConfig, Transport};
use futures::{SinkExt, StreamExt};
use std::time::Duration;
use tendermint_proto::v0_38::abci::{request, response, Request, Response};
use tokio::time::timeout;
use tokio_util::codec::Framed;
use tracing::{debug, info, warn};

/// ABCI client implementation with automatic reconnection.
pub struct DefaultABCIClient {
    config: ConnectionConfig,
    connection: Option<Framed<Transport, ABCICodec>>,
    reconnect_attempts: usize,
}

impl DefaultABCIClient {
    /// Create a new ABCI client with the given configuration.
    pub fn new(config: ConnectionConfig) -> Self {
        Self {
            config,
            connection: None,
            reconnect_attempts: 0,
        }
    }

    /// Connect to the ABCI application.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection fails.
    pub async fn connect(&mut self) -> ClientResult<()> {
        let transport = timeout(
            Duration::from_secs(self.config.timeout_secs),
            self.config.connect(),
        )
        .await
        .map_err(|_| ClientError::Timeout)?
        .map_err(ClientError::Io)?;

        let framed = Framed::new(transport, ABCICodec::new());
        self.connection = Some(framed);
        self.reconnect_attempts = 0;

        info!(
            address = %self.config.address,
            "Connected to ABCI application"
        );

        Ok(())
    }

    /// Attempt to reconnect if disconnected.
    async fn ensure_connected(&mut self) -> ClientResult<()> {
        if self.connection.is_some() {
            return Ok(());
        }

        if !self.config.auto_reconnect {
            return Err(ClientError::Connection("Not connected".to_string()));
        }

        if self.config.max_reconnect_attempts > 0
            && self.reconnect_attempts >= self.config.max_reconnect_attempts
        {
            return Err(ClientError::Connection(format!(
                "Max reconnection attempts ({}) exceeded",
                self.config.max_reconnect_attempts
            )));
        }

        self.reconnect_attempts += 1;
        warn!(
            attempt = self.reconnect_attempts,
            max_attempts = self.config.max_reconnect_attempts,
            "Reconnecting to ABCI application"
        );

        // Exponential backoff
        let backoff = Duration::from_secs(2u64.pow(self.reconnect_attempts.min(5) as u32));
        tokio::time::sleep(backoff).await;

        self.connect().await
    }

    /// Send a request and receive a response.
    async fn send_request(&mut self, request: Request) -> ClientResult<Response> {
        self.ensure_connected().await?;

        let connection = self
            .connection
            .as_mut()
            .ok_or_else(|| ClientError::Connection("Not connected".to_string()))?;

        // Send request
        connection
            .send(request)
            .await
            .map_err(ClientError::Io)?;

        // Receive response
        let response = connection
            .next()
            .await
            .ok_or_else(|| ClientError::Connection("Connection closed".to_string()))?
            .map_err(|e| {
                // Connection error, clear the connection for reconnection
                self.connection = None;
                ClientError::Io(e)
            })?;

        Ok(response)
    }

}

#[async_trait::async_trait]
impl ABCIClient for DefaultABCIClient {
    async fn info(&mut self, request: RequestInfo) -> ClientResult<ResponseInfo> {
        debug!("Sending Info request");
        let req = Request {
            value: Some(request::Value::Info(request)),
        };
        let response = self.send_request(req).await?;
        match response.value {
            Some(response::Value::Info(r)) => Ok(r),
            _ => Err(ClientError::Codec("Expected Info response".to_string())),
        }
    }

    async fn init_chain(&mut self, request: RequestInitChain) -> ClientResult<ResponseInitChain> {
        debug!("Sending InitChain request");
        let req = Request {
            value: Some(request::Value::InitChain(request)),
        };
        let response = self.send_request(req).await?;
        match response.value {
            Some(response::Value::InitChain(r)) => Ok(r),
            _ => Err(ClientError::Codec("Expected InitChain response".to_string())),
        }
    }

    async fn prepare_proposal(
        &mut self,
        request: RequestPrepareProposal,
    ) -> ClientResult<ResponsePrepareProposal> {
        debug!("Sending PrepareProposal request");
        let req = Request {
            value: Some(request::Value::PrepareProposal(request)),
        };
        let response = self.send_request(req).await?;
        match response.value {
            Some(response::Value::PrepareProposal(r)) => Ok(r),
            _ => Err(ClientError::Codec("Expected PrepareProposal response".to_string())),
        }
    }

    async fn process_proposal(
        &mut self,
        request: RequestProcessProposal,
    ) -> ClientResult<ResponseProcessProposal> {
        debug!("Sending ProcessProposal request");
        let req = Request {
            value: Some(request::Value::ProcessProposal(request)),
        };
        let response = self.send_request(req).await?;
        match response.value {
            Some(response::Value::ProcessProposal(r)) => Ok(r),
            _ => Err(ClientError::Codec("Expected ProcessProposal response".to_string())),
        }
    }

    async fn finalize_block(
        &mut self,
        request: RequestFinalizeBlock,
    ) -> ClientResult<ResponseFinalizeBlock> {
        debug!(height = request.height, "Sending FinalizeBlock request");
        let req = Request {
            value: Some(request::Value::FinalizeBlock(request)),
        };
        let response = self.send_request(req).await?;
        match response.value {
            Some(response::Value::FinalizeBlock(r)) => Ok(r),
            _ => Err(ClientError::Codec("Expected FinalizeBlock response".to_string())),
        }
    }

    async fn commit(&mut self, request: RequestCommit) -> ClientResult<ResponseCommit> {
        debug!("Sending Commit request");
        let req = Request {
            value: Some(request::Value::Commit(request)),
        };
        let response = self.send_request(req).await?;
        match response.value {
            Some(response::Value::Commit(r)) => Ok(r),
            _ => Err(ClientError::Codec("Expected Commit response".to_string())),
        }
    }

    async fn check_tx(&mut self, request: RequestCheckTx) -> ClientResult<ResponseCheckTx> {
        debug!("Sending CheckTx request");
        let req = Request {
            value: Some(request::Value::CheckTx(request)),
        };
        let response = self.send_request(req).await?;
        match response.value {
            Some(response::Value::CheckTx(r)) => Ok(r),
            _ => Err(ClientError::Codec("Expected CheckTx response".to_string())),
        }
    }

    async fn query(&mut self, request: RequestQuery) -> ClientResult<ResponseQuery> {
        debug!(path = %request.path, "Sending Query request");
        let req = Request {
            value: Some(request::Value::Query(request)),
        };
        let response = self.send_request(req).await?;
        match response.value {
            Some(response::Value::Query(r)) => Ok(r),
            _ => Err(ClientError::Codec("Expected Query response".to_string())),
        }
    }
}
