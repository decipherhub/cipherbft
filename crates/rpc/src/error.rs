//! RPC error types and result aliases.

use jsonrpsee::types::ErrorObjectOwned;
use thiserror::Error;

/// RPC-specific errors.
#[derive(Debug, Error)]
pub enum RpcError {
    /// Internal server error.
    #[error("Internal error: {0}")]
    Internal(String),

    /// Invalid parameters provided.
    #[error("Invalid params: {0}")]
    InvalidParams(String),

    /// Resource not found.
    #[error("Not found: {0}")]
    NotFound(String),

    /// Method not supported.
    #[error("Method not supported: {0}")]
    MethodNotSupported(String),

    /// Rate limit exceeded.
    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    /// Block range too large for eth_getLogs.
    #[error("Block range too large: requested {requested}, max {max}")]
    BlockRangeTooLarge { requested: u64, max: u64 },

    /// Storage error.
    #[error("Storage error: {0}")]
    Storage(String),

    /// Execution error.
    #[error("Execution error: {0}")]
    Execution(String),

    /// Transaction validation error.
    #[error("Transaction error: {0}")]
    Transaction(String),

    /// Resource limit exceeded (e.g., max filters).
    #[error("Resource limit: {0}")]
    ResourceLimit(String),
}

/// RPC result type alias.
pub type RpcResult<T> = Result<T, RpcError>;

impl From<RpcError> for ErrorObjectOwned {
    fn from(err: RpcError) -> Self {
        let (code, message) = match &err {
            RpcError::Internal(msg) => (-32603, format!("Internal error: {}", msg)),
            RpcError::InvalidParams(msg) => (-32602, format!("Invalid params: {}", msg)),
            RpcError::NotFound(msg) => (-32602, format!("Not found: {}", msg)),
            RpcError::MethodNotSupported(msg) => (-32601, format!("Method not found: {}", msg)),
            RpcError::RateLimitExceeded => (-32005, "Rate limit exceeded".to_string()),
            RpcError::BlockRangeTooLarge { requested, max } => (
                -32005,
                format!("Block range too large: {} > {}", requested, max),
            ),
            RpcError::Storage(msg) => (-32603, format!("Storage error: {}", msg)),
            RpcError::Execution(msg) => (-32603, format!("Execution error: {}", msg)),
            RpcError::Transaction(msg) => (-32603, format!("Transaction error: {}", msg)),
            RpcError::ResourceLimit(msg) => (-32005, format!("Resource limit: {}", msg)),
        };

        ErrorObjectOwned::owned(code, message, None::<()>)
    }
}

/// Convert RpcError to jsonrpsee error for RPC handlers.
pub fn internal_error<E: std::fmt::Display>(err: E) -> ErrorObjectOwned {
    RpcError::Internal(err.to_string()).into()
}
