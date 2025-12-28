//! Error types for mempool operations
//!
//! MP-1 단계: 데이터 구조 정의만 유지. Reth PoolError를 감싸고 최소한의
//! BFT 정책 에러만 노출한다.

use reth_transaction_pool::error::PoolError;
use thiserror::Error;

/// Mempool error types (minimal surface for MP-1)
#[derive(Error, Debug)]
pub enum MempoolError {
    /// Bubble up errors coming from the underlying Reth pool.
    #[error(transparent)]
    Pool(#[from] PoolError),

    /// Gas price below policy threshold.
    #[error("Insufficient gas price")]
    InsufficientGasPrice,

    /// Nonce gap exceeds configured maximum.
    #[error("Nonce gap exceeds maximum: gap={gap} > max={max}")]
    NonceGapExceeded { gap: u64, max: u64 },

    /// Internal error marker.
    #[error("Internal error: {0}")]
    Internal(String),
}
