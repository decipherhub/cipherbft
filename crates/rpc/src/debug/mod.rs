//! Debug namespace RPC API implementation.
//!
//! Provides debugging and tracing functionality:
//! - `debug_traceTransaction` - Trace a transaction execution
//! - `debug_traceCall` - Trace a call without executing on-chain
//! - `debug_traceBlockByNumber` - Trace all transactions in a block
//! - `debug_traceBlockByHash` - Trace all transactions in a block by hash

use std::sync::Arc;

use alloy_primitives::B256;
use cipherbft_execution::{TraceOptions, TraceResult};
use jsonrpsee::core::RpcResult as JsonRpcResult;
use jsonrpsee::proc_macros::rpc;
use tracing::{debug, trace};

use crate::config::RpcConfig;
use crate::error::RpcError;
use crate::eth::CallRequest;
use crate::traits::{BlockNumberOrTag, DebugExecutionApi, RpcStorage};

/// Debug namespace RPC trait.
#[rpc(server, namespace = "debug")]
pub trait DebugRpc {
    /// Returns trace of a transaction execution.
    #[method(name = "traceTransaction")]
    async fn trace_transaction(
        &self,
        tx_hash: B256,
        options: Option<TraceOptions>,
    ) -> JsonRpcResult<TraceResult>;

    /// Executes a call and returns the trace.
    #[method(name = "traceCall")]
    async fn trace_call(
        &self,
        call_request: CallRequest,
        block: Option<String>,
        options: Option<TraceOptions>,
    ) -> JsonRpcResult<TraceResult>;

    /// Returns traces for all transactions in a block.
    #[method(name = "traceBlockByNumber")]
    async fn trace_block_by_number(
        &self,
        block: String,
        options: Option<TraceOptions>,
    ) -> JsonRpcResult<Vec<TraceResult>>;

    /// Returns traces for all transactions in a block by hash.
    #[method(name = "traceBlockByHash")]
    async fn trace_block_by_hash(
        &self,
        block_hash: B256,
        options: Option<TraceOptions>,
    ) -> JsonRpcResult<Vec<TraceResult>>;
}

/// Debug namespace RPC handler.
pub struct DebugApi<S, D>
where
    S: RpcStorage,
    D: DebugExecutionApi,
{
    /// Storage interface.
    storage: Arc<S>,
    /// Debug execution interface.
    debug_executor: Arc<D>,
    /// RPC configuration.
    #[allow(dead_code)]
    config: Arc<RpcConfig>,
}

impl<S, D> DebugApi<S, D>
where
    S: RpcStorage,
    D: DebugExecutionApi,
{
    /// Create a new DebugApi instance.
    pub fn new(storage: Arc<S>, debug_executor: Arc<D>, config: Arc<RpcConfig>) -> Self {
        Self {
            storage,
            debug_executor,
            config,
        }
    }

    /// Parse a block number or tag from a string.
    fn parse_block_number(
        &self,
        block: Option<String>,
    ) -> Result<BlockNumberOrTag, jsonrpsee::types::ErrorObjectOwned> {
        match block.as_deref() {
            None | Some("latest") => Ok(BlockNumberOrTag::Latest),
            Some("earliest") => Ok(BlockNumberOrTag::Earliest),
            Some("pending") => Ok(BlockNumberOrTag::Pending),
            Some("safe") => Ok(BlockNumberOrTag::Safe),
            Some("finalized") => Ok(BlockNumberOrTag::Finalized),
            Some(s) => {
                let num = if let Some(hex_str) = s.strip_prefix("0x") {
                    u64::from_str_radix(hex_str, 16).map_err(|_| {
                        RpcError::InvalidParams(format!("Invalid block number: {}", s))
                    })?
                } else {
                    s.parse::<u64>().map_err(|_| {
                        RpcError::InvalidParams(format!("Invalid block number: {}", s))
                    })?
                };
                Ok(BlockNumberOrTag::Number(num))
            }
        }
    }

    /// Convert internal RpcError to jsonrpsee ErrorObjectOwned.
    fn to_json_rpc_error(err: RpcError) -> jsonrpsee::types::ErrorObjectOwned {
        err.into()
    }

    /// Get default tracer config based on options.
    #[allow(dead_code)]
    fn get_tracer_type(options: &Option<TraceOptions>) -> TracerType {
        match options.as_ref().and_then(|o| o.tracer.as_deref()) {
            Some("callTracer") => TracerType::Call,
            Some("prestateTracer") => TracerType::Prestate,
            _ => TracerType::StructLogs, // Default to opcode tracing
        }
    }
}

/// Type of tracer to use.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
enum TracerType {
    /// Call tracer (tracks call stack).
    Call,
    /// Opcode tracer (struct logs).
    StructLogs,
    /// Prestate tracer (state diff).
    Prestate,
}

#[async_trait::async_trait]
impl<S, D> DebugRpcServer for DebugApi<S, D>
where
    S: RpcStorage + 'static,
    D: DebugExecutionApi + 'static,
{
    async fn trace_transaction(
        &self,
        tx_hash: B256,
        options: Option<TraceOptions>,
    ) -> JsonRpcResult<TraceResult> {
        debug!("debug_traceTransaction: hash={}", tx_hash);

        // Get the transaction
        let tx = self
            .storage
            .get_transaction_by_hash(tx_hash)
            .await
            .map_err(Self::to_json_rpc_error)?
            .ok_or_else(|| RpcError::NotFound(format!("Transaction {} not found", tx_hash)))?;

        // Get the block containing this transaction
        let block_hash = tx
            .block_hash
            .ok_or_else(|| RpcError::Internal("Transaction has no block hash".to_string()))?;

        let block = self
            .storage
            .get_block_by_hash(block_hash, true)
            .await
            .map_err(Self::to_json_rpc_error)?
            .ok_or_else(|| RpcError::Internal(format!("Block {} not found", block_hash)))?;

        let block_number = block.header.number;

        self.debug_executor
            .trace_transaction(tx_hash, BlockNumberOrTag::Number(block_number), options)
            .await
            .map_err(Self::to_json_rpc_error)
    }

    async fn trace_call(
        &self,
        call_request: CallRequest,
        block: Option<String>,
        options: Option<TraceOptions>,
    ) -> JsonRpcResult<TraceResult> {
        trace!("debug_traceCall: {:?}, block={:?}", call_request, block);

        let block_num = self.parse_block_number(block)?;

        self.debug_executor
            .trace_call(
                call_request.from,
                call_request.to,
                call_request.gas.map(|g| g.to::<u64>()),
                call_request.gas_price,
                call_request.value,
                call_request.data,
                block_num,
                options,
            )
            .await
            .map_err(Self::to_json_rpc_error)
    }

    async fn trace_block_by_number(
        &self,
        block: String,
        options: Option<TraceOptions>,
    ) -> JsonRpcResult<Vec<TraceResult>> {
        debug!("debug_traceBlockByNumber: block={}", block);

        let block_num = self.parse_block_number(Some(block))?;

        self.debug_executor
            .trace_block(block_num, options)
            .await
            .map_err(Self::to_json_rpc_error)
    }

    async fn trace_block_by_hash(
        &self,
        block_hash: B256,
        options: Option<TraceOptions>,
    ) -> JsonRpcResult<Vec<TraceResult>> {
        debug!("debug_traceBlockByHash: hash={}", block_hash);

        // Get block number from hash
        let block = self
            .storage
            .get_block_by_hash(block_hash, false)
            .await
            .map_err(Self::to_json_rpc_error)?
            .ok_or_else(|| RpcError::Internal(format!("Block {} not found", block_hash)))?;

        let block_number = block.header.number;

        self.debug_executor
            .trace_block(BlockNumberOrTag::Number(block_number), options)
            .await
            .map_err(Self::to_json_rpc_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracer_type_default() {
        assert!(matches!(
            DebugApi::<crate::adapters::StubRpcStorage, crate::adapters::StubDebugExecutionApi>::get_tracer_type(&None),
            TracerType::StructLogs
        ));
    }

    #[test]
    fn test_tracer_type_call_tracer() {
        let options = Some(TraceOptions {
            tracer: Some("callTracer".to_string()),
            ..Default::default()
        });
        assert!(matches!(
            DebugApi::<crate::adapters::StubRpcStorage, crate::adapters::StubDebugExecutionApi>::get_tracer_type(&options),
            TracerType::Call
        ));
    }
}
