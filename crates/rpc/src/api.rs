use alloy_primitives::{keccak256, Address, B256, Bytes, U64};
use alloy_rpc_types::{BlockId, Filter, TransactionRequest};
use jsonrpsee::core::server::RpcModule;
use jsonrpsee::types::ErrorObjectOwned;

use crate::providers::{BlockProvider, EvmExecutor, LogsProvider, ProviderError, StateProvider, TxPoolProvider};

fn provider_error(err: ProviderError) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32000, err.to_string(), None::<()>)
}

fn not_implemented(message: &'static str) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32001, message, None::<()>)
}

/// Shared context for all RPC namespaces.
pub struct RpcContext<B, S, P, E, L> {
    pub block: B,
    pub state: S,
    pub pool: P,
    pub evm: E,
    pub logs: L,
    pub chain_id: u64,
    pub network_id: u64,
    pub client_version: String,
    pub listening: bool,
    pub peer_count: U64,
}

impl<B, S, P, E, L> RpcContext<B, S, P, E, L> {
    pub fn new(
        block: B,
        state: S,
        pool: P,
        evm: E,
        logs: L,
        chain_id: u64,
        network_id: u64,
        client_version: String,
        listening: bool,
        peer_count: U64,
    ) -> Self {
        Self {
            block,
            state,
            pool,
            evm,
            logs,
            chain_id,
            network_id,
            client_version,
            listening,
            peer_count,
        }
    }
}

/// Build a jsonrpsee module with eth/net/web3/txpool namespaces.
pub fn build_rpc_module<B, S, P, E, L>(ctx: RpcContext<B, S, P, E, L>) -> RpcModule<RpcContext<B, S, P, E, L>>
where
    B: BlockProvider + Send + Sync + 'static,
    S: StateProvider + Send + Sync + 'static,
    P: TxPoolProvider + Send + Sync + 'static,
    E: EvmExecutor + Send + Sync + 'static,
    L: LogsProvider + Send + Sync + 'static,
{
    let mut module = RpcModule::new(ctx);

    // eth namespace
    module
        .register_async_method("eth_chainId", |_, ctx, _| async move {
            Ok::<_, ErrorObjectOwned>(U64::from(ctx.chain_id))
        })
        .unwrap();

    module
        .register_async_method("eth_blockNumber", |_, ctx, _| async move {
            ctx.block
                .block_number()
                .await
                .map(U64::from)
                .map_err(provider_error)
        })
        .unwrap();

    module
        .register_async_method("eth_getBalance", |params, ctx, _| async move {
            let (address, block): (Address, Option<BlockId>) = params.parse()?;
            let block = block.unwrap_or_else(BlockId::latest);
            ctx.state.balance(address, block).await.map_err(provider_error)
        })
        .unwrap();

    module
        .register_async_method("eth_getCode", |params, ctx, _| async move {
            let (address, block): (Address, Option<BlockId>) = params.parse()?;
            let block = block.unwrap_or_else(BlockId::latest);
            ctx.state.code(address, block).await.map_err(provider_error)
        })
        .unwrap();

    module
        .register_async_method("eth_getStorageAt", |params, ctx, _| async move {
            let (address, slot, block): (Address, B256, Option<BlockId>) = params.parse()?;
            let block = block.unwrap_or_else(BlockId::latest);
            ctx.state
                .storage_at(address, slot, block)
                .await
                .map_err(provider_error)
        })
        .unwrap();

    module
        .register_async_method("eth_getTransactionCount", |params, ctx, _| async move {
            let (address, block): (Address, Option<BlockId>) = params.parse()?;
            let block = block.unwrap_or_else(BlockId::latest);
            ctx.state
                .transaction_count(address, block)
                .await
                .map(U64::from)
                .map_err(provider_error)
        })
        .unwrap();

    module
        .register_async_method("eth_sendRawTransaction", |params, ctx, _| async move {
            let tx: Bytes = params.one()?;
            ctx.pool.send_raw_transaction(tx).await.map_err(provider_error)
        })
        .unwrap();

    module
        .register_async_method("eth_call", |params, ctx, _| async move {
            let (request, block): (TransactionRequest, Option<BlockId>) = params.parse()?;
            let block = block.unwrap_or_else(BlockId::latest);
            ctx.evm.call(request, block).await.map_err(provider_error)
        })
        .unwrap();

    module
        .register_async_method("eth_estimateGas", |params, ctx, _| async move {
            let (request, block): (TransactionRequest, Option<BlockId>) = params.parse()?;
            let block = block.unwrap_or_else(BlockId::latest);
            ctx.evm
                .estimate_gas(request, block)
                .await
                .map_err(provider_error)
        })
        .unwrap();

    module
        .register_async_method("eth_getLogs", |params, ctx, _| async move {
            let filter: Filter = params.one()?;
            ctx.logs.logs(filter).await.map_err(provider_error)
        })
        .unwrap();

    module
        .register_async_method("eth_gasPrice", |_, ctx, _| async move {
            ctx.pool.gas_price().await.map_err(provider_error)
        })
        .unwrap();

    // Placeholder handlers for block/tx/receipt RPCs that require RPC type conversions.
    module
        .register_async_method("eth_getBlockByHash", |_, _, _| async move {
            Err::<serde_json::Value, ErrorObjectOwned>(not_implemented(
                "block/tx conversion not wired",
            ))
        })
        .unwrap();
    module
        .register_async_method("eth_getBlockByNumber", |_, _, _| async move {
            Err::<serde_json::Value, ErrorObjectOwned>(not_implemented(
                "block/tx conversion not wired",
            ))
        })
        .unwrap();
    module
        .register_async_method("eth_getTransactionByHash", |_, _, _| async move {
            Err::<serde_json::Value, ErrorObjectOwned>(not_implemented(
                "block/tx conversion not wired",
            ))
        })
        .unwrap();
    module
        .register_async_method("eth_getTransactionReceipt", |_, _, _| async move {
            Err::<serde_json::Value, ErrorObjectOwned>(not_implemented(
                "receipt conversion not wired",
            ))
        })
        .unwrap();

    // net namespace
    module
        .register_method("net_version", |_, ctx, _| ctx.network_id.to_string())
        .unwrap();
    module
        .register_method("net_listening", |_, ctx, _| ctx.listening)
        .unwrap();
    module
        .register_method("net_peerCount", |_, ctx, _| {
            Ok::<_, ErrorObjectOwned>(ctx.peer_count)
        })
        .unwrap();

    // web3 namespace
    module
        .register_method("web3_clientVersion", |_, ctx, _| ctx.client_version.clone())
        .unwrap();
    module
        .register_method("web3_sha3", |params, _, _| {
            let input: Bytes = params.one()?;
            let hash = keccak256(input);
            Ok::<B256, ErrorObjectOwned>(hash)
        })
        .unwrap();

    // txpool namespace (placeholder)
    module
        .register_method("txpool_status", |_, _, _| Err::<serde_json::Value, _>(not_implemented("txpool not wired")))
        .unwrap();
    module
        .register_method("txpool_content", |_, _, _| Err::<serde_json::Value, _>(not_implemented("txpool not wired")))
        .unwrap();
    module
        .register_method("txpool_inspect", |_, _, _| Err::<serde_json::Value, _>(not_implemented("txpool not wired")))
        .unwrap();

    module
}
