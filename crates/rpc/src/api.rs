use alloy_primitives::{keccak256, Address, B256, Bytes, U64};
use alloy_rpc_types::{
    Block, BlockId, BlockNumberOrTag, BlockTransactionsKind, Filter, TransactionInfo,
    TransactionRequest,
};
use alloy_serde::WithOtherFields;
use jsonrpsee::core::server::RpcModule;
use jsonrpsee::types::ErrorObjectOwned;
use reth_primitives::TransactionMeta;
use reth_rpc_types_compat::{block as compat_block, transaction as compat_tx};

use crate::providers::{
    BlockProvider, EvmExecutor, LogsProvider, ProviderError, StateProvider, TxPoolProvider,
};

fn provider_error(err: ProviderError) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32000, err.to_string(), None::<()>)
}

fn not_implemented(message: &'static str) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32001, message, None::<()>)
}

type RpcTransaction = WithOtherFields<alloy_rpc_types::Transaction>;
type RpcBlock = Block<RpcTransaction>;

/// EthApi wraps CipherBFT providers for jsonrpsee handlers.
pub struct EthApi<B, S, P, E, L> {
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

impl<B, S, P, E, L> EthApi<B, S, P, E, L> {
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

    /// Build a jsonrpsee module with eth/net/web3/txpool namespaces.
    pub fn into_rpc_module(self) -> RpcModule<Self>
    where
        B: BlockProvider + Send + Sync + 'static,
        S: StateProvider + Send + Sync + 'static,
        P: TxPoolProvider + Send + Sync + 'static,
        E: EvmExecutor + Send + Sync + 'static,
        L: LogsProvider + Send + Sync + 'static,
    {
        build_rpc_module(self)
    }
}

/// Build a jsonrpsee module with eth/net/web3/txpool namespaces.
pub fn build_rpc_module<B, S, P, E, L>(
    ctx: EthApi<B, S, P, E, L>,
) -> RpcModule<EthApi<B, S, P, E, L>>
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

    // Block/tx handlers (minimal RPC-2 support).
    module
        .register_async_method("eth_getBlockByHash", |params, ctx, _| async move {
            let (hash, full): (B256, bool) = params.parse()?;
            let block = ctx
                .block
                .block_with_senders_by_hash(hash)
                .await
                .map_err(provider_error)?;
            let total_difficulty = ctx
                .block
                .total_difficulty_by_hash(hash)
                .await
                .map_err(provider_error)?
                .unwrap_or_default();

            let response = block.map(|block| {
                let kind = if full {
                    BlockTransactionsKind::Full
                } else {
                    BlockTransactionsKind::Hashes
                };
                compat_block::from_block::<()>(block, total_difficulty, kind, Some(hash))
                    .map_err(|err| provider_error(ProviderError::Storage(err.to_string())))
            });

            match response {
                Some(Ok(block)) => Ok::<Option<RpcBlock>, ErrorObjectOwned>(Some(block)),
                Some(Err(err)) => Err(err),
                None => Ok::<Option<RpcBlock>, ErrorObjectOwned>(None),
            }
        })
        .unwrap();
    module
        .register_async_method("eth_getBlockByNumber", |params, ctx, _| async move {
            let (block_id, full): (BlockId, bool) = params.parse()?;

            let (block, total_difficulty, block_hash) = match block_id {
                BlockId::Hash(hash) => {
                    let block = ctx
                        .block
                        .block_with_senders_by_hash(hash.block_hash)
                        .await
                        .map_err(provider_error)?;
                    let td = ctx
                        .block
                        .total_difficulty_by_hash(hash.block_hash)
                        .await
                        .map_err(provider_error)?;
                    (block, td, Some(hash.block_hash))
                }
                BlockId::Number(tag) => {
                    let number = match tag {
                        BlockNumberOrTag::Latest
                        | BlockNumberOrTag::Pending
                        | BlockNumberOrTag::Safe
                        | BlockNumberOrTag::Finalized => ctx
                            .block
                            .block_number()
                            .await
                            .map_err(provider_error)?,
                        BlockNumberOrTag::Earliest => 0,
                        BlockNumberOrTag::Number(num) => num,
                    };
                    let block = ctx
                        .block
                        .block_with_senders_by_number(number)
                        .await
                        .map_err(provider_error)?;
                    let td = ctx
                        .block
                        .total_difficulty_by_number(number)
                        .await
                        .map_err(provider_error)?;
                    (block, td, None)
                }
            };

            let total_difficulty = total_difficulty.unwrap_or_default();
            let response = block.map(|block| {
                let kind = if full {
                    BlockTransactionsKind::Full
                } else {
                    BlockTransactionsKind::Hashes
                };
                compat_block::from_block::<()>(block, total_difficulty, kind, block_hash)
                    .map_err(|err| provider_error(ProviderError::Storage(err.to_string())))
            });

            match response {
                Some(Ok(block)) => Ok::<Option<RpcBlock>, ErrorObjectOwned>(Some(block)),
                Some(Err(err)) => Err(err),
                None => Ok::<Option<RpcBlock>, ErrorObjectOwned>(None),
            }
        })
        .unwrap();
    module
        .register_async_method("eth_getTransactionByHash", |params, ctx, _| async move {
            let hash: B256 = params.one()?;
            let result = ctx
                .block
                .transaction_by_hash_with_meta(hash)
                .await
                .map_err(provider_error)?;

            let Some((tx, meta)) = result else {
                return Ok::<Option<RpcTransaction>, ErrorObjectOwned>(None);
            };

            let tx = tx.try_ecrecovered().ok_or_else(|| {
                provider_error(ProviderError::Storage("invalid transaction signature".to_string()))
            })?;

            let tx_info = transaction_info(meta);
            let rpc_tx = compat_tx::from_recovered_with_block_context::<()>(tx, tx_info);

            Ok::<Option<RpcTransaction>, ErrorObjectOwned>(Some(rpc_tx))
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

fn transaction_info(meta: TransactionMeta) -> TransactionInfo {
    TransactionInfo {
        hash: Some(meta.tx_hash),
        index: Some(meta.index),
        block_hash: Some(meta.block_hash),
        block_number: Some(meta.block_number),
        base_fee: meta.base_fee.map(u128::from),
    }
}
