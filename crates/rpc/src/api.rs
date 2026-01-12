use alloy_primitives::{keccak256, Address, B256, Bytes, TxKind, U64};
use alloy_rpc_types::{
    AnyReceiptEnvelope, Block, BlockId, BlockNumberOrTag, BlockTransactionsKind, Filter, Log,
    FilteredParams, ReceiptWithBloom, TransactionInfo, TransactionReceipt, TransactionRequest,
};
use alloy_rpc_types::txpool::{TxpoolContent, TxpoolInspect, TxpoolInspectSummary, TxpoolStatus};
use alloy_rpc_types::pubsub::SubscriptionKind;
use alloy_serde::WithOtherFields;
use jsonrpsee::core::{server::RpcModule, StringError};
use jsonrpsee::SubscriptionMessage;
use jsonrpsee::types::ErrorObjectOwned;
use reth_primitives::{SealedHeader, TransactionMeta, TransactionSigned};
use reth_rpc_types_compat::{block as compat_block, transaction as compat_tx};
use std::collections::BTreeMap;

use crate::pubsub::RpcEventChannels;
use crate::providers::{
    BlockProvider, EvmExecutor, LogsProvider, ProviderError, StateProvider, TxPoolProvider,
};

fn provider_error(err: ProviderError) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32000, err.to_string(), None::<()>)
}

type RpcTransaction = WithOtherFields<alloy_rpc_types::Transaction>;
type RpcBlock = Block<RpcTransaction>;
type RpcReceipt = WithOtherFields<TransactionReceipt<AnyReceiptEnvelope<Log>>>;

/// EthApi wraps CipherBFT providers for jsonrpsee handlers.
pub struct EthApi<B, S, P, E, L> {
    pub block: B,
    pub state: S,
    pub pool: P,
    pub evm: E,
    pub logs: L,
    pub events: Option<RpcEventChannels>,
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
            events: None,
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

    pub fn with_events(mut self, events: RpcEventChannels) -> Self {
        self.events = Some(events);
        self
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
        .register_async_method("eth_getTransactionReceipt", |params, ctx, _| async move {
            let hash: B256 = params.one()?;
            let result = ctx
                .block
                .transaction_by_hash_with_meta(hash)
                .await
                .map_err(provider_error)?;

            let Some((tx, meta)) = result else {
                return Ok::<Option<RpcReceipt>, ErrorObjectOwned>(None);
            };

            let receipt = ctx
                .block
                .receipt_by_hash(hash)
                .await
                .map_err(provider_error)?;
            let Some(receipt) = receipt else {
                return Ok::<Option<RpcReceipt>, ErrorObjectOwned>(None);
            };

            let all_receipts = ctx
                .block
                .receipts_by_block_hash(meta.block_hash)
                .await
                .map_err(provider_error)?;
            let Some(all_receipts) = all_receipts else {
                return Ok::<Option<RpcReceipt>, ErrorObjectOwned>(None);
            };

            let from = tx.recover_signer_unchecked().ok_or_else(|| {
                provider_error(ProviderError::Storage(
                    "invalid transaction signature".to_string(),
                ))
            })?;

            let gas_used = if meta.index == 0 {
                receipt.cumulative_gas_used
            } else {
                let prev_idx = (meta.index - 1) as usize;
                all_receipts
                    .get(prev_idx)
                    .map(|prev| receipt.cumulative_gas_used - prev.cumulative_gas_used)
                    .unwrap_or_default()
            };

            let mut prior_logs = 0usize;
            for prev in all_receipts.iter().take(meta.index as usize) {
                prior_logs += prev.logs.len();
            }

            let logs: Vec<Log> = receipt
                .logs
                .iter()
                .enumerate()
                .map(|(tx_log_idx, log)| Log {
                    inner: log.clone(),
                    block_hash: Some(meta.block_hash),
                    block_number: Some(meta.block_number),
                    block_timestamp: Some(meta.timestamp),
                    transaction_hash: Some(meta.tx_hash),
                    transaction_index: Some(meta.index),
                    log_index: Some((prior_logs + tx_log_idx) as u64),
                    removed: false,
                })
                .collect();

            let rpc_receipt = alloy_rpc_types::Receipt {
                status: receipt.success.into(),
                cumulative_gas_used: receipt.cumulative_gas_used as u128,
                logs,
            };
            let logs_bloom = receipt.bloom_slow();
            let envelope = AnyReceiptEnvelope {
                inner: ReceiptWithBloom {
                    receipt: rpc_receipt,
                    logs_bloom,
                },
                r#type: tx.transaction.tx_type().into(),
            };

            let (contract_address, to) = match tx.transaction.kind() {
                TxKind::Create => (Some(from.create(tx.transaction.nonce())), None),
                TxKind::Call(addr) => (None, Some(addr)),
            };

            let tx_receipt = TransactionReceipt {
                inner: envelope,
                transaction_hash: meta.tx_hash,
                transaction_index: Some(meta.index),
                block_hash: Some(meta.block_hash),
                block_number: Some(meta.block_number),
                gas_used: gas_used as u128,
                effective_gas_price: tx.transaction.effective_gas_price(meta.base_fee),
                blob_gas_used: tx.transaction.blob_gas_used().map(u128::from),
                blob_gas_price: None,
                from,
                to,
                contract_address,
                state_root: None,
                authorization_list: tx.authorization_list().map(|list| list.to_vec()),
            };

            Ok::<Option<RpcReceipt>, ErrorObjectOwned>(Some(WithOtherFields {
                inner: tx_receipt,
                other: Default::default(),
            }))
        })
        .unwrap();

    module
        .register_subscription(
            "eth_subscribe",
            "eth_subscription",
            "eth_unsubscribe",
            |params, pending, ctx, _| async move {
                let events = ctx
                    .events
                    .clone()
                    .ok_or_else(|| StringError::from("subscriptions not wired"))?;
                let params: Vec<serde_json::Value> = params
                    .parse()
                    .map_err(|err| StringError::from(err.to_string()))?;
                let kind = params
                    .get(0)
                    .ok_or_else(|| StringError::from("missing subscription kind"))
                    .and_then(|value| {
                        serde_json::from_value::<SubscriptionKind>(value.clone()).map_err(|_| {
                            StringError::from("invalid subscription kind")
                        })
                    })?;

                let filter = params
                    .get(1)
                    .and_then(|value| serde_json::from_value::<Filter>(value.clone()).ok());

                let sink = pending
                    .accept()
                    .await
                    .map_err(|err| StringError::from(err.to_string()))?;

                match kind {
                    SubscriptionKind::NewHeads => {
                        let mut rx = events.new_heads.subscribe();
                        tokio::spawn(async move {
                            while let Ok(header) = rx.recv().await {
                                let header = format_rpc_header(header);
                                let msg = match SubscriptionMessage::from_json(&header) {
                                    Ok(msg) => msg,
                                    Err(_) => continue,
                                };
                                if sink.send(msg).await.is_err() {
                                    break;
                                }
                            }
                        });
                    }
                    SubscriptionKind::Logs => {
                        let filter = filter.unwrap_or_default();
                        let mut rx = events.logs.subscribe();
                        tokio::spawn(async move {
                            while let Ok(log) = rx.recv().await {
                                if !log_matches(&filter, &log) {
                                    continue;
                                }
                                let msg = match SubscriptionMessage::from_json(&log) {
                                    Ok(msg) => msg,
                                    Err(_) => continue,
                                };
                                if sink.send(msg).await.is_err() {
                                    break;
                                }
                            }
                        });
                    }
                    SubscriptionKind::NewPendingTransactions => {
                        if matches!(params.get(1), Some(serde_json::Value::Bool(true))) {
                            return Err(StringError::from(
                                "full tx subscriptions not supported",
                            ));
                        }
                        let mut rx = events.pending_txs.subscribe();
                        tokio::spawn(async move {
                            while let Ok(hash) = rx.recv().await {
                                let msg = match SubscriptionMessage::from_json(&hash) {
                                    Ok(msg) => msg,
                                    Err(_) => continue,
                                };
                                if sink.send(msg).await.is_err() {
                                    break;
                                }
                            }
                        });
                    }
                    SubscriptionKind::Syncing => {
                        let mut rx = events.syncing.subscribe();
                        tokio::spawn(async move {
                            while let Ok(status) = rx.recv().await {
                                let msg = match SubscriptionMessage::from_json(&status) {
                                    Ok(msg) => msg,
                                    Err(_) => continue,
                                };
                                if sink.send(msg).await.is_err() {
                                    break;
                                }
                            }
                        });
                    }
                }

                Ok::<_, StringError>(())
            },
        )
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

    // txpool namespace
    module
        .register_async_method("txpool_status", |_, ctx, _| async move {
            let stats = ctx.pool.txpool_status().await.map_err(provider_error)?;
            Ok::<_, ErrorObjectOwned>(TxpoolStatus {
                pending: stats.pending as u64,
                queued: stats.queued as u64,
            })
        })
        .unwrap();
    module
        .register_async_method("txpool_content", |_, ctx, _| async move {
            let pending = ctx
                .pool
                .pending_transactions()
                .await
                .map_err(provider_error)?;
            let queued = ctx
                .pool
                .queued_transactions()
                .await
                .map_err(provider_error)?;

            Ok::<_, ErrorObjectOwned>(txpool_content(pending, queued))
        })
        .unwrap();
    module
        .register_async_method("txpool_inspect", |_, ctx, _| async move {
            let pending = ctx
                .pool
                .pending_transactions()
                .await
                .map_err(provider_error)?;
            let queued = ctx
                .pool
                .queued_transactions()
                .await
                .map_err(provider_error)?;

            Ok::<_, ErrorObjectOwned>(txpool_inspect(pending, queued))
        })
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

fn format_rpc_header(header: SealedHeader) -> WithOtherFields<alloy_rpc_types::Header> {
    WithOtherFields {
        inner: compat_block::from_primitive_with_hash(header),
        other: Default::default(),
    }
}

fn log_matches(filter: &Filter, log: &Log) -> bool {
    if let Some(hash) = filter.get_block_hash() {
        if log.block_hash != Some(hash) {
            return false;
        }
    }

    if let Some(block_number) = log.block_number {
        if let Some(from_block) = filter.get_from_block() {
            if block_number < from_block {
                return false;
            }
        }
        if let Some(to_block) = filter.get_to_block() {
            if block_number > to_block {
                return false;
            }
        }
    } else if filter.get_from_block().is_some() || filter.get_to_block().is_some() {
        return false;
    }

    let params = FilteredParams::new(Some(filter.clone()));
    if !params.filter_address(&log.inner.address) {
        return false;
    }

    if !params.filter_topics(log.inner.topics()) {
        return false;
    }

    true
}

fn txpool_content(
    pending: Vec<TransactionSigned>,
    queued: Vec<TransactionSigned>,
) -> TxpoolContent<RpcTransaction> {
    let mut content = TxpoolContent {
        pending: BTreeMap::new(),
        queued: BTreeMap::new(),
    };

    for tx in pending {
        insert_txpool_transaction(&mut content.pending, tx);
    }
    for tx in queued {
        insert_txpool_transaction(&mut content.queued, tx);
    }

    content
}

fn txpool_inspect(pending: Vec<TransactionSigned>, queued: Vec<TransactionSigned>) -> TxpoolInspect {
    let mut inspect = TxpoolInspect {
        pending: BTreeMap::new(),
        queued: BTreeMap::new(),
    };

    for tx in pending {
        insert_txpool_inspect(&mut inspect.pending, tx);
    }
    for tx in queued {
        insert_txpool_inspect(&mut inspect.queued, tx);
    }

    inspect
}

fn insert_txpool_transaction(
    map: &mut BTreeMap<Address, BTreeMap<String, RpcTransaction>>,
    tx: TransactionSigned,
) {
    let recovered = match tx.try_ecrecovered() {
        Some(recovered) => recovered,
        None => return,
    };
    let sender = recovered.signer();
    let nonce_key = tx.transaction.nonce().to_string();
    let rpc_tx = compat_tx::from_recovered::<()>(recovered);

    map.entry(sender).or_default().insert(nonce_key, rpc_tx);
}

fn insert_txpool_inspect(
    map: &mut BTreeMap<Address, BTreeMap<String, TxpoolInspectSummary>>,
    tx: TransactionSigned,
) {
    let recovered = match tx.try_ecrecovered() {
        Some(recovered) => recovered,
        None => return,
    };
    let sender = recovered.signer();
    let nonce_key = tx.transaction.nonce().to_string();
    let to = match tx.transaction.kind() {
        TxKind::Create => None,
        TxKind::Call(addr) => Some(addr),
    };

    let summary = TxpoolInspectSummary {
        to,
        value: tx.transaction.value(),
        gas: u128::from(tx.transaction.gas_limit()),
        gas_price: tx.transaction.max_fee_per_gas(),
    };

    map.entry(sender).or_default().insert(nonce_key, summary);
}
