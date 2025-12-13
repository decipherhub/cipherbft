# ADR 008: JSON-RPC Interface

## Changelog

* 2025-12-07: Initial draft

## Status

PROPOSED Not Implemented

## Abstract

CipherBFT provides a standard Ethereum JSON-RPC interface for client interaction. This ADR defines the supported RPC namespaces, methods, and WebSocket subscriptions, leveraging `reth-rpc-types` for type definitions.

## Context

CipherBFT requires an RPC interface for:
1. **Transaction submission**: Users submit transactions via `eth_sendRawTransaction`
2. **State queries**: Clients query balances, contract state, and transaction receipts
3. **Block access**: Explorers and indexers fetch block data
4. **Real-time updates**: DApps subscribe to new blocks, logs, and pending transactions

### Design Goals

- **Ethereum compatibility**: Standard eth_*, web3_*, net_* namespaces
- **Type safety**: Use `reth-rpc-types` for all request/response types
- **Performance**: Async handlers with connection pooling
- **Observability**: Request logging and metrics

## Alternatives

### Alternative 1: Custom RPC Types

Define all RPC types from scratch.

**Pros:**
- Maximum control over serialization
- No external dependencies

**Cons:**
- High implementation cost
- Risk of Ethereum incompatibility
- Must track EIP changes manually

### Alternative 2: jsonrpsee + Custom Types

Use jsonrpsee transport with custom type definitions.

**Pros:**
- Good async support
- Flexible

**Cons:**
- Still need to define all types
- Compatibility testing burden

### Alternative 3: Reth RPC Types (Chosen)

Use `reth-rpc-types` for type definitions with jsonrpsee transport.

**Pros:**
- Battle-tested Ethereum compatibility
- Automatic EIP support updates
- Consistent with other Reth crate usage
- Type-safe request/response handling

**Cons:**
- Dependency on Reth release cycle
- Must adapt to Reth's type structure

## Decision

Use `reth-rpc-types` for all JSON-RPC type definitions with jsonrpsee as the transport layer.

### Supported Namespaces

#### eth_* Namespace

| Method | Description | Implementation |
|--------|-------------|----------------|
| `eth_chainId` | Returns chain ID | Direct from config |
| `eth_blockNumber` | Latest block height | Query storage |
| `eth_getBlockByHash` | Block by hash | Query storage |
| `eth_getBlockByNumber` | Block by number | Query storage |
| `eth_getBalance` | Account balance | Query state trie |
| `eth_getTransactionByHash` | Transaction by hash | Query storage |
| `eth_getTransactionReceipt` | Transaction receipt | Query storage |
| `eth_sendRawTransaction` | Submit transaction | Add to mempool |
| `eth_call` | Execute call (no state change) | Execute via revm |
| `eth_estimateGas` | Estimate gas usage | Execute via revm |
| `eth_getLogs` | Query event logs | Query storage |
| `eth_getCode` | Contract bytecode | Query state trie |
| `eth_getStorageAt` | Contract storage slot | Query state trie |
| `eth_getTransactionCount` | Account nonce | Query state trie |
| `eth_gasPrice` | Current gas price | From base fee |
| `eth_feeHistory` | Historical fee data | Query storage |

#### web3_* Namespace

| Method | Description |
|--------|-------------|
| `web3_clientVersion` | Returns "CipherBFT/v0.1.0" |
| `web3_sha3` | Keccak256 hash of input |

#### net_* Namespace

| Method | Description |
|--------|-------------|
| `net_version` | Network ID (same as chain ID) |
| `net_listening` | True if accepting connections |
| `net_peerCount` | Number of connected peers |

### WebSocket Subscriptions

| Subscription | Description |
|--------------|-------------|
| `eth_subscribe("newHeads")` | New block headers |
| `eth_subscribe("newPendingTransactions")` | Pending transaction hashes |
| `eth_subscribe("logs", {filter})` | Matching event logs |
| `eth_subscribe("syncing")` | Sync status changes |

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       JSON-RPC SERVER                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    Transport Layer                          ││
│  │  - HTTP (jsonrpsee-http-server)                             ││
│  │  - WebSocket (jsonrpsee-ws-server)                          ││
│  │  - Connection pooling and rate limiting                     ││
│  └─────────────────────────────────────────────────────────────┘│
│                              │                                   │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    RPC Handlers                             ││
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐              ││
│  │  │   eth_*   │  │  web3_*   │  │   net_*   │              ││
│  │  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘              ││
│  │        │              │              │                      ││
│  └────────┼──────────────┼──────────────┼──────────────────────┘│
│           │              │              │                        │
│  ┌────────┴──────────────┴──────────────┴──────────────────────┐│
│  │                    Backend Services                          ││
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   ││
│  │  │ Storage  │  │ Mempool  │  │   EVM    │  │   P2P    │   ││
│  │  │ (reth-db)│  │  (pool)  │  │  (revm)  │  │(network) │   ││
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘   ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Implementation

```rust
// crates/rpc/src/lib.rs
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use reth_rpc_types::{
    Block, BlockNumberOrTag, Transaction, TransactionReceipt,
    TransactionRequest, Log, Filter, SyncStatus,
};

#[rpc(server, namespace = "eth")]
pub trait EthApi {
    #[method(name = "chainId")]
    async fn chain_id(&self) -> RpcResult<U64>;

    #[method(name = "blockNumber")]
    async fn block_number(&self) -> RpcResult<U64>;

    #[method(name = "getBlockByHash")]
    async fn get_block_by_hash(
        &self,
        hash: B256,
        full_transactions: bool,
    ) -> RpcResult<Option<Block>>;

    #[method(name = "getBlockByNumber")]
    async fn get_block_by_number(
        &self,
        number: BlockNumberOrTag,
        full_transactions: bool,
    ) -> RpcResult<Option<Block>>;

    #[method(name = "getBalance")]
    async fn get_balance(
        &self,
        address: Address,
        block: Option<BlockNumberOrTag>,
    ) -> RpcResult<U256>;

    #[method(name = "getTransactionByHash")]
    async fn get_transaction_by_hash(
        &self,
        hash: B256,
    ) -> RpcResult<Option<Transaction>>;

    #[method(name = "getTransactionReceipt")]
    async fn get_transaction_receipt(
        &self,
        hash: B256,
    ) -> RpcResult<Option<TransactionReceipt>>;

    #[method(name = "sendRawTransaction")]
    async fn send_raw_transaction(
        &self,
        bytes: Bytes,
    ) -> RpcResult<B256>;

    #[method(name = "call")]
    async fn call(
        &self,
        request: TransactionRequest,
        block: Option<BlockNumberOrTag>,
    ) -> RpcResult<Bytes>;

    #[method(name = "estimateGas")]
    async fn estimate_gas(
        &self,
        request: TransactionRequest,
        block: Option<BlockNumberOrTag>,
    ) -> RpcResult<U256>;

    #[method(name = "getLogs")]
    async fn get_logs(&self, filter: Filter) -> RpcResult<Vec<Log>>;
}
```

### Handler Implementation

```rust
// crates/rpc/src/eth.rs
pub struct EthHandler<S, P, E> {
    storage: Arc<S>,
    pool: Arc<P>,
    evm: Arc<E>,
    chain_id: u64,
}

#[async_trait]
impl<S, P, E> EthApiServer for EthHandler<S, P, E>
where
    S: Storage + Send + Sync + 'static,
    P: TransactionPool + Send + Sync + 'static,
    E: EvmExecutor + Send + Sync + 'static,
{
    async fn chain_id(&self) -> RpcResult<U64> {
        Ok(U64::from(self.chain_id))
    }

    async fn block_number(&self) -> RpcResult<U64> {
        let height = self.storage.latest_block_height()?;
        Ok(U64::from(height))
    }

    async fn send_raw_transaction(&self, bytes: Bytes) -> RpcResult<B256> {
        // Decode transaction
        let tx = TransactionSigned::decode(&mut bytes.as_ref())
            .map_err(|_| ErrorCode::InvalidParams)?;

        // Add to mempool
        let hash = tx.hash();
        self.pool.add_transaction(tx).await
            .map_err(|e| ErrorObject::owned(-32000, e.to_string(), None::<()>))?;

        Ok(hash)
    }

    async fn call(
        &self,
        request: TransactionRequest,
        block: Option<BlockNumberOrTag>,
    ) -> RpcResult<Bytes> {
        let block_num = block.unwrap_or(BlockNumberOrTag::Latest);
        let state = self.storage.state_at(block_num)?;

        let result = self.evm.call(request, state)?;
        Ok(result.output)
    }
}
```

### WebSocket Subscription Handler

```rust
// crates/rpc/src/pubsub.rs
use jsonrpsee::PendingSubscriptionSink;

#[rpc(server, namespace = "eth")]
pub trait EthPubSub {
    #[subscription(name = "subscribe", unsubscribe = "unsubscribe", item = Value)]
    async fn subscribe(
        &self,
        pending: PendingSubscriptionSink,
        kind: SubscriptionKind,
        params: Option<FilterParams>,
    );
}

pub struct PubSubHandler {
    new_heads_tx: broadcast::Sender<Block>,
    pending_tx_tx: broadcast::Sender<B256>,
    logs_tx: broadcast::Sender<Log>,
}

impl PubSubHandler {
    pub async fn handle_subscription(
        &self,
        sink: SubscriptionSink,
        kind: SubscriptionKind,
        filter: Option<FilterParams>,
    ) {
        match kind {
            SubscriptionKind::NewHeads => {
                let mut rx = self.new_heads_tx.subscribe();
                while let Ok(block) = rx.recv().await {
                    if sink.send(&block).await.is_err() {
                        break;
                    }
                }
            }
            SubscriptionKind::Logs => {
                let filter = filter.unwrap_or_default();
                let mut rx = self.logs_tx.subscribe();
                while let Ok(log) = rx.recv().await {
                    if filter.matches(&log) {
                        if sink.send(&log).await.is_err() {
                            break;
                        }
                    }
                }
            }
            // ... other subscription types
        }
    }
}
```

### Configuration

```rust
pub struct RpcConfig {
    /// HTTP server bind address
    pub http_addr: SocketAddr,  // Default: 127.0.0.1:8545

    /// WebSocket server bind address
    pub ws_addr: SocketAddr,    // Default: 127.0.0.1:8546

    /// Maximum concurrent connections
    pub max_connections: u32,   // Default: 100

    /// Request rate limit (per IP)
    pub rate_limit: u32,        // Default: 1000 req/s

    /// Enabled namespaces
    pub namespaces: Vec<String>, // Default: ["eth", "web3", "net"]
}
```

## Consequences

### Backwards Compatibility

N/A - greenfield implementation.

### Positive

1. **Ethereum compatibility**: Standard RPC interface works with existing tools
2. **Type safety**: `reth-rpc-types` ensures correct serialization
3. **Ecosystem integration**: Works with ethers.js, web3.js, Foundry, etc.
4. **WebSocket support**: Real-time updates for DApps
5. **Consistent with Reth**: Same types as storage layer

### Negative

1. **Limited customization**: Must follow Ethereum RPC spec
2. **No CometBFT RPC**: Cosmos ecosystem tools won't work
3. **Reth dependency**: Tied to Reth type updates

### Neutral

1. **No debug_* namespace**: Advanced debugging deferred
2. **No trace_* namespace**: Transaction tracing deferred
3. **No admin_* namespace**: Node administration via CLI only

## Test Cases

1. **eth_chainId**: Returns configured chain ID
2. **eth_blockNumber**: Returns latest block height
3. **eth_getBlockByHash**: Returns block with correct structure
4. **eth_getBalance**: Returns correct balance at latest and historical blocks
5. **eth_sendRawTransaction**: Accepts valid transaction, rejects invalid
6. **eth_call**: Executes call without state modification
7. **eth_estimateGas**: Returns reasonable gas estimate
8. **eth_getLogs**: Returns matching logs with correct filtering
9. **eth_subscribe(newHeads)**: Receives new block headers
10. **eth_subscribe(logs)**: Receives matching logs in real-time

## References

* [Ethereum JSON-RPC Specification](https://ethereum.github.io/execution-apis/api-documentation/)
* [reth-rpc-types](https://github.com/paradigmxyz/reth/tree/main/crates/rpc/rpc-types)
* [jsonrpsee](https://github.com/paritytech/jsonrpsee)
* [EIP-1474: Remote procedure call specification](https://eips.ethereum.org/EIPS/eip-1474)
