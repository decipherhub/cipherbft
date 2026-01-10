use reth_evm::{execute::BlockExecutorProvider, ConfigureEvm};
use reth_network_api::{NetworkInfo, Peers};
use reth_primitives::Header;
use reth_provider::{AccountReader, CanonStateSubscriptions, ChangeSetReader, FullRpcProvider};
use reth_rpc::EthApi;
use reth_rpc_builder::{RethRpcModule, RpcModuleBuilder, TransportRpcModuleConfig, TransportRpcModules};
use reth_tasks::TaskSpawner;
use reth_transaction_pool::TransactionPool;

/// Default module selection for CipherBFT's HTTP RPC transport.
pub fn default_reth_modules() -> TransportRpcModuleConfig {
    TransportRpcModuleConfig::default().with_http(vec![
        RethRpcModule::Eth,
        RethRpcModule::Net,
        RethRpcModule::Web3,
        RethRpcModule::Txpool,
    ])
}

/// Build reth RPC modules with the provided components.
pub fn build_reth_modules<Provider, Pool, Network, Tasks, Events, EvmConfig, BlockExecutor>(
    provider: Provider,
    pool: Pool,
    network: Network,
    executor: Tasks,
    events: Events,
    evm_config: EvmConfig,
    block_executor: BlockExecutor,
    module_config: TransportRpcModuleConfig,
) -> TransportRpcModules<()>
where
    Provider: FullRpcProvider + AccountReader + ChangeSetReader,
    Pool: TransactionPool + 'static,
    Network: NetworkInfo + Peers + Clone + 'static,
    Tasks: TaskSpawner + Clone + 'static,
    Events: CanonStateSubscriptions + Clone + 'static,
    EvmConfig: ConfigureEvm<Header = Header>,
    BlockExecutor: BlockExecutorProvider,
{
    RpcModuleBuilder::new(
        provider,
        pool,
        network,
        executor,
        events,
        evm_config,
        block_executor,
    )
    .build(module_config, Box::new(EthApi::with_spawner))
}
