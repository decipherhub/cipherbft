use async_trait::async_trait;
use alloy_rpc_types::{Filter, Log};

use super::ProviderResult;

/// Provides log filtering for eth_getLogs.
#[async_trait]
pub trait LogsProvider: Send + Sync {
    async fn logs(&self, filter: Filter) -> ProviderResult<Vec<Log>>;
}
