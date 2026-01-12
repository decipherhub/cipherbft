use async_trait::async_trait;
use alloy_rpc_types::{Filter, Log};
use std::future::Future;

use super::ProviderResult;

/// Provides log filtering for eth_getLogs.
#[async_trait]
pub trait LogsProvider: Send + Sync {
    async fn logs(&self, filter: Filter) -> ProviderResult<Vec<Log>>;
}

/// Logs provider backed by an async log-fetching function.
#[derive(Debug, Clone)]
pub struct LogsProviderFn<F> {
    fetch: F,
}

impl<F> LogsProviderFn<F> {
    pub fn new(fetch: F) -> Self {
        Self { fetch }
    }
}

#[async_trait]
impl<F, Fut> LogsProvider for LogsProviderFn<F>
where
    F: Fn(Filter) -> Fut + Send + Sync,
    Fut: Future<Output = ProviderResult<Vec<Log>>> + Send,
{
    async fn logs(&self, filter: Filter) -> ProviderResult<Vec<Log>> {
        (self.fetch)(filter).await
    }
}
