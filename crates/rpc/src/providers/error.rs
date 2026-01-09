#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("provider not wired: {0}")]
    NotReady(&'static str),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("execution error: {0}")]
    Execution(String),
    #[error("mempool error: {0}")]
    Mempool(String),
}

pub type ProviderResult<T> = Result<T, ProviderError>;
