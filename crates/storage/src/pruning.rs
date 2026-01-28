//! Background pruning service for storage garbage collection
//!
//! Provides automatic cleanup of old data based on configurable retention policies.
//! The pruning task runs periodically and removes:
//! - Finalized Cuts older than the retention threshold
//! - Unreferenced Cars, Attestations, and Batches

use crate::dcl::DclStore;
use cipherbft_metrics::storage::{STORAGE_COMPACTION, STORAGE_COMPACTION_DURATION};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Notify;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, trace};

/// Configuration for the background pruning task
#[derive(Debug, Clone)]
pub struct PruningConfig {
    /// Number of blocks to retain (default: 100,000)
    pub retention_blocks: u64,
    /// Interval between pruning runs in blocks (default: 1,000)
    pub prune_interval_blocks: u64,
    /// Minimum interval between pruning runs (default: 60 seconds)
    pub min_prune_interval: Duration,
}

impl Default for PruningConfig {
    fn default() -> Self {
        Self {
            retention_blocks: 100_000,
            prune_interval_blocks: 1_000,
            min_prune_interval: Duration::from_secs(60),
        }
    }
}

impl PruningConfig {
    /// Create a new pruning configuration
    pub fn new(retention_blocks: u64, prune_interval_blocks: u64) -> Self {
        Self {
            retention_blocks,
            prune_interval_blocks,
            min_prune_interval: Duration::from_secs(60),
        }
    }

    /// Set the minimum interval between pruning runs
    pub fn with_min_interval(mut self, interval: Duration) -> Self {
        self.min_prune_interval = interval;
        self
    }
}

/// Handle for controlling the background pruning task
pub struct PruningHandle {
    /// Shutdown signal
    shutdown: Arc<AtomicBool>,
    /// Notify for immediate pruning trigger
    trigger: Arc<Notify>,
    /// Last pruned height
    last_pruned_height: Arc<AtomicU64>,
    /// Current finalized height (updated externally)
    current_height: Arc<AtomicU64>,
}

impl PruningHandle {
    /// Create a new pruning handle
    fn new() -> Self {
        Self {
            shutdown: Arc::new(AtomicBool::new(false)),
            trigger: Arc::new(Notify::new()),
            last_pruned_height: Arc::new(AtomicU64::new(0)),
            current_height: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Signal shutdown to the pruning task
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        self.trigger.notify_one();
    }

    /// Trigger immediate pruning
    pub fn trigger_prune(&self) {
        self.trigger.notify_one();
    }

    /// Update the current finalized height
    ///
    /// This should be called when new blocks are finalized.
    /// The pruning task will use this to determine when to prune.
    pub fn update_height(&self, height: u64) {
        self.current_height.store(height, Ordering::SeqCst);
    }

    /// Get the last height that was pruned
    pub fn last_pruned_height(&self) -> u64 {
        self.last_pruned_height.load(Ordering::SeqCst)
    }

    /// Check if the pruning task is still running
    pub fn is_running(&self) -> bool {
        !self.shutdown.load(Ordering::SeqCst)
    }
}

impl Clone for PruningHandle {
    fn clone(&self) -> Self {
        Self {
            shutdown: Arc::clone(&self.shutdown),
            trigger: Arc::clone(&self.trigger),
            last_pruned_height: Arc::clone(&self.last_pruned_height),
            current_height: Arc::clone(&self.current_height),
        }
    }
}

/// Background pruning task
///
/// Spawns a tokio task that periodically prunes old data from storage.
pub struct PruningTask<S: DclStore> {
    store: Arc<S>,
    config: PruningConfig,
    handle: PruningHandle,
}

impl<S: DclStore + Send + Sync + 'static> PruningTask<S> {
    /// Create a new pruning task
    pub fn new(store: Arc<S>, config: PruningConfig) -> Self {
        Self {
            store,
            config,
            handle: PruningHandle::new(),
        }
    }

    /// Get a handle for controlling the pruning task
    pub fn handle(&self) -> PruningHandle {
        self.handle.clone()
    }

    /// Start the background pruning task
    ///
    /// Returns a JoinHandle for the spawned task.
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        let store = self.store;
        let config = self.config;
        let handle = self.handle;

        tokio::spawn(async move {
            info!(
                retention_blocks = config.retention_blocks,
                prune_interval_blocks = config.prune_interval_blocks,
                "Starting background pruning task"
            );

            let mut interval_timer = interval(config.min_prune_interval);
            let mut last_checked_height = 0u64;

            loop {
                tokio::select! {
                    _ = interval_timer.tick() => {
                        // Check if it's time to prune based on block interval
                    }
                    _ = handle.trigger.notified() => {
                        if handle.shutdown.load(Ordering::SeqCst) {
                            info!("Pruning task received shutdown signal");
                            break;
                        }
                        // Immediate prune triggered
                        trace!("Immediate prune triggered");
                    }
                }

                if handle.shutdown.load(Ordering::SeqCst) {
                    break;
                }

                let current_height = handle.current_height.load(Ordering::SeqCst);

                // Check if we've advanced enough blocks to warrant pruning
                if current_height < last_checked_height + config.prune_interval_blocks {
                    continue;
                }

                // Check if we have enough blocks to apply retention policy
                if current_height < config.retention_blocks {
                    trace!(
                        current_height,
                        retention_blocks = config.retention_blocks,
                        "Not enough blocks to prune yet"
                    );
                    continue;
                }

                let prune_before_height = current_height.saturating_sub(config.retention_blocks);
                let last_pruned = handle.last_pruned_height.load(Ordering::SeqCst);

                // Skip if we've already pruned up to this height
                if prune_before_height <= last_pruned {
                    trace!(
                        prune_before_height,
                        last_pruned,
                        "Already pruned up to this height"
                    );
                    last_checked_height = current_height;
                    continue;
                }

                debug!(current_height, prune_before_height, "Running pruning cycle");

                let prune_start = Instant::now();
                match store.prune_before(prune_before_height).await {
                    Ok(pruned_count) => {
                        let duration = prune_start.elapsed();
                        STORAGE_COMPACTION.inc();
                        STORAGE_COMPACTION_DURATION
                            .with_label_values(&[])
                            .observe(duration.as_secs_f64());

                        if pruned_count > 0 {
                            info!(
                                pruned_count,
                                prune_before_height,
                                duration_ms = duration.as_millis(),
                                "Pruning cycle completed"
                            );
                        } else {
                            debug!(prune_before_height, "Pruning cycle completed (no entries)");
                        }
                        handle
                            .last_pruned_height
                            .store(prune_before_height, Ordering::SeqCst);
                    }
                    Err(e) => {
                        error!(error = %e, prune_before_height, "Pruning cycle failed");
                    }
                }

                last_checked_height = current_height;
            }

            info!("Background pruning task stopped");
        })
    }
}

/// Convenience function to start a pruning task with default configuration
pub fn spawn_pruning_task<S: DclStore + Send + Sync + 'static>(
    store: Arc<S>,
) -> (PruningHandle, tokio::task::JoinHandle<()>) {
    spawn_pruning_task_with_config(store, PruningConfig::default())
}

/// Start a pruning task with custom configuration
pub fn spawn_pruning_task_with_config<S: DclStore + Send + Sync + 'static>(
    store: Arc<S>,
    config: PruningConfig,
) -> (PruningHandle, tokio::task::JoinHandle<()>) {
    let task = PruningTask::new(store, config);
    let handle = task.handle();
    let join_handle = task.spawn();
    (handle, join_handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::InMemoryStore;
    use tokio::time::sleep;

    #[test]
    fn test_pruning_config_default() {
        let config = PruningConfig::default();
        assert_eq!(config.retention_blocks, 100_000);
        assert_eq!(config.prune_interval_blocks, 1_000);
        assert_eq!(config.min_prune_interval, Duration::from_secs(60));
    }

    #[test]
    fn test_pruning_config_builder() {
        let config = PruningConfig::new(50_000, 500).with_min_interval(Duration::from_secs(30));
        assert_eq!(config.retention_blocks, 50_000);
        assert_eq!(config.prune_interval_blocks, 500);
        assert_eq!(config.min_prune_interval, Duration::from_secs(30));
    }

    #[tokio::test]
    async fn test_pruning_handle_lifecycle() {
        let store = Arc::new(InMemoryStore::new());
        let config = PruningConfig::new(10, 5).with_min_interval(Duration::from_millis(10));

        let (handle, join_handle) = spawn_pruning_task_with_config(store, config);

        assert!(handle.is_running());
        assert_eq!(handle.last_pruned_height(), 0);

        // Update height
        handle.update_height(100);

        // Give task time to run
        sleep(Duration::from_millis(50)).await;

        // Shutdown
        handle.shutdown();
        join_handle.await.unwrap();

        assert!(!handle.is_running());
    }
}
