//! Task Supervision for CipherBFT Node
//!
//! This module implements a structured task supervision tree similar to Erlang/OTP,
//! using tokio-util's `TaskTracker` and `CancellationToken` for:
//!
//! - **Coordinated Shutdown**: All tasks receive cancellation signals in a controlled order
//! - **Failure Propagation**: If one critical task fails, others are notified
//! - **Resource Cleanup**: Ensures storage is flushed before process exit
//!
//! # Shutdown Order
//!
//! 1. Stop accepting new network connections
//! 2. Drain in-flight consensus rounds
//! 3. Flush pending storage writes
//! 4. Close database connections
//! 5. Exit
//!
//! # Example
//!
//! ```ignore
//! let supervisor = NodeSupervisor::new();
//!
//! // Spawn tasks under supervision
//! supervisor.spawn("network", async move {
//!     // Network task
//!     Ok(())
//! });
//!
//! // Graceful shutdown
//! supervisor.shutdown().await;
//! ```

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{error, info, warn};

/// Default timeout for graceful shutdown before forcing termination
const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

/// Result type for supervised tasks
pub type SupervisedResult = Result<(), anyhow::Error>;

/// A supervisor that manages the lifecycle of all node tasks.
///
/// Implements a hierarchical task management strategy:
/// - All spawned tasks are tracked by `TaskTracker`
/// - Cancellation is signaled via `CancellationToken`
/// - Shutdown waits for all tasks to complete gracefully
#[derive(Clone)]
pub struct NodeSupervisor {
    /// Tracks all spawned tasks
    tracker: TaskTracker,
    /// Token for signaling cancellation to all tasks
    token: CancellationToken,
    /// Flag indicating shutdown has been initiated
    shutting_down: Arc<AtomicBool>,
    /// Timeout for graceful shutdown
    shutdown_timeout: Duration,
}

impl Default for NodeSupervisor {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeSupervisor {
    /// Create a new supervisor with default settings
    pub fn new() -> Self {
        Self {
            tracker: TaskTracker::new(),
            token: CancellationToken::new(),
            shutting_down: Arc::new(AtomicBool::new(false)),
            shutdown_timeout: DEFAULT_SHUTDOWN_TIMEOUT,
        }
    }

    /// Create a new supervisor with custom shutdown timeout
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            tracker: TaskTracker::new(),
            token: CancellationToken::new(),
            shutting_down: Arc::new(AtomicBool::new(false)),
            shutdown_timeout: timeout,
        }
    }

    /// Get a clone of the cancellation token for use in tasks
    pub fn cancellation_token(&self) -> CancellationToken {
        self.token.clone()
    }

    /// Check if shutdown has been initiated
    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::SeqCst)
    }

    /// Spawn a supervised task.
    ///
    /// The task will be:
    /// - Tracked by the supervisor
    /// - Cancelled when shutdown is initiated
    /// - Logged on completion or failure
    ///
    /// # Arguments
    ///
    /// * `name` - Human-readable name for logging
    /// * `future` - The async task to run
    pub fn spawn<F>(&self, name: &'static str, future: F)
    where
        F: Future<Output = SupervisedResult> + Send + 'static,
    {
        let token = self.token.clone();
        let shutting_down = self.shutting_down.clone();

        self.tracker.spawn(async move {
            tokio::select! {
                biased;

                // Check for cancellation first
                _ = token.cancelled() => {
                    info!("[{}] Received shutdown signal, stopping gracefully", name);
                }

                // Run the actual task
                result = future => {
                    match result {
                        Ok(()) => {
                            info!("[{}] Task completed successfully", name);
                        }
                        Err(e) => {
                            // Check if this is during shutdown - if so, log as info, not error
                            if shutting_down.load(Ordering::SeqCst) {
                                info!("[{}] Task stopped during shutdown: {}", name, e);
                            } else {
                                error!("[{}] Task failed: {:?}", name, e);
                            }
                        }
                    }
                }
            }
        });
    }

    /// Spawn a supervised task that should complete quickly on cancellation.
    ///
    /// Unlike `spawn`, this variant expects the task to handle cancellation
    /// internally and complete promptly when cancelled.
    ///
    /// # Arguments
    ///
    /// * `name` - Human-readable name for logging
    /// * `future` - The async task that accepts a cancellation token
    pub fn spawn_cancellable<F, Fut>(&self, name: &'static str, f: F)
    where
        F: FnOnce(CancellationToken) -> Fut + Send + 'static,
        Fut: Future<Output = SupervisedResult> + Send + 'static,
    {
        let token = self.token.clone();
        let shutting_down = self.shutting_down.clone();

        self.tracker.spawn(async move {
            let result = f(token).await;
            match result {
                Ok(()) => {
                    info!("[{}] Task completed successfully", name);
                }
                Err(e) => {
                    if shutting_down.load(Ordering::SeqCst) {
                        info!("[{}] Task stopped during shutdown: {}", name, e);
                    } else {
                        error!("[{}] Task failed: {:?}", name, e);
                    }
                }
            }
        });
    }

    /// Spawn a critical task that triggers full shutdown on failure.
    ///
    /// If this task fails unexpectedly (not during shutdown), it will
    /// initiate shutdown of all other tasks.
    ///
    /// # Arguments
    ///
    /// * `name` - Human-readable name for logging
    /// * `future` - The async task to run
    pub fn spawn_critical<F>(&self, name: &'static str, future: F)
    where
        F: Future<Output = SupervisedResult> + Send + 'static,
    {
        let token = self.token.clone();
        let shutting_down = self.shutting_down.clone();
        let self_token = self.token.clone();

        self.tracker.spawn(async move {
            tokio::select! {
                biased;

                _ = token.cancelled() => {
                    info!("[{}] Critical task received shutdown signal", name);
                }

                result = future => {
                    match result {
                        Ok(()) => {
                            info!("[{}] Critical task completed successfully", name);
                        }
                        Err(e) => {
                            if !shutting_down.load(Ordering::SeqCst) {
                                error!("[{}] CRITICAL TASK FAILED: {:?}", name, e);
                                error!("Initiating emergency shutdown due to critical task failure");
                                // Trigger shutdown of all tasks
                                self_token.cancel();
                            } else {
                                info!("[{}] Critical task stopped during shutdown: {}", name, e);
                            }
                        }
                    }
                }
            }
        });
    }

    /// Initiate graceful shutdown.
    ///
    /// This will:
    /// 1. Signal all tasks to stop via cancellation token
    /// 2. Close the task tracker to prevent new tasks
    /// 3. Wait for all tasks to complete (with timeout)
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all tasks completed within the timeout,
    /// or `Err` if the timeout was exceeded (tasks may still be running).
    pub async fn shutdown(&self) -> Result<(), ShutdownError> {
        if self.shutting_down.swap(true, Ordering::SeqCst) {
            // Already shutting down
            warn!("Shutdown already in progress");
            return Ok(());
        }

        info!("Initiating graceful shutdown...");

        // Step 1: Close the tracker to prevent new tasks
        self.tracker.close();

        // Step 2: Signal all tasks to stop
        self.token.cancel();

        // Step 3: Wait for all tasks with timeout
        let wait_result = tokio::time::timeout(self.shutdown_timeout, self.tracker.wait()).await;

        match wait_result {
            Ok(()) => {
                info!("All tasks terminated gracefully");
                Ok(())
            }
            Err(_) => {
                error!(
                    "Shutdown timeout ({:?}) exceeded, some tasks may still be running",
                    self.shutdown_timeout
                );
                Err(ShutdownError::Timeout)
            }
        }
    }

    /// Initiate shutdown and wait indefinitely for all tasks to complete.
    ///
    /// Use this only when you're certain all tasks will eventually stop.
    pub async fn shutdown_and_wait(&self) {
        if self.shutting_down.swap(true, Ordering::SeqCst) {
            warn!("Shutdown already in progress");
            return;
        }

        info!("Initiating shutdown (waiting indefinitely)...");

        self.tracker.close();
        self.token.cancel();
        self.tracker.wait().await;

        info!("All tasks terminated");
    }

    /// Wait for all tracked tasks to complete without initiating shutdown.
    ///
    /// This is useful for waiting on tasks that are expected to complete
    /// naturally (e.g., after receiving a result).
    pub async fn wait(&self) {
        self.tracker.wait().await;
    }

    /// Get the number of currently tracked tasks.
    ///
    /// Note: This is approximate due to the async nature of task spawning/completion.
    pub fn task_count(&self) -> usize {
        self.tracker.len()
    }
}

/// Errors that can occur during shutdown
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownError {
    /// Shutdown timed out waiting for tasks to complete
    Timeout,
}

impl std::fmt::Display for ShutdownError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShutdownError::Timeout => write!(f, "shutdown timeout exceeded"),
        }
    }
}

impl std::error::Error for ShutdownError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_supervisor_spawn_and_shutdown() {
        let supervisor = NodeSupervisor::with_timeout(Duration::from_secs(5));
        let counter = Arc::new(AtomicU32::new(0));

        // Spawn some tasks
        for _ in 0..3 {
            let counter = counter.clone();
            supervisor.spawn("test-task", async move {
                counter.fetch_add(1, Ordering::SeqCst);
                sleep(Duration::from_millis(100)).await;
                Ok(())
            });
        }

        // Give tasks time to start
        sleep(Duration::from_millis(50)).await;

        // Shutdown should wait for tasks
        let result = supervisor.shutdown().await;
        assert!(result.is_ok());

        // All tasks should have incremented counter
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_supervisor_cancellation() {
        let supervisor = NodeSupervisor::new();
        let completed = Arc::new(AtomicBool::new(false));
        let cancelled = Arc::new(AtomicBool::new(false));

        let cancelled_clone = cancelled.clone();
        supervisor.spawn_cancellable("cancellable-task", move |token| {
            let cancelled = cancelled_clone;
            async move {
                tokio::select! {
                    _ = token.cancelled() => {
                        cancelled.store(true, Ordering::SeqCst);
                    }
                    _ = sleep(Duration::from_secs(60)) => {
                        // This should never complete
                    }
                }
                Ok(())
            }
        });

        // Give task time to start
        sleep(Duration::from_millis(50)).await;

        // Initiate shutdown
        let result = supervisor.shutdown().await;
        assert!(result.is_ok());

        // Task should have been cancelled
        assert!(cancelled.load(Ordering::SeqCst));
        assert!(!completed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_critical_task_failure_triggers_shutdown() {
        let supervisor = NodeSupervisor::new();
        let other_task_cancelled = Arc::new(AtomicBool::new(false));

        // Spawn a task that will observe the cancellation
        let cancelled_clone = other_task_cancelled.clone();
        let token = supervisor.cancellation_token();
        tokio::spawn(async move {
            token.cancelled().await;
            cancelled_clone.store(true, Ordering::SeqCst);
        });

        // Spawn a critical task that fails
        supervisor.spawn_critical("failing-critical", async move {
            sleep(Duration::from_millis(50)).await;
            Err(anyhow::anyhow!("Critical failure!"))
        });

        // Wait a bit for the critical task to fail and trigger shutdown
        sleep(Duration::from_millis(200)).await;

        // The other task should have been cancelled
        assert!(other_task_cancelled.load(Ordering::SeqCst));
    }
}
