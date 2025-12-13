//! Batch maker for Worker
//!
//! Assembles transactions into batches based on size and time thresholds.

use crate::batch::{Batch, Transaction};
use std::time::{Duration, Instant};

/// Batch maker - assembles transactions into batches
pub struct BatchMaker {
    /// Worker ID
    worker_id: u8,
    /// Maximum batch size in bytes
    max_bytes: usize,
    /// Maximum transaction count per batch
    max_txs: usize,
    /// Pending transactions
    pending_txs: Vec<Transaction>,
    /// Current pending size in bytes
    pending_size: usize,
    /// When the first transaction in current batch was added
    batch_started: Option<Instant>,
}

impl BatchMaker {
    /// Create a new batch maker
    pub fn new(worker_id: u8, max_bytes: usize, max_txs: usize) -> Self {
        Self {
            worker_id,
            max_bytes,
            max_txs,
            pending_txs: Vec::new(),
            pending_size: 0,
            batch_started: None,
        }
    }

    /// Add a transaction
    ///
    /// Returns Some(Batch) if the batch threshold is reached
    pub fn add_transaction(&mut self, tx: Transaction) -> Option<Batch> {
        // Start timer on first transaction
        if self.batch_started.is_none() {
            self.batch_started = Some(Instant::now());
        }

        self.pending_size += tx.len();
        self.pending_txs.push(tx);

        // Check if threshold reached
        if self.should_flush() {
            return self.flush();
        }

        None
    }

    /// Check if batch should be flushed
    fn should_flush(&self) -> bool {
        self.pending_size >= self.max_bytes || self.pending_txs.len() >= self.max_txs
    }

    /// Force flush current batch
    ///
    /// Returns None if there are no pending transactions
    pub fn flush(&mut self) -> Option<Batch> {
        if self.pending_txs.is_empty() {
            return None;
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let batch = Batch::new(
            self.worker_id,
            std::mem::take(&mut self.pending_txs),
            timestamp,
        );

        self.pending_size = 0;
        self.batch_started = None;

        Some(batch)
    }

    /// Check if there are pending transactions
    pub fn has_pending(&self) -> bool {
        !self.pending_txs.is_empty()
    }

    /// Get pending transaction count
    pub fn pending_count(&self) -> usize {
        self.pending_txs.len()
    }

    /// Get pending size in bytes
    pub fn pending_bytes(&self) -> usize {
        self.pending_size
    }

    /// Get time since batch started (for time-based flushing)
    pub fn time_since_batch_start(&self) -> Option<Duration> {
        self.batch_started.map(|start| start.elapsed())
    }

    /// Check if time threshold exceeded
    pub fn should_flush_by_time(&self, max_duration: Duration) -> bool {
        self.batch_started
            .map(|start| start.elapsed() >= max_duration)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_transaction() {
        let mut maker = BatchMaker::new(0, 1000, 100);

        // Add small transaction, no flush
        let result = maker.add_transaction(vec![1, 2, 3]);
        assert!(result.is_none());
        assert_eq!(maker.pending_count(), 1);
        assert_eq!(maker.pending_bytes(), 3);
    }

    #[test]
    fn test_size_threshold_flush() {
        let mut maker = BatchMaker::new(0, 100, 1000);

        // Add transactions up to threshold
        for i in 0..10 {
            let result = maker.add_transaction(vec![0u8; 10]);
            if i < 9 {
                assert!(result.is_none());
            } else {
                // 10th transaction reaches 100 bytes
                assert!(result.is_some());
                let batch = result.unwrap();
                assert_eq!(batch.transactions.len(), 10);
                assert_eq!(batch.worker_id, 0);
            }
        }

        assert!(!maker.has_pending());
    }

    #[test]
    fn test_count_threshold_flush() {
        let mut maker = BatchMaker::new(0, 1000000, 5);

        // Add 5 transactions
        for i in 0..5 {
            let result = maker.add_transaction(vec![i as u8]);
            if i < 4 {
                assert!(result.is_none());
            } else {
                assert!(result.is_some());
            }
        }
    }

    #[test]
    fn test_manual_flush() {
        let mut maker = BatchMaker::new(0, 1000, 100);

        maker.add_transaction(vec![1, 2, 3]);
        maker.add_transaction(vec![4, 5, 6]);

        assert!(maker.has_pending());

        let batch = maker.flush().unwrap();
        assert_eq!(batch.transactions.len(), 2);
        assert!(!maker.has_pending());
    }

    #[test]
    fn test_empty_flush() {
        let mut maker = BatchMaker::new(0, 1000, 100);

        let result = maker.flush();
        assert!(result.is_none());
    }

    #[test]
    fn test_batch_started_timing() {
        let mut maker = BatchMaker::new(0, 1000, 100);

        assert!(maker.time_since_batch_start().is_none());

        maker.add_transaction(vec![1]);

        let elapsed = maker.time_since_batch_start();
        assert!(elapsed.is_some());
        assert!(elapsed.unwrap() < Duration::from_millis(100));
    }

    #[test]
    fn test_should_flush_by_time() {
        let mut maker = BatchMaker::new(0, 1000, 100);

        // No pending transactions
        assert!(!maker.should_flush_by_time(Duration::from_millis(100)));

        // Add transaction
        maker.add_transaction(vec![1]);

        // Just added, shouldn't exceed 100ms threshold
        assert!(!maker.should_flush_by_time(Duration::from_millis(100)));

        // Should exceed 0ms threshold
        std::thread::sleep(Duration::from_millis(1));
        assert!(maker.should_flush_by_time(Duration::from_millis(0)));
    }
}
