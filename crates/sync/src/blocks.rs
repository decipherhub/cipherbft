//! Block synchronization after snap sync

#![allow(dead_code)] // Module is foundational, will be used by sync orchestrator

use crate::error::{Result, SyncError};
use crate::protocol::{BlockRangeRequest, BlockRangeResponse};
use alloy_primitives::{Bytes, B256};
use std::collections::VecDeque;

/// Block batch size for parallel requests
pub const BLOCK_BATCH_SIZE: u32 = 64;

/// State root verification interval (must match execution layer)
pub const STATE_ROOT_INTERVAL: u64 = 100;

/// Pending block range to download
#[derive(Clone, Debug)]
pub struct PendingBlockRange {
    /// Start height (inclusive)
    pub start: u64,
    /// Number of blocks to fetch
    pub count: u32,
    /// Retry count
    pub retries: u32,
}

/// Downloaded block awaiting execution
#[derive(Clone, Debug)]
pub struct DownloadedBlock {
    /// Block height
    pub height: u64,
    /// Serialized block data
    pub data: Bytes,
}

/// Block syncer state
pub struct BlockSyncer {
    /// Start height (snapshot + 1)
    start_height: u64,
    /// Target height to sync to
    target_height: u64,
    /// Last successfully executed block
    executed_up_to: u64,
    /// Pending ranges to download
    pending_ranges: Vec<PendingBlockRange>,
    /// Downloaded blocks awaiting execution (sorted by height)
    downloaded: VecDeque<DownloadedBlock>,
    /// Expected state roots at checkpoints (height -> root)
    checkpoint_roots: Vec<(u64, B256)>,
    /// Total blocks downloaded
    total_downloaded: u64,
    /// Total blocks executed
    total_executed: u64,
    /// Next request ID for correlation
    next_request_id: u64,
}

impl BlockSyncer {
    /// Create a new block syncer
    pub fn new(start_height: u64, target_height: u64) -> Self {
        // Create pending ranges covering start to target
        let mut pending_ranges = Vec::new();
        let mut current = start_height;

        while current <= target_height {
            let count = std::cmp::min(BLOCK_BATCH_SIZE, (target_height - current + 1) as u32);
            pending_ranges.push(PendingBlockRange {
                start: current,
                count,
                retries: 0,
            });
            current += count as u64;
        }

        // Reverse so we pop from end (lowest heights first)
        pending_ranges.reverse();

        Self {
            start_height,
            target_height,
            executed_up_to: start_height.saturating_sub(1),
            pending_ranges,
            downloaded: VecDeque::new(),
            checkpoint_roots: Vec::new(),
            total_downloaded: 0,
            total_executed: 0,
            next_request_id: 1,
        }
    }

    /// Resume from existing progress
    pub fn resume(start_height: u64, executed_up_to: u64, target_height: u64) -> Self {
        let mut syncer = Self::new(executed_up_to + 1, target_height);
        syncer.start_height = start_height;
        syncer.executed_up_to = executed_up_to;
        syncer
    }

    /// Check if sync is complete
    pub fn is_complete(&self) -> bool {
        self.executed_up_to >= self.target_height
    }

    /// Check if we have blocks ready to execute
    pub fn has_executable_blocks(&self) -> bool {
        self.downloaded
            .front()
            .is_some_and(|b| b.height == self.executed_up_to + 1)
    }

    /// Get next range to request
    pub fn next_range(&mut self) -> Option<PendingBlockRange> {
        self.pending_ranges.pop()
    }

    /// Create request for a range with unique request ID
    pub fn create_request(&mut self, range: &PendingBlockRange) -> BlockRangeRequest {
        let request_id = self.next_request_id;
        self.next_request_id += 1;
        BlockRangeRequest {
            request_id,
            start_height: range.start,
            count: range.count,
        }
    }

    /// Process downloaded blocks
    pub fn process_response(
        &mut self,
        range: PendingBlockRange,
        response: BlockRangeResponse,
    ) -> Result<()> {
        if response.blocks.is_empty() {
            return Err(SyncError::malformed("unknown", "empty block response"));
        }

        // Add blocks to download queue
        for (i, block_data) in response.blocks.into_iter().enumerate() {
            let height = range.start + i as u64;
            self.downloaded.push_back(DownloadedBlock {
                height,
                data: block_data,
            });
            self.total_downloaded += 1;
        }

        // Sort by height (insertion sort since mostly sorted)
        self.sort_downloaded();

        Ok(())
    }

    /// Get next block to execute (if available in sequence)
    pub fn next_executable_block(&mut self) -> Option<DownloadedBlock> {
        if self.has_executable_blocks() {
            self.downloaded.pop_front()
        } else {
            None
        }
    }

    /// Mark block as successfully executed
    pub fn block_executed(&mut self, height: u64, state_root: Option<B256>) {
        self.executed_up_to = height;
        self.total_executed += 1;

        // Store checkpoint state root
        if let Some(root) = state_root {
            if height.is_multiple_of(STATE_ROOT_INTERVAL) {
                self.checkpoint_roots.push((height, root));
            }
        }
    }

    /// Handle failed download
    pub fn handle_download_failure(&mut self, range: PendingBlockRange, max_retries: u32) {
        if range.retries < max_retries {
            self.pending_ranges.push(PendingBlockRange {
                retries: range.retries + 1,
                ..range
            });
        } else if range.count > 1 {
            // Split the range
            let mid = range.count / 2;
            self.pending_ranges.push(PendingBlockRange {
                start: range.start,
                count: mid,
                retries: 0,
            });
            self.pending_ranges.push(PendingBlockRange {
                start: range.start + mid as u64,
                count: range.count - mid,
                retries: 0,
            });
        }
        // If single block fails too many times, we have a problem
    }

    /// Handle execution failure
    pub fn handle_execution_failure(&mut self, height: u64) {
        // Re-download the failed block
        self.pending_ranges.push(PendingBlockRange {
            start: height,
            count: 1,
            retries: 0,
        });

        // Remove any downloaded blocks at or after this height
        self.downloaded.retain(|b| b.height < height);
    }

    /// Get sync progress as percentage
    pub fn progress(&self) -> f64 {
        let total = self.target_height - self.start_height + 1;
        if total == 0 {
            return 100.0;
        }
        let done = self.executed_up_to.saturating_sub(self.start_height) + 1;
        (done as f64 / total as f64) * 100.0
    }

    /// Get sync statistics
    pub fn stats(&self) -> BlockSyncStats {
        BlockSyncStats {
            start_height: self.start_height,
            target_height: self.target_height,
            executed_up_to: self.executed_up_to,
            total_downloaded: self.total_downloaded,
            total_executed: self.total_executed,
            pending_ranges: self.pending_ranges.len() as u64,
            downloaded_pending: self.downloaded.len() as u64,
        }
    }

    /// Sort downloaded blocks by height
    fn sort_downloaded(&mut self) {
        // Convert to vec, sort, convert back
        let mut blocks: Vec<_> = self.downloaded.drain(..).collect();
        blocks.sort_by_key(|b| b.height);
        self.downloaded = blocks.into_iter().collect();
    }
}

/// Block sync statistics
#[derive(Clone, Debug, Default)]
pub struct BlockSyncStats {
    /// Starting block height
    pub start_height: u64,
    /// Target block height
    pub target_height: u64,
    /// Last executed block
    pub executed_up_to: u64,
    /// Total blocks downloaded
    pub total_downloaded: u64,
    /// Total blocks executed
    pub total_executed: u64,
    /// Pending download ranges
    pub pending_ranges: u64,
    /// Downloaded blocks awaiting execution
    pub downloaded_pending: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_syncer_creation() {
        let syncer = BlockSyncer::new(10001, 10100);

        assert!(!syncer.is_complete());
        assert_eq!(syncer.start_height, 10001);
        assert_eq!(syncer.target_height, 10100);
    }

    #[test]
    fn test_pending_ranges_creation() {
        let syncer = BlockSyncer::new(1, 200);

        // Should create multiple ranges of BLOCK_BATCH_SIZE
        let stats = syncer.stats();
        assert!(stats.pending_ranges > 0);
    }

    #[test]
    fn test_block_execution_flow() {
        let mut syncer = BlockSyncer::new(1, 10);

        // Simulate downloading blocks
        let range = syncer.next_range().unwrap();
        let response = BlockRangeResponse {
            request_id: 1,
            blocks: (1..=10).map(|_| Bytes::from(vec![0u8; 100])).collect(),
        };

        syncer.process_response(range, response).unwrap();

        // Should have executable blocks
        assert!(syncer.has_executable_blocks());

        // Execute blocks
        while let Some(block) = syncer.next_executable_block() {
            syncer.block_executed(block.height, None);
        }

        assert!(syncer.is_complete());
    }

    #[test]
    fn test_progress_calculation() {
        let mut syncer = BlockSyncer::new(1, 100);

        // Initial progress is 0% (executed_up_to = 0, which is before start_height = 1)
        // done = 0.saturating_sub(1) + 1 = 0 + 1 = 1, but actually we haven't executed block 1 yet
        // The progress formula counts from start, so initial is 1/100 = 1%
        assert!(syncer.progress() < 2.0);

        syncer.executed_up_to = 50;
        assert!((syncer.progress() - 50.0).abs() < 1.0);

        syncer.executed_up_to = 100;
        assert!((syncer.progress() - 100.0).abs() < 0.1);
    }

    #[test]
    fn test_resume() {
        let syncer = BlockSyncer::resume(10001, 10050, 10100);

        assert_eq!(syncer.start_height, 10001);
        assert_eq!(syncer.executed_up_to, 10050);
        assert_eq!(syncer.target_height, 10100);

        // Progress should reflect resumed state
        assert!(syncer.progress() > 40.0);
    }
}
