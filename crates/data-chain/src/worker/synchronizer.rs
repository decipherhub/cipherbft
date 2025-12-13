//! Batch synchronizer for Worker
//!
//! Handles batch synchronization requests from Primary and peer Workers.

use cipherbft_types::{Hash, ValidatorId};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// Request state for tracking pending sync requests
#[derive(Debug)]
struct PendingRequest {
    /// Digests being requested
    digests: Vec<Hash>,
    /// Target validator
    target: ValidatorId,
    /// When request was sent
    sent_at: Instant,
    /// Number of retries
    retries: u32,
}

/// Batch synchronizer
pub struct Synchronizer {
    /// Pending sync requests (request_id -> request)
    pending_requests: HashMap<u64, PendingRequest>,
    /// Next request ID
    next_request_id: u64,
    /// Digests currently being synced
    syncing: HashSet<Hash>,
    /// Request timeout
    timeout: Duration,
    /// Maximum retries
    max_retries: u32,
}

impl Synchronizer {
    /// Create a new synchronizer
    pub fn new(timeout: Duration, max_retries: u32) -> Self {
        Self {
            pending_requests: HashMap::new(),
            next_request_id: 0,
            syncing: HashSet::new(),
            timeout,
            max_retries,
        }
    }

    /// Start syncing batches from a target validator
    ///
    /// Returns request ID for tracking
    pub fn start_sync(&mut self, digests: Vec<Hash>, target: ValidatorId) -> u64 {
        let request_id = self.next_request_id;
        self.next_request_id += 1;

        // Mark digests as syncing
        for digest in &digests {
            self.syncing.insert(*digest);
        }

        self.pending_requests.insert(
            request_id,
            PendingRequest {
                digests,
                target,
                sent_at: Instant::now(),
                retries: 0,
            },
        );

        request_id
    }

    /// Mark a digest as successfully synced
    pub fn mark_synced(&mut self, digest: &Hash) {
        self.syncing.remove(digest);

        // Remove from pending requests if all digests synced
        self.pending_requests.retain(|_, req| {
            req.digests.retain(|d| d != digest);
            !req.digests.is_empty()
        });
    }

    /// Mark a sync as failed
    pub fn mark_failed(&mut self, request_id: u64) {
        if let Some(req) = self.pending_requests.remove(&request_id) {
            for digest in &req.digests {
                self.syncing.remove(digest);
            }
        }
    }

    /// Check if a digest is currently being synced
    pub fn is_syncing(&self, digest: &Hash) -> bool {
        self.syncing.contains(digest)
    }

    /// Check for timed out requests
    ///
    /// Returns requests that should be retried or failed
    pub fn check_timeouts(&mut self) -> Vec<(u64, Vec<Hash>, ValidatorId, bool)> {
        let now = Instant::now();
        let mut results = Vec::new();

        for (id, req) in &mut self.pending_requests {
            if now.duration_since(req.sent_at) >= self.timeout {
                if req.retries < self.max_retries {
                    // Should retry
                    req.retries += 1;
                    req.sent_at = now;
                    results.push((*id, req.digests.clone(), req.target, true));
                } else {
                    // Max retries exceeded
                    results.push((*id, req.digests.clone(), req.target, false));
                }
            }
        }

        // Remove failed requests
        for (id, _, _, should_retry) in &results {
            if !should_retry {
                if let Some(req) = self.pending_requests.remove(id) {
                    for digest in &req.digests {
                        self.syncing.remove(digest);
                    }
                }
            }
        }

        results
    }

    /// Get pending request count
    pub fn pending_count(&self) -> usize {
        self.pending_requests.len()
    }

    /// Get syncing digest count
    pub fn syncing_count(&self) -> usize {
        self.syncing.len()
    }

    /// Check if there are pending syncs
    pub fn has_pending(&self) -> bool {
        !self.pending_requests.is_empty()
    }

    /// Get all digests being synced
    pub fn syncing_digests(&self) -> Vec<Hash> {
        self.syncing.iter().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_start_sync() {
        let mut sync = Synchronizer::new(Duration::from_millis(100), 3);

        let digests = vec![Hash::compute(b"1"), Hash::compute(b"2")];
        let target = ValidatorId::from_bytes([1u8; 32]);

        let id = sync.start_sync(digests.clone(), target);

        assert!(sync.is_syncing(&digests[0]));
        assert!(sync.is_syncing(&digests[1]));
        assert_eq!(sync.pending_count(), 1);
    }

    #[test]
    fn test_mark_synced() {
        let mut sync = Synchronizer::new(Duration::from_millis(100), 3);

        let digests = vec![Hash::compute(b"1"), Hash::compute(b"2")];
        let target = ValidatorId::from_bytes([1u8; 32]);

        sync.start_sync(digests.clone(), target);

        // Mark first as synced
        sync.mark_synced(&digests[0]);
        assert!(!sync.is_syncing(&digests[0]));
        assert!(sync.is_syncing(&digests[1]));
        assert_eq!(sync.pending_count(), 1); // Still pending

        // Mark second as synced
        sync.mark_synced(&digests[1]);
        assert!(!sync.is_syncing(&digests[1]));
        assert_eq!(sync.pending_count(), 0); // All done
    }

    #[test]
    fn test_mark_failed() {
        let mut sync = Synchronizer::new(Duration::from_millis(100), 3);

        let digests = vec![Hash::compute(b"1")];
        let target = ValidatorId::from_bytes([1u8; 32]);

        let id = sync.start_sync(digests.clone(), target);
        assert!(sync.is_syncing(&digests[0]));

        sync.mark_failed(id);
        assert!(!sync.is_syncing(&digests[0]));
        assert_eq!(sync.pending_count(), 0);
    }

    #[test]
    fn test_timeout_retry() {
        let mut sync = Synchronizer::new(Duration::from_millis(1), 3);

        let digests = vec![Hash::compute(b"1")];
        let target = ValidatorId::from_bytes([1u8; 32]);

        sync.start_sync(digests.clone(), target);

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(5));

        let timeouts = sync.check_timeouts();
        assert_eq!(timeouts.len(), 1);
        assert!(timeouts[0].3); // should_retry = true

        // Still pending (retry)
        assert_eq!(sync.pending_count(), 1);
    }

    #[test]
    fn test_max_retries_exceeded() {
        let mut sync = Synchronizer::new(Duration::from_millis(1), 0); // 0 retries

        let digests = vec![Hash::compute(b"1")];
        let target = ValidatorId::from_bytes([1u8; 32]);

        sync.start_sync(digests.clone(), target);

        std::thread::sleep(Duration::from_millis(5));

        let timeouts = sync.check_timeouts();
        assert_eq!(timeouts.len(), 1);
        assert!(!timeouts[0].3); // should_retry = false

        // Request removed
        assert_eq!(sync.pending_count(), 0);
        assert!(!sync.is_syncing(&digests[0]));
    }
}
