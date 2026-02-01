//! Storage range synchronization

#![allow(dead_code)] // Module is foundational, will be used by sync orchestrator

use crate::error::Result;
use crate::protocol::{StorageRangeRequest, StorageRangeResponse, MAX_STORAGE_PER_RESPONSE};
use crate::snap::verify::verify_storage_range_proof;
use crate::snapshot::StateSnapshot;
use alloy_primitives::{Address, B256};
use std::collections::VecDeque;

/// Pending storage range to download
#[derive(Clone, Debug)]
pub struct PendingStorageRange {
    /// Account address
    pub account: Address,
    /// Account's storage root
    pub storage_root: B256,
    /// Start slot (inclusive)
    pub start: B256,
    /// End slot (exclusive)
    pub end: B256,
    /// Retry count
    pub retries: u32,
}

impl PendingStorageRange {
    /// Create initial range for an account (full storage space)
    pub fn new(account: Address, storage_root: B256) -> Self {
        Self {
            account,
            storage_root,
            start: B256::ZERO,
            end: B256::repeat_byte(0xff),
            retries: 0,
        }
    }
}

/// Storage range syncer
pub struct StorageRangeSyncer {
    /// Target snapshot
    snapshot: StateSnapshot,
    /// Accounts pending storage download
    pending_accounts: VecDeque<(Address, B256)>,
    /// Current account being synced
    current_ranges: Vec<PendingStorageRange>,
    /// Total slots downloaded
    total_slots: u64,
    /// Total bytes downloaded
    total_bytes: u64,
    /// Completed accounts count
    completed_accounts: u64,
    /// Next request ID for correlation
    next_request_id: u64,
}

impl StorageRangeSyncer {
    /// Create a new storage range syncer
    pub fn new(snapshot: StateSnapshot, accounts: Vec<(Address, B256)>) -> Self {
        Self {
            snapshot,
            pending_accounts: accounts.into_iter().collect(),
            current_ranges: Vec::new(),
            total_slots: 0,
            total_bytes: 0,
            completed_accounts: 0,
            next_request_id: 1,
        }
    }

    /// Check if sync is complete
    pub fn is_complete(&self) -> bool {
        self.pending_accounts.is_empty() && self.current_ranges.is_empty()
    }

    /// Get next range to request
    pub fn next_range(&mut self) -> Option<PendingStorageRange> {
        // First try current ranges
        if let Some(range) = self.current_ranges.pop() {
            return Some(range);
        }

        // Start next account
        if let Some((account, storage_root)) = self.pending_accounts.pop_front() {
            return Some(PendingStorageRange::new(account, storage_root));
        }

        None
    }

    /// Create request for a range with unique request ID
    pub fn create_request(&mut self, range: &PendingStorageRange) -> StorageRangeRequest {
        let request_id = self.next_request_id;
        self.next_request_id += 1;
        StorageRangeRequest {
            request_id,
            snapshot_height: self.snapshot.block_number,
            state_root: self.snapshot.state_root,
            account: range.account,
            storage_root: range.storage_root,
            start_slot: range.start,
            limit_slot: range.end,
            max_slots: MAX_STORAGE_PER_RESPONSE,
        }
    }

    /// Process response for a range
    pub fn process_response(
        &mut self,
        range: PendingStorageRange,
        response: StorageRangeResponse,
    ) -> Result<()> {
        // Verify the proof
        self.verify_storage_proof(&range, &response)?;

        self.total_slots += response.slots.len() as u64;
        self.total_bytes += estimate_storage_response_size(&response);

        // If more slots exist, add continuation range
        if response.more {
            if let Some((last_key, _)) = response.slots.last() {
                let next_start = increment_b256(*last_key);
                self.current_ranges.push(PendingStorageRange {
                    account: range.account,
                    storage_root: range.storage_root,
                    start: next_start,
                    end: range.end,
                    retries: 0,
                });
            }
        } else {
            // Account storage complete
            self.completed_accounts += 1;
        }

        Ok(())
    }

    /// Handle failed request
    pub fn handle_failure(&mut self, range: PendingStorageRange, max_retries: u32) {
        if range.retries < max_retries {
            self.current_ranges.push(PendingStorageRange {
                retries: range.retries + 1,
                ..range
            });
        } else {
            // Re-queue the account to try again later
            self.pending_accounts
                .push_back((range.account, range.storage_root));
        }
    }

    /// Verify storage range proof using MPT proof verification.
    fn verify_storage_proof(
        &self,
        range: &PendingStorageRange,
        response: &StorageRangeResponse,
    ) -> Result<()> {
        verify_storage_range_proof(
            range.storage_root,
            range.start,
            &response.slots,
            &response.proof,
        )
    }

    /// Get sync statistics
    pub fn stats(&self) -> StorageSyncStats {
        StorageSyncStats {
            total_slots: self.total_slots,
            total_bytes: self.total_bytes,
            completed_accounts: self.completed_accounts,
            pending_accounts: self.pending_accounts.len() as u64,
            pending_ranges: self.current_ranges.len() as u64,
        }
    }
}

/// Storage sync statistics
#[derive(Clone, Debug, Default)]
pub struct StorageSyncStats {
    /// Total storage slots downloaded
    pub total_slots: u64,
    /// Total bytes downloaded
    pub total_bytes: u64,
    /// Number of accounts completed
    pub completed_accounts: u64,
    /// Number of accounts still pending
    pub pending_accounts: u64,
    /// Number of ranges in progress
    pub pending_ranges: u64,
}

// Helper functions

fn increment_b256(val: B256) -> B256 {
    let mut bytes = val.0;
    for i in (0..32).rev() {
        if bytes[i] < 255 {
            bytes[i] += 1;
            return B256::from(bytes);
        }
        bytes[i] = 0;
    }
    B256::ZERO // Overflow wraps
}

fn estimate_storage_response_size(response: &StorageRangeResponse) -> u64 {
    // 64 bytes per slot (key + value) + proof size
    let slots_size = response.slots.len() as u64 * 64;
    let proof_size: u64 = response.proof.iter().map(|p| p.len() as u64).sum();
    slots_size + proof_size
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pending_storage_range() {
        let range = PendingStorageRange::new(Address::repeat_byte(0x42), B256::repeat_byte(0xab));

        assert_eq!(range.start, B256::ZERO);
        assert_eq!(range.account, Address::repeat_byte(0x42));
    }

    #[test]
    fn test_storage_syncer_creation() {
        let snapshot = StateSnapshot::new(10000, B256::ZERO, B256::repeat_byte(0xab), 12345);

        let accounts = vec![
            (Address::repeat_byte(0x01), B256::repeat_byte(0xaa)),
            (Address::repeat_byte(0x02), B256::repeat_byte(0xbb)),
        ];

        let syncer = StorageRangeSyncer::new(snapshot, accounts);
        assert!(!syncer.is_complete());

        let stats = syncer.stats();
        assert_eq!(stats.pending_accounts, 2);
    }

    #[test]
    fn test_storage_syncer_next_range() {
        let snapshot = StateSnapshot::new(10000, B256::ZERO, B256::ZERO, 0);
        let accounts = vec![(Address::repeat_byte(0x01), B256::repeat_byte(0xaa))];

        let mut syncer = StorageRangeSyncer::new(snapshot, accounts);

        let range = syncer.next_range();
        assert!(range.is_some());
        assert_eq!(range.unwrap().account, Address::repeat_byte(0x01));

        // No more ranges
        assert!(syncer.next_range().is_none());
    }

    #[test]
    fn test_increment_b256() {
        let val = B256::ZERO;
        let next = increment_b256(val);
        assert_eq!(next.0[31], 1);

        let val = B256::repeat_byte(0xff);
        let next = increment_b256(val);
        assert_eq!(next, B256::ZERO); // Overflow
    }
}
