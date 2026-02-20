//! Account range synchronization

#![allow(dead_code)] // Module is foundational, will be used by sync orchestrator

use crate::error::Result;
use crate::protocol::{AccountRangeRequest, AccountRangeResponse, MAX_ACCOUNTS_PER_RESPONSE};
use crate::snap::verify::verify_account_range_proof;
use crate::snapshot::StateSnapshot;
use alloy_primitives::{Address, B256, U256};
use alloy_trie::EMPTY_ROOT_HASH;

/// Number of parallel address ranges to download
pub const PARALLEL_RANGES: usize = 16;

/// Pending account range to download
#[derive(Clone, Debug)]
pub struct PendingRange {
    /// Start address (inclusive)
    pub start: Address,
    /// End address (exclusive)
    pub end: Address,
    /// Number of retry attempts
    pub retries: u32,
}

impl PendingRange {
    /// Create initial ranges covering the full 160-bit address space
    pub fn initial_ranges() -> Vec<Self> {
        let mut ranges = Vec::with_capacity(PARALLEL_RANGES);
        // Full 160-bit address space: 2^160
        let address_space = U256::from(1) << 160;
        let step = address_space / U256::from(PARALLEL_RANGES);

        for i in 0..PARALLEL_RANGES {
            let start_val = step * U256::from(i);
            let end_val = if i == PARALLEL_RANGES - 1 {
                address_space - U256::from(1) // Max address: 0xFF..FF (20 bytes)
            } else {
                step * U256::from(i + 1)
            };

            let start = address_from_u256(start_val);
            let end = address_from_u256(end_val);

            ranges.push(PendingRange {
                start,
                end,
                retries: 0,
            });
        }
        ranges
    }

    /// Split this range in half for retry
    pub fn split(&self) -> (Self, Self) {
        let mid = midpoint_address(&self.start, &self.end);
        (
            PendingRange {
                start: self.start,
                end: mid,
                retries: self.retries,
            },
            PendingRange {
                start: mid,
                end: self.end,
                retries: self.retries,
            },
        )
    }
}

/// Account range syncer
pub struct AccountRangeSyncer {
    /// Target snapshot
    snapshot: StateSnapshot,
    /// Pending ranges to download
    pending: Vec<PendingRange>,
    /// Accounts that need storage downloaded (address, storage_root)
    accounts_with_storage: Vec<(Address, B256)>,
    /// Total accounts downloaded
    total_accounts: u64,
    /// Total bytes downloaded
    total_bytes: u64,
    /// Next request ID for correlation
    next_request_id: u64,
}

impl AccountRangeSyncer {
    /// Create a new account range syncer
    pub fn new(snapshot: StateSnapshot) -> Self {
        Self {
            snapshot,
            pending: PendingRange::initial_ranges(),
            accounts_with_storage: Vec::new(),
            total_accounts: 0,
            total_bytes: 0,
            next_request_id: 1,
        }
    }

    /// Resume from progress state
    pub fn resume(snapshot: StateSnapshot, completed_up_to: Option<Address>) -> Self {
        let pending = if let Some(addr) = completed_up_to {
            // Resume from where we left off
            vec![PendingRange {
                start: addr,
                end: Address::repeat_byte(0xff),
                retries: 0,
            }]
        } else {
            PendingRange::initial_ranges()
        };

        Self {
            snapshot,
            pending,
            accounts_with_storage: Vec::new(),
            total_accounts: 0,
            total_bytes: 0,
            next_request_id: 1,
        }
    }

    /// Check if sync is complete
    pub fn is_complete(&self) -> bool {
        self.pending.is_empty()
    }

    /// Get next range to request
    pub fn next_range(&mut self) -> Option<PendingRange> {
        self.pending.pop()
    }

    /// Create request for a range with unique request ID
    pub fn create_request(&mut self, range: &PendingRange) -> AccountRangeRequest {
        let request_id = self.next_request_id;
        self.next_request_id += 1;
        AccountRangeRequest {
            request_id,
            snapshot_height: self.snapshot.block_number,
            state_root: self.snapshot.state_root,
            start_address: range.start,
            limit_address: range.end,
            max_accounts: MAX_ACCOUNTS_PER_RESPONSE,
        }
    }

    /// Process response for a range
    pub fn process_response(
        &mut self,
        range: PendingRange,
        response: AccountRangeResponse,
    ) -> Result<()> {
        // Verify the proof with the actual range start address
        self.verify_account_proof(&range, &response)?;

        // Track accounts with non-empty storage (preserve their storage root)
        for account in &response.accounts {
            if account.storage_root != EMPTY_ROOT_HASH {
                self.accounts_with_storage
                    .push((account.address, account.storage_root));
            }
        }

        self.total_accounts += response.accounts.len() as u64;
        self.total_bytes += estimate_response_size(&response);

        // If more accounts exist, add continuation range
        if response.more {
            if let Some(last) = response.accounts.last() {
                // Next range starts after last account (None means we hit max address)
                if let Some(next_start) = increment_address(last.address) {
                    self.pending.push(PendingRange {
                        start: next_start,
                        end: range.end,
                        retries: 0,
                    });
                }
            }
        }

        Ok(())
    }

    /// Handle failed request
    pub fn handle_failure(&mut self, range: PendingRange, max_retries: u32) {
        if range.retries < max_retries {
            // Retry with incremented counter
            self.pending.push(PendingRange {
                retries: range.retries + 1,
                ..range
            });
        } else {
            // Split range and retry both halves
            let (left, right) = range.split();
            self.pending.push(left);
            self.pending.push(right);
        }
    }

    /// Verify account range proof using MPT proof verification.
    fn verify_account_proof(
        &self,
        range: &PendingRange,
        response: &AccountRangeResponse,
    ) -> Result<()> {
        // Use the actual range start address for proper verification
        verify_account_range_proof(
            self.snapshot.state_root,
            range.start,
            &response.accounts,
            &response.proof,
        )
    }

    /// Get accounts that need storage downloaded (address, storage_root)
    pub fn accounts_needing_storage(&self) -> &[(Address, B256)] {
        &self.accounts_with_storage
    }

    /// Get sync statistics
    pub fn stats(&self) -> (u64, u64, usize) {
        (self.total_accounts, self.total_bytes, self.pending.len())
    }
}

// Helper functions

fn address_from_u256(val: U256) -> Address {
    let be_bytes: [u8; 32] = val.to_be_bytes();
    // Take the last 20 bytes (address is rightmost 160 bits)
    let mut addr_bytes = [0u8; 20];
    addr_bytes.copy_from_slice(&be_bytes[12..32]);
    Address::from(addr_bytes)
}

fn midpoint_address(start: &Address, end: &Address) -> Address {
    // Simple midpoint calculation
    let start_bytes = start.as_slice();
    let end_bytes = end.as_slice();
    let mut mid_bytes = [0u8; 20];

    let mut carry = 0u16;
    for i in (0..20).rev() {
        let sum = start_bytes[i] as u16 + end_bytes[i] as u16 + carry;
        mid_bytes[i] = (sum / 2) as u8;
        carry = (sum % 2) << 8;
    }

    Address::from(mid_bytes)
}

fn increment_address(addr: Address) -> Option<Address> {
    let mut bytes = addr.0;
    for i in (0..20).rev() {
        if bytes[i] < 255 {
            bytes[i] += 1;
            return Some(Address::from(bytes));
        }
        bytes[i] = 0;
    }
    None // Overflow: already at max address
}

fn estimate_response_size(response: &AccountRangeResponse) -> u64 {
    // Rough estimate: 100 bytes per account + proof size
    let accounts_size = response.accounts.len() as u64 * 100;
    let proof_size: u64 = response.proof.iter().map(|p| p.len() as u64).sum();
    accounts_size + proof_size
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;

    #[test]
    fn test_initial_ranges() {
        let ranges = PendingRange::initial_ranges();
        assert_eq!(ranges.len(), PARALLEL_RANGES);

        // First range starts at 0
        assert_eq!(ranges[0].start, Address::ZERO);
    }

    #[test]
    fn test_range_split() {
        let range = PendingRange {
            start: Address::ZERO,
            end: Address::repeat_byte(0xff),
            retries: 0,
        };

        let (left, right) = range.split();
        assert_eq!(left.start, range.start);
        assert_eq!(right.end, range.end);
        // Midpoint should be between start and end
        assert!(left.end == right.start);
    }

    #[test]
    fn test_syncer_creation() {
        let snapshot = StateSnapshot::new(10000, B256::ZERO, B256::repeat_byte(0xab), 12345);

        let syncer = AccountRangeSyncer::new(snapshot);
        assert!(!syncer.is_complete());
        assert_eq!(syncer.accounts_needing_storage().len(), 0);
    }

    #[test]
    fn test_increment_address() {
        let addr = Address::ZERO;
        let next = increment_address(addr).unwrap();
        assert_eq!(next.0[19], 1);

        let addr = Address::repeat_byte(0xff);
        let next = increment_address(addr);
        assert_eq!(next, None); // Overflow returns None
    }
}
