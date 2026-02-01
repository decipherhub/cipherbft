//! Snap sync P2P protocol messages
//!
//! Protocol identifier: `/cipherbft/snap/1.0.0`

use alloy_primitives::{Address, Bytes, B256, U256};
use serde::{Deserialize, Serialize};

/// Protocol identifier for snap sync
pub const SNAP_PROTOCOL_ID: &str = "/cipherbft/snap/1.0.0";

/// Maximum accounts per range response
pub const MAX_ACCOUNTS_PER_RESPONSE: u32 = 4096;

/// Maximum storage slots per range response
pub const MAX_STORAGE_PER_RESPONSE: u32 = 8192;

/// Maximum blocks per response
pub const MAX_BLOCKS_PER_RESPONSE: u32 = 128;

/// Snap sync protocol messages
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SnapSyncMessage {
    // === Discovery ===
    /// Request peer's sync status
    GetStatus,

    /// Response with current status
    Status(StatusResponse),

    // === Account Ranges ===
    /// Request accounts in address range
    GetAccountRange(AccountRangeRequest),

    /// Response with accounts and proof
    AccountRange(AccountRangeResponse),

    // === Storage Ranges ===
    /// Request storage slots for account
    GetStorageRange(StorageRangeRequest),

    /// Response with storage slots and proof
    StorageRange(StorageRangeResponse),

    // === Blocks ===
    /// Request block range
    GetBlocks(BlockRangeRequest),

    /// Response with blocks
    Blocks(BlockRangeResponse),
}

/// Peer status response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatusResponse {
    /// Peer's tip block height
    pub tip_height: u64,
    /// Peer's tip block hash
    pub tip_hash: B256,
    /// Available snapshots with state roots (sorted by height descending)
    /// Each entry contains (height, state_root, block_hash)
    pub snapshots: Vec<SnapshotInfo>,
}

/// Snapshot information advertised by a peer
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotInfo {
    /// Block height of the snapshot
    pub height: u64,
    /// State root (MPT root) at this height
    pub state_root: B256,
    /// Block hash at this height
    pub block_hash: B256,
}

/// Account range request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountRangeRequest {
    /// Unique request identifier for response correlation
    pub request_id: u64,
    /// Snapshot height to sync from
    pub snapshot_height: u64,
    /// Expected state root at snapshot
    pub state_root: B256,
    /// Start of address range (inclusive)
    pub start_address: Address,
    /// End of address range (exclusive)
    pub limit_address: Address,
    /// Maximum accounts to return
    pub max_accounts: u32,
}

/// Account range response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountRangeResponse {
    /// Request ID echoed back for correlation
    pub request_id: u64,
    /// Accounts in range: (address, nonce, balance, code_hash, storage_root)
    pub accounts: Vec<AccountData>,
    /// Merkle proof nodes
    pub proof: Vec<Bytes>,
    /// True if more accounts exist after this range
    pub more: bool,
}

/// Account data for sync
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountData {
    /// Account address
    pub address: Address,
    /// Account nonce
    pub nonce: u64,
    /// Account balance
    pub balance: U256,
    /// Hash of contract bytecode (or empty account hash)
    pub code_hash: B256,
    /// Root of storage trie
    pub storage_root: B256,
}

/// Storage range request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageRangeRequest {
    /// Unique request identifier for response correlation
    pub request_id: u64,
    /// Snapshot height
    pub snapshot_height: u64,
    /// Expected state root
    pub state_root: B256,
    /// Account to fetch storage for
    pub account: Address,
    /// Account's storage root (for verification)
    pub storage_root: B256,
    /// Start storage slot (inclusive)
    pub start_slot: B256,
    /// End storage slot (exclusive)
    pub limit_slot: B256,
    /// Maximum slots to return
    pub max_slots: u32,
}

/// Storage range response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageRangeResponse {
    /// Request ID echoed back for correlation
    pub request_id: u64,
    /// Storage slots: (key, value)
    pub slots: Vec<(B256, B256)>,
    /// Merkle proof nodes
    pub proof: Vec<Bytes>,
    /// True if more slots exist after this range
    pub more: bool,
}

/// Block range request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockRangeRequest {
    /// Unique request identifier for response correlation
    pub request_id: u64,
    /// Start block height (inclusive)
    pub start_height: u64,
    /// Number of blocks to fetch
    pub count: u32,
}

/// Block range response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockRangeResponse {
    /// Request ID echoed back for correlation
    pub request_id: u64,
    /// Serialized blocks
    pub blocks: Vec<Bytes>,
}

impl SnapSyncMessage {
    /// Get message type name for logging
    pub fn message_type(&self) -> &'static str {
        match self {
            Self::GetStatus => "GetStatus",
            Self::Status(_) => "Status",
            Self::GetAccountRange(_) => "GetAccountRange",
            Self::AccountRange(_) => "AccountRange",
            Self::GetStorageRange(_) => "GetStorageRange",
            Self::StorageRange(_) => "StorageRange",
            Self::GetBlocks(_) => "GetBlocks",
            Self::Blocks(_) => "Blocks",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_serialization_roundtrip() {
        let msg = SnapSyncMessage::GetAccountRange(AccountRangeRequest {
            request_id: 1,
            snapshot_height: 10000,
            state_root: B256::ZERO,
            start_address: Address::ZERO,
            limit_address: Address::repeat_byte(0xff),
            max_accounts: 1000,
        });

        let encoded = bincode::serialize(&msg).unwrap();
        let decoded: SnapSyncMessage = bincode::deserialize(&encoded).unwrap();

        assert!(matches!(decoded, SnapSyncMessage::GetAccountRange(_)));
    }

    #[test]
    fn test_status_response() {
        let status = StatusResponse {
            tip_height: 1_000_000,
            tip_hash: B256::repeat_byte(0xab),
            snapshots: vec![
                SnapshotInfo {
                    height: 990_000,
                    state_root: B256::repeat_byte(0x01),
                    block_hash: B256::repeat_byte(0x02),
                },
                SnapshotInfo {
                    height: 980_000,
                    state_root: B256::repeat_byte(0x03),
                    block_hash: B256::repeat_byte(0x04),
                },
                SnapshotInfo {
                    height: 970_000,
                    state_root: B256::repeat_byte(0x05),
                    block_hash: B256::repeat_byte(0x06),
                },
            ],
        };

        let encoded = bincode::serialize(&status).unwrap();
        // Status response is now larger due to state roots and block hashes
        assert!(encoded.len() < 1500);
    }
}
