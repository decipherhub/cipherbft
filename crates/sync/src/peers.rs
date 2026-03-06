//! Peer tracking and selection for sync

#![allow(dead_code)] // Module is used by other sync components (WIP)

use crate::error::SyncError;
use crate::protocol::StatusResponse;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Maximum concurrent requests per peer
pub const MAX_REQUESTS_PER_PEER: u32 = 4;

/// Total maximum concurrent requests
pub const MAX_TOTAL_REQUESTS: u32 = 16;

/// Default request timeout
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Ban duration for misbehaving peers
pub const BAN_DURATION: Duration = Duration::from_secs(3600);

/// Peer performance metrics
#[derive(Clone, Debug)]
pub struct PeerMetrics {
    /// Exponential moving average of response latency
    pub avg_latency_ms: f64,
    /// Throughput in bytes/sec
    pub throughput_bps: f64,
    /// Request success rate (0.0 - 1.0)
    pub success_rate: f64,
    /// Total completed requests
    pub total_requests: u64,
    /// Total failed requests
    pub failed_requests: u64,
}

impl Default for PeerMetrics {
    fn default() -> Self {
        Self {
            avg_latency_ms: 100.0, // Assume 100ms initially
            throughput_bps: 0.0,
            success_rate: 1.0, // Assume good until proven otherwise
            total_requests: 0,
            failed_requests: 0,
        }
    }
}

impl PeerMetrics {
    /// Update metrics after successful request
    pub fn record_success(&mut self, latency: Duration, bytes: u64) {
        let latency_ms = latency.as_secs_f64() * 1000.0;

        // Exponential moving average (alpha = 0.3)
        self.avg_latency_ms = 0.7 * self.avg_latency_ms + 0.3 * latency_ms;

        if latency.as_secs_f64() > 0.0 {
            let bps = bytes as f64 / latency.as_secs_f64();
            self.throughput_bps = 0.7 * self.throughput_bps + 0.3 * bps;
        }

        self.total_requests += 1;
        self.success_rate = 1.0 - (self.failed_requests as f64 / self.total_requests as f64);
    }

    /// Update metrics after failed request
    pub fn record_failure(&mut self) {
        self.total_requests += 1;
        self.failed_requests += 1;
        self.success_rate = 1.0 - (self.failed_requests as f64 / self.total_requests as f64);

        // Penalize latency on failure
        self.avg_latency_ms += 500.0;
    }
}

/// Tracked peer state
#[derive(Clone, Debug)]
pub struct PeerState {
    /// Peer identifier
    pub peer_id: String,
    /// Peer's reported status
    pub status: Option<StatusResponse>,
    /// Performance metrics
    pub metrics: PeerMetrics,
    /// Current in-flight requests
    pub pending_requests: u32,
    /// Last successful interaction
    pub last_seen: Instant,
    /// Ban expiry (if banned)
    pub banned_until: Option<Instant>,
}

impl PeerState {
    /// Create a new peer state
    pub fn new(peer_id: String) -> Self {
        Self {
            peer_id,
            status: None,
            metrics: PeerMetrics::default(),
            pending_requests: 0,
            last_seen: Instant::now(),
            banned_until: None,
        }
    }

    /// Calculate peer score (higher is better)
    pub fn score(&self) -> f64 {
        if self.is_banned() {
            return f64::NEG_INFINITY;
        }

        let latency_score = 1000.0 / (self.metrics.avg_latency_ms + 10.0);
        let throughput_score = self.metrics.throughput_bps / 1_000_000.0; // MB/s
        let reliability_score = self.metrics.success_rate * 10.0;
        let capacity_score = (MAX_REQUESTS_PER_PEER - self.pending_requests) as f64;

        latency_score + throughput_score + reliability_score + capacity_score
    }

    /// Check if peer is banned
    pub fn is_banned(&self) -> bool {
        self.banned_until.is_some_and(|t| Instant::now() < t)
    }

    /// Check if peer can accept more requests
    pub fn can_accept_request(&self) -> bool {
        !self.is_banned() && self.pending_requests < MAX_REQUESTS_PER_PEER
    }

    /// Check if peer has the snapshot we need
    pub fn has_snapshot(&self, height: u64) -> bool {
        self.status
            .as_ref()
            .is_some_and(|s| s.snapshots.iter().any(|snap| snap.height == height))
    }
}

/// Peer manager for sync
pub struct PeerManager {
    peers: HashMap<String, PeerState>,
    total_pending: u32,
}

impl PeerManager {
    /// Create a new peer manager
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            total_pending: 0,
        }
    }

    /// Add or update a peer
    pub fn add_peer(&mut self, peer_id: String) {
        self.peers
            .entry(peer_id.clone())
            .or_insert_with(|| PeerState::new(peer_id));
    }

    /// Update peer status
    pub fn update_status(&mut self, peer_id: &str, status: StatusResponse) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.status = Some(status);
            peer.last_seen = Instant::now();
        }
    }

    /// Remove a peer
    pub fn remove_peer(&mut self, peer_id: &str) {
        if let Some(peer) = self.peers.remove(peer_id) {
            self.total_pending = self.total_pending.saturating_sub(peer.pending_requests);
        }
    }

    /// Get number of available peers
    pub fn peer_count(&self) -> usize {
        self.peers.values().filter(|p| !p.is_banned()).count()
    }

    /// Get peers that have a specific snapshot
    pub fn peers_with_snapshot(&self, height: u64) -> Vec<&PeerState> {
        self.peers
            .values()
            .filter(|p| !p.is_banned() && p.has_snapshot(height))
            .collect()
    }

    /// Select best peer for a request
    pub fn select_peer(&self, snapshot_height: Option<u64>) -> Option<&PeerState> {
        if self.total_pending >= MAX_TOTAL_REQUESTS {
            return None;
        }

        self.peers
            .values()
            .filter(|p| p.can_accept_request())
            .filter(|p| snapshot_height.is_none_or(|h| p.has_snapshot(h)))
            .max_by(|a, b| a.score().partial_cmp(&b.score()).unwrap())
    }

    /// Mark request started for peer
    pub fn request_started(&mut self, peer_id: &str) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.pending_requests += 1;
            self.total_pending += 1;
        }
    }

    /// Mark request completed for peer
    pub fn request_completed(&mut self, peer_id: &str, latency: Duration, bytes: u64) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.pending_requests = peer.pending_requests.saturating_sub(1);
            peer.metrics.record_success(latency, bytes);
            peer.last_seen = Instant::now();
        }
        self.total_pending = self.total_pending.saturating_sub(1);
    }

    /// Mark request failed for peer
    pub fn request_failed(&mut self, peer_id: &str) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.pending_requests = peer.pending_requests.saturating_sub(1);
            peer.metrics.record_failure();
        }
        self.total_pending = self.total_pending.saturating_sub(1);
    }

    /// Ban a misbehaving peer
    pub fn ban_peer(&mut self, peer_id: &str, duration: Duration) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.banned_until = Some(Instant::now() + duration);
            // Return pending requests
            self.total_pending = self.total_pending.saturating_sub(peer.pending_requests);
            peer.pending_requests = 0;
        }
    }

    /// Handle peer misbehavior
    pub fn handle_misbehavior(&mut self, peer_id: &str, error: &SyncError) {
        if error.is_peer_misbehavior() {
            self.ban_peer(peer_id, BAN_DURATION);
        } else if error.is_retriable() {
            self.request_failed(peer_id);
        }
    }
}

impl Default for PeerManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerManager {
    /// Iterate over all peers
    pub fn iter(&self) -> impl Iterator<Item = (&String, &PeerState)> {
        self.peers.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::SnapshotInfo;
    use alloy_primitives::B256;

    fn make_status(height: u64, snapshot_heights: Vec<u64>) -> StatusResponse {
        StatusResponse {
            tip_height: height,
            tip_hash: B256::ZERO,
            snapshots: snapshot_heights
                .into_iter()
                .map(|h| SnapshotInfo {
                    height: h,
                    state_root: B256::repeat_byte((h % 256) as u8),
                    block_hash: B256::repeat_byte(((h / 256) % 256) as u8),
                })
                .collect(),
        }
    }

    #[test]
    fn test_peer_scoring() {
        let mut peer = PeerState::new("peer1".to_string());

        // Default score
        let initial_score = peer.score();

        // Record some success
        peer.metrics
            .record_success(Duration::from_millis(50), 10000);
        let better_score = peer.score();

        assert!(better_score > initial_score);
    }

    #[test]
    fn test_peer_selection() {
        let mut manager = PeerManager::new();

        manager.add_peer("peer1".to_string());
        manager.add_peer("peer2".to_string());

        manager.update_status("peer1", make_status(100000, vec![90000, 80000]));
        manager.update_status("peer2", make_status(100000, vec![90000]));

        // Both have snapshot 90000
        let peer = manager.select_peer(Some(90000));
        assert!(peer.is_some());

        // Only peer1 has snapshot 80000
        let peer = manager.select_peer(Some(80000));
        assert_eq!(peer.map(|p| p.peer_id.as_str()), Some("peer1"));
    }

    #[test]
    fn test_peer_banning() {
        let mut manager = PeerManager::new();
        manager.add_peer("bad_peer".to_string());

        assert_eq!(manager.peer_count(), 1);

        manager.ban_peer("bad_peer", Duration::from_secs(60));

        assert_eq!(manager.peer_count(), 0);
        assert!(manager.select_peer(None).is_none());
    }

    #[test]
    fn test_request_tracking() {
        let mut manager = PeerManager::new();
        manager.add_peer("peer1".to_string());

        manager.request_started("peer1");
        assert_eq!(manager.total_pending, 1);

        manager.request_completed("peer1", Duration::from_millis(100), 5000);
        assert_eq!(manager.total_pending, 0);
    }

    #[test]
    fn test_misbehavior_handling() {
        let mut manager = PeerManager::new();
        manager.add_peer("peer1".to_string());

        // Invalid proof should ban
        let error = SyncError::invalid_proof("peer1", "bad proof");
        manager.handle_misbehavior("peer1", &error);

        assert_eq!(manager.peer_count(), 0);
    }
}
