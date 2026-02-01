//! Network adapter for snap sync protocol
//!
//! This module provides the bridge between the node's network layer and the
//! [`StateSyncManager`](cipherbft_sync::StateSyncManager). It handles the routing
//! of snap sync messages to and from peers.
//!
//! # Architecture
//!
//! ```text
//! +-----------------+     +-------------------+     +----------------+
//! |  Network Layer  | <-> | SyncNetworkAdapter| <-> | StateSyncManager |
//! +-----------------+     +-------------------+     +----------------+
//! ```
//!
//! The adapter uses channels to decouple the network I/O from the sync logic,
//! allowing both to operate concurrently.
//!
//! # Integration with TcpPrimaryNetwork
//!
//! The [`wire_sync_to_network`] function connects the sync adapter to the
//! TCP network layer:
//!
//! ```text
//! Incoming: TcpPrimaryNetwork -> SyncNetworkSender -> channels -> SyncNetworkAdapter
//! Outgoing: SyncNetworkAdapter -> channels -> start_snap_sync_sender task -> TcpPrimaryNetwork
//! ```

use crate::network::TcpPrimaryNetwork;
use cipherbft_sync::protocol::SnapSyncMessage;
use cipherbft_sync::SyncNetworkSender;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Snap sync network adapter
///
/// Bridges between the node's network layer and StateSyncManager.
/// Uses async channels for non-blocking message passing.
pub struct SyncNetworkAdapter {
    /// Outbound message sender (to network layer)
    outbound_tx: mpsc::Sender<(String, SnapSyncMessage)>,
    /// Inbound message receiver (from network layer)
    inbound_rx: mpsc::Receiver<(String, SnapSyncMessage)>,
}

impl SyncNetworkAdapter {
    /// Create a new adapter with provided channels
    ///
    /// # Arguments
    ///
    /// * `outbound_tx` - Channel sender for outgoing messages to the network
    /// * `inbound_rx` - Channel receiver for incoming messages from the network
    pub fn new(
        outbound_tx: mpsc::Sender<(String, SnapSyncMessage)>,
        inbound_rx: mpsc::Receiver<(String, SnapSyncMessage)>,
    ) -> Self {
        Self {
            outbound_tx,
            inbound_rx,
        }
    }

    /// Send a message to a specific peer
    ///
    /// # Arguments
    ///
    /// * `peer_id` - The peer's identifier
    /// * `message` - The snap sync message to send
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the message was queued successfully, or an error
    /// if the channel is closed.
    pub async fn send(&self, peer_id: &str, message: SnapSyncMessage) -> Result<(), String> {
        self.outbound_tx
            .send((peer_id.to_string(), message))
            .await
            .map_err(|e| format!("failed to send snap sync message: {}", e))
    }

    /// Receive the next inbound message
    ///
    /// # Returns
    ///
    /// Returns `Some((peer_id, message))` if a message is available,
    /// or `None` if the channel has been closed.
    pub async fn recv(&mut self) -> Option<(String, SnapSyncMessage)> {
        self.inbound_rx.recv().await
    }

    /// Try to receive a message without blocking
    ///
    /// # Returns
    ///
    /// Returns `Some((peer_id, message))` if a message is immediately available,
    /// `None` if no message is available (does not block).
    pub fn try_recv(&mut self) -> Option<(String, SnapSyncMessage)> {
        self.inbound_rx.try_recv().ok()
    }

    /// Broadcast a message to multiple peers
    ///
    /// # Arguments
    ///
    /// * `peer_ids` - List of peer identifiers to send to
    /// * `message` - The snap sync message to broadcast
    ///
    /// # Returns
    ///
    /// Returns the number of peers the message was successfully queued for.
    pub async fn broadcast(&self, peer_ids: &[String], message: &SnapSyncMessage) -> usize {
        let mut success_count = 0;
        for peer_id in peer_ids {
            if self.send(peer_id, message.clone()).await.is_ok() {
                success_count += 1;
            }
        }
        success_count
    }
}

/// Channel buffer size for sync messages
const SYNC_CHANNEL_SIZE: usize = 1000;

/// Create sync network adapter with channels
///
/// Returns a tuple containing:
/// - The adapter for use by the sync manager
/// - Sender for the network layer to forward incoming messages to sync
/// - Receiver for the network layer to get outgoing messages from sync
///
/// # Example
///
/// ```ignore
/// let (adapter, network_to_sync_tx, sync_to_network_rx) = create_sync_adapter();
///
/// // Network layer uses:
/// //   network_to_sync_tx.send((peer_id, message)) - forward incoming
/// //   sync_to_network_rx.recv() - get outgoing
///
/// // Sync manager uses:
/// //   adapter.recv() - get incoming
/// //   adapter.send(peer_id, message) - send outgoing
/// ```
#[allow(clippy::type_complexity)]
pub fn create_sync_adapter() -> (
    SyncNetworkAdapter,
    mpsc::Sender<(String, SnapSyncMessage)>, // for network to send to sync
    mpsc::Receiver<(String, SnapSyncMessage)>, // for network to receive from sync
) {
    // Channel for messages from network to sync (inbound to sync)
    let (inbound_tx, inbound_rx) = mpsc::channel(SYNC_CHANNEL_SIZE);
    // Channel for messages from sync to network (outbound from sync)
    let (outbound_tx, outbound_rx) = mpsc::channel(SYNC_CHANNEL_SIZE);

    let adapter = SyncNetworkAdapter::new(outbound_tx, inbound_rx);
    (adapter, inbound_tx, outbound_rx)
}

/// Wire the sync adapter to the TcpPrimaryNetwork
///
/// This function sets up the bidirectional message routing between the sync
/// adapter and the TCP network layer:
///
/// - **Incoming**: Messages received by `TcpPrimaryNetwork` are forwarded to the
///   sync adapter via `SyncNetworkSender`
/// - **Outgoing**: Messages sent by the sync adapter are routed through the
///   `start_snap_sync_sender` task to `TcpPrimaryNetwork`
///
/// # Arguments
///
/// * `network` - Mutable reference to the TCP primary network (for setting sender)
/// * `network_arc` - Arc reference to the same network (for starting sender task)
/// * `network_to_sync_tx` - Sender from `create_sync_adapter` for incoming messages
/// * `sync_to_network_rx` - Receiver from `create_sync_adapter` for outgoing messages
///
/// # Example
///
/// ```ignore
/// // Create the sync adapter
/// let (adapter, network_to_sync_tx, sync_to_network_rx) = create_sync_adapter();
///
/// // Wire it to the network
/// wire_sync_to_network(
///     &mut network,
///     network.clone(),  // Arc<TcpPrimaryNetwork>
///     network_to_sync_tx,
///     sync_to_network_rx,
/// );
///
/// // Now use the adapter with the sync manager
/// ```
pub async fn wire_sync_to_network(
    network: &TcpPrimaryNetwork,
    network_arc: Arc<TcpPrimaryNetwork>,
    network_to_sync_tx: mpsc::Sender<(String, SnapSyncMessage)>,
    sync_to_network_rx: mpsc::Receiver<(String, SnapSyncMessage)>,
) {
    // Create a SyncNetworkSender that forwards to our channel-based adapter
    // This wraps the (String, SnapSyncMessage) channel in the SyncNetworkSender interface
    let sync_sender = create_bridge_sender(network_to_sync_tx);
    network.set_snap_sync_sender(sync_sender).await;

    // Start the outgoing message processor task
    // This reads from sync_to_network_rx and sends via TcpPrimaryNetwork
    start_outgoing_processor(network_arc, sync_to_network_rx);
}

/// Create a SyncNetworkSender that bridges to the local channel
///
/// The sync crate's SyncNetworkSender expects IncomingSnapMessage, but our local
/// adapter uses (String, SnapSyncMessage) tuples. This creates a bridge sender.
fn create_bridge_sender(tx: mpsc::Sender<(String, SnapSyncMessage)>) -> SyncNetworkSender {
    // Create a channel that the SyncNetworkSender will use
    let (bridge_tx, mut bridge_rx) =
        mpsc::channel::<cipherbft_sync::IncomingSnapMessage>(SYNC_CHANNEL_SIZE);

    // Spawn a task that forwards from bridge to local adapter format
    tokio::spawn(async move {
        while let Some(incoming) = bridge_rx.recv().await {
            if tx.send((incoming.peer_id, incoming.message)).await.is_err() {
                break;
            }
        }
    });

    SyncNetworkSender::new(bridge_tx)
}

/// Start the outgoing message processor
///
/// Reads messages from the sync adapter's outgoing channel and sends them
/// via the TcpPrimaryNetwork.
fn start_outgoing_processor(
    network: Arc<TcpPrimaryNetwork>,
    mut rx: mpsc::Receiver<(String, SnapSyncMessage)>,
) {
    tokio::spawn(async move {
        while let Some((peer_id, message)) = rx.recv().await {
            if peer_id == "*" || peer_id.is_empty() {
                // Broadcast to all peers
                network.broadcast_snap_sync(message).await;
            } else {
                // Parse peer_id and send to specific peer
                // The peer_id is in format "ValidatorId(0x...)" from Debug
                if let Some(vid) = TcpPrimaryNetwork::parse_peer_id(&peer_id) {
                    network.send_snap_sync(vid, message).await;
                } else {
                    tracing::warn!(
                        "Could not parse peer ID for outgoing sync message: {}",
                        peer_id
                    );
                }
            }
        }
        tracing::info!("Outgoing sync message processor ended");
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;
    use cipherbft_sync::protocol::{SnapshotInfo, StatusResponse};

    #[tokio::test]
    async fn test_adapter_send_recv() {
        let (adapter, _inbound_tx, mut outbound_rx) = create_sync_adapter();

        // Send a message through the adapter
        let msg = SnapSyncMessage::GetStatus;
        adapter.send("peer1", msg).await.unwrap();

        // Verify it comes out on the network side
        let (peer_id, received) = outbound_rx.recv().await.unwrap();
        assert_eq!(peer_id, "peer1");
        assert!(matches!(received, SnapSyncMessage::GetStatus));
    }

    #[tokio::test]
    async fn test_adapter_recv_from_network() {
        let (mut adapter, inbound_tx, _outbound_rx) = create_sync_adapter();

        // Simulate network sending a message
        let status = StatusResponse {
            tip_height: 100,
            tip_hash: B256::ZERO,
            snapshots: vec![
                SnapshotInfo {
                    height: 90,
                    state_root: B256::repeat_byte(0x01),
                    block_hash: B256::repeat_byte(0x02),
                },
                SnapshotInfo {
                    height: 80,
                    state_root: B256::repeat_byte(0x03),
                    block_hash: B256::repeat_byte(0x04),
                },
            ],
        };
        inbound_tx
            .send(("peer2".to_string(), SnapSyncMessage::Status(status)))
            .await
            .unwrap();

        // Verify adapter receives it
        let (peer_id, received) = adapter.recv().await.unwrap();
        assert_eq!(peer_id, "peer2");
        assert!(matches!(received, SnapSyncMessage::Status(_)));
    }

    #[tokio::test]
    async fn test_broadcast() {
        let (adapter, _inbound_tx, mut outbound_rx) = create_sync_adapter();

        let peers = vec![
            "peer1".to_string(),
            "peer2".to_string(),
            "peer3".to_string(),
        ];
        let msg = SnapSyncMessage::GetStatus;

        let count = adapter.broadcast(&peers, &msg).await;
        assert_eq!(count, 3);

        // Verify all messages were sent
        for _ in 0..3 {
            let (_, received) = outbound_rx.recv().await.unwrap();
            assert!(matches!(received, SnapSyncMessage::GetStatus));
        }
    }
}
