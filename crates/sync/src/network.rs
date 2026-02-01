//! Network adapter for snap sync
//!
//! Provides a channel-based interface between the network layer and the sync manager.
//! This decouples the sync logic from the network implementation.

use crate::protocol::SnapSyncMessage;
use tokio::sync::mpsc;
use tracing::warn;

/// Message with peer context for incoming messages
#[derive(Debug, Clone)]
pub struct IncomingSnapMessage {
    /// Peer that sent the message
    pub peer_id: String,
    /// The snap sync message
    pub message: SnapSyncMessage,
}

/// Message with target peer for outgoing messages
#[derive(Debug, Clone)]
pub struct OutgoingSnapMessage {
    /// Target peer (None for broadcast)
    pub target_peer: Option<String>,
    /// The snap sync message to send
    pub message: SnapSyncMessage,
}

/// Channel capacity for snap sync messages
pub const SNAP_CHANNEL_CAPACITY: usize = 256;

/// Network adapter connecting sync manager to network layer
///
/// The sync manager uses this to receive messages from peers
/// and send messages to peers without knowing about the network
/// implementation details.
pub struct SyncNetworkAdapter {
    /// Receiver for incoming snap sync messages from network
    incoming_rx: mpsc::Receiver<IncomingSnapMessage>,
    /// Sender for outgoing snap sync messages to network
    outgoing_tx: mpsc::Sender<OutgoingSnapMessage>,
}

impl SyncNetworkAdapter {
    /// Create a new adapter with connected channel ends
    ///
    /// Returns the adapter and the channel ends that should be given to the network layer.
    #[allow(clippy::type_complexity)]
    pub fn new() -> (
        Self,
        mpsc::Sender<IncomingSnapMessage>,
        mpsc::Receiver<OutgoingSnapMessage>,
    ) {
        let (incoming_tx, incoming_rx) = mpsc::channel(SNAP_CHANNEL_CAPACITY);
        let (outgoing_tx, outgoing_rx) = mpsc::channel(SNAP_CHANNEL_CAPACITY);

        let adapter = Self {
            incoming_rx,
            outgoing_tx,
        };

        (adapter, incoming_tx, outgoing_rx)
    }

    /// Receive the next incoming message (async)
    pub async fn recv(&mut self) -> Option<IncomingSnapMessage> {
        self.incoming_rx.recv().await
    }

    /// Try to receive a message without blocking
    pub fn try_recv(&mut self) -> Option<IncomingSnapMessage> {
        self.incoming_rx.try_recv().ok()
    }

    /// Send a message to a specific peer
    pub async fn send(&self, peer_id: String, message: SnapSyncMessage) {
        let outgoing = OutgoingSnapMessage {
            target_peer: Some(peer_id),
            message,
        };
        if self.outgoing_tx.send(outgoing).await.is_err() {
            warn!("Failed to send snap sync message - channel closed");
        }
    }

    /// Broadcast a message to all peers
    pub async fn broadcast(&self, message: SnapSyncMessage) {
        let outgoing = OutgoingSnapMessage {
            target_peer: None,
            message,
        };
        if self.outgoing_tx.send(outgoing).await.is_err() {
            warn!("Failed to broadcast snap sync message - channel closed");
        }
    }

    /// Request status from all peers
    pub async fn request_status_from_all(&self) {
        self.broadcast(SnapSyncMessage::GetStatus).await;
    }
}

/// Handle for the network layer to send incoming messages to sync
#[derive(Clone)]
pub struct SyncNetworkSender {
    tx: mpsc::Sender<IncomingSnapMessage>,
}

impl SyncNetworkSender {
    /// Create from the sender channel
    pub fn new(tx: mpsc::Sender<IncomingSnapMessage>) -> Self {
        Self { tx }
    }

    /// Forward a received snap sync message from a peer
    pub async fn forward_message(&self, peer_id: String, message: SnapSyncMessage) {
        let incoming = IncomingSnapMessage { peer_id, message };
        if self.tx.send(incoming).await.is_err() {
            warn!("Failed to forward snap sync message - sync receiver dropped");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::StatusResponse;
    use alloy_primitives::B256;

    #[tokio::test]
    async fn test_adapter_creation() {
        let (adapter, _incoming_tx, _outgoing_rx) = SyncNetworkAdapter::new();
        // Adapter should be created successfully
        drop(adapter);
    }

    #[tokio::test]
    async fn test_send_and_receive() {
        let (mut adapter, incoming_tx, mut outgoing_rx) = SyncNetworkAdapter::new();

        // Send incoming message
        let msg = IncomingSnapMessage {
            peer_id: "peer1".to_string(),
            message: SnapSyncMessage::GetStatus,
        };
        incoming_tx.send(msg).await.unwrap();

        // Receive it through adapter
        let received = adapter.recv().await.unwrap();
        assert_eq!(received.peer_id, "peer1");
        assert!(matches!(received.message, SnapSyncMessage::GetStatus));

        // Send outgoing message
        adapter
            .send(
                "peer2".to_string(),
                SnapSyncMessage::Status(StatusResponse {
                    tip_height: 100,
                    tip_hash: B256::ZERO,
                    snapshots: vec![],
                }),
            )
            .await;

        // Receive outgoing message
        let outgoing = outgoing_rx.recv().await.unwrap();
        assert_eq!(outgoing.target_peer, Some("peer2".to_string()));
        assert!(matches!(outgoing.message, SnapSyncMessage::Status(_)));
    }

    #[tokio::test]
    async fn test_broadcast() {
        let (adapter, _incoming_tx, mut outgoing_rx) = SyncNetworkAdapter::new();

        adapter.broadcast(SnapSyncMessage::GetStatus).await;

        let outgoing = outgoing_rx.recv().await.unwrap();
        assert_eq!(outgoing.target_peer, None); // Broadcast has no specific target
        assert!(matches!(outgoing.message, SnapSyncMessage::GetStatus));
    }

    #[tokio::test]
    async fn test_network_sender() {
        let (mut adapter, incoming_tx, _outgoing_rx) = SyncNetworkAdapter::new();

        let sender = SyncNetworkSender::new(incoming_tx);
        sender
            .forward_message("peer1".to_string(), SnapSyncMessage::GetStatus)
            .await;

        let received = adapter.recv().await.unwrap();
        assert_eq!(received.peer_id, "peer1");
    }
}
