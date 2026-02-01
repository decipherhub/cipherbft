//! TCP Network layer for Primary-to-Primary and Worker-to-Worker communication
//!
//! # Concurrency Model
//!
//! This module uses a hierarchical locking strategy:
//!
//! 1. **Peers Map (`Arc<RwLock<HashMap<ValidatorId, PeerConnection>>>`)**:
//!    - Read lock: Getting/iterating peer connections
//!    - Write lock: Adding/removing peers
//!    - Lock duration: Minimized by cloning `Arc<Mutex<WriteHalf>>` and releasing
//!
//! 2. **Writer (`Arc<Mutex<tokio::io::WriteHalf<TcpStream>>>`)**:
//!    - Protects individual TCP write operations
//!    - Held during I/O (unavoidable for correct ordering)
//!
//! # Lock Ordering
//!
//! When both locks are needed: `peers` (read) → `writer` (exclusive)
//!
//! However, the design ensures the `peers` lock is always released before
//! I/O operations, so in practice:
//! 1. Acquire `peers` read lock
//! 2. Clone the `Arc<Mutex<WriteHalf>>`
//! 3. Release `peers` lock
//! 4. Acquire `writer` lock and perform I/O
//!
//! This prevents the `peers` lock from being held during slow network operations.

use crate::config::PeerConfig;
use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::{Buf, BufMut, BytesMut};
use cipherbft_data_chain::{
    error::MAX_MESSAGE_SIZE, primary::runner::PrimaryNetwork, worker::core::WorkerNetwork,
    Attestation, Car, DclMessage, WorkerMessage,
};
use cipherbft_metrics::network::{
    P2P_BYTES_RECEIVED, P2P_BYTES_SENT, P2P_CONNECTION_ERRORS, P2P_MESSAGES_RECEIVED,
    P2P_MESSAGES_SENT, P2P_PEERS_CONNECTED, P2P_PEERS_INBOUND, P2P_PEERS_OUTBOUND,
};
use cipherbft_sync::{OutgoingSnapMessage, SnapSyncMessage, SyncNetworkSender};
use cipherbft_types::ValidatorId;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, error, info, warn};

/// Message frame header size (4 bytes for length)
const HEADER_SIZE: usize = 4;

/// Network message types
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum NetworkMessage {
    /// DCL message (for Primary) - boxed to reduce enum size
    Dcl(Box<DclMessage>),
    /// Worker message (for Worker)
    Worker(WorkerMessage),
    /// Snap sync message (for state synchronization)
    SnapSync(SnapSyncMessage),
}

impl NetworkMessage {
    /// Get message type name for logging
    pub fn type_name(&self) -> &'static str {
        match self {
            NetworkMessage::Dcl(msg) => msg.type_name(),
            NetworkMessage::Worker(msg) => msg.type_name(),
            NetworkMessage::SnapSync(msg) => msg.message_type(),
        }
    }
}

/// TCP-based Primary network implementation
pub struct TcpPrimaryNetwork {
    /// Our validator ID (for identification)
    #[allow(dead_code)]
    our_id: ValidatorId,
    /// Peer connections (validator -> connection)
    peers: Arc<RwLock<HashMap<ValidatorId, PeerConnection>>>,
    /// Peer addresses
    peer_addrs: HashMap<ValidatorId, SocketAddr>,
    /// Incoming message channel
    incoming_tx: mpsc::Sender<(ValidatorId, DclMessage)>,
    /// Snap sync network sender for forwarding sync messages
    /// Uses RwLock for interior mutability (can be set after Arc creation)
    snap_sync_sender: RwLock<Option<SyncNetworkSender>>,
    /// Whether the network listener is active
    listening: AtomicBool,
}

/// Connection to a peer
#[derive(Clone)]
struct PeerConnection {
    writer: Arc<Mutex<tokio::io::WriteHalf<TcpStream>>>,
}

impl TcpPrimaryNetwork {
    /// Create a new TCP primary network
    pub fn new(
        our_id: ValidatorId,
        peers: &[PeerConfig],
        incoming_tx: mpsc::Sender<(ValidatorId, DclMessage)>,
    ) -> Self {
        let peer_addrs: HashMap<_, _> = peers
            .iter()
            .filter_map(|p| {
                let vid = parse_validator_id(&p.validator_id).ok()?;
                Some((vid, p.primary_addr))
            })
            .collect();

        Self {
            our_id,
            peers: Arc::new(RwLock::new(HashMap::new())),
            peer_addrs,
            incoming_tx,
            snap_sync_sender: RwLock::new(None),
            listening: AtomicBool::new(false),
        }
    }

    /// Set the snap sync sender for forwarding incoming sync messages
    ///
    /// This method uses interior mutability via RwLock, so it can be called
    /// even after the network is wrapped in Arc.
    pub async fn set_snap_sync_sender(&self, sender: SyncNetworkSender) {
        *self.snap_sync_sender.write().await = Some(sender);
    }

    /// Returns whether the network listener is active.
    pub fn is_listening(&self) -> bool {
        self.listening.load(Ordering::Acquire)
    }

    /// Returns the number of currently connected peers.
    pub async fn connected_peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    /// Start listening for incoming connections
    pub async fn start_listener(self: Arc<Self>, listen_addr: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(listen_addr).await.with_context(|| {
            format!(
                "Failed to bind primary network listener to {}. \
                 Port {} may already be in use. \
                 Check with: lsof -i :{}",
                listen_addr,
                listen_addr.port(),
                listen_addr.port()
            )
        })?;
        info!("Primary listening on {}", listen_addr);
        self.listening.store(true, Ordering::Release);

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        debug!("Accepted connection from {}", addr);
                        P2P_PEERS_INBOUND.inc();
                        P2P_PEERS_CONNECTED.inc();
                        let self_clone = Arc::clone(&self);
                        tokio::spawn(async move {
                            if let Err(e) = self_clone.handle_connection(stream).await {
                                error!("Connection error from {}: {}", addr, e);
                            }
                            // Connection ended - decrement metrics
                            P2P_PEERS_INBOUND.dec();
                            P2P_PEERS_CONNECTED.dec();
                        });
                    }
                    Err(e) => {
                        error!("Accept error: {}", e);
                        P2P_CONNECTION_ERRORS.inc();
                    }
                }
            }
        });

        Ok(())
    }

    /// Handle an incoming connection
    async fn handle_connection(&self, stream: TcpStream) -> Result<()> {
        let (mut reader, writer) = tokio::io::split(stream);
        let writer = Arc::new(Mutex::new(writer));

        let mut buf = BytesMut::with_capacity(4096);

        loop {
            // Read more data
            let n = reader.read_buf(&mut buf).await?;
            if n == 0 {
                break; // Connection closed
            }

            // Try to parse messages
            while buf.len() >= HEADER_SIZE {
                let len = (&buf[..HEADER_SIZE]).get_u32() as usize;
                if (len as u64) > MAX_MESSAGE_SIZE {
                    anyhow::bail!("Message too large: {}", len);
                }

                if buf.len() < HEADER_SIZE + len {
                    break; // Need more data
                }

                buf.advance(HEADER_SIZE);
                let msg_bytes = buf.split_to(len);

                // Track bytes received
                P2P_BYTES_RECEIVED.inc_by(msg_bytes.len() as f64);

                match bincode::deserialize::<NetworkMessage>(&msg_bytes) {
                    Ok(NetworkMessage::Dcl(dcl_msg)) => {
                        let msg_type = match dcl_msg.as_ref() {
                            DclMessage::Car(_) => "car",
                            DclMessage::Attestation(_) => "attestation",
                            _ => "other",
                        };
                        P2P_MESSAGES_RECEIVED.with_label_values(&[msg_type]).inc();

                        let from = match dcl_msg.as_ref() {
                            DclMessage::Car(car) => car.proposer,
                            DclMessage::Attestation(att) => att.attester,
                            DclMessage::CarWithAttestation { car, .. } => car.proposer,
                            // For request/response messages, we still need to forward them
                            // The Primary runner handles these messages correctly
                            DclMessage::CarRequest { validator, .. } => *validator,
                            DclMessage::CarResponse(_) => {
                                // Response messages don't have a clear "from" - skip tracking peer
                                // but still forward the message
                                if self
                                    .incoming_tx
                                    .send((ValidatorId::default(), *dcl_msg))
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                                continue;
                            }
                            DclMessage::BatchRequest { .. } | DclMessage::BatchResponse { .. } => {
                                // Batch request/response - skip tracking but forward
                                if self
                                    .incoming_tx
                                    .send((ValidatorId::default(), *dcl_msg))
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                                continue;
                            }
                        };

                        // Store connection if not already
                        {
                            let mut peers = self.peers.write().await;
                            peers.entry(from).or_insert_with(|| PeerConnection {
                                writer: Arc::clone(&writer),
                            });
                        }

                        // Forward to handler
                        if self.incoming_tx.send((from, *dcl_msg)).await.is_err() {
                            break;
                        }
                    }
                    Ok(NetworkMessage::SnapSync(snap_msg)) => {
                        debug!("Received snap sync message: {}", snap_msg.message_type());
                        // Forward to sync manager via channel
                        let sender_guard = self.snap_sync_sender.read().await;
                        if let Some(ref sender) = *sender_guard {
                            // For incoming connections, we don't have a validator ID yet
                            // Use "unknown" as peer ID - the sync manager can track peers by socket
                            sender
                                .forward_message("unknown".to_string(), snap_msg)
                                .await;
                        }
                    }
                    Ok(NetworkMessage::Worker(_)) => {
                        warn!("Received Worker message on Primary connection");
                    }
                    Err(e) => {
                        error!("Failed to deserialize message: {}", e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Connect to a peer
    pub async fn connect_to_peer(&self, validator_id: ValidatorId) -> Result<()> {
        if self.peers.read().await.contains_key(&validator_id) {
            return Ok(()); // Already connected
        }

        let addr = self
            .peer_addrs
            .get(&validator_id)
            .ok_or_else(|| anyhow::anyhow!("Unknown peer: {:?}", validator_id))?;

        debug!("Connecting to peer {:?} at {}", validator_id, addr);

        let stream = match TcpStream::connect(addr).await {
            Ok(s) => s,
            Err(e) => {
                P2P_CONNECTION_ERRORS.inc();
                return Err(e.into());
            }
        };
        let (reader, writer) = tokio::io::split(stream);

        self.peers.write().await.insert(
            validator_id,
            PeerConnection {
                writer: Arc::new(Mutex::new(writer)),
            },
        );

        // Track outbound connection
        P2P_PEERS_OUTBOUND.inc();
        P2P_PEERS_CONNECTED.inc();

        // Spawn a reader task to handle incoming messages on this outgoing connection.
        // This is critical: without this, responses (e.g., attestations) sent back on
        // this connection would never be read, causing attestation timeouts.
        let incoming_tx = self.incoming_tx.clone();
        let snap_sender = self.snap_sync_sender.read().await.clone();
        let peer_id = format!("{:?}", validator_id);
        tokio::spawn(async move {
            if let Err(e) =
                Self::handle_outgoing_connection_reader(reader, incoming_tx, peer_id, snap_sender)
                    .await
            {
                debug!("Outgoing connection reader ended: {}", e);
            }
            // Connection ended - decrement metrics
            P2P_PEERS_OUTBOUND.dec();
            P2P_PEERS_CONNECTED.dec();
        });

        info!("Connected to peer {:?}", validator_id);
        Ok(())
    }

    /// Handle reading from an outgoing connection
    ///
    /// When we initiate a connection to a peer, we can send messages via the writer.
    /// But we also need to read responses (e.g., attestations) that the peer sends back.
    /// This reader task handles that incoming data.
    async fn handle_outgoing_connection_reader(
        mut reader: tokio::io::ReadHalf<TcpStream>,
        incoming_tx: mpsc::Sender<(ValidatorId, DclMessage)>,
        peer_id: String,
        snap_sync_sender: Option<SyncNetworkSender>,
    ) -> Result<()> {
        let mut buf = BytesMut::with_capacity(4096);

        loop {
            // Read more data
            let n = reader.read_buf(&mut buf).await?;
            if n == 0 {
                break; // Connection closed
            }

            // Try to parse messages
            while buf.len() >= HEADER_SIZE {
                let len = (&buf[..HEADER_SIZE]).get_u32() as usize;
                if (len as u64) > MAX_MESSAGE_SIZE {
                    anyhow::bail!("Message too large: {}", len);
                }

                if buf.len() < HEADER_SIZE + len {
                    break; // Need more data
                }

                buf.advance(HEADER_SIZE);
                let msg_bytes = buf.split_to(len);

                match bincode::deserialize::<NetworkMessage>(&msg_bytes) {
                    Ok(NetworkMessage::Dcl(dcl_msg)) => {
                        let from = match dcl_msg.as_ref() {
                            DclMessage::Car(car) => car.proposer,
                            DclMessage::Attestation(att) => att.attester,
                            DclMessage::CarWithAttestation { car, .. } => car.proposer,
                            DclMessage::CarRequest { validator, .. } => *validator,
                            // Response/request messages still need to be forwarded
                            DclMessage::CarResponse(_)
                            | DclMessage::BatchRequest { .. }
                            | DclMessage::BatchResponse { .. } => ValidatorId::default(),
                        };

                        // Forward to handler
                        if incoming_tx.send((from, *dcl_msg)).await.is_err() {
                            break;
                        }
                    }
                    Ok(NetworkMessage::SnapSync(snap_msg)) => {
                        debug!(
                            "Received snap sync message on outgoing connection: {}",
                            snap_msg.message_type()
                        );
                        // Forward to sync manager via channel
                        if let Some(ref sender) = snap_sync_sender {
                            sender.forward_message(peer_id.clone(), snap_msg).await;
                        }
                    }
                    Ok(NetworkMessage::Worker(_)) => {
                        warn!("Received Worker message on outgoing connection");
                    }
                    Err(e) => {
                        error!(
                            "Failed to deserialize message on outgoing connection: {}",
                            e
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Connect to all known peers
    pub async fn connect_to_all_peers(&self) {
        for validator_id in self.peer_addrs.keys().cloned().collect::<Vec<_>>() {
            if let Err(e) = self.connect_to_peer(validator_id).await {
                warn!("Failed to connect to peer {:?}: {}", validator_id, e);
            }
        }
    }

    /// Send a message to a specific peer
    ///
    /// # Concurrency
    ///
    /// This method minimizes lock duration by:
    /// 1. Quickly cloning the Arc<Mutex<WriteHalf>> under a short read lock
    /// 2. Releasing the peers lock before any I/O
    /// 3. Serializing and writing without holding the peers lock
    ///
    /// This allows other operations on the peers map to proceed while I/O is in progress.
    async fn send_to(&self, validator_id: ValidatorId, msg: &NetworkMessage) -> Result<()> {
        // Get writer Arc with minimal lock duration - just clone the Arc
        let writer = {
            let peers = self.peers.read().await;
            peers
                .get(&validator_id)
                .map(|conn| Arc::clone(&conn.writer))
        }; // Read lock released here

        // If peer not found, try to connect
        let writer = match writer {
            Some(w) => w,
            None => {
                self.connect_to_peer(validator_id).await?;
                // Get the writer after connecting
                let peers = self.peers.read().await;
                peers
                    .get(&validator_id)
                    .map(|conn| Arc::clone(&conn.writer))
                    .ok_or_else(|| anyhow::anyhow!("Failed to establish connection"))?
            }
        }; // Read lock released here

        // Track message type for metrics
        let msg_type = match msg {
            NetworkMessage::Dcl(dcl_msg) => match dcl_msg.as_ref() {
                DclMessage::Car(_) => "car",
                DclMessage::Attestation(_) => "attestation",
                _ => "other",
            },
            NetworkMessage::Worker(_) => "worker",
            NetworkMessage::SnapSync(_) => "snap_sync",
        };

        // Serialize message AFTER releasing peers lock
        let data = bincode::serialize(msg)?;
        let mut frame = BytesMut::with_capacity(HEADER_SIZE + data.len());
        frame.put_u32(data.len() as u32);
        frame.extend_from_slice(&data);

        // Track bytes and messages sent
        P2P_BYTES_SENT.inc_by(frame.len() as f64);
        P2P_MESSAGES_SENT.with_label_values(&[msg_type]).inc();

        // Now perform I/O with only the writer lock held (not peers lock)
        let mut guard = writer.lock().await;
        guard.write_all(&frame).await?;
        guard.flush().await?;

        Ok(())
    }

    /// Broadcast a message to all peers
    async fn broadcast(&self, msg: &NetworkMessage) {
        let peer_ids: Vec<_> = self.peer_addrs.keys().cloned().collect();

        for validator_id in peer_ids {
            if let Err(e) = self.send_to(validator_id, msg).await {
                warn!("Failed to send to peer {:?}: {}", validator_id, e);
            }
        }
    }

    /// Send a snap sync message to a specific peer by validator ID
    pub async fn send_snap_sync(&self, validator_id: ValidatorId, message: SnapSyncMessage) {
        let msg = NetworkMessage::SnapSync(message);
        if let Err(e) = self.send_to(validator_id, &msg).await {
            warn!("Failed to send snap sync to {:?}: {}", validator_id, e);
        }
    }

    /// Broadcast a snap sync message to all peers
    pub async fn broadcast_snap_sync(&self, message: SnapSyncMessage) {
        let msg = NetworkMessage::SnapSync(message);
        self.broadcast(&msg).await;
    }

    /// Start processing outgoing snap sync messages from the adapter
    ///
    /// This spawns a background task that reads from the outgoing message channel
    /// and sends messages via the TCP network.
    pub fn start_snap_sync_sender(
        self: Arc<Self>,
        mut outgoing_rx: mpsc::Receiver<OutgoingSnapMessage>,
    ) {
        tokio::spawn(async move {
            while let Some(outgoing) = outgoing_rx.recv().await {
                match outgoing.target_peer {
                    Some(peer_id) => {
                        // Parse peer_id string to extract validator ID
                        // Format is typically "ValidatorId(0x...)" from Debug
                        if let Some(vid) = Self::parse_peer_id(&peer_id) {
                            self.send_snap_sync(vid, outgoing.message).await;
                        } else {
                            warn!("Could not parse peer ID: {}", peer_id);
                        }
                    }
                    None => {
                        // Broadcast to all peers
                        self.broadcast_snap_sync(outgoing.message).await;
                    }
                }
            }
            info!("Snap sync sender task ended");
        });
    }

    /// Parse a peer ID string back to ValidatorId
    ///
    /// Handles both raw hex strings and "ValidatorId(0x...)" format
    pub fn parse_peer_id(peer_id: &str) -> Option<ValidatorId> {
        // Try to extract hex from "ValidatorId(0x...)" format
        let hex_str = if let Some(start) = peer_id.find("0x") {
            let end = peer_id[start..].find(')').unwrap_or(peer_id.len() - start);
            &peer_id[start + 2..start + end]
        } else if let Some(stripped) = peer_id.strip_prefix("0x") {
            stripped
        } else {
            peer_id
        };

        // Trim any trailing characters
        let hex_str = hex_str.trim_end_matches(|c: char| !c.is_ascii_hexdigit());

        parse_validator_id(hex_str).ok()
    }
}

#[async_trait]
impl PrimaryNetwork for TcpPrimaryNetwork {
    async fn broadcast_car(&self, car: &Car) {
        debug!("Broadcasting Car position={}", car.position);
        let msg = NetworkMessage::Dcl(Box::new(DclMessage::Car(car.clone())));
        self.broadcast(&msg).await;
    }

    async fn send_attestation(&self, proposer: ValidatorId, attestation: &Attestation) {
        debug!("Sending attestation to {:?}", proposer);
        let msg = NetworkMessage::Dcl(Box::new(DclMessage::Attestation(attestation.clone())));
        if let Err(e) = TcpPrimaryNetwork::send_to(self, proposer, &msg).await {
            warn!("Failed to send attestation: {}", e);
        }
    }

    async fn broadcast(&self, message: &DclMessage) {
        let msg = NetworkMessage::Dcl(Box::new(message.clone()));
        TcpPrimaryNetwork::broadcast(self, &msg).await;
    }

    async fn send_to(&self, peer: ValidatorId, message: &DclMessage) {
        debug!("Sending message to peer {:?}", peer);
        let msg = NetworkMessage::Dcl(Box::new(message.clone()));
        if let Err(e) = TcpPrimaryNetwork::send_to(self, peer, &msg).await {
            warn!("Failed to send message to peer {:?}: {}", peer, e);
        }
    }
}

/// TCP-based Worker network implementation
#[derive(Clone)]
pub struct TcpWorkerNetwork {
    /// Our validator ID
    our_id: ValidatorId,
    /// Worker ID
    worker_id: u8,
    /// Peer worker connections
    peers: Arc<RwLock<HashMap<ValidatorId, PeerConnection>>>,
    /// Peer worker addresses
    peer_addrs: HashMap<ValidatorId, SocketAddr>,
    /// Incoming message channel
    incoming_tx: mpsc::Sender<(ValidatorId, WorkerMessage)>,
}

impl TcpWorkerNetwork {
    /// Create a new TCP worker network
    pub fn new(
        our_id: ValidatorId,
        worker_id: u8,
        peers: &[PeerConfig],
        incoming_tx: mpsc::Sender<(ValidatorId, WorkerMessage)>,
    ) -> Self {
        let peer_addrs: HashMap<_, _> = peers
            .iter()
            .filter_map(|p| {
                let vid = parse_validator_id(&p.validator_id).ok()?;
                let addr = p.worker_addrs.get(worker_id as usize)?;
                Some((vid, *addr))
            })
            .collect();

        Self {
            our_id,
            worker_id,
            peers: Arc::new(RwLock::new(HashMap::new())),
            peer_addrs,
            incoming_tx,
        }
    }

    /// Start listening for incoming connections
    pub async fn start_listener(self: Arc<Self>, listen_addr: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(listen_addr).await.with_context(|| {
            format!(
                "Failed to bind worker network listener to {}. \
                 Port {} may already be in use.",
                listen_addr,
                listen_addr.port()
            )
        })?;
        info!("Worker {} listening on {}", self.worker_id, listen_addr);

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        debug!(
                            "Worker {} accepted connection from {}",
                            self.worker_id, addr
                        );
                        P2P_PEERS_INBOUND.inc();
                        P2P_PEERS_CONNECTED.inc();
                        let self_clone = Arc::clone(&self);
                        tokio::spawn(async move {
                            if let Err(e) = self_clone.handle_connection(stream).await {
                                error!("Worker connection error from {}: {}", addr, e);
                            }
                            // Connection ended - decrement metrics
                            P2P_PEERS_INBOUND.dec();
                            P2P_PEERS_CONNECTED.dec();
                        });
                    }
                    Err(e) => {
                        error!("Worker accept error: {}", e);
                        P2P_CONNECTION_ERRORS.inc();
                    }
                }
            }
        });

        Ok(())
    }

    /// Handle an incoming connection
    async fn handle_connection(&self, stream: TcpStream) -> Result<()> {
        let (mut reader, writer) = tokio::io::split(stream);
        let writer = Arc::new(Mutex::new(writer));

        let mut buf = BytesMut::with_capacity(4096);

        loop {
            // Read more data
            let n = reader.read_buf(&mut buf).await?;
            if n == 0 {
                break; // Connection closed
            }

            // Try to parse messages
            while buf.len() >= HEADER_SIZE {
                let len = (&buf[..HEADER_SIZE]).get_u32() as usize;
                if (len as u64) > MAX_MESSAGE_SIZE {
                    anyhow::bail!("Message too large: {}", len);
                }

                if buf.len() < HEADER_SIZE + len {
                    break; // Need more data
                }

                buf.advance(HEADER_SIZE);
                let msg_bytes = buf.split_to(len);

                // Track bytes received
                P2P_BYTES_RECEIVED.inc_by(msg_bytes.len() as f64);

                match bincode::deserialize::<NetworkMessage>(&msg_bytes) {
                    Ok(NetworkMessage::Worker(worker_msg)) => {
                        let msg_type = match &worker_msg {
                            WorkerMessage::Batch(_) => "batch",
                            WorkerMessage::BatchRequest { .. } => "batch_request",
                            WorkerMessage::BatchResponse { .. } => "batch_response",
                        };
                        P2P_MESSAGES_RECEIVED.with_label_values(&[msg_type]).inc();

                        // Extract sender from message where available
                        // BatchRequest has requestor field, others use ZERO (not needed for response routing)
                        let from = match &worker_msg {
                            WorkerMessage::BatchRequest { requestor, .. } => *requestor,
                            _ => ValidatorId::ZERO,
                        };

                        // Store connection if sender is known (for potential future responses)
                        if from != ValidatorId::ZERO {
                            let mut peers = self.peers.write().await;
                            peers.entry(from).or_insert_with(|| PeerConnection {
                                writer: Arc::clone(&writer),
                            });
                        }

                        // Forward to handler
                        if self.incoming_tx.send((from, worker_msg)).await.is_err() {
                            break;
                        }
                    }
                    Ok(_) => {
                        warn!("Received non-Worker message on Worker connection");
                    }
                    Err(e) => {
                        error!("Failed to deserialize worker message: {}", e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Connect to all known peers
    pub async fn connect_to_all_peers(&self) {
        for validator_id in self.peer_addrs.keys().cloned().collect::<Vec<_>>() {
            if let Err(e) = self.connect_to_peer(validator_id).await {
                warn!(
                    "Worker {} failed to connect to peer {:?}: {}",
                    self.worker_id, validator_id, e
                );
            }
        }
    }

    /// Connect to a peer
    async fn connect_to_peer(&self, validator_id: ValidatorId) -> Result<()> {
        if self.peers.read().await.contains_key(&validator_id) {
            return Ok(());
        }

        let addr = self
            .peer_addrs
            .get(&validator_id)
            .ok_or_else(|| anyhow::anyhow!("Unknown peer: {:?}", validator_id))?;

        let stream = match TcpStream::connect(addr).await {
            Ok(s) => s,
            Err(e) => {
                P2P_CONNECTION_ERRORS.inc();
                return Err(e.into());
            }
        };
        let (_, writer) = tokio::io::split(stream);

        self.peers.write().await.insert(
            validator_id,
            PeerConnection {
                writer: Arc::new(Mutex::new(writer)),
            },
        );

        // Track outbound connection
        P2P_PEERS_OUTBOUND.inc();
        P2P_PEERS_CONNECTED.inc();

        Ok(())
    }

    /// Send a message to a peer worker
    ///
    /// # Concurrency
    ///
    /// Uses the same "clone Arc and release" pattern as TcpPrimaryNetwork::send_to
    /// to minimize lock duration during I/O operations.
    async fn send_to(&self, validator_id: ValidatorId, msg: &WorkerMessage) -> Result<()> {
        // Get writer Arc with minimal lock duration
        let writer = {
            let peers = self.peers.read().await;
            peers
                .get(&validator_id)
                .map(|conn| Arc::clone(&conn.writer))
        }; // Read lock released here

        // If peer not found, try to connect
        let writer = match writer {
            Some(w) => w,
            None => {
                self.connect_to_peer(validator_id).await?;
                let peers = self.peers.read().await;
                peers
                    .get(&validator_id)
                    .map(|conn| Arc::clone(&conn.writer))
                    .ok_or_else(|| anyhow::anyhow!("Failed to establish connection"))?
            }
        }; // Read lock released here

        // Track message type for metrics
        let msg_type = match msg {
            WorkerMessage::Batch(_) => "batch",
            WorkerMessage::BatchRequest { .. } => "batch_request",
            WorkerMessage::BatchResponse { .. } => "batch_response",
        };

        // Serialize message AFTER releasing peers lock
        let net_msg = NetworkMessage::Worker(msg.clone());
        let data = bincode::serialize(&net_msg)?;
        let mut frame = BytesMut::with_capacity(HEADER_SIZE + data.len());
        frame.put_u32(data.len() as u32);
        frame.extend_from_slice(&data);

        // Track bytes and messages sent
        P2P_BYTES_SENT.inc_by(frame.len() as f64);
        P2P_MESSAGES_SENT.with_label_values(&[msg_type]).inc();

        // Perform I/O with only the writer lock held
        let mut guard = writer.lock().await;
        guard.write_all(&frame).await?;
        guard.flush().await?;

        Ok(())
    }
}

#[async_trait]
impl WorkerNetwork for TcpWorkerNetwork {
    async fn broadcast_batch(&self, batch: &cipherbft_data_chain::Batch) {
        let msg = WorkerMessage::Batch(batch.clone());
        for validator_id in self.peer_addrs.keys().cloned().collect::<Vec<_>>() {
            if let Err(e) = self.send_to(validator_id, &msg).await {
                warn!("Failed to broadcast batch to {:?}: {}", validator_id, e);
            }
        }
    }

    async fn send_to_peer(&self, peer: ValidatorId, message: WorkerMessage) {
        if let Err(e) = self.send_to(peer, &message).await {
            warn!("Failed to send to peer {:?}: {}", peer, e);
        }
    }

    async fn request_batches(&self, target: ValidatorId, digests: Vec<cipherbft_types::Hash>) {
        let msg = WorkerMessage::BatchRequest {
            digests,
            requestor: self.our_id,
        };
        if let Err(e) = self.send_to(target, &msg).await {
            warn!("Failed to request batches from {:?}: {}", target, e);
        }
    }
}

/// Parse validator ID from hex string
fn parse_validator_id(hex_str: &str) -> Result<ValidatorId> {
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != 20 {
        anyhow::bail!("Invalid validator ID length: {}", bytes.len());
    }
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&bytes);
    Ok(ValidatorId::from_bytes(arr))
}
