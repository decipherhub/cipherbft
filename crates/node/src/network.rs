//! TCP Network layer for Primary-to-Primary and Worker-to-Worker communication

use crate::config::PeerConfig;
use anyhow::Result;
use async_trait::async_trait;
use bytes::{Buf, BufMut, BytesMut};
use cipherbft_data_chain::{
    primary::runner::PrimaryNetwork, worker::core::WorkerNetwork, Attestation, Car, DclMessage,
    WorkerMessage,
};
use cipherbft_types::ValidatorId;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, error, info, warn};

/// Message frame header size (4 bytes for length)
const HEADER_SIZE: usize = 4;
/// Maximum message size (10MB)
const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// Network message types
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum NetworkMessage {
    /// DCL message (for Primary) - boxed to reduce enum size
    Dcl(Box<DclMessage>),
    /// Worker message (for Worker)
    Worker(WorkerMessage),
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
}

/// Connection to a peer
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
        }
    }

    /// Start listening for incoming connections
    pub async fn start_listener(self: Arc<Self>, listen_addr: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(listen_addr).await?;
        info!("Primary listening on {}", listen_addr);

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        debug!("Accepted connection from {}", addr);
                        let self_clone = Arc::clone(&self);
                        tokio::spawn(async move {
                            if let Err(e) = self_clone.handle_connection(stream).await {
                                error!("Connection error from {}: {}", addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Accept error: {}", e);
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
                if len > MAX_MESSAGE_SIZE {
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
                            _ => continue,
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
                    Ok(_) => {
                        warn!("Received non-DCL message on Primary connection");
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

        let stream = TcpStream::connect(addr).await?;
        let (_, writer) = tokio::io::split(stream);

        self.peers.write().await.insert(
            validator_id,
            PeerConnection {
                writer: Arc::new(Mutex::new(writer)),
            },
        );

        info!("Connected to peer {:?}", validator_id);
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
    async fn send_to(&self, validator_id: ValidatorId, msg: &NetworkMessage) -> Result<()> {
        let peers = self.peers.read().await;

        if let Some(conn) = peers.get(&validator_id) {
            let data = bincode::serialize(msg)?;
            let mut frame = BytesMut::with_capacity(HEADER_SIZE + data.len());
            frame.put_u32(data.len() as u32);
            frame.extend_from_slice(&data);

            let mut writer = conn.writer.lock().await;
            writer.write_all(&frame).await?;
            writer.flush().await?;
        } else {
            // Try to connect first
            drop(peers);
            self.connect_to_peer(validator_id).await?;

            let peers = self.peers.read().await;
            if let Some(conn) = peers.get(&validator_id) {
                let data = bincode::serialize(msg)?;
                let mut frame = BytesMut::with_capacity(HEADER_SIZE + data.len());
                frame.put_u32(data.len() as u32);
                frame.extend_from_slice(&data);

                let mut writer = conn.writer.lock().await;
                writer.write_all(&frame).await?;
                writer.flush().await?;
            }
        }

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
        if let Err(e) = self.send_to(proposer, &msg).await {
            warn!("Failed to send attestation: {}", e);
        }
    }

    async fn broadcast(&self, message: &DclMessage) {
        let msg = NetworkMessage::Dcl(Box::new(message.clone()));
        TcpPrimaryNetwork::broadcast(self, &msg).await;
    }
}

/// TCP-based Worker network implementation
pub struct TcpWorkerNetwork {
    /// Our validator ID
    #[allow(dead_code)]
    our_id: ValidatorId,
    /// Worker ID
    #[allow(dead_code)]
    worker_id: u8,
    /// Peer worker connections
    peers: Arc<RwLock<HashMap<ValidatorId, PeerConnection>>>,
    /// Peer worker addresses
    peer_addrs: HashMap<ValidatorId, SocketAddr>,
}

impl TcpWorkerNetwork {
    /// Create a new TCP worker network
    pub fn new(our_id: ValidatorId, worker_id: u8, peers: &[PeerConfig]) -> Self {
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

        let stream = TcpStream::connect(addr).await?;
        let (_, writer) = tokio::io::split(stream);

        self.peers.write().await.insert(
            validator_id,
            PeerConnection {
                writer: Arc::new(Mutex::new(writer)),
            },
        );

        Ok(())
    }

    async fn send_to(&self, validator_id: ValidatorId, msg: &WorkerMessage) -> Result<()> {
        let peers = self.peers.read().await;

        if let Some(conn) = peers.get(&validator_id) {
            let net_msg = NetworkMessage::Worker(msg.clone());
            let data = bincode::serialize(&net_msg)?;
            let mut frame = BytesMut::with_capacity(HEADER_SIZE + data.len());
            frame.put_u32(data.len() as u32);
            frame.extend_from_slice(&data);

            let mut writer = conn.writer.lock().await;
            writer.write_all(&frame).await?;
            writer.flush().await?;
        } else {
            drop(peers);
            self.connect_to_peer(validator_id).await?;

            let peers = self.peers.read().await;
            if let Some(conn) = peers.get(&validator_id) {
                let net_msg = NetworkMessage::Worker(msg.clone());
                let data = bincode::serialize(&net_msg)?;
                let mut frame = BytesMut::with_capacity(HEADER_SIZE + data.len());
                frame.put_u32(data.len() as u32);
                frame.extend_from_slice(&data);

                let mut writer = conn.writer.lock().await;
                writer.write_all(&frame).await?;
                writer.flush().await?;
            }
        }

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
