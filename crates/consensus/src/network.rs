//! Network Actor for Malachite consensus messages.
//!
//! This module implements the Network actor that handles consensus message
//! transmission and reception using TCP, integrated with the existing DCL network.

use crate::codec::ConsensusCodec;
use crate::context::CipherBftContext;
use crate::validator_set::ConsensusAddress;
use anyhow::Result;
use informalsystems_malachitebft_engine::network::{Network, NetworkRef};
use std::collections::HashMap;
use std::net::SocketAddr;
use tracing::info;

/// Spawn a Malachite Network actor for consensus messages.
///
/// # Arguments
/// * `listen_addr` - Address to listen for incoming consensus messages
/// * `peer_addrs` - Map of validator addresses to their network addresses
///
/// # Returns
/// * `NetworkRef<CipherBftContext>` - Reference to the spawned network actor
pub async fn spawn_network(
    listen_addr: SocketAddr,
    peer_addrs: HashMap<ConsensusAddress, SocketAddr>,
) -> Result<NetworkRef<CipherBftContext>> {
    info!("Spawning consensus network actor on {}", listen_addr);

    // Create codec for message serialization
    let codec = ConsensusCodec::default();

    // Spawn network actor using Malachite's Network::spawn
    // Network will handle message encoding/decoding and peer communication
    let network_ref = Network::<CipherBftContext>::spawn(
        listen_addr,
        peer_addrs,
        codec,
    )
    .await?;

    info!("Consensus network actor spawned successfully");
    Ok(network_ref)
}
