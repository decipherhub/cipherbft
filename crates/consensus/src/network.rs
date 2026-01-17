//! Network Actor for Malachite consensus messages.
//!
//! This module implements the Network actor that handles consensus message
//! transmission and reception using libp2p, integrated with the existing DCL network.

use crate::codec::CipherBftCodec;
use crate::context::CipherBftContext;
use anyhow::Result;
use informalsystems_malachitebft_engine::network::{Network, NetworkRef};
use informalsystems_malachitebft_metrics::SharedRegistry;
use informalsystems_malachitebft_network::{Config as NetworkConfig, Keypair};
use tracing::{info, info_span};

/// Spawn a Malachite Network actor for consensus messages.
///
/// # Arguments
/// * `keypair` - libp2p keypair for node identity and signing
/// * `config` - Network configuration (listen addresses, peers, etc.)
/// * `metrics` - Shared metrics registry
///
/// # Returns
/// * `NetworkRef<CipherBftContext>` - Reference to the spawned network actor
pub async fn spawn_network(
    keypair: Keypair,
    config: NetworkConfig,
    metrics: SharedRegistry,
) -> Result<NetworkRef<CipherBftContext>> {
    info!("Spawning consensus network actor");

    // Create codec for message serialization (unit struct, no Default needed)
    let codec = CipherBftCodec;

    // Create tracing span for this network actor
    let span = info_span!("consensus-network");

    // Spawn network actor using Malachite's Network::spawn
    let network_ref =
        Network::<CipherBftContext, CipherBftCodec>::spawn(keypair, config, metrics, codec, span)
            .await?;

    info!("Consensus network actor spawned successfully");
    Ok(network_ref)
}
