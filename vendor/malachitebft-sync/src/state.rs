use std::collections::BTreeMap;
use std::time::Instant;

use malachitebft_core_types::{Context, Height};
use malachitebft_peer::PeerId;

use crate::scoring::{ema, PeerScorer, Strategy};
use crate::{Config, OutboundRequestId, Status};

/// State of a decided value request.
///
/// State transitions:
/// WaitingResponse -> WaitingValidation -> Validated
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RequestState {
    /// Initial state: waiting for a response from a peer
    WaitingResponse,
    /// Response received: waiting for value validation by consensus
    WaitingValidation,
    /// Value validated: request is complete
    Validated,
}

pub struct State<Ctx>
where
    Ctx: Context,
{
    rng: Box<dyn rand::RngCore + Send>,

    /// Configuration for the sync state and behaviour.
    pub config: Config,

    /// Consensus has started
    pub started: bool,

    /// Height of last decided value
    pub tip_height: Ctx::Height,

    /// Height currently syncing.
    pub sync_height: Ctx::Height,

    /// Decided value requests for these heights have been sent out to peers.
    /// Tuple contains: (request_id, state, timestamp_when_sent)
    pub pending_value_requests: BTreeMap<Ctx::Height, (OutboundRequestId, RequestState, Instant)>,

    /// Maps request ID to height for pending decided value requests.
    pub height_per_request_id: BTreeMap<OutboundRequestId, Ctx::Height>,

    /// The set of peers we are connected to in order to get values, certificates and votes.
    pub peers: BTreeMap<PeerId, Status<Ctx>>,

    /// Peer scorer for scoring peers based on their performance.
    pub peer_scorer: PeerScorer,
}

impl<Ctx> State<Ctx>
where
    Ctx: Context,
{
    pub fn new(
        // Random number generator for selecting peers
        rng: Box<dyn rand::RngCore + Send>,
        // Sync configuration
        config: Config,
    ) -> Self {
        let peer_scorer = match config.scoring_strategy {
            Strategy::Ema => PeerScorer::new(ema::ExponentialMovingAverage::default()),
        };

        Self {
            rng,
            config,
            started: false,
            tip_height: Ctx::Height::ZERO,
            sync_height: Ctx::Height::ZERO,
            pending_value_requests: BTreeMap::new(),
            height_per_request_id: BTreeMap::new(),
            peers: BTreeMap::new(),
            peer_scorer,
        }
    }

    pub fn update_status(&mut self, status: Status<Ctx>) {
        self.peers.insert(status.peer_id, status);
    }

    /// Select at random a peer whose tip is at or above the given height and with min height below the given height.
    /// In other words, `height` is in `status.history_min_height..=status.tip_height` range.
    pub fn random_peer_with_tip_at_or_above(&mut self, height: Ctx::Height) -> Option<PeerId>
    where
        Ctx: Context,
    {
        let peers = self
            .peers
            .iter()
            .filter_map(|(&peer, status)| {
                (status.history_min_height..=status.tip_height)
                    .contains(&height)
                    .then_some(peer)
            })
            .collect::<Vec<_>>();

        self.peer_scorer.select_peer(&peers, &mut self.rng)
    }

    /// Same as [`Self::random_peer_with_tip_at_or_above`], but excludes the given peer.
    pub fn random_peer_with_tip_at_or_above_except(
        &mut self,
        height: Ctx::Height,
        except: PeerId,
    ) -> Option<PeerId> {
        let peers = self
            .peers
            .iter()
            .filter_map(|(&peer, status)| {
                (status.history_min_height..=status.tip_height)
                    .contains(&height)
                    .then_some(peer)
            })
            .filter(|&peer| peer != except)
            .collect::<Vec<_>>();

        self.peer_scorer.select_peer(&peers, &mut self.rng)
    }

    /// Store a pending decided value request for a given height and request ID.
    ///
    /// State transition: None -> WaitingResponse
    pub fn store_pending_value_request(
        &mut self,
        height: Ctx::Height,
        request_id: OutboundRequestId,
    ) {
        self.height_per_request_id
            .insert(request_id.clone(), height);

        self.pending_value_requests
            .insert(height, (request_id, RequestState::WaitingResponse, Instant::now()));
    }

    /// Mark that a response has been received for a height.
    ///
    /// State transition: WaitingResponse -> WaitingValidation
    pub fn response_received(&mut self, request_id: OutboundRequestId, height: Ctx::Height) {
        if let Some((req_id, state, _)) = self.pending_value_requests.get_mut(&height) {
            if req_id != &request_id {
                return; // A new request has been made in the meantime, ignore this response.
            }
            if *state == RequestState::WaitingResponse {
                *state = RequestState::WaitingValidation;
            }
        }
    }

    /// Mark that a decided value has been validated for a height.
    ///
    /// State transition: WaitingValidation -> Validated
    /// It is also possible to have the following transition: WaitingResponse -> Validated.
    pub fn validate_response(&mut self, height: Ctx::Height) {
        if let Some((_, state, _)) = self.pending_value_requests.get_mut(&height) {
            *state = RequestState::Validated;
        }
    }

    /// Get the height for a given request ID.
    pub fn get_height_for_request_id(&self, request_id: &OutboundRequestId) -> Option<Ctx::Height> {
        self.height_per_request_id.get(request_id).cloned()
    }

    /// Remove the pending decided value request for a given height.
    pub fn remove_pending_request_by_height(&mut self, height: &Ctx::Height) {
        if let Some((request_id, _, _)) = self.pending_value_requests.remove(height) {
            self.height_per_request_id.remove(&request_id);
        }
    }

    /// Remove a pending decided value request by its ID and return the height it was associated with.
    pub fn remove_pending_value_request_by_id(
        &mut self,
        request_id: &OutboundRequestId,
    ) -> Option<Ctx::Height> {
        let height = self.height_per_request_id.remove(request_id)?;

        self.pending_value_requests.remove(&height);

        Some(height)
    }

    /// Check if there are any pending decided value requests for a given height.
    pub fn has_pending_value_request(&self, height: &Ctx::Height) -> bool {
        self.pending_value_requests.contains_key(height)
    }

    /// Check if a pending decided value request for a given height is in the `Validated` state.
    pub fn is_pending_value_request_validated_by_height(&self, height: &Ctx::Height) -> bool {
        if let Some((_, state, _)) = self.pending_value_requests.get(height) {
            *state == RequestState::Validated
        } else {
            false
        }
    }

    /// Check if a pending decided value request for a given request ID is in the `Validated` state.
    pub fn is_pending_value_request_validated_by_id(&self, request_id: &OutboundRequestId) -> bool {
        if let Some(height) = self.height_per_request_id.get(request_id) {
            self.is_pending_value_request_validated_by_height(height)
        } else {
            false
        }
    }

    /// Clear stale pending requests that have been waiting longer than the configured timeout.
    /// Returns the number of cleared requests.
    pub fn clear_stale_pending_requests(&mut self) -> usize {
        let timeout = self.config.request_timeout;
        let now = Instant::now();

        // Find heights with stale requests (not yet validated and older than timeout)
        let stale_heights: Vec<Ctx::Height> = self
            .pending_value_requests
            .iter()
            .filter(|(_, (_, state, sent_at))| {
                *state != RequestState::Validated && now.duration_since(*sent_at) > timeout
            })
            .map(|(height, _)| *height)
            .collect();

        let count = stale_heights.len();

        // Remove stale requests
        for height in stale_heights {
            self.remove_pending_request_by_height(&height);
        }

        count
    }

    /// Find the earliest height that any peer can serve, above the given height.
    /// Returns the height and a peer that can serve it.
    /// This is used when the requested height is not available from any peer.
    pub fn find_earliest_syncable_height(
        &mut self,
        above_height: Ctx::Height,
    ) -> Option<(Ctx::Height, PeerId)> {
        // Find the minimum history_min_height among all peers that is greater than above_height
        // and that the peer can actually serve (i.e., history_min_height <= tip_height)
        let mut candidates: Vec<(Ctx::Height, PeerId)> = self
            .peers
            .iter()
            .filter_map(|(&peer, status)| {
                // The peer must have a valid range
                if status.history_min_height > status.tip_height {
                    return None;
                }
                // We need a height greater than above_height
                if status.history_min_height > above_height {
                    Some((status.history_min_height, peer))
                } else if status.tip_height > above_height {
                    // Peer can serve heights from above_height+1 to tip_height
                    // but their history_min_height might be below above_height
                    // In this case, use above_height + 1 as the target
                    Some((above_height.increment(), peer))
                } else {
                    None
                }
            })
            .collect();

        // Sort by height to find the earliest
        candidates.sort_by(|a, b| a.0.cmp(&b.0));

        // Return the earliest height and use peer scoring to select the best peer for that height
        if let Some((earliest_height, _)) = candidates.first() {
            let peers_at_height: Vec<PeerId> = candidates
                .iter()
                .filter(|(h, _)| h == earliest_height)
                .map(|(_, p)| *p)
                .collect();

            if let Some(peer) = self
                .peer_scorer
                .select_peer(&peers_at_height, &mut self.rng)
            {
                return Some((*earliest_height, peer));
            }
        }

        None
    }
}
