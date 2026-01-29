//! Primary process state management

use crate::attestation::{AggregatedAttestation, Attestation};
use crate::batch::BatchDigest;
use crate::car::Car;
use crate::cut::Cut;
use cipherbft_types::{Hash, ValidatorId};
use std::collections::HashMap;
use std::time::Instant;

/// Pending Car awaiting attestations
#[derive(Clone, Debug)]
pub struct PendingCar {
    /// The Car itself
    pub car: Car,
    /// When the Car was created
    pub created_at: Instant,
    /// Attestations received so far
    pub attestations: Vec<Attestation>,
    /// Current backoff multiplier for timeout
    pub backoff_multiplier: u32,
}

impl PendingCar {
    /// Create a new pending car
    pub fn new(car: Car) -> Self {
        Self {
            car,
            created_at: Instant::now(),
            attestations: Vec::new(),
            backoff_multiplier: 1,
        }
    }

    /// Add an attestation
    pub fn add_attestation(&mut self, attestation: Attestation) {
        self.attestations.push(attestation);
    }

    /// Get attestation count
    pub fn attestation_count(&self) -> usize {
        // +1 for self-attestation (implicit)
        self.attestations.len() + 1
    }
}

/// Car awaiting batch synchronization
#[derive(Clone, Debug)]
pub struct CarAwaitingBatches {
    /// The Car that needs batches
    pub car: Car,
    /// Missing batch digests
    pub missing_digests: Vec<Hash>,
    /// When the sync request was made
    pub requested_at: Instant,
}

/// Car awaiting gap synchronization (received out of order)
///
/// When we receive a Car at position N but expect position M (where M < N),
/// we queue the Car here and request the missing predecessors via CarRequest.
#[derive(Clone, Debug)]
pub struct CarAwaitingGapSync {
    /// The Car that arrived out of order
    pub car: Car,
    /// The position we expected (the gap starts here)
    pub expected_position: u64,
    /// When we first received this out-of-order Car
    pub received_at: Instant,
    /// Number of retry attempts for requesting missing Cars
    pub retry_count: u32,
}

/// Pipeline stage for tracking consensus progress (T111)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelineStage {
    /// Collecting attestations for current height
    Collecting,
    /// Cut formed, awaiting consensus decision
    Proposing,
    /// Consensus timeout, preserving attestations
    TimedOut,
}

/// Primary process state
#[derive(Debug)]
pub struct PrimaryState {
    /// Our validator identity
    pub our_id: ValidatorId,
    /// Next height to produce (= last_finalized_height + 1)
    pub current_height: u64,
    /// Pending batch digests from Workers (to be included in next Car)
    pub pending_digests: Vec<BatchDigest>,
    /// Available batch digests we've received from Workers
    pub available_batches: std::collections::HashSet<Hash>,
    /// Last Car position we created
    pub our_position: u64,
    /// Hash of our last created Car (for parent_ref)
    pub last_car_hash: Option<Hash>,
    /// Consecutive empty Car count
    pub empty_car_count: u32,
    /// Last seen position per validator (for position validation)
    pub last_seen_positions: HashMap<ValidatorId, u64>,
    /// Last seen Car hash per validator (for parent_ref validation)
    pub last_seen_car_hashes: HashMap<ValidatorId, Hash>,
    /// Pending Cars awaiting attestations (keyed by Car hash)
    pub pending_cars: HashMap<Hash, PendingCar>,
    /// Cars awaiting batch synchronization (keyed by Car hash)
    pub cars_awaiting_batches: HashMap<Hash, CarAwaitingBatches>,
    /// Cars awaiting gap synchronization (keyed by (validator, position))
    /// These are Cars received out of order, waiting for predecessors
    pub cars_awaiting_gap_sync: HashMap<(ValidatorId, u64), CarAwaitingGapSync>,
    /// Pending CarRequest tracking (validator, position) -> request time
    /// Used to avoid sending duplicate requests and implement backoff
    pub pending_car_requests: HashMap<(ValidatorId, u64), Instant>,
    /// Highest attested Car per validator (ready for Cut inclusion)
    /// Stores the Car and its aggregated attestation (with aggregated BLS signature)
    pub attested_cars: HashMap<ValidatorId, (Car, AggregatedAttestation)>,
    /// Last attested validator index (for round-robin fairness)
    pub last_attested_idx: usize,
    /// Known equivocations (validator -> position -> multiple car hashes)
    pub equivocations: HashMap<ValidatorId, HashMap<u64, Vec<Hash>>>,
    /// Number of heights to retain equivocation data
    equivocation_retention: u64,

    // =========================================================
    // Pipeline state tracking (T111)
    // =========================================================
    /// Current pipeline stage
    pub pipeline_stage: PipelineStage,
    /// Next height attestations (received before current height is decided)
    /// Map of height -> (Car hash -> attestations)
    pub next_height_attestations: HashMap<u64, HashMap<Hash, Vec<Attestation>>>,
    /// Preserved attested Cars from timed-out rounds (T113)
    /// These should be included in the next Cut attempt
    pub preserved_attested_cars: HashMap<ValidatorId, (Car, AggregatedAttestation)>,
    /// Last finalized height
    pub last_finalized_height: u64,
    /// Last Car position included in a decided Cut, per validator
    /// Used to determine if an attested Car has already been "used"
    pub last_included_positions: HashMap<ValidatorId, u64>,
}

impl PrimaryState {
    /// Create new state for a validator
    ///
    /// # Arguments
    /// * `our_id` - Our validator identity
    /// * `equivocation_retention` - Number of heights to retain equivocation data
    pub fn new(our_id: ValidatorId, equivocation_retention: u64) -> Self {
        Self {
            our_id,
            // Start at height 1 (first height to produce after genesis)
            // Invariant: current_height = last_finalized_height + 1
            current_height: 1,
            pending_digests: Vec::new(),
            available_batches: std::collections::HashSet::new(),
            our_position: 0,
            last_car_hash: None,
            empty_car_count: 0,
            last_seen_positions: HashMap::new(),
            last_seen_car_hashes: HashMap::new(),
            pending_cars: HashMap::new(),
            cars_awaiting_batches: HashMap::new(),
            cars_awaiting_gap_sync: HashMap::new(),
            pending_car_requests: HashMap::new(),
            attested_cars: HashMap::new(),
            last_included_positions: HashMap::new(),
            last_attested_idx: 0,
            equivocations: HashMap::new(),
            equivocation_retention,
            // Pipeline state (T111)
            pipeline_stage: PipelineStage::Collecting,
            next_height_attestations: HashMap::new(),
            preserved_attested_cars: HashMap::new(),
            last_finalized_height: 0,
        }
    }

    /// Create state initialized from the last finalized Cut
    ///
    /// This is critical for restart recovery. When a validator restarts, it must
    /// restore position tracking from the last finalized cut so that:
    /// 1. Other validators accept our CARs (they expect the correct position)
    /// 2. We correctly validate incoming CARs from other validators
    ///
    /// Without this, restarted validators would create CARs at position 0, but
    /// other validators expect continuity from the last finalized position,
    /// causing all CARs to be rejected with PositionGap errors.
    ///
    /// # Arguments
    /// * `our_id` - Our validator identity
    /// * `equivocation_retention` - Number of heights to retain equivocation data
    /// * `cut` - The last finalized Cut to restore state from
    ///
    /// # State Restored
    /// * `our_position` - Set to our last finalized position + 1 (next position to create)
    /// * `last_car_hash` - Set to our last finalized CAR hash (for parent_ref)
    /// * `last_seen_positions` - Populated from all CARs in the cut
    /// * `last_seen_car_hashes` - Populated from all CARs in the cut
    /// * `current_height` - Set to cut.height + 1 (next height to produce)
    /// * `last_finalized_height` - Set to cut.height
    pub fn from_cut(our_id: ValidatorId, equivocation_retention: u64, cut: &Cut) -> Self {
        let mut state = Self::new(our_id, equivocation_retention);

        // Set height state from the cut
        state.last_finalized_height = cut.height;
        state.current_height = cut.height + 1;

        // Restore position tracking from all CARs in the cut
        for (validator, car) in &cut.cars {
            state.last_seen_positions.insert(*validator, car.position);
            state.last_seen_car_hashes.insert(*validator, car.hash());
            // Track positions included in the cut (used for batch preservation logic)
            state
                .last_included_positions
                .insert(*validator, car.position);

            // If this is our own CAR, restore our position state
            if *validator == our_id {
                state.our_position = car.position + 1; // Next position to create
                state.last_car_hash = Some(car.hash());
            }
        }
        // Note: If our validator is not in the restored cut, we start at position 0.
        // This is correct because:
        // 1. If we were never active, position 0 is the correct starting point
        // 2. If we were offline and missed being included in recent cuts, other
        //    validators track expected positions per-validator based on finalized
        //    cuts. They will have "forgotten" our old position and expect us to
        //    start fresh, which prevents permanent PositionGap deadlock.

        tracing::info!(
            validator = %our_id,
            restored_height = cut.height,
            our_position = state.our_position,
            tracked_validators = state.last_seen_positions.len(),
            "Primary state restored from finalized cut"
        );

        state
    }

    /// Add batch digest from Worker
    pub fn add_batch_digest(&mut self, digest: BatchDigest) {
        // Track as available for batch availability checking
        self.available_batches.insert(digest.digest);
        self.pending_digests.push(digest);
    }

    /// Take pending digests (clears the pending list)
    pub fn take_pending_digests(&mut self) -> Vec<BatchDigest> {
        std::mem::take(&mut self.pending_digests)
    }

    /// Update our position after creating a Car
    pub fn update_our_position(&mut self, position: u64, car_hash: Hash, is_empty: bool) {
        self.our_position = position;
        self.last_car_hash = Some(car_hash);

        if is_empty {
            self.empty_car_count += 1;
        } else {
            self.empty_car_count = 0;
        }
    }

    /// Check if we can create another empty Car
    pub fn can_create_empty_car(&self, max_empty: u32) -> bool {
        self.empty_car_count < max_empty
    }

    /// Get expected position for a validator's next Car
    pub fn expected_position(&self, validator: &ValidatorId) -> u64 {
        self.last_seen_positions
            .get(validator)
            .map(|p| p + 1)
            .unwrap_or(0)
    }

    /// Update last seen position for a validator
    pub fn update_last_seen(&mut self, validator: ValidatorId, position: u64, car_hash: Hash) {
        self.last_seen_positions.insert(validator, position);
        self.last_seen_car_hashes.insert(validator, car_hash);
    }

    /// Sync position tracking from a decided Cut
    ///
    /// When consensus decides on a Cut, all validators must update their position
    /// tracking to reflect the decided state. This is critical because:
    /// 1. A validator may not have received all CARs during the collection phase
    /// 2. Position validation requires sequential positions (no gaps)
    /// 3. Without syncing, future CARs will be rejected with PositionGap errors
    ///
    /// This method updates `last_seen_positions` and `last_seen_car_hashes` for
    /// each CAR in the decided Cut if the position is higher than what we've seen.
    ///
    /// IMPORTANT: Also syncs our own position from finalized cuts to prevent drift.
    /// During sync, a validator creates Cars at regular intervals that fail attestation
    /// (peers haven't caught up yet), but our_position keeps incrementing. When sync
    /// completes, our_position has drifted far ahead of what peers expect. By resetting
    /// our_position from the finalized cut containing our Car, we re-sync with the network.
    pub fn sync_positions_from_cut(&mut self, cut: &Cut) {
        tracing::info!(
            height = cut.height,
            car_count = cut.cars.len(),
            "sync_positions_from_cut called"
        );

        for (validator, car) in &cut.cars {
            let current_pos = self.last_seen_positions.get(validator).copied();
            // Only update if the decided position is higher than our current tracking
            if current_pos.is_none_or(|p| car.position > p) {
                self.last_seen_positions.insert(*validator, car.position);
                self.last_seen_car_hashes.insert(*validator, car.hash());
            }
            // Track which positions have been included in decided Cuts
            // This is used by mark_attested to determine if a Car with batches
            // has already been "used" and can be safely replaced
            let old_last_included = self.last_included_positions.get(validator).copied();
            if old_last_included.is_none_or(|p| car.position > p) {
                self.last_included_positions
                    .insert(*validator, car.position);
                tracing::info!(
                    validator = %validator,
                    car_position = car.position,
                    old_last_included = old_last_included.unwrap_or(0),
                    batches = car.batch_digests.len(),
                    "Updated last_included_positions"
                );
            }

            // CRITICAL: Remove attested Cars that were included in this Cut
            // This prevents the same Car from being included in subsequent Cuts.
            // Only remove if the attested Car's position matches what was included;
            // if a newer Car arrived while consensus was deciding, it has a higher
            // position and should be preserved for the next Cut.
            if let Some((attested_car, _)) = self.attested_cars.get(validator) {
                if attested_car.position == car.position {
                    self.attested_cars.remove(validator);
                }
            }

            // Also sync our own position from finalized cuts to prevent position drift
            // This is critical for validators catching up during sync:
            // - While syncing, we create Cars that fail attestation (position mismatch)
            // - our_position increments on creation, not finalization
            // - By sync completion, our_position has drifted ahead of peers' expectations
            // - Reset our_position from finalized cut to re-sync with network consensus
            if *validator == self.our_id {
                let finalized_next = car.position + 1;
                // Only reset if the finalized position is behind our current position
                // This handles the case where we're catching up and need to re-sync
                if finalized_next <= self.our_position && self.our_position > 0 {
                    tracing::info!(
                        validator = %self.our_id,
                        old_position = self.our_position,
                        finalized_position = car.position,
                        new_position = finalized_next,
                        "Resetting our_position from finalized cut (position drift correction)"
                    );
                    self.our_position = finalized_next;
                    self.last_car_hash = Some(car.hash());
                }
            }
        }
    }

    /// Get last seen Car hash for parent_ref validation
    pub fn last_seen_car_hash(&self, validator: &ValidatorId) -> Option<&Hash> {
        self.last_seen_car_hashes.get(validator)
    }

    /// Add pending Car
    pub fn add_pending_car(&mut self, car: Car) {
        let hash = car.hash();
        self.pending_cars.insert(hash, PendingCar::new(car));
    }

    /// Get pending Car by hash
    pub fn get_pending_car(&self, hash: &Hash) -> Option<&PendingCar> {
        self.pending_cars.get(hash)
    }

    /// Get mutable pending Car by hash
    pub fn get_pending_car_mut(&mut self, hash: &Hash) -> Option<&mut PendingCar> {
        self.pending_cars.get_mut(hash)
    }

    /// Remove pending Car (when attested or timed out)
    pub fn remove_pending_car(&mut self, hash: &Hash) -> Option<PendingCar> {
        self.pending_cars.remove(hash)
    }

    /// Mark Car as attested (move from pending to attested)
    ///
    /// # Arguments
    /// * `car` - The Car that has been attested
    /// * `aggregated` - The aggregated attestation with BLS aggregate signature
    ///
    /// # Note
    /// This implements a policy to preserve Cars with batches (transactions):
    /// - A Car with batches will always be stored
    /// - An empty Car will only overwrite if:
    ///   - The existing Car is also empty, OR
    ///   - The existing Car's position has been included in a decided Cut
    /// - This prevents the race condition where empty Cars get attested faster
    ///   than Cars with batches (due to batch sync delays), causing transactions
    ///   to be lost from Cuts.
    pub fn mark_attested(&mut self, car: Car, aggregated: AggregatedAttestation) {
        let validator = car.proposer;
        let new_has_batches = !car.batch_digests.is_empty();

        // Check if we should replace the existing attested Car
        if let Some((existing_car, _)) = self.attested_cars.get(&validator) {
            let existing_has_batches = !existing_car.batch_digests.is_empty();
            let last_included = self
                .last_included_positions
                .get(&validator)
                .copied()
                .unwrap_or(0);

            // Don't replace a Car with batches with an empty Car, UNLESS the
            // existing Car's position has already been included in a decided Cut
            if existing_has_batches
                && !new_has_batches
                && car.position > existing_car.position
                && existing_car.position > last_included
            {
                tracing::info!(
                    validator = %validator,
                    existing_position = existing_car.position,
                    existing_batches = existing_car.batch_digests.len(),
                    new_position = car.position,
                    last_included,
                    "Preserving Car with batches, deferring empty Car"
                );
                return;
            }

            // Allow replacement if:
            // 1. New Car has batches (prioritize transactions)
            // 2. Both are empty (normal progression)
            // 3. Existing Car was already included in a Cut (position <= last_included)
        }

        self.attested_cars.insert(validator, (car, aggregated));
    }

    /// Get attested cars for Cut formation
    ///
    /// Returns a reference to the map of validator -> (Car, AggregatedAttestation)
    pub fn get_attested_cars(&self) -> &HashMap<ValidatorId, (Car, AggregatedAttestation)> {
        &self.attested_cars
    }

    /// Record equivocation evidence
    pub fn record_equivocation(&mut self, validator: ValidatorId, position: u64, car_hash: Hash) {
        self.equivocations
            .entry(validator)
            .or_default()
            .entry(position)
            .or_default()
            .push(car_hash);
    }

    /// Check if validator has equivocated at position
    pub fn has_equivocated(&self, validator: &ValidatorId, position: u64) -> bool {
        self.equivocations
            .get(validator)
            .and_then(|positions| positions.get(&position))
            .map(|hashes| hashes.len() > 1)
            .unwrap_or(false)
    }

    /// Get validators with attested Cars (for Cut formation)
    pub fn validators_with_attested_cars(&self) -> Vec<ValidatorId> {
        self.attested_cars.keys().cloned().collect()
    }

    /// Clear state for new height
    pub fn advance_height(&mut self, new_height: u64) {
        self.current_height = new_height;
        self.pending_cars.clear();
        // Keep attested_cars as they may be used in the new height's Cut
    }

    // =========================================================
    // Batch availability checking (T097)
    // =========================================================

    /// Check if we have all batch data for a Car
    ///
    /// Returns (has_all, missing_digests)
    pub fn check_batch_availability(&self, car: &Car) -> (bool, Vec<Hash>) {
        let mut missing = Vec::new();
        for batch_digest in &car.batch_digests {
            if !self.available_batches.contains(&batch_digest.digest) {
                missing.push(batch_digest.digest);
            }
        }
        (missing.is_empty(), missing)
    }

    /// Mark a batch as available (when synced from peer)
    pub fn mark_batch_available(&mut self, digest: Hash) {
        self.available_batches.insert(digest);
    }

    /// Check if a batch is available
    pub fn has_batch(&self, digest: &Hash) -> bool {
        self.available_batches.contains(digest)
    }

    // =========================================================
    // Cars awaiting batches (T098)
    // =========================================================

    /// Add Car to awaiting batches queue
    pub fn add_car_awaiting_batches(&mut self, car: Car, missing_digests: Vec<Hash>) {
        let car_hash = car.hash();
        self.cars_awaiting_batches.insert(
            car_hash,
            CarAwaitingBatches {
                car,
                missing_digests,
                requested_at: Instant::now(),
            },
        );
    }

    /// Get Cars that are ready (all batches now available)
    ///
    /// Returns Cars that can now be processed
    pub fn get_ready_cars(&mut self) -> Vec<Car> {
        let mut ready = Vec::new();
        let mut ready_hashes = Vec::new();

        for (hash, awaiting) in &self.cars_awaiting_batches {
            let (has_all, _) = self.check_batch_availability(&awaiting.car);
            if has_all {
                ready.push(awaiting.car.clone());
                ready_hashes.push(*hash);
            }
        }

        // Remove ready cars from waiting
        for hash in ready_hashes {
            self.cars_awaiting_batches.remove(&hash);
        }

        ready
    }

    /// Check if a Car is already waiting for batches
    pub fn is_awaiting_batches(&self, car_hash: &Hash) -> bool {
        self.cars_awaiting_batches.contains_key(car_hash)
    }

    // =========================================================
    // Gap recovery for out-of-order Cars (Issue #106)
    // =========================================================

    /// Queue a Car that arrived out of order (position gap detected)
    ///
    /// When we receive a Car at position N but expect position M < N,
    /// we queue it here and will process it once we receive the missing
    /// predecessors via CarRequest/CarResponse.
    pub fn queue_car_awaiting_gap(&mut self, car: Car, expected_position: u64) {
        let key = (car.proposer, car.position);
        // Don't re-queue if already waiting
        if self.cars_awaiting_gap_sync.contains_key(&key) {
            return;
        }
        self.cars_awaiting_gap_sync.insert(
            key,
            CarAwaitingGapSync {
                car,
                expected_position,
                received_at: Instant::now(),
                retry_count: 0,
            },
        );
    }

    /// Check if a Car is already queued for gap sync
    pub fn is_awaiting_gap_sync(&self, validator: &ValidatorId, position: u64) -> bool {
        self.cars_awaiting_gap_sync
            .contains_key(&(*validator, position))
    }

    /// Get Cars that are ready after a gap is filled
    ///
    /// When we receive missing Cars via CarResponse, this method returns
    /// queued Cars that can now be processed (their expected_position matches
    /// the newly updated last_seen_position + 1).
    ///
    /// Returns Cars in position order for the given validator.
    pub fn get_cars_ready_after_gap_filled(&mut self, validator: &ValidatorId) -> Vec<Car> {
        let expected = self.expected_position(validator);

        let mut ready = Vec::new();
        let mut ready_keys = Vec::new();

        // Find all queued Cars for this validator that are now at expected position
        for ((v, pos), awaiting) in &self.cars_awaiting_gap_sync {
            if v == validator && *pos == expected {
                ready.push(awaiting.car.clone());
                ready_keys.push((*v, *pos));
            }
        }

        // Remove the ready Cars from the queue
        for key in ready_keys {
            self.cars_awaiting_gap_sync.remove(&key);
        }

        ready
    }

    /// Get all unique validators that have queued CARs awaiting gap sync.
    ///
    /// This is useful when processing consensus decisions to ensure we check
    /// ALL validators with queued CARs, not just those in the decided cut.
    pub fn get_validators_with_queued_cars(&self) -> Vec<ValidatorId> {
        let mut validators: std::collections::HashSet<ValidatorId> =
            std::collections::HashSet::new();
        for (validator, _) in self.cars_awaiting_gap_sync.keys() {
            validators.insert(*validator);
        }
        validators.into_iter().collect()
    }

    /// Track a pending CarRequest to avoid duplicates
    pub fn track_car_request(&mut self, validator: ValidatorId, position: u64) {
        self.pending_car_requests
            .insert((validator, position), Instant::now());
    }

    /// Check if a CarRequest is already pending
    pub fn is_car_request_pending(&self, validator: &ValidatorId, position: u64) -> bool {
        self.pending_car_requests
            .contains_key(&(*validator, position))
    }

    /// Clear a pending CarRequest (e.g., after receiving response)
    pub fn clear_car_request(&mut self, validator: &ValidatorId, position: u64) {
        self.pending_car_requests.remove(&(*validator, position));
    }

    /// Get stale CarRequests that should be retried
    ///
    /// Returns (validator, position) pairs for requests older than the timeout.
    pub fn get_stale_car_requests(&self, timeout: std::time::Duration) -> Vec<(ValidatorId, u64)> {
        let now = Instant::now();
        self.pending_car_requests
            .iter()
            .filter_map(|((v, pos), requested_at)| {
                if now.duration_since(*requested_at) > timeout {
                    Some((*v, *pos))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get all missing positions for a validator that need CarRequests
    ///
    /// Given the expected position and a received position, returns all
    /// positions in between that we need to request.
    pub fn get_missing_positions(
        &self,
        validator: &ValidatorId,
        received_position: u64,
    ) -> Vec<u64> {
        let expected = self.expected_position(validator);
        if received_position <= expected {
            return Vec::new();
        }
        (expected..received_position)
            .filter(|pos| !self.is_car_request_pending(validator, *pos))
            .collect()
    }

    /// Cleanup stale gap sync data
    fn cleanup_stale_gap_sync_data(&mut self, timeout: std::time::Duration) {
        let now = Instant::now();

        // Cleanup old Cars awaiting gap sync
        self.cars_awaiting_gap_sync
            .retain(|_, awaiting| now.duration_since(awaiting.received_at) < timeout);

        // Cleanup old pending CarRequests
        self.pending_car_requests
            .retain(|_, requested_at| now.duration_since(*requested_at) < timeout);
    }

    // =========================================================
    // Pipeline state management (T111-T113)
    // =========================================================

    /// Set pipeline stage (T111)
    pub fn set_pipeline_stage(&mut self, stage: PipelineStage) {
        self.pipeline_stage = stage;
    }

    /// Store attestation for a future height (T112)
    ///
    /// When we receive attestations for height > current_height,
    /// we store them for later use.
    pub fn store_next_height_attestation(&mut self, height: u64, attestation: Attestation) {
        let car_hash = attestation.car_hash;
        self.next_height_attestations
            .entry(height)
            .or_default()
            .entry(car_hash)
            .or_default()
            .push(attestation);
    }

    /// Get and clear attestations for a specific height (T112)
    ///
    /// Called when advancing to a new height to process pre-received attestations.
    pub fn take_next_height_attestations(
        &mut self,
        height: u64,
    ) -> HashMap<Hash, Vec<Attestation>> {
        self.next_height_attestations
            .remove(&height)
            .unwrap_or_default()
    }

    /// Preserve current attested Cars on consensus timeout (T113)
    ///
    /// When a consensus round times out, we preserve attested Cars
    /// so they can be included in the next Cut attempt.
    pub fn preserve_attested_cars_on_timeout(&mut self) {
        // Merge current attested cars into preserved
        // Newer attestations (higher positions) take precedence
        for (validator, (car, attestation)) in std::mem::take(&mut self.attested_cars) {
            let should_update = self
                .preserved_attested_cars
                .get(&validator)
                .map(|(existing, _)| car.position > existing.position)
                .unwrap_or(true);

            if should_update {
                self.preserved_attested_cars
                    .insert(validator, (car, attestation));
            }
        }
        self.pipeline_stage = PipelineStage::TimedOut;
    }

    /// Restore preserved attested Cars into current state (T113)
    ///
    /// Called when starting a new round to include preserved Cars.
    pub fn restore_preserved_attested_cars(&mut self) {
        // Move preserved into current attested_cars
        for (validator, (car, attestation)) in std::mem::take(&mut self.preserved_attested_cars) {
            let should_update = self
                .attested_cars
                .get(&validator)
                .map(|(existing, _)| car.position > existing.position)
                .unwrap_or(true);

            if should_update {
                self.attested_cars.insert(validator, (car, attestation));
            }
        }
        self.pipeline_stage = PipelineStage::Collecting;
    }

    /// Finalize a height (T111)
    ///
    /// Called when consensus decides on a Cut.
    pub fn finalize_height(&mut self, height: u64) {
        self.last_finalized_height = height;
        self.current_height = height + 1;
        self.pipeline_stage = PipelineStage::Collecting;

        // Clear preserved cars since consensus succeeded
        self.preserved_attested_cars.clear();

        // Clear old next-height attestations (anything before new current height)
        self.next_height_attestations
            .retain(|h, _| *h >= self.current_height);

        // Cleanup stale data to prevent memory leaks
        // Keep equivocation data for configured retention window
        self.cleanup_stale_equivocations(self.equivocation_retention);

        // Cleanup old pending cars and cars awaiting batches
        self.cleanup_stale_pending_data();
    }

    // =========================================================
    // Memory Management / Garbage Collection
    // =========================================================

    /// Cleanup equivocation records older than the retention window.
    ///
    /// Equivocation data is important for slashing evidence but doesn't need
    /// to be kept indefinitely. This method removes records for positions
    /// that are older than `current_height - retention_heights`.
    ///
    /// # Arguments
    /// * `retention_heights` - Number of heights to retain equivocation data for
    pub fn cleanup_stale_equivocations(&mut self, retention_heights: u64) {
        let min_position_to_keep = self.current_height.saturating_sub(retention_heights);

        for positions in self.equivocations.values_mut() {
            positions.retain(|pos, _| *pos >= min_position_to_keep);
        }

        // Remove validators with no remaining equivocation records
        self.equivocations
            .retain(|_, positions| !positions.is_empty());
    }

    /// Cleanup available batches that are no longer needed.
    ///
    /// Removes batch hashes that are not in the provided set of referenced batches.
    /// This should be called periodically with the set of batches still needed
    /// for pending/attested Cars.
    ///
    /// # Arguments
    /// * `referenced_batches` - Set of batch hashes that are still referenced
    pub fn cleanup_available_batches(
        &mut self,
        referenced_batches: &std::collections::HashSet<Hash>,
    ) {
        self.available_batches
            .retain(|hash| referenced_batches.contains(hash));
    }

    /// Get all batch hashes currently referenced by pending or attested Cars.
    ///
    /// Useful for determining which batches can be safely removed.
    pub fn get_referenced_batch_hashes(&self) -> std::collections::HashSet<Hash> {
        let mut referenced = std::collections::HashSet::new();

        // Collect from pending Cars
        for pending in self.pending_cars.values() {
            for digest in &pending.car.batch_digests {
                referenced.insert(digest.digest);
            }
        }

        // Collect from Cars awaiting batches
        for awaiting in self.cars_awaiting_batches.values() {
            for digest in &awaiting.car.batch_digests {
                referenced.insert(digest.digest);
            }
        }

        // Collect from attested Cars
        for (car, _) in self.attested_cars.values() {
            for digest in &car.batch_digests {
                referenced.insert(digest.digest);
            }
        }

        // Collect from preserved attested Cars
        for (car, _) in self.preserved_attested_cars.values() {
            for digest in &car.batch_digests {
                referenced.insert(digest.digest);
            }
        }

        // Also keep pending digests
        for digest in &self.pending_digests {
            referenced.insert(digest.digest);
        }

        referenced
    }

    /// Cleanup stale pending data (pending cars, cars awaiting batches, gap sync).
    ///
    /// Removes entries that have been pending for too long (likely orphaned).
    /// Uses a timeout-based approach: entries older than 5 minutes are removed.
    fn cleanup_stale_pending_data(&mut self) {
        use std::time::Duration;

        const STALE_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes

        // Cleanup old pending cars
        self.pending_cars
            .retain(|_, pending| pending.created_at.elapsed() < STALE_TIMEOUT);

        // Cleanup old cars awaiting batches
        self.cars_awaiting_batches
            .retain(|_, awaiting| awaiting.requested_at.elapsed() < STALE_TIMEOUT);

        // Cleanup old gap sync data
        self.cleanup_stale_gap_sync_data(STALE_TIMEOUT);
    }

    /// Perform full memory cleanup.
    ///
    /// Call this periodically (e.g., every N finalized heights) for comprehensive cleanup.
    pub fn full_cleanup(&mut self) {
        // Cleanup equivocations
        self.cleanup_stale_equivocations(1000);

        // Cleanup available batches - keep only referenced ones
        let referenced = self.get_referenced_batch_hashes();
        self.cleanup_available_batches(&referenced);

        // Cleanup stale pending data
        self.cleanup_stale_pending_data();
    }

    /// Get combined attested Cars (current + preserved) for Cut formation
    pub fn get_all_attested_cars(&self) -> HashMap<ValidatorId, (Car, AggregatedAttestation)> {
        let mut combined = self.preserved_attested_cars.clone();

        // Current attested cars take precedence (might have newer positions)
        for (validator, (car, attestation)) in &self.attested_cars {
            let should_update = combined
                .get(validator)
                .map(|(existing, _)| car.position > existing.position)
                .unwrap_or(true);

            if should_update {
                combined.insert(*validator, (car.clone(), attestation.clone()));
            }
        }

        combined
    }

    /// Check if we have pending next-height attestations
    pub fn has_pending_next_height_attestations(&self) -> bool {
        !self.next_height_attestations.is_empty()
    }

    /// Get pipeline state summary for diagnostics
    pub fn pipeline_summary(&self) -> PipelineSummary {
        PipelineSummary {
            current_height: self.current_height,
            last_finalized_height: self.last_finalized_height,
            stage: self.pipeline_stage,
            attested_car_count: self.attested_cars.len(),
            preserved_car_count: self.preserved_attested_cars.len(),
            next_height_attestation_count: self.next_height_attestations.len(),
        }
    }
}

/// Summary of pipeline state for diagnostics (T111)
#[derive(Debug, Clone)]
pub struct PipelineSummary {
    pub current_height: u64,
    pub last_finalized_height: u64,
    pub stage: PipelineStage,
    pub attested_car_count: usize,
    pub preserved_car_count: usize,
    pub next_height_attestation_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbft_crypto::BlsKeyPair;
    use cipherbft_types::VALIDATOR_ID_SIZE;

    /// Create a properly signed attestation for testing
    fn create_signed_attestation(
        car: &crate::car::Car,
        attester_index: usize,
    ) -> crate::attestation::Attestation {
        let kp = BlsKeyPair::generate(&mut rand::thread_rng());
        let attester_id = ValidatorId::from_bytes([attester_index as u8; VALIDATOR_ID_SIZE]);
        let mut att = crate::attestation::Attestation::from_car(car, attester_id);
        att.signature = kp.sign_attestation(&att.get_signing_bytes());
        att
    }

    /// Create a properly aggregated attestation for testing
    fn create_aggregated_attestation(
        car: &crate::car::Car,
        attester_indices: &[usize],
        validator_count: usize,
    ) -> AggregatedAttestation {
        let attestations_with_indices: Vec<(crate::attestation::Attestation, usize)> =
            attester_indices
                .iter()
                .map(|&idx| (create_signed_attestation(car, idx), idx))
                .collect();

        AggregatedAttestation::aggregate_with_indices(&attestations_with_indices, validator_count)
            .expect("aggregation should succeed with valid attestations")
    }

    #[test]
    fn test_empty_car_tracking() {
        let mut state = PrimaryState::new(ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]), 1000);

        // Initially can create empty cars
        assert!(state.can_create_empty_car(3));

        // After 3 empty cars, should not be able to create more
        state.update_our_position(0, Hash::compute(b"car0"), true);
        assert!(state.can_create_empty_car(3));
        state.update_our_position(1, Hash::compute(b"car1"), true);
        assert!(state.can_create_empty_car(3));
        state.update_our_position(2, Hash::compute(b"car2"), true);
        assert!(!state.can_create_empty_car(3));

        // Non-empty car resets counter
        state.update_our_position(3, Hash::compute(b"car3"), false);
        assert!(state.can_create_empty_car(3));
        assert_eq!(state.empty_car_count, 0);
    }

    #[test]
    fn test_position_tracking() {
        let mut state = PrimaryState::new(ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]), 1000);
        let validator = ValidatorId::from_bytes([2u8; VALIDATOR_ID_SIZE]);

        // Expected position for unknown validator is 0
        assert_eq!(state.expected_position(&validator), 0);

        // Update and check
        state.update_last_seen(validator, 5, Hash::compute(b"car5"));
        assert_eq!(state.expected_position(&validator), 6);
    }

    #[test]
    fn test_equivocation_detection() {
        let mut state = PrimaryState::new(ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]), 1000);
        let validator = ValidatorId::from_bytes([2u8; VALIDATOR_ID_SIZE]);

        // First car at position 5
        state.record_equivocation(validator, 5, Hash::compute(b"car5a"));
        assert!(!state.has_equivocated(&validator, 5));

        // Second car at same position = equivocation
        state.record_equivocation(validator, 5, Hash::compute(b"car5b"));
        assert!(state.has_equivocated(&validator, 5));

        // Different position is fine
        assert!(!state.has_equivocated(&validator, 6));
    }

    // =========================================================
    // Pipeline State Tests (T117)
    // =========================================================

    #[test]
    fn test_pipeline_stage_transitions() {
        let mut state = PrimaryState::new(ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]), 1000);

        // Initially in Collecting stage
        assert_eq!(state.pipeline_stage, PipelineStage::Collecting);

        // Transition to Proposing
        state.set_pipeline_stage(PipelineStage::Proposing);
        assert_eq!(state.pipeline_stage, PipelineStage::Proposing);

        // Timeout preserves attestations
        state.preserve_attested_cars_on_timeout();
        assert_eq!(state.pipeline_stage, PipelineStage::TimedOut);

        // Restore moves back to Collecting
        state.restore_preserved_attested_cars();
        assert_eq!(state.pipeline_stage, PipelineStage::Collecting);
    }

    #[test]
    fn test_preserve_attested_cars_on_timeout() {
        use crate::car::Car;

        let our_id = ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]);
        let mut state = PrimaryState::new(our_id, 1000);

        let validator1 = ValidatorId::from_bytes([2u8; VALIDATOR_ID_SIZE]);
        let validator2 = ValidatorId::from_bytes([3u8; VALIDATOR_ID_SIZE]);

        // Add attested cars
        let car1 = Car::new(validator1, 5, vec![], None);
        let car2 = Car::new(validator2, 3, vec![], None);

        // Create properly aggregated attestations (validators 0 and 1 attesting)
        let agg1 = create_aggregated_attestation(&car1, &[0, 1], 4);
        let agg2 = create_aggregated_attestation(&car2, &[0, 1], 4);

        state.mark_attested(car1.clone(), agg1.clone());
        state.mark_attested(car2.clone(), agg2.clone());

        assert_eq!(state.attested_cars.len(), 2);
        assert_eq!(state.preserved_attested_cars.len(), 0);

        // Timeout preserves cars
        state.preserve_attested_cars_on_timeout();

        assert_eq!(state.attested_cars.len(), 0);
        assert_eq!(state.preserved_attested_cars.len(), 2);

        // Restore moves them back
        state.restore_preserved_attested_cars();

        assert_eq!(state.attested_cars.len(), 2);
        assert_eq!(state.preserved_attested_cars.len(), 0);
    }

    #[test]
    fn test_next_height_attestations() {
        use crate::car::Car;

        let our_id = ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]);
        let mut state = PrimaryState::new(our_id, 1000);
        state.current_height = 5;

        let attester = ValidatorId::from_bytes([2u8; VALIDATOR_ID_SIZE]);

        // Create a car for the attestation
        let car = Car::new(attester, 0, vec![], None);
        let car_hash = car.hash();

        // Create properly signed attestation for future height
        let attestation = create_signed_attestation(&car, 2);

        // Store for height 6 (next height)
        state.store_next_height_attestation(6, attestation.clone());

        assert!(state.has_pending_next_height_attestations());

        // Take attestations when we reach height 6
        let next_atts = state.take_next_height_attestations(6);
        assert_eq!(next_atts.len(), 1);
        assert!(next_atts.contains_key(&car_hash));
        assert_eq!(next_atts.get(&car_hash).unwrap().len(), 1);

        // Should be empty now
        assert!(!state.has_pending_next_height_attestations());
    }

    #[test]
    fn test_finalize_height() {
        use crate::car::Car;

        let our_id = ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]);
        let mut state = PrimaryState::new(our_id, 1000);
        state.current_height = 5;

        // Create a car for the attestation
        let car = Car::new(our_id, 0, vec![], None);

        // Create properly signed attestation
        let attestation = create_signed_attestation(&car, 0);

        state.store_next_height_attestation(4, attestation.clone()); // Old - should be cleared
        state.store_next_height_attestation(6, attestation.clone()); // Future - should be kept

        // Finalize height 5
        state.finalize_height(5);

        assert_eq!(state.last_finalized_height, 5);
        assert_eq!(state.current_height, 6);
        assert_eq!(state.pipeline_stage, PipelineStage::Collecting);

        // Old attestations should be cleared, future ones kept
        assert_eq!(state.next_height_attestations.len(), 1);
        assert!(state.next_height_attestations.contains_key(&6));
    }

    #[test]
    fn test_get_all_attested_cars_merges_preserved() {
        use crate::car::Car;

        let our_id = ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]);
        let mut state = PrimaryState::new(our_id, 1000);

        let validator = ValidatorId::from_bytes([2u8; VALIDATOR_ID_SIZE]);

        // Create preserved car at position 3 with proper aggregated attestation
        let car_old = Car::new(validator, 3, vec![], None);
        let agg_old = create_aggregated_attestation(&car_old, &[0, 1], 4);
        state
            .preserved_attested_cars
            .insert(validator, (car_old.clone(), agg_old));

        // Create current car at position 5 (newer) with proper aggregated attestation
        let car_new = Car::new(validator, 5, vec![], None);
        let agg_new = create_aggregated_attestation(&car_new, &[0, 1], 4);
        state
            .attested_cars
            .insert(validator, (car_new.clone(), agg_new));

        // Get all should return the newer one
        let all = state.get_all_attested_cars();
        assert_eq!(all.len(), 1);
        assert_eq!(all.get(&validator).unwrap().0.position, 5);
    }

    #[test]
    fn test_pipeline_summary() {
        let our_id = ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]);
        let mut state = PrimaryState::new(our_id, 1000);
        state.current_height = 10;
        state.last_finalized_height = 9;

        let summary = state.pipeline_summary();
        assert_eq!(summary.current_height, 10);
        assert_eq!(summary.last_finalized_height, 9);
        assert_eq!(summary.stage, PipelineStage::Collecting);
        assert_eq!(summary.attested_car_count, 0);
        assert_eq!(summary.preserved_car_count, 0);
        assert_eq!(summary.next_height_attestation_count, 0);
    }

    // =========================================================
    // Queued CAR Processing After Consensus Decision Tests
    // =========================================================

    /// Test that verifies the race condition fix: queued CARs become ready
    /// after sync_positions_from_cut() updates position tracking.
    ///
    /// Scenario:
    /// 1. Validator A has seen position 4 for validator B
    /// 2. Consensus decides a cut with validator B at position 6
    /// 3. Validator A receives validator B's CAR at position 7 (queued due to gap)
    /// 4. Validator A processes consensus decision, sync_positions_from_cut() sets B's position to 6
    /// 5. Now the queued CAR at position 7 should be returned by get_cars_ready_after_gap_filled()
    #[test]
    fn test_queued_cars_ready_after_consensus_sync() {
        use crate::car::Car;
        use crate::cut::Cut;

        let our_id = ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]);
        let mut state = PrimaryState::new(our_id, 1000);

        let validator_b = ValidatorId::from_bytes([2u8; VALIDATOR_ID_SIZE]);

        // Step 1: Validator A has seen position 4 for validator B
        state.update_last_seen(validator_b, 4, Hash::compute(b"car4"));
        assert_eq!(state.expected_position(&validator_b), 5);

        // Step 2: Validator A receives validator B's CAR at position 7 (out of order)
        // This gets queued because expected_position is 5, but we received 7
        let car_at_7 = Car::new(validator_b, 7, vec![], Some(Hash::compute(b"car6")));
        state.queue_car_awaiting_gap(car_at_7.clone(), 5); // expected was 5 when received

        // Verify the CAR is queued
        assert!(state.is_awaiting_gap_sync(&validator_b, 7));

        // Step 3: Check that get_cars_ready_after_gap_filled returns nothing
        // because expected_position (5) != queued car position (7)
        let ready_before = state.get_cars_ready_after_gap_filled(&validator_b);
        assert!(
            ready_before.is_empty(),
            "No CARs should be ready before sync"
        );

        // Re-queue the CAR since get_cars_ready_after_gap_filled clears checked positions
        state.queue_car_awaiting_gap(car_at_7.clone(), 5);

        // Step 4: Consensus decides a cut with validator B at position 6
        let mut decided_cut = Cut::new(2);
        let car_at_6 = Car::new(validator_b, 6, vec![], Some(Hash::compute(b"car5")));
        decided_cut.cars.insert(validator_b, car_at_6);

        // Sync positions from the decided cut
        state.sync_positions_from_cut(&decided_cut);

        // Expected position should now be 7 (6 + 1)
        assert_eq!(state.expected_position(&validator_b), 7);

        // Step 5: Now the queued CAR at position 7 should be ready
        let ready_after = state.get_cars_ready_after_gap_filled(&validator_b);
        assert_eq!(ready_after.len(), 1, "CAR at position 7 should be ready");
        assert_eq!(ready_after[0].position, 7);
        assert_eq!(ready_after[0].proposer, validator_b);

        // Verify the CAR is no longer queued
        assert!(!state.is_awaiting_gap_sync(&validator_b, 7));
    }

    /// Test that queued CARs for multiple validators are handled correctly
    /// after sync_positions_from_cut().
    #[test]
    fn test_queued_cars_multiple_validators_after_sync() {
        use crate::car::Car;
        use crate::cut::Cut;

        let our_id = ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]);
        let mut state = PrimaryState::new(our_id, 1000);

        let validator_b = ValidatorId::from_bytes([2u8; VALIDATOR_ID_SIZE]);
        let validator_c = ValidatorId::from_bytes([3u8; VALIDATOR_ID_SIZE]);

        // Set up initial positions
        state.update_last_seen(validator_b, 2, Hash::compute(b"b_car2"));
        state.update_last_seen(validator_c, 3, Hash::compute(b"c_car3"));

        // Queue CARs that arrived out of order
        let car_b_at_5 = Car::new(validator_b, 5, vec![], Some(Hash::compute(b"b_car4")));
        let car_c_at_6 = Car::new(validator_c, 6, vec![], Some(Hash::compute(b"c_car5")));

        state.queue_car_awaiting_gap(car_b_at_5.clone(), 3); // expected was 3
        state.queue_car_awaiting_gap(car_c_at_6.clone(), 4); // expected was 4

        // Create a decided cut that advances both validators
        let mut decided_cut = Cut::new(2);
        let car_b_at_4 = Car::new(validator_b, 4, vec![], Some(Hash::compute(b"b_car3")));
        let car_c_at_5 = Car::new(validator_c, 5, vec![], Some(Hash::compute(b"c_car4")));
        decided_cut.cars.insert(validator_b, car_b_at_4);
        decided_cut.cars.insert(validator_c, car_c_at_5);

        // Sync positions
        state.sync_positions_from_cut(&decided_cut);

        // Check validator B: expected is now 5, queued CAR is at 5 -> should be ready
        assert_eq!(state.expected_position(&validator_b), 5);
        let ready_b = state.get_cars_ready_after_gap_filled(&validator_b);
        assert_eq!(ready_b.len(), 1);
        assert_eq!(ready_b[0].position, 5);

        // Check validator C: expected is now 6, queued CAR is at 6 -> should be ready
        assert_eq!(state.expected_position(&validator_c), 6);
        let ready_c = state.get_cars_ready_after_gap_filled(&validator_c);
        assert_eq!(ready_c.len(), 1);
        assert_eq!(ready_c[0].position, 6);
    }

    /// Test that sync_positions_from_cut only updates if position is higher
    #[test]
    fn test_sync_positions_only_advances() {
        use crate::car::Car;
        use crate::cut::Cut;

        let our_id = ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]);
        let mut state = PrimaryState::new(our_id, 1000);

        let validator = ValidatorId::from_bytes([2u8; VALIDATOR_ID_SIZE]);

        // Set initial position to 5
        state.update_last_seen(validator, 5, Hash::compute(b"car5"));
        assert_eq!(state.expected_position(&validator), 6);

        // Try to sync with a cut that has a lower position (3)
        let mut old_cut = Cut::new(1);
        let car_at_3 = Car::new(validator, 3, vec![], None);
        old_cut.cars.insert(validator, car_at_3);

        state.sync_positions_from_cut(&old_cut);

        // Position should NOT have changed (5 > 3)
        assert_eq!(
            state.expected_position(&validator),
            6,
            "Position should not go backwards"
        );

        // Now sync with a higher position (7)
        let mut new_cut = Cut::new(2);
        let car_at_7 = Car::new(validator, 7, vec![], Some(Hash::compute(b"car6")));
        new_cut.cars.insert(validator, car_at_7);

        state.sync_positions_from_cut(&new_cut);

        // Position should now be 7, so expected is 8
        assert_eq!(
            state.expected_position(&validator),
            8,
            "Position should advance to 8"
        );
    }

    /// Test get_validators_with_queued_cars returns all unique validators with queued CARs.
    ///
    /// This is critical for the consensus decision handling: we need to check ALL
    /// validators with queued CARs, not just those in the decided cut.
    #[test]
    fn test_get_validators_with_queued_cars() {
        use crate::car::Car;

        let our_id = ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]);
        let mut state = PrimaryState::new(our_id, 1000);

        // Initially no validators with queued CARs
        assert!(
            state.get_validators_with_queued_cars().is_empty(),
            "Should have no validators with queued CARs initially"
        );

        let validator_a = ValidatorId::from_bytes([2u8; VALIDATOR_ID_SIZE]);
        let validator_b = ValidatorId::from_bytes([3u8; VALIDATOR_ID_SIZE]);
        let validator_c = ValidatorId::from_bytes([4u8; VALIDATOR_ID_SIZE]);

        // Queue CARs from different validators at different positions
        let car_a_pos5 = Car::new(validator_a, 5, vec![], None);
        let car_a_pos6 = Car::new(validator_a, 6, vec![], Some(Hash::compute(b"a_car5")));
        let car_b_pos3 = Car::new(validator_b, 3, vec![], None);
        let car_c_pos10 = Car::new(validator_c, 10, vec![], None);

        state.queue_car_awaiting_gap(car_a_pos5, 3); // validator_a at position 5
        state.queue_car_awaiting_gap(car_a_pos6, 3); // validator_a at position 6
        state.queue_car_awaiting_gap(car_b_pos3, 1); // validator_b at position 3
        state.queue_car_awaiting_gap(car_c_pos10, 5); // validator_c at position 10

        // Should return exactly 3 unique validators
        let validators = state.get_validators_with_queued_cars();
        assert_eq!(
            validators.len(),
            3,
            "Should have 3 validators with queued CARs"
        );

        // All validators should be present
        assert!(
            validators.contains(&validator_a),
            "Should contain validator_a"
        );
        assert!(
            validators.contains(&validator_b),
            "Should contain validator_b"
        );
        assert!(
            validators.contains(&validator_c),
            "Should contain validator_c"
        );
    }

    /// Test that processing queued CARs works for validators NOT in the decided cut.
    ///
    /// This simulates the scenario where:
    /// 1. A cut is decided with validators A and B
    /// 2. Validator C has queued CARs
    /// 3. We should still check validator C (even though their position won't advance)
    #[test]
    fn test_queued_cars_from_validators_not_in_cut() {
        use crate::car::Car;
        use crate::cut::Cut;

        let our_id = ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]);
        let mut state = PrimaryState::new(our_id, 1000);

        let validator_a = ValidatorId::from_bytes([2u8; VALIDATOR_ID_SIZE]);
        let validator_b = ValidatorId::from_bytes([3u8; VALIDATOR_ID_SIZE]);
        let validator_c = ValidatorId::from_bytes([4u8; VALIDATOR_ID_SIZE]); // NOT in cut

        // Set initial positions
        state.update_last_seen(validator_a, 4, Hash::compute(b"a_car4"));
        state.update_last_seen(validator_b, 4, Hash::compute(b"b_car4"));
        state.update_last_seen(validator_c, 4, Hash::compute(b"c_car4"));

        // Queue a CAR from validator_c at position 5 (expected position)
        let car_c_at_5 = Car::new(validator_c, 5, vec![], Some(Hash::compute(b"c_car4")));
        state.queue_car_awaiting_gap(car_c_at_5.clone(), 5);

        // Create a decided cut with only validators A and B (NOT C)
        let mut decided_cut = Cut::new(2);
        let car_a_at_6 = Car::new(validator_a, 6, vec![], Some(Hash::compute(b"a_car5")));
        let car_b_at_5 = Car::new(validator_b, 5, vec![], Some(Hash::compute(b"b_car4")));
        decided_cut.cars.insert(validator_a, car_a_at_6);
        decided_cut.cars.insert(validator_b, car_b_at_5);

        // Sync positions (only affects validators A and B)
        state.sync_positions_from_cut(&decided_cut);

        // Verify positions updated for A and B
        assert_eq!(state.expected_position(&validator_a), 7);
        assert_eq!(state.expected_position(&validator_b), 6);
        // Validator C's position unchanged
        assert_eq!(state.expected_position(&validator_c), 5);

        // get_validators_with_queued_cars should include validator_c
        let validators_with_queued = state.get_validators_with_queued_cars();
        assert!(
            validators_with_queued.contains(&validator_c),
            "Validator C should be in the list of validators with queued CARs"
        );

        // The queued CAR for validator_c at position 5 should now be ready
        // (because expected_position is 5)
        let ready_c = state.get_cars_ready_after_gap_filled(&validator_c);
        assert_eq!(
            ready_c.len(),
            1,
            "Validator C's CAR at position 5 should be ready"
        );
        assert_eq!(ready_c[0].position, 5);
    }

    /// Test that a chain of queued CARs can be processed iteratively.
    ///
    /// This simulates the scenario where:
    /// 1. Multiple CARs are queued at consecutive positions (10, 11, 12)
    /// 2. After sync, position 10 becomes expected
    /// 3. Processing CAR at 10 should make 11 expected, then 12, etc.
    ///
    /// The runner.rs loop should handle this by repeatedly calling
    /// get_cars_ready_after_gap_filled until no more CARs are ready.
    #[test]
    fn test_queued_car_chain_processing() {
        use crate::car::Car;
        use crate::cut::Cut;

        let our_id = ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]);
        let mut state = PrimaryState::new(our_id, 1000);

        let validator = ValidatorId::from_bytes([2u8; VALIDATOR_ID_SIZE]);

        // Set initial position to 8
        state.update_last_seen(validator, 8, Hash::compute(b"car8"));

        // Queue CARs at positions 10, 11, 12 (chain with gap)
        let car_at_10 = Car::new(validator, 10, vec![], Some(Hash::compute(b"car9")));
        let car_at_11 = Car::new(validator, 11, vec![], Some(Hash::compute(b"car10")));
        let car_at_12 = Car::new(validator, 12, vec![], Some(Hash::compute(b"car11")));

        state.queue_car_awaiting_gap(car_at_10.clone(), 9);
        state.queue_car_awaiting_gap(car_at_11.clone(), 9);
        state.queue_car_awaiting_gap(car_at_12.clone(), 9);

        // Verify all 3 CARs are queued
        assert!(state.is_awaiting_gap_sync(&validator, 10));
        assert!(state.is_awaiting_gap_sync(&validator, 11));
        assert!(state.is_awaiting_gap_sync(&validator, 12));

        // Sync with a cut that has position 9 (filling the immediate gap)
        let mut decided_cut = Cut::new(2);
        let car_at_9 = Car::new(validator, 9, vec![], Some(Hash::compute(b"car8")));
        decided_cut.cars.insert(validator, car_at_9);
        state.sync_positions_from_cut(&decided_cut);

        // Expected position should now be 10
        assert_eq!(state.expected_position(&validator), 10);

        // First iteration: CAR at 10 should be ready
        let ready_1 = state.get_cars_ready_after_gap_filled(&validator);
        assert_eq!(ready_1.len(), 1);
        assert_eq!(ready_1[0].position, 10);

        // Simulate processing: update last_seen to 10
        state.update_last_seen(validator, 10, car_at_10.hash());
        assert_eq!(state.expected_position(&validator), 11);

        // Second iteration: CAR at 11 should now be ready
        let ready_2 = state.get_cars_ready_after_gap_filled(&validator);
        assert_eq!(ready_2.len(), 1);
        assert_eq!(ready_2[0].position, 11);

        // Simulate processing: update last_seen to 11
        state.update_last_seen(validator, 11, car_at_11.hash());
        assert_eq!(state.expected_position(&validator), 12);

        // Third iteration: CAR at 12 should now be ready
        let ready_3 = state.get_cars_ready_after_gap_filled(&validator);
        assert_eq!(ready_3.len(), 1);
        assert_eq!(ready_3[0].position, 12);

        // Simulate processing: update last_seen to 12
        state.update_last_seen(validator, 12, car_at_12.hash());
        assert_eq!(state.expected_position(&validator), 13);

        // Fourth iteration: no more CARs should be ready
        let ready_4 = state.get_cars_ready_after_gap_filled(&validator);
        assert!(ready_4.is_empty(), "No more CARs should be ready");

        // All queued CARs should have been removed
        assert!(!state.is_awaiting_gap_sync(&validator, 10));
        assert!(!state.is_awaiting_gap_sync(&validator, 11));
        assert!(!state.is_awaiting_gap_sync(&validator, 12));
    }

    // =========================================================
    // State Restoration from Cut Tests (Restart Recovery)
    // =========================================================

    /// Test that from_cut correctly restores state for restart recovery.
    ///
    /// This is the fix for the PositionGap errors on validator restart:
    /// Without state restoration, a restarted validator creates CARs at position 0,
    /// but other validators expect continuity from the last finalized position.
    #[test]
    fn test_from_cut_restores_position_state() {
        use crate::car::Car;
        use crate::cut::Cut;

        let our_id = ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]);
        let validator_b = ValidatorId::from_bytes([2u8; VALIDATOR_ID_SIZE]);
        let validator_c = ValidatorId::from_bytes([3u8; VALIDATOR_ID_SIZE]);

        // Create a finalized cut at height 100 with:
        // - Our validator at position 50
        // - Validator B at position 42
        // - Validator C at position 37
        let mut cut = Cut::new(100);

        let car_ours = Car::new(our_id, 50, vec![], Some(Hash::compute(b"our_car49")));
        let car_b = Car::new(validator_b, 42, vec![], Some(Hash::compute(b"b_car41")));
        let car_c = Car::new(validator_c, 37, vec![], Some(Hash::compute(b"c_car36")));

        cut.cars.insert(our_id, car_ours.clone());
        cut.cars.insert(validator_b, car_b.clone());
        cut.cars.insert(validator_c, car_c.clone());

        // Create state from the cut
        let state = PrimaryState::from_cut(our_id, 1000, &cut);

        // Verify height state is restored
        assert_eq!(state.last_finalized_height, 100);
        assert_eq!(state.current_height, 101); // next height to produce

        // Verify invariant: current_height = last_finalized_height + 1
        assert_eq!(
            state.current_height,
            state.last_finalized_height + 1,
            "Invariant: current_height = last_finalized_height + 1"
        );

        // Verify our own position is restored correctly
        // our_position should be 51 (next position to create after 50)
        assert_eq!(state.our_position, 51);
        assert_eq!(state.last_car_hash, Some(car_ours.hash()));

        // Verify expected positions for other validators
        assert_eq!(state.expected_position(&validator_b), 43); // 42 + 1
        assert_eq!(state.expected_position(&validator_c), 38); // 37 + 1

        // Verify last_seen_car_hashes are set
        assert_eq!(state.last_seen_car_hash(&our_id), Some(&car_ours.hash()));
        assert_eq!(state.last_seen_car_hash(&validator_b), Some(&car_b.hash()));
        assert_eq!(state.last_seen_car_hash(&validator_c), Some(&car_c.hash()));

        // Verify we're in collecting stage (ready to start producing)
        assert_eq!(state.pipeline_stage, PipelineStage::Collecting);
    }

    /// Test from_cut with an empty cut (first start, not restart)
    #[test]
    fn test_from_cut_empty_cut() {
        use crate::cut::Cut;

        let our_id = ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]);

        // Empty cut at height 0 (genesis scenario)
        let cut = Cut::new(0);

        let state = PrimaryState::from_cut(our_id, 1000, &cut);

        // Height should be set from cut
        assert_eq!(state.last_finalized_height, 0);
        assert_eq!(state.current_height, 1);

        // Our position should start at 0 (not in the cut)
        assert_eq!(state.our_position, 0);
        assert_eq!(state.last_car_hash, None);

        // No position tracking for validators not in cut
        let other_validator = ValidatorId::from_bytes([2u8; VALIDATOR_ID_SIZE]);
        assert_eq!(state.expected_position(&other_validator), 0);
    }

    /// Test that from_cut handles case where our validator is not in the cut
    /// (e.g., we were offline and didn't contribute to this cut)
    #[test]
    fn test_from_cut_our_validator_not_in_cut() {
        use crate::car::Car;
        use crate::cut::Cut;

        let our_id = ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]);
        let validator_b = ValidatorId::from_bytes([2u8; VALIDATOR_ID_SIZE]);

        // Create a cut without our validator
        let mut cut = Cut::new(50);
        let car_b = Car::new(validator_b, 25, vec![], None);
        cut.cars.insert(validator_b, car_b.clone());

        let state = PrimaryState::from_cut(our_id, 1000, &cut);

        // Height is still restored
        assert_eq!(state.last_finalized_height, 50);
        assert_eq!(state.current_height, 51);

        // But our position starts at 0 since we weren't in the cut
        // This is correct - we need to start fresh since we have no record
        assert_eq!(state.our_position, 0);
        assert_eq!(state.last_car_hash, None);

        // Other validator's position is tracked
        assert_eq!(state.expected_position(&validator_b), 26);
    }

    // =========================================================
    // Position Drift Correction Tests
    // =========================================================

    /// Test that sync_positions_from_cut corrects position drift during sync.
    ///
    /// This is the fix for Car attestation failures after validator restart:
    /// - While syncing, validator creates Cars at 100ms intervals
    /// - All Cars fail attestation (peers haven't caught up yet)
    /// - But our_position increments on creation, not finalization
    /// - By sync completion, our_position has drifted far ahead
    /// - sync_positions_from_cut must reset our_position from finalized cuts
    #[test]
    fn test_sync_positions_corrects_our_position_drift() {
        use crate::car::Car;
        use crate::cut::Cut;

        let our_id = ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]);
        let mut state = PrimaryState::new(our_id, 1000);

        // Simulate position drift during sync:
        // - We created Cars at positions 0, 1, 2, ... 100 that all failed attestation
        // - Our position is now 101 (next to create)
        state.our_position = 101;
        state.last_car_hash = Some(Hash::compute(b"our_car100"));

        // But consensus only decided on our Car at position 50
        // (the last one that actually got attested before we fell behind)
        let mut decided_cut = Cut::new(10);
        let car_at_50 = Car::new(our_id, 50, vec![], Some(Hash::compute(b"our_car49")));
        decided_cut.cars.insert(our_id, car_at_50.clone());

        // Before sync, our_position is drifted ahead
        assert_eq!(state.our_position, 101);

        // Sync from finalized cut
        state.sync_positions_from_cut(&decided_cut);

        // After sync, our_position should be reset to 51 (finalized 50 + 1)
        assert_eq!(
            state.our_position, 51,
            "our_position should be reset from finalized cut to correct drift"
        );
        assert_eq!(
            state.last_car_hash,
            Some(car_at_50.hash()),
            "last_car_hash should be updated to finalized Car"
        );
    }

    /// Test that sync_positions_from_cut does NOT reset position if we're ahead legitimately.
    ///
    /// This ensures the fix doesn't break normal operation where our_position
    /// is ahead because we've successfully created and had Cars attested.
    #[test]
    fn test_sync_positions_does_not_reset_if_finalized_is_behind() {
        use crate::car::Car;
        use crate::cut::Cut;

        let our_id = ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]);
        let mut state = PrimaryState::new(our_id, 1000);

        // Normal operation: we're at position 10 and properly synced
        state.our_position = 10;
        state.last_car_hash = Some(Hash::compute(b"our_car9"));

        // Receive a cut containing our Car at position 9 (the previous one)
        // This is normal - we created position 10 but it's not in this cut yet
        let mut decided_cut = Cut::new(5);
        let car_at_9 = Car::new(our_id, 9, vec![], Some(Hash::compute(b"our_car8")));
        decided_cut.cars.insert(our_id, car_at_9.clone());

        // Sync from cut
        state.sync_positions_from_cut(&decided_cut);

        // our_position should remain 10 - we don't want to go backwards
        // in normal operation when we're just one step ahead
        assert_eq!(
            state.our_position, 10,
            "our_position should not be reset when legitimately ahead"
        );
    }

    /// Test position drift correction with position 0 edge case.
    #[test]
    fn test_sync_positions_handles_zero_position() {
        use crate::car::Car;
        use crate::cut::Cut;

        let our_id = ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]);
        let mut state = PrimaryState::new(our_id, 1000);

        // Start fresh at position 0
        assert_eq!(state.our_position, 0);

        // Receive cut with our Car at position 0
        let mut decided_cut = Cut::new(1);
        let car_at_0 = Car::new(our_id, 0, vec![], None);
        decided_cut.cars.insert(our_id, car_at_0.clone());

        // Sync from cut
        state.sync_positions_from_cut(&decided_cut);

        // Position 0 finalized means next is 1, but we're also at 0
        // The condition `finalized_next <= our_position && our_position > 0` is false
        // so we don't reset (correct behavior - we're not drifted)
        assert_eq!(state.our_position, 0);
    }

    /// Test sync_positions_from_cut when our validator is NOT in the cut.
    #[test]
    fn test_sync_positions_our_validator_not_in_cut() {
        use crate::car::Car;
        use crate::cut::Cut;

        let our_id = ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]);
        let validator_b = ValidatorId::from_bytes([2u8; VALIDATOR_ID_SIZE]);
        let mut state = PrimaryState::new(our_id, 1000);

        // We have drifted position
        state.our_position = 50;

        // Cut doesn't contain our validator
        let mut decided_cut = Cut::new(10);
        let car_b = Car::new(validator_b, 20, vec![], None);
        decided_cut.cars.insert(validator_b, car_b);

        // Sync from cut
        state.sync_positions_from_cut(&decided_cut);

        // our_position unchanged since we're not in the cut
        assert_eq!(
            state.our_position, 50,
            "our_position should not change if we're not in the cut"
        );

        // But other validator's position is updated
        assert_eq!(state.expected_position(&validator_b), 21);
    }

    // =========================================================
    // Attested Cars Clearing After Cut Decision Tests
    // =========================================================

    /// Test that attested Cars are cleared after being included in a decided Cut.
    ///
    /// This prevents the same Car from being included in multiple Cuts, which
    /// would cause duplicate transaction execution attempts.
    #[test]
    fn test_attested_cars_cleared_after_cut_decision() {
        use crate::car::Car;
        use crate::cut::Cut;

        let our_id = ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]);
        let mut state = PrimaryState::new(our_id, 1000);

        let validator = ValidatorId::from_bytes([2u8; VALIDATOR_ID_SIZE]);

        // Create and attest a Car at position 5
        let car_at_5 = Car::new(validator, 5, vec![], None);
        let agg = create_aggregated_attestation(&car_at_5, &[0, 1], 4);
        state.mark_attested(car_at_5.clone(), agg);

        // Verify the Car is in attested_cars
        assert!(
            state.attested_cars.contains_key(&validator),
            "Car should be in attested_cars before cut decision"
        );
        assert_eq!(state.attested_cars.get(&validator).unwrap().0.position, 5);

        // Consensus decides with this Car
        let mut decided_cut = Cut::new(1);
        decided_cut.cars.insert(validator, car_at_5.clone());

        // Sync from the decided cut
        state.sync_positions_from_cut(&decided_cut);

        // Attested Car should be CLEARED because it was included in the cut
        assert!(
            !state.attested_cars.contains_key(&validator),
            "Attested Car should be cleared after being included in a decided Cut"
        );

        // Position tracking should be updated
        assert_eq!(state.expected_position(&validator), 6);
        assert_eq!(
            state.last_included_positions.get(&validator),
            Some(&5),
            "last_included_positions should track the included position"
        );
    }

    /// Test that newer attested Cars are NOT cleared after cut decision.
    ///
    /// If a newer Car arrives while consensus is deciding, it should be preserved
    /// for inclusion in the next Cut.
    #[test]
    fn test_newer_attested_car_preserved_after_cut_decision() {
        use crate::car::Car;
        use crate::cut::Cut;

        let our_id = ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]);
        let mut state = PrimaryState::new(our_id, 1000);

        let validator = ValidatorId::from_bytes([2u8; VALIDATOR_ID_SIZE]);

        // Create and attest a Car at position 6 (newer than what will be in the cut)
        let car_at_6 = Car::new(validator, 6, vec![], Some(Hash::compute(b"car5")));
        let agg = create_aggregated_attestation(&car_at_6, &[0, 1], 4);
        state.mark_attested(car_at_6.clone(), agg);

        // Verify the Car is in attested_cars
        assert_eq!(state.attested_cars.get(&validator).unwrap().0.position, 6);

        // Consensus decides with an OLDER Car at position 5
        // (this simulates a newer Car arriving while consensus was deciding)
        let mut decided_cut = Cut::new(1);
        let car_at_5 = Car::new(validator, 5, vec![], None);
        decided_cut.cars.insert(validator, car_at_5);

        // Sync from the decided cut
        state.sync_positions_from_cut(&decided_cut);

        // Attested Car at position 6 should be PRESERVED (not cleared)
        // because it's newer than what was included
        assert!(
            state.attested_cars.contains_key(&validator),
            "Newer attested Car should be preserved"
        );
        assert_eq!(
            state.attested_cars.get(&validator).unwrap().0.position,
            6,
            "The preserved Car should still be at position 6"
        );
    }
}
