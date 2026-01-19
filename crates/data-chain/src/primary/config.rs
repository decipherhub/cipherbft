//! Primary process configuration

use cipherbft_crypto::BlsSecretKey;
use cipherbft_types::ValidatorId;
use std::time::Duration;

/// Primary process configuration
#[derive(Clone)]
pub struct PrimaryConfig {
    /// Our validator identity
    pub validator_id: ValidatorId,
    /// BLS signing key for Cars
    pub bls_secret_key: BlsSecretKey,
    /// Car creation interval (default: 100ms)
    pub car_interval: Duration,
    /// Attestation timeout base (default: 500ms)
    pub attestation_timeout_base: Duration,
    /// Attestation timeout max (default: 5000ms)
    pub attestation_timeout_max: Duration,
    /// Maximum consecutive empty Cars (default: 3)
    pub max_empty_cars: u32,
    /// Number of workers per validator (default: 1)
    pub worker_count: u8,
    /// Number of heights to retain equivocation data (default: 1000).
    ///
    /// Higher values preserve forensic evidence longer for slashing proofs,
    /// at the cost of increased memory usage.
    pub equivocation_retention: u64,
    /// Startup delay before beginning CAR creation (default: 2s).
    ///
    /// This delay allows the network to establish peer connections before
    /// the Primary starts creating and broadcasting CARs. Without this delay,
    /// position 0 CARs may be broadcast when no peers are connected and lost,
    /// causing PositionGap errors when later CARs arrive.
    pub startup_delay: Duration,
}

impl PrimaryConfig {
    /// Create a new configuration with defaults
    pub fn new(validator_id: ValidatorId, bls_secret_key: BlsSecretKey) -> Self {
        Self {
            validator_id,
            bls_secret_key,
            car_interval: Duration::from_millis(100),
            attestation_timeout_base: Duration::from_millis(500),
            attestation_timeout_max: Duration::from_millis(5000),
            max_empty_cars: 3,
            worker_count: 1,
            equivocation_retention: 1000,
            startup_delay: Duration::from_secs(2),
        }
    }

    /// Set Car creation interval
    pub fn with_car_interval(mut self, interval: Duration) -> Self {
        self.car_interval = interval;
        self
    }

    /// Set attestation timeout parameters
    pub fn with_attestation_timeout(mut self, base: Duration, max: Duration) -> Self {
        self.attestation_timeout_base = base;
        self.attestation_timeout_max = max;
        self
    }

    /// Set maximum consecutive empty Cars
    pub fn with_max_empty_cars(mut self, max: u32) -> Self {
        self.max_empty_cars = max;
        self
    }

    /// Set worker count
    pub fn with_worker_count(mut self, count: u8) -> Self {
        self.worker_count = count;
        self
    }

    /// Set equivocation retention (number of heights to keep equivocation data)
    pub fn with_equivocation_retention(mut self, retention: u64) -> Self {
        self.equivocation_retention = retention;
        self
    }

    /// Set startup delay before CAR creation begins
    pub fn with_startup_delay(mut self, delay: Duration) -> Self {
        self.startup_delay = delay;
        self
    }
}

impl std::fmt::Debug for PrimaryConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrimaryConfig")
            .field("validator_id", &self.validator_id)
            .field("car_interval", &self.car_interval)
            .field("attestation_timeout_base", &self.attestation_timeout_base)
            .field("attestation_timeout_max", &self.attestation_timeout_max)
            .field("max_empty_cars", &self.max_empty_cars)
            .field("worker_count", &self.worker_count)
            .field("equivocation_retention", &self.equivocation_retention)
            .field("startup_delay", &self.startup_delay)
            .finish()
    }
}
