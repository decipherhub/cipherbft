//! DCL message types for Primary-Worker and inter-node communication
//!
//! # Security
//!
//! All message types implement bounded deserialization to prevent OOM attacks.
//! The [`decode`] and [`decode_bounded`] methods enforce size limits defined
//! in the [`crate::error`] module.

use crate::attestation::{AggregatedAttestation, Attestation};
use crate::batch::Batch;
use crate::car::Car;
use crate::error::{MAX_MESSAGE_SIZE, MAX_RESPONSE_DATA_SIZE, MAX_SYNC_DIGESTS};
use bincode::Options;
use cipherbft_types::{Hash, ValidatorId};
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

/// Messages from Worker to Primary (internal channel)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WorkerToPrimary {
    /// Worker sealed a new batch and reports its digest
    BatchDigest {
        /// Worker ID (0-7)
        worker_id: u8,
        /// SHA-256 hash of the batch
        digest: Hash,
        /// Number of transactions
        tx_count: u32,
        /// Total byte size
        byte_size: u32,
    },

    /// Worker has synced a batch (response to Synchronize command)
    BatchSynced {
        /// Batch digest that was synced
        digest: Hash,
        /// Whether sync was successful
        success: bool,
    },

    /// Worker is ready (initialization complete)
    Ready {
        /// Worker ID
        worker_id: u8,
    },
}

// ============================================================================
// Bounded Deserialization Helpers
// ============================================================================

/// Create bincode options with size limits for safe deserialization.
///
/// This prevents OOM attacks by limiting the maximum size of deserialized messages.
fn bincode_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_limit(MAX_MESSAGE_SIZE)
        .with_fixint_encoding()
        .allow_trailing_bytes()
}

/// Deserialize a Vec<Hash> with bounds checking.
fn deserialize_bounded_hashes<'de, D>(deserializer: D) -> Result<Vec<Hash>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedHashVecVisitor;

    impl<'de> Visitor<'de> for BoundedHashVecVisitor {
        type Value = Vec<Hash>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(
                formatter,
                "a sequence of at most {} hashes",
                MAX_SYNC_DIGESTS
            )
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            // Check size hint to reject early
            if let Some(size) = seq.size_hint() {
                if size > MAX_SYNC_DIGESTS {
                    return Err(serde::de::Error::custom(format!(
                        "hash vec size {} exceeds maximum of {}",
                        size, MAX_SYNC_DIGESTS
                    )));
                }
            }

            let capacity = seq.size_hint().unwrap_or(0).min(MAX_SYNC_DIGESTS);
            let mut hashes = Vec::with_capacity(capacity);

            while let Some(hash) = seq.next_element()? {
                if hashes.len() >= MAX_SYNC_DIGESTS {
                    return Err(serde::de::Error::custom(format!(
                        "hash vec size exceeds maximum of {}",
                        MAX_SYNC_DIGESTS
                    )));
                }
                hashes.push(hash);
            }

            Ok(hashes)
        }
    }

    deserializer.deserialize_seq(BoundedHashVecVisitor)
}

/// Deserialize an Option<Vec<u8>> with bounds checking for response data.
fn deserialize_bounded_bytes<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<Vec<u8>> = Option::deserialize(deserializer)?;

    if let Some(ref bytes) = opt {
        if bytes.len() > MAX_RESPONSE_DATA_SIZE {
            return Err(serde::de::Error::custom(format!(
                "response data size {} exceeds maximum of {}",
                bytes.len(),
                MAX_RESPONSE_DATA_SIZE
            )));
        }
    }

    Ok(opt)
}

// ============================================================================
// Message Types
// ============================================================================

/// Messages from Primary to Worker (internal channel)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PrimaryToWorker {
    /// Request Worker to sync missing batches for attestation
    Synchronize {
        /// Batch digests to sync (bounded by MAX_SYNC_DIGESTS)
        #[serde(deserialize_with = "deserialize_bounded_hashes")]
        digests: Vec<Hash>,
        /// Validator whose Worker should be contacted
        target_validator: ValidatorId,
    },

    /// Garbage collection trigger after finalization
    Cleanup {
        /// Height that was finalized
        finalized_height: u64,
    },

    /// Shutdown request
    Shutdown,
}

/// Messages between Primary nodes (over network)
///
/// # Security
///
/// All message variants with variable-size data use bounded deserialization
/// to prevent OOM attacks from malicious peers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DclMessage {
    /// Broadcast new Car
    Car(Car),

    /// Attestation for received Car
    Attestation(Attestation),

    /// Request missing Car by validator and position
    CarRequest {
        /// Validator who created the Car
        validator: ValidatorId,
        /// Position in the validator's lane
        position: u64,
    },

    /// Response to CarRequest
    CarResponse(Option<Car>),

    /// Request missing batch data
    BatchRequest {
        /// Batch digest
        digest: Hash,
    },

    /// Response to BatchRequest
    BatchResponse {
        /// Batch digest
        digest: Hash,
        /// Batch data (None if not found, bounded by MAX_RESPONSE_DATA_SIZE)
        #[serde(deserialize_with = "deserialize_bounded_bytes")]
        data: Option<Vec<u8>>,
    },

    /// Broadcast when Car reaches attestation threshold
    ///
    /// Contains the Car and its aggregated attestation (with 2f+1 signatures).
    /// Allows all validators to include this Car in their Cut, even if they
    /// weren't the Car proposer and didn't collect attestations for it.
    CarWithAttestation {
        /// The Car that reached attestation threshold
        car: Car,
        /// Aggregated attestation with 2f+1 signatures
        attestation: AggregatedAttestation,
    },
}

impl DclMessage {
    /// Message type discriminant for encoding
    pub fn type_id(&self) -> u8 {
        match self {
            DclMessage::Car(_) => 0x01,
            DclMessage::Attestation(_) => 0x02,
            DclMessage::CarRequest { .. } => 0x03,
            DclMessage::CarResponse(_) => 0x04,
            DclMessage::BatchRequest { .. } => 0x05,
            DclMessage::BatchResponse { .. } => 0x06,
            DclMessage::CarWithAttestation { .. } => 0x07,
        }
    }

    /// Encode message to bytes
    /// Note: type_id is prepended for network routing, but full message
    /// (including enum discriminant) is serialized for decode symmetry.
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("serialization cannot fail")
    }

    /// Decode message from bytes with size limits.
    ///
    /// # Security
    ///
    /// This method enforces a maximum message size of [`MAX_MESSAGE_SIZE`] bytes
    /// to prevent OOM attacks from malicious peers.
    pub fn decode(data: &[u8]) -> Result<Self, String> {
        if data.is_empty() {
            return Err("empty message".to_string());
        }
        if data.len() as u64 > MAX_MESSAGE_SIZE {
            return Err(format!(
                "message size {} exceeds maximum of {}",
                data.len(),
                MAX_MESSAGE_SIZE
            ));
        }
        bincode_options()
            .deserialize(data)
            .map_err(|e| e.to_string())
    }

    /// Get message type name for logging
    pub fn type_name(&self) -> &'static str {
        match self {
            DclMessage::Car(_) => "Car",
            DclMessage::Attestation(_) => "Attestation",
            DclMessage::CarRequest { .. } => "CarRequest",
            DclMessage::CarResponse(_) => "CarResponse",
            DclMessage::BatchRequest { .. } => "BatchRequest",
            DclMessage::BatchResponse { .. } => "BatchResponse",
            DclMessage::CarWithAttestation { .. } => "CarWithAttestation",
        }
    }
}

/// Messages between Worker nodes (over network, same worker_id peers)
///
/// # Security
///
/// All message variants with variable-size data use bounded deserialization
/// to prevent OOM attacks from malicious peers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WorkerMessage {
    /// Full batch data broadcast
    Batch(Batch),

    /// Request missing batches
    BatchRequest {
        /// Batch digests to request (bounded by MAX_SYNC_DIGESTS)
        #[serde(deserialize_with = "deserialize_bounded_hashes")]
        digests: Vec<Hash>,
        /// Requesting validator
        requestor: ValidatorId,
    },

    /// Response with batch data
    BatchResponse {
        /// Batch digest
        digest: Hash,
        /// Batch data (None if not found)
        data: Option<Batch>,
    },
}

impl WorkerMessage {
    /// Message type discriminant for encoding
    pub fn type_id(&self) -> u8 {
        match self {
            WorkerMessage::Batch(_) => 0x10,
            WorkerMessage::BatchRequest { .. } => 0x11,
            WorkerMessage::BatchResponse { .. } => 0x12,
        }
    }

    /// Encode message to bytes
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("serialization cannot fail")
    }

    /// Decode message from bytes with size limits.
    ///
    /// # Security
    ///
    /// This method enforces a maximum message size of [`MAX_MESSAGE_SIZE`] bytes
    /// to prevent OOM attacks from malicious peers.
    pub fn decode(data: &[u8]) -> Result<Self, String> {
        if data.is_empty() {
            return Err("empty message".to_string());
        }
        if data.len() as u64 > MAX_MESSAGE_SIZE {
            return Err(format!(
                "message size {} exceeds maximum of {}",
                data.len(),
                MAX_MESSAGE_SIZE
            ));
        }
        bincode_options()
            .deserialize(data)
            .map_err(|e| e.to_string())
    }

    /// Get message type name for logging
    pub fn type_name(&self) -> &'static str {
        match self {
            WorkerMessage::Batch(_) => "Batch",
            WorkerMessage::BatchRequest { .. } => "BatchRequest",
            WorkerMessage::BatchResponse { .. } => "BatchResponse",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbft_types::VALIDATOR_ID_SIZE;

    /// Helper to derive ValidatorId from BLS public key (for tests only)
    fn validator_id_from_bls_pubkey(pubkey: &cipherbft_crypto::BlsPublicKey) -> ValidatorId {
        let hash = pubkey.hash();
        let mut bytes = [0u8; VALIDATOR_ID_SIZE];
        bytes.copy_from_slice(&hash[12..32]); // last 20 bytes
        ValidatorId::from_bytes(bytes)
    }

    #[test]
    fn test_worker_to_primary_serialization() {
        let msg = WorkerToPrimary::BatchDigest {
            worker_id: 0,
            digest: Hash::compute(b"batch"),
            tx_count: 100,
            byte_size: 1024,
        };

        let bytes = bincode::serialize(&msg).unwrap();
        let decoded: WorkerToPrimary = bincode::deserialize(&bytes).unwrap();

        match decoded {
            WorkerToPrimary::BatchDigest {
                worker_id,
                tx_count,
                byte_size,
                ..
            } => {
                assert_eq!(worker_id, 0);
                assert_eq!(tx_count, 100);
                assert_eq!(byte_size, 1024);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_dcl_message_encode_decode() {
        use cipherbft_crypto::BlsKeyPair;

        // Create a properly signed Car for serialization test
        let keypair = BlsKeyPair::generate(&mut rand::thread_rng());
        let validator_id = validator_id_from_bls_pubkey(&keypair.public_key);
        let mut car = Car::new(validator_id, 0, vec![], None);

        // Sign the Car to get a valid signature
        let signing_bytes = car.signing_bytes();
        car.signature = keypair.sign_car(&signing_bytes);

        let msg = DclMessage::Car(car.clone());
        let encoded = msg.encode();
        let decoded = DclMessage::decode(&encoded).unwrap();

        match decoded {
            DclMessage::Car(decoded_car) => {
                assert_eq!(decoded_car.proposer, car.proposer);
                assert_eq!(decoded_car.position, car.position);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_dcl_message_type_names() {
        let msg = DclMessage::CarRequest {
            validator: ValidatorId::ZERO,
            position: 0,
        };
        assert_eq!(msg.type_name(), "CarRequest");
    }

    #[test]
    fn test_worker_message_serialization() {
        let batch = Batch::new(0, vec![vec![1, 2, 3]], 12345);
        let msg = WorkerMessage::Batch(batch.clone());

        let encoded = msg.encode();
        let decoded = WorkerMessage::decode(&encoded).unwrap();

        match decoded {
            WorkerMessage::Batch(decoded_batch) => {
                assert_eq!(decoded_batch.worker_id, batch.worker_id);
                assert_eq!(decoded_batch.transactions.len(), 1);
            }
            _ => panic!("wrong variant"),
        }
    }
}
