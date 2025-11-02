//! Ed25519 signature operations.

use ed25519_consensus::{SigningKey, VerificationKey};

/// Ed25519 public key.
pub type PublicKey = VerificationKey;

/// Ed25519 private key.
pub type PrivateKey = SigningKey;

/// Ed25519 signature.
pub type Signature = ed25519_consensus::Signature;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        let private_key = PrivateKey::new(rand::thread_rng());
        let public_key = VerificationKey::from(&private_key);

        let message = b"test message";
        let signature = private_key.sign(message);

        assert!(public_key.verify(&signature, message).is_ok());
    }
}
