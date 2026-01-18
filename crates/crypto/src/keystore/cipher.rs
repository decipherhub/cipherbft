//! AES-128-CTR cipher implementation for keystore encryption
//!
//! Implements symmetric encryption following EIP-2335 specification.
//! Uses AES-128-CTR mode which provides confidentiality without padding.

use aes::Aes128;
use cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use serde::{Deserialize, Serialize};

use super::error::{KeystoreError, KeystoreResult};
use crate::secure::SecretBytes;

/// IV (initialization vector) length for AES-128-CTR
pub const IV_LENGTH: usize = 16;

/// AES-128 key length
pub const AES_KEY_LENGTH: usize = 16;

/// Type alias for AES-128-CTR cipher
type Aes128Ctr = Ctr128BE<Aes128>;

/// Cipher module for EIP-2335 keystore
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CipherModule {
    /// Cipher function identifier (e.g., "aes-128-ctr")
    pub function: String,
    /// Cipher parameters
    pub params: CipherParams,
    /// Encrypted message as hex string
    pub message: String,
}

impl CipherModule {
    /// Create a new AES-128-CTR cipher module
    pub fn new(iv: Vec<u8>, ciphertext: Vec<u8>) -> Self {
        Self {
            function: "aes-128-ctr".to_string(),
            params: CipherParams {
                iv: hex::encode(&iv),
            },
            message: hex::encode(&ciphertext),
        }
    }

    /// Get the IV bytes
    pub fn iv(&self) -> KeystoreResult<Vec<u8>> {
        hex::decode(&self.params.iv)
            .map_err(|e| KeystoreError::HexError(format!("invalid IV hex: {}", e)))
    }

    /// Get the ciphertext bytes
    pub fn ciphertext(&self) -> KeystoreResult<Vec<u8>> {
        hex::decode(&self.message)
            .map_err(|e| KeystoreError::HexError(format!("invalid ciphertext hex: {}", e)))
    }

    /// Decrypt the message using the provided decryption key
    pub fn decrypt(&self, decryption_key: &[u8]) -> KeystoreResult<SecretBytes> {
        let iv = self.iv()?;
        let ciphertext = self.ciphertext()?;
        decrypt_secret(&ciphertext, decryption_key, &iv)
    }
}

/// Cipher parameters for AES-128-CTR
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CipherParams {
    /// Initialization vector as hex string
    pub iv: String,
}

impl CipherParams {
    /// Validate the parameters
    pub fn validate(&self) -> KeystoreResult<()> {
        let iv_bytes = hex::decode(&self.iv)
            .map_err(|e| KeystoreError::InvalidCipherParams(format!("invalid IV hex: {}", e)))?;

        if iv_bytes.len() != IV_LENGTH {
            return Err(KeystoreError::InvalidCipherParams(format!(
                "IV must be {} bytes, got {}",
                IV_LENGTH,
                iv_bytes.len()
            )));
        }

        Ok(())
    }
}

/// Encrypt secret data using AES-128-CTR
///
/// # Arguments
///
/// * `secret` - The secret data to encrypt
/// * `encryption_key` - The first 16 bytes of the derived key
/// * `iv` - 16-byte initialization vector
///
/// # Returns
///
/// Ciphertext bytes
pub fn encrypt_secret(secret: &[u8], encryption_key: &[u8], iv: &[u8]) -> KeystoreResult<Vec<u8>> {
    if encryption_key.len() < AES_KEY_LENGTH {
        return Err(KeystoreError::InvalidCipherParams(format!(
            "encryption key must be at least {} bytes, got {}",
            AES_KEY_LENGTH,
            encryption_key.len()
        )));
    }

    if iv.len() != IV_LENGTH {
        return Err(KeystoreError::InvalidCipherParams(format!(
            "IV must be {} bytes, got {}",
            IV_LENGTH,
            iv.len()
        )));
    }

    // Use first 16 bytes of derived key for AES-128
    let key: [u8; AES_KEY_LENGTH] = encryption_key[..AES_KEY_LENGTH]
        .try_into()
        .map_err(|_| KeystoreError::CipherError("key conversion failed".to_string()))?;

    let iv_arr: [u8; IV_LENGTH] = iv
        .try_into()
        .map_err(|_| KeystoreError::CipherError("IV conversion failed".to_string()))?;

    let mut cipher = Aes128Ctr::new(&key.into(), &iv_arr.into());

    let mut ciphertext = secret.to_vec();
    cipher.apply_keystream(&mut ciphertext);

    Ok(ciphertext)
}

/// Decrypt secret data using AES-128-CTR
///
/// # Arguments
///
/// * `ciphertext` - The encrypted data
/// * `decryption_key` - The first 16 bytes of the derived key
/// * `iv` - 16-byte initialization vector (same as used for encryption)
///
/// # Returns
///
/// Decrypted secret as SecretBytes
pub fn decrypt_secret(
    ciphertext: &[u8],
    decryption_key: &[u8],
    iv: &[u8],
) -> KeystoreResult<SecretBytes> {
    if decryption_key.len() < AES_KEY_LENGTH {
        return Err(KeystoreError::InvalidCipherParams(format!(
            "decryption key must be at least {} bytes, got {}",
            AES_KEY_LENGTH,
            decryption_key.len()
        )));
    }

    if iv.len() != IV_LENGTH {
        return Err(KeystoreError::InvalidCipherParams(format!(
            "IV must be {} bytes, got {}",
            IV_LENGTH,
            iv.len()
        )));
    }

    // Use first 16 bytes of derived key for AES-128
    let key: [u8; AES_KEY_LENGTH] = decryption_key[..AES_KEY_LENGTH]
        .try_into()
        .map_err(|_| KeystoreError::CipherError("key conversion failed".to_string()))?;

    let iv_arr: [u8; IV_LENGTH] = iv
        .try_into()
        .map_err(|_| KeystoreError::CipherError("IV conversion failed".to_string()))?;

    let mut cipher = Aes128Ctr::new(&key.into(), &iv_arr.into());

    let mut plaintext = ciphertext.to_vec();
    cipher.apply_keystream(&mut plaintext);

    Ok(secrecy::SecretBox::new(Box::new(plaintext)))
}

/// Generate a random IV
pub fn generate_iv() -> Vec<u8> {
    use rand::RngCore;
    let mut iv = vec![0u8; IV_LENGTH];
    rand::thread_rng().fill_bytes(&mut iv);
    iv
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let secret = b"my-secret-key-material-32-bytes!";
        let key = vec![0xAA; 32]; // 32-byte derived key
        let iv = vec![0xBB; 16];

        let ciphertext = encrypt_secret(secret, &key, &iv).unwrap();

        // Ciphertext should be same length as plaintext (CTR mode)
        assert_eq!(ciphertext.len(), secret.len());

        // Ciphertext should differ from plaintext
        assert_ne!(&ciphertext, secret);

        let decrypted = decrypt_secret(&ciphertext, &key, &iv).unwrap();
        assert_eq!(decrypted.expose_secret(), secret);
    }

    #[test]
    fn test_ctr_mode_no_padding() {
        // CTR mode should handle any length without padding
        for len in [1, 7, 15, 16, 17, 31, 32, 33, 64] {
            let secret = vec![0x42; len];
            let key = vec![0xAA; 32];
            let iv = vec![0xBB; 16];

            let ciphertext = encrypt_secret(&secret, &key, &iv).unwrap();
            assert_eq!(ciphertext.len(), len, "CTR mode should preserve length");

            let decrypted = decrypt_secret(&ciphertext, &key, &iv).unwrap();
            assert_eq!(decrypted.expose_secret(), &secret);
        }
    }

    #[test]
    fn test_different_iv_different_ciphertext() {
        let secret = b"same-plaintext";
        let key = vec![0xAA; 32];

        let ciphertext1 = encrypt_secret(secret, &key, &[0x11; 16]).unwrap();
        let ciphertext2 = encrypt_secret(secret, &key, &[0x22; 16]).unwrap();

        // Different IVs should produce different ciphertexts
        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_invalid_key_length() {
        let secret = b"test";
        let short_key = vec![0xAA; 8]; // Too short
        let iv = vec![0xBB; 16];

        let result = encrypt_secret(secret, &short_key, &iv);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_iv_length() {
        let secret = b"test";
        let key = vec![0xAA; 32];
        let short_iv = vec![0xBB; 8]; // Too short

        let result = encrypt_secret(secret, &key, &short_iv);
        assert!(result.is_err());
    }

    #[test]
    fn test_cipher_module() {
        let iv = vec![0xCC; 16];
        let ciphertext = vec![0xDD; 32];

        let module = CipherModule::new(iv.clone(), ciphertext.clone());

        assert_eq!(module.function, "aes-128-ctr");
        assert_eq!(module.iv().unwrap(), iv);
        assert_eq!(module.ciphertext().unwrap(), ciphertext);
    }

    #[test]
    fn test_cipher_module_serialization() {
        let iv = vec![0xEE; 16];
        let ciphertext = vec![0xFF; 32];

        let module = CipherModule::new(iv, ciphertext);

        let json = serde_json::to_string(&module).unwrap();
        let parsed: CipherModule = serde_json::from_str(&json).unwrap();

        assert_eq!(module, parsed);
    }

    #[test]
    fn test_generate_iv() {
        let iv1 = generate_iv();
        let iv2 = generate_iv();

        assert_eq!(iv1.len(), IV_LENGTH);
        assert_eq!(iv2.len(), IV_LENGTH);
        // IVs should be different (extremely high probability)
        assert_ne!(iv1, iv2);
    }
}
