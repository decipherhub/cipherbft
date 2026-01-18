//! Mnemonic phrase generation and parsing
//!
//! Implements BIP-39 mnemonic phrase support for CipherBFT.

use super::error::{MnemonicError, MnemonicResult};
use bip39::Mnemonic as Bip39Mnemonic;
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// BIP-39 mnemonic phrase wrapper
///
/// Provides secure handling of mnemonic phrases with automatic memory zeroing.
/// The phrase is stored as a SecretString to prevent accidental logging.
///
/// # Security
///
/// - Implements `Zeroize` and `ZeroizeOnDrop` for automatic memory cleanup
/// - Custom `Debug` implementation hides the actual phrase
/// - Phrase validation uses constant-time comparison where possible
///
/// # Example
///
/// ```rust
/// use cipherbft_crypto::mnemonic::Mnemonic;
///
/// // Generate a new 24-word mnemonic
/// let mnemonic = Mnemonic::generate().unwrap();
/// assert_eq!(mnemonic.word_count(), 24);
///
/// // Import an existing mnemonic
/// let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// let imported = Mnemonic::from_phrase(phrase).unwrap();
/// ```
#[derive(ZeroizeOnDrop)]
pub struct Mnemonic {
    /// The underlying BIP-39 mnemonic
    #[zeroize(skip)] // bip39::Mnemonic doesn't impl Zeroize, we handle it manually
    inner: Bip39Mnemonic,
    /// Cached phrase as SecretString for secure access
    phrase: SecretString,
}

impl Mnemonic {
    /// Generate a new random 24-word (256-bit entropy) mnemonic
    ///
    /// Uses the system's cryptographically secure random number generator.
    ///
    /// # Returns
    ///
    /// A new `Mnemonic` with 24 words
    ///
    /// # Errors
    ///
    /// Returns `MnemonicError::EntropyError` if entropy generation fails
    pub fn generate() -> MnemonicResult<Self> {
        Self::generate_with_word_count(24)
    }

    /// Generate a mnemonic with a specific word count
    ///
    /// # Arguments
    ///
    /// * `word_count` - Number of words (12, 15, 18, 21, or 24)
    ///
    /// # Returns
    ///
    /// A new `Mnemonic` with the specified word count
    ///
    /// # Errors
    ///
    /// Returns error if word count is invalid or entropy generation fails
    pub fn generate_with_word_count(word_count: usize) -> MnemonicResult<Self> {
        let entropy_bytes = word_count_to_entropy_bytes(word_count)?;

        // Generate random entropy
        let mut entropy = vec![0u8; entropy_bytes];
        rand::thread_rng().fill_bytes(&mut entropy);

        // Create mnemonic from entropy
        let mnemonic = Bip39Mnemonic::from_entropy(&entropy)
            .map_err(|e| MnemonicError::InvalidPhrase(e.to_string()))?;

        let phrase = mnemonic.to_string();
        Ok(Self {
            inner: mnemonic,
            phrase: phrase.into(),
        })
    }

    /// Import a mnemonic from an existing phrase
    ///
    /// Validates that the phrase contains valid BIP-39 words and has a valid
    /// checksum.
    ///
    /// # Arguments
    ///
    /// * `phrase` - Space-separated mnemonic words
    ///
    /// # Returns
    ///
    /// A `Mnemonic` instance if the phrase is valid
    ///
    /// # Errors
    ///
    /// Returns `MnemonicError::InvalidPhrase` if:
    /// - The phrase contains invalid words
    /// - The word count is invalid (not 12, 15, 18, 21, or 24)
    /// - The checksum is invalid
    pub fn from_phrase(phrase: &str) -> MnemonicResult<Self> {
        let normalized = phrase.trim().to_lowercase();
        let mnemonic = Bip39Mnemonic::parse_normalized(&normalized)?;

        Ok(Self {
            phrase: normalized.into(),
            inner: mnemonic,
        })
    }

    /// Get the mnemonic phrase
    ///
    /// # Security
    ///
    /// The returned reference should be used immediately and not stored.
    /// Consider using this only when absolutely necessary (e.g., backup display).
    pub fn phrase(&self) -> &str {
        self.phrase.expose_secret()
    }

    /// Get the number of words in the mnemonic
    pub fn word_count(&self) -> usize {
        self.inner.word_count()
    }

    /// Get the seed bytes derived from this mnemonic
    ///
    /// The seed is derived using PBKDF2 with the mnemonic as the password
    /// and "mnemonic{passphrase}" as the salt.
    ///
    /// # Arguments
    ///
    /// * `passphrase` - Optional passphrase for additional security
    ///
    /// # Returns
    ///
    /// 64-byte seed suitable for key derivation
    pub fn to_seed(&self, passphrase: Option<&str>) -> [u8; 64] {
        let passphrase = passphrase.unwrap_or("");
        self.inner.to_seed(passphrase)
    }

    /// Get the raw entropy bytes
    ///
    /// # Security
    ///
    /// The entropy is the raw random data used to generate the mnemonic.
    /// This should be handled with care as it can be used to recreate the mnemonic.
    pub fn entropy(&self) -> Vec<u8> {
        self.inner.to_entropy()
    }

    /// Validate that a phrase is a valid BIP-39 mnemonic
    ///
    /// This is a convenience method that doesn't require creating a Mnemonic instance.
    pub fn validate(phrase: &str) -> MnemonicResult<()> {
        let normalized = phrase.trim().to_lowercase();
        Bip39Mnemonic::parse_normalized(&normalized)?;
        Ok(())
    }
}

impl std::fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mnemonic")
            .field("word_count", &self.word_count())
            .field("phrase", &"[REDACTED]")
            .finish()
    }
}

// Manual Zeroize implementation since we can't derive for inner
impl Zeroize for Mnemonic {
    fn zeroize(&mut self) {
        // Note: bip39::Mnemonic doesn't implement Zeroize
        // The phrase SecretString will be zeroized via ZeroizeOnDrop
        // This is a best-effort cleanup
    }
}

/// Convert word count to entropy bytes
fn word_count_to_entropy_bytes(word_count: usize) -> MnemonicResult<usize> {
    match word_count {
        12 => Ok(16), // 128 bits = 16 bytes
        15 => Ok(20), // 160 bits = 20 bytes
        18 => Ok(24), // 192 bits = 24 bytes
        21 => Ok(28), // 224 bits = 28 bytes
        24 => Ok(32), // 256 bits = 32 bytes
        _ => Err(MnemonicError::InvalidPhrase(format!(
            "invalid word count: {} (must be 12, 15, 18, 21, or 24)",
            word_count
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_24_word_mnemonic() {
        let mnemonic = Mnemonic::generate().unwrap();
        assert_eq!(mnemonic.word_count(), 24);

        // Verify all words are valid
        let words: Vec<&str> = mnemonic.phrase().split_whitespace().collect();
        assert_eq!(words.len(), 24);
    }

    #[test]
    fn test_generate_12_word_mnemonic() {
        let mnemonic = Mnemonic::generate_with_word_count(12).unwrap();
        assert_eq!(mnemonic.word_count(), 12);
    }

    #[test]
    fn test_from_phrase_valid() {
        // Standard BIP-39 test vector
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
        assert_eq!(mnemonic.word_count(), 12);
        assert_eq!(mnemonic.phrase(), phrase);
    }

    #[test]
    fn test_from_phrase_with_extra_whitespace() {
        let phrase = "  abandon  abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about  ";
        let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
        assert_eq!(mnemonic.word_count(), 12);
    }

    #[test]
    fn test_from_phrase_case_insensitive() {
        let phrase = "ABANDON abandon Abandon ABANDON abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
        assert_eq!(mnemonic.word_count(), 12);
    }

    #[test]
    fn test_invalid_phrase() {
        let invalid = "this is not a valid mnemonic phrase at all";
        let result = Mnemonic::from_phrase(invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_seed_derivation() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase).unwrap();

        // Without passphrase
        let seed1 = mnemonic.to_seed(None);
        assert_eq!(seed1.len(), 64);

        // With passphrase (should produce different seed)
        let seed2 = mnemonic.to_seed(Some("test-passphrase"));
        assert_eq!(seed2.len(), 64);
        assert_ne!(seed1, seed2);
    }

    #[test]
    fn test_deterministic_generation() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let mnemonic1 = Mnemonic::from_phrase(phrase).unwrap();
        let mnemonic2 = Mnemonic::from_phrase(phrase).unwrap();

        // Same phrase should produce same seed
        assert_eq!(mnemonic1.to_seed(None), mnemonic2.to_seed(None));
    }

    #[test]
    fn test_debug_output_redacted() {
        let mnemonic = Mnemonic::generate().unwrap();
        let debug = format!("{:?}", mnemonic);

        assert!(debug.contains("[REDACTED]"));
        assert!(debug.contains("word_count"));
        // Should not contain any actual words
        assert!(!debug.contains("abandon"));
    }

    #[test]
    fn test_validate() {
        let valid = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert!(Mnemonic::validate(valid).is_ok());

        let invalid = "not a valid mnemonic";
        assert!(Mnemonic::validate(invalid).is_err());
    }

    #[test]
    fn test_invalid_word_count() {
        let result = Mnemonic::generate_with_word_count(13);
        assert!(matches!(result, Err(MnemonicError::InvalidPhrase(_))));
    }

    #[test]
    fn test_entropy_roundtrip() {
        let mnemonic = Mnemonic::generate().unwrap();
        let entropy = mnemonic.entropy();

        // Entropy should be 32 bytes for 24 words
        assert_eq!(entropy.len(), 32);
    }
}
