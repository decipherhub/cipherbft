//! Secret wrapper utilities for consistent secret handling
//!
//! Provides type aliases and utilities around the `secrecy` crate for
//! handling sensitive strings and byte arrays.

use secrecy::{SecretBox, SecretString as SecrecySecretString};
use zeroize::Zeroize;

/// A secret byte array that is zeroized on drop.
///
/// Use this for storing sensitive binary data like keys, salts, or derived bytes.
/// The inner value can only be accessed via `expose_secret()`.
///
/// # Example
///
/// ```rust
/// use cipherbft_crypto::secure::SecretBytes;
/// use secrecy::ExposeSecret;
///
/// let secret = SecretBytes::new(Box::new(vec![1, 2, 3, 4]));
/// let bytes = secret.expose_secret();
/// assert_eq!(bytes, &vec![1, 2, 3, 4]);
/// // Memory is zeroized when `secret` goes out of scope
/// ```
pub type SecretBytes = SecretBox<Vec<u8>>;

/// A secret string that is zeroized on drop.
///
/// Use this for storing sensitive text like passphrases or mnemonics.
/// The inner value can only be accessed via `expose_secret()`.
///
/// # Example
///
/// ```rust
/// use cipherbft_crypto::secure::SecretString;
/// use secrecy::ExposeSecret;
///
/// let passphrase: SecretString = "my-secret-passphrase".to_string().into();
/// let value: &str = passphrase.expose_secret();
/// assert_eq!(value, "my-secret-passphrase");
/// // Memory is zeroized when `passphrase` goes out of scope
/// ```
pub type SecretString = SecrecySecretString;

/// A fixed-size secret byte array.
///
/// Unlike `SecretBytes`, this is for fixed-size secrets like seeds.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SecretArray<const N: usize> {
    inner: [u8; N],
}

impl<const N: usize> SecretArray<N> {
    /// Create a new secret array from bytes.
    pub fn new(bytes: [u8; N]) -> Self {
        Self { inner: bytes }
    }

    /// Expose the secret bytes.
    ///
    /// # Security
    ///
    /// Use this sparingly and only when necessary.
    /// The returned reference should not be stored.
    pub fn expose_secret(&self) -> &[u8; N] {
        &self.inner
    }
}

impl<const N: usize> std::fmt::Debug for SecretArray<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretArray")
            .field("length", &N)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

// Don't implement Clone to prevent accidental copies
// impl<const N: usize> Clone for SecretArray<N> { ... } - NOT IMPLEMENTED

/// Extension trait for creating secret values.
pub trait IntoSecret {
    /// The secret type this converts into.
    type Secret;

    /// Convert into a secret value.
    fn into_secret(self) -> Self::Secret;
}

impl IntoSecret for String {
    type Secret = SecretString;

    fn into_secret(self) -> Self::Secret {
        self.into() // Uses From<String> for SecretString
    }
}

impl IntoSecret for Vec<u8> {
    type Secret = SecretBytes;

    fn into_secret(self) -> Self::Secret {
        SecretBox::new(Box::new(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn test_secret_string() {
        let secret: SecretString = "my-passphrase".to_string().into();
        let exposed: &str = secret.expose_secret();
        assert_eq!(exposed, "my-passphrase");
    }

    #[test]
    fn test_secret_bytes() {
        let data = vec![1, 2, 3, 4, 5];
        let secret = SecretBox::new(Box::new(data));
        assert_eq!(secret.expose_secret(), &vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_secret_array() {
        let arr = [0xABu8; 32];
        let secret = SecretArray::new(arr);
        assert_eq!(secret.expose_secret(), &arr);
    }

    #[test]
    fn test_secret_array_debug() {
        let arr = [0xABu8; 32];
        let secret = SecretArray::new(arr);
        let debug = format!("{:?}", secret);

        assert!(debug.contains("[REDACTED]"));
        assert!(debug.contains("length"));
        assert!(!debug.contains("171")); // 0xAB = 171
    }

    #[test]
    fn test_into_secret_string() {
        let s = "my-secret".to_string();
        let secret = s.into_secret();
        let exposed: &str = secret.expose_secret();
        assert_eq!(exposed, "my-secret");
    }

    #[test]
    fn test_into_secret_bytes() {
        let data = vec![1, 2, 3];
        let secret = data.into_secret();
        assert_eq!(secret.expose_secret(), &vec![1, 2, 3]);
    }
}
