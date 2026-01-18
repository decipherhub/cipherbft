//! Common utilities for key management CLI commands

use anyhow::{anyhow, Context, Result};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// Default keys directory name within home
pub const DEFAULT_KEYS_DIR: &str = "keys";

/// Minimum passphrase length
pub const MIN_PASSPHRASE_LENGTH: usize = 8;

/// Get the default keys directory
pub fn default_keys_dir(home: &Path) -> PathBuf {
    home.join(DEFAULT_KEYS_DIR)
}

/// Resolve keys directory: use provided path or default
pub fn resolve_keys_dir(home: &Path, keys_dir: Option<PathBuf>) -> PathBuf {
    keys_dir.unwrap_or_else(|| default_keys_dir(home))
}

/// Ensure a directory exists with proper permissions
pub fn ensure_keys_dir(dir: &Path) -> Result<()> {
    if !dir.exists() {
        fs::create_dir_all(dir).context("Failed to create keys directory")?;

        // Set directory permissions to 0700 (owner only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o700);
            fs::set_permissions(dir, perms).context("Failed to set directory permissions")?;
        }
    }
    Ok(())
}

/// Read passphrase from file or prompt interactively
pub fn get_passphrase(
    passphrase_file: Option<&Path>,
    prompt: &str,
    confirm: bool,
) -> Result<String> {
    if let Some(file) = passphrase_file {
        read_passphrase_from_file(file)
    } else {
        prompt_passphrase(prompt, confirm)
    }
}

/// Read passphrase from a file
pub fn read_passphrase_from_file(path: &Path) -> Result<String> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read passphrase file: {}", path.display()))?;

    let passphrase = content.trim().to_string();

    if passphrase.is_empty() {
        return Err(anyhow!("Passphrase file is empty"));
    }

    Ok(passphrase)
}

/// Prompt for passphrase with optional confirmation
pub fn prompt_passphrase(prompt: &str, confirm: bool) -> Result<String> {
    let passphrase = rpassword::prompt_password(prompt).context("Failed to read passphrase")?;

    if passphrase.len() < MIN_PASSPHRASE_LENGTH {
        return Err(anyhow!(
            "Passphrase must be at least {} characters",
            MIN_PASSPHRASE_LENGTH
        ));
    }

    if confirm {
        let confirmation = rpassword::prompt_password("Confirm passphrase: ")
            .context("Failed to read passphrase confirmation")?;

        if passphrase != confirmation {
            return Err(anyhow!("Passphrases do not match"));
        }
    }

    Ok(passphrase)
}

/// Read mnemonic from file or prompt interactively
pub fn get_mnemonic(mnemonic_file: Option<&Path>) -> Result<String> {
    if let Some(file) = mnemonic_file {
        read_mnemonic_from_file(file)
    } else {
        prompt_mnemonic()
    }
}

/// Read mnemonic from a file
pub fn read_mnemonic_from_file(path: &Path) -> Result<String> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read mnemonic file: {}", path.display()))?;

    let mnemonic = content.trim().to_string();

    if mnemonic.is_empty() {
        return Err(anyhow!("Mnemonic file is empty"));
    }

    // Basic validation: should have 12, 15, 18, 21, or 24 words
    let word_count = mnemonic.split_whitespace().count();
    if ![12, 15, 18, 21, 24].contains(&word_count) {
        return Err(anyhow!(
            "Invalid mnemonic: expected 12, 15, 18, 21, or 24 words, got {}",
            word_count
        ));
    }

    Ok(mnemonic)
}

/// Prompt for mnemonic phrase interactively
pub fn prompt_mnemonic() -> Result<String> {
    println!("Enter your mnemonic phrase (12, 15, 18, 21, or 24 words):");
    print!("> ");
    io::stdout().flush()?;

    let mut mnemonic = String::new();
    io::stdin().read_line(&mut mnemonic)?;

    let mnemonic = mnemonic.trim().to_string();

    // Basic validation
    let word_count = mnemonic.split_whitespace().count();
    if ![12, 15, 18, 21, 24].contains(&word_count) {
        return Err(anyhow!(
            "Invalid mnemonic: expected 12, 15, 18, 21, or 24 words, got {}",
            word_count
        ));
    }

    Ok(mnemonic)
}

/// Check if a path represents an existing keystore
pub fn keystore_exists(path: &Path) -> bool {
    path.exists() && path.is_file() && path.extension().is_some_and(|ext| ext == "json")
}

/// Get keystore path for a given key type
pub fn keystore_path(dir: &Path, account: u32, key_type: &str) -> PathBuf {
    dir.join(format!("validator_{}", account))
        .join(format!("{}.json", key_type))
}

/// Securely clear a string from memory
pub fn secure_clear(mut s: String) {
    // SAFETY: We're modifying the string's bytes in place before dropping
    unsafe {
        s.as_bytes_mut().zeroize();
    }
    drop(s);
}

/// Display warning about mnemonic security
pub fn display_mnemonic_warning(mnemonic: &str) {
    println!();
    println!("============================================================");
    println!("                    IMPORTANT - SAVE THIS!");
    println!("============================================================");
    println!();
    println!("Your mnemonic recovery phrase:");
    println!();

    // Display words in groups of 4 for readability
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    for (i, chunk) in words.chunks(4).enumerate() {
        let start_num = i * 4 + 1;
        let formatted: Vec<String> = chunk
            .iter()
            .enumerate()
            .map(|(j, word)| format!("{:2}. {:<12}", start_num + j, word))
            .collect();
        println!("  {}", formatted.join("  "));
    }

    println!();
    println!("============================================================");
    println!("  This phrase is the ONLY way to recover your validator keys.");
    println!("  Store it securely offline. Never share it with anyone.");
    println!("  Anyone with this phrase can control your validator.");
    println!("============================================================");
    println!();
}

/// Validate passphrase strength
pub fn validate_passphrase_strength(passphrase: &str) -> Result<()> {
    if passphrase.len() < MIN_PASSPHRASE_LENGTH {
        return Err(anyhow!(
            "Passphrase must be at least {} characters",
            MIN_PASSPHRASE_LENGTH
        ));
    }

    // Check for basic complexity (at least 2 of: uppercase, lowercase, digit, special)
    let has_upper = passphrase.chars().any(|c| c.is_uppercase());
    let has_lower = passphrase.chars().any(|c| c.is_lowercase());
    let has_digit = passphrase.chars().any(|c| c.is_ascii_digit());
    let has_special = passphrase.chars().any(|c| !c.is_alphanumeric());

    let complexity_count = [has_upper, has_lower, has_digit, has_special]
        .iter()
        .filter(|&&x| x)
        .count();

    if complexity_count < 2 {
        println!("Warning: Consider using a stronger passphrase with mixed characters.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_validate_passphrase_strength() {
        // Too short
        assert!(validate_passphrase_strength("short").is_err());

        // Valid length
        assert!(validate_passphrase_strength("longEnoughPassphrase").is_ok());
        assert!(validate_passphrase_strength("12345678").is_ok());
    }

    #[test]
    fn test_keystore_path() {
        let dir = Path::new("/home/user/.cipherd/keys");
        let path = keystore_path(dir, 0, "consensus");
        assert_eq!(
            path,
            PathBuf::from("/home/user/.cipherd/keys/validator_0/consensus.json")
        );
    }

    #[test]
    fn test_read_passphrase_from_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("passphrase.txt");

        // Empty file should fail
        fs::write(&file_path, "").unwrap();
        assert!(read_passphrase_from_file(&file_path).is_err());

        // Valid passphrase should work
        fs::write(&file_path, "my-secure-passphrase\n").unwrap();
        let passphrase = read_passphrase_from_file(&file_path).unwrap();
        assert_eq!(passphrase, "my-secure-passphrase");
    }

    #[test]
    fn test_read_mnemonic_from_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("mnemonic.txt");

        // Invalid word count should fail
        fs::write(&file_path, "one two three").unwrap();
        assert!(read_mnemonic_from_file(&file_path).is_err());

        // Valid 12-word mnemonic should work
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        fs::write(&file_path, mnemonic).unwrap();
        let result = read_mnemonic_from_file(&file_path).unwrap();
        assert_eq!(result, mnemonic);
    }
}
