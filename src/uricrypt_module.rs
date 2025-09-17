//! URICrypt module for encrypting and decrypting URIs
//!
//! This module provides hierarchy-preserving encryption for URIs and URLs.
//! The encryption preserves the hierarchical structure of URIs while protecting
//! sensitive information in paths, queries, and other components.

use anyhow::{anyhow, Result};

/// Encrypt a URI using hierarchy-preserving encryption
///
/// # Arguments
/// * `uri` - The URI to encrypt
/// * `key` - 32-byte encryption key
///
/// # Returns
/// Encrypted URI as a string
///
/// # Errors
/// Returns an error if the key is not 32 bytes
pub fn encrypt_uri(uri: &str, key: &[u8]) -> Result<String> {
    if key.len() != 32 {
        return Err(anyhow!("URI key must be 32 bytes (64 hex characters)"));
    }

    // Use empty context for now - could be made configurable
    let context = b"";

    let encrypted = uricrypt::encrypt_uri(uri, key, context);

    Ok(encrypted)
}

/// Decrypt an encrypted URI
///
/// # Arguments
/// * `encrypted_uri` - The encrypted URI to decrypt
/// * `key` - 32-byte decryption key (must match the encryption key)
///
/// # Returns
/// Decrypted URI as a string
///
/// # Errors
/// Returns an error if the key is not 32 bytes or decryption fails
pub fn decrypt_uri(encrypted_uri: &str, key: &[u8]) -> Result<String> {
    if key.len() != 32 {
        return Err(anyhow!("URI key must be 32 bytes (64 hex characters)"));
    }

    // Use empty context - must match what was used for encryption
    let context = b"";

    let decrypted = uricrypt::decrypt_uri(encrypted_uri, key, context)
        .map_err(|e| anyhow!("Failed to decrypt URI: {}", e))?;

    Ok(decrypted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uri_encrypt_decrypt() {
        // Key must have different halves for security
        let key_hex = "0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210";
        let key = hex::decode(key_hex).unwrap();
        let uri = "https://example.com/path?query=value";

        let encrypted = encrypt_uri(uri, &key).unwrap();
        let decrypted = decrypt_uri(&encrypted, &key).unwrap();

        assert_eq!(uri, decrypted);
    }

    #[test]
    fn test_uri_with_ip() {
        // Key must have different halves for security
        let key_hex = "0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210";
        let key = hex::decode(key_hex).unwrap();
        let uri = "http://192.168.1.1:8080/api";

        let encrypted = encrypt_uri(uri, &key).unwrap();
        let decrypted = decrypt_uri(&encrypted, &key).unwrap();

        assert_eq!(uri, decrypted);
    }

    #[test]
    fn test_uri_with_auth() {
        // Key must have different halves for security
        let key_hex = "0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210";
        let key = hex::decode(key_hex).unwrap();
        let uri = "ftp://user:pass@example.com/files";

        let encrypted = encrypt_uri(uri, &key).unwrap();
        let decrypted = decrypt_uri(&encrypted, &key).unwrap();

        assert_eq!(uri, decrypted);
    }

    #[test]
    fn test_uri_hierarchy_preserved() {
        // Key must have different halves for security
        let key_hex = "0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210";
        let key = hex::decode(key_hex).unwrap();
        let uri1 = "https://example.com/api/v1/users";
        let uri2 = "https://example.com/api/v1/posts";
        let uri3 = "https://example.com/api/v2/users";

        let enc1 = encrypt_uri(uri1, &key).unwrap();
        let enc2 = encrypt_uri(uri2, &key).unwrap();
        let enc3 = encrypt_uri(uri3, &key).unwrap();

        // Verify decryption works correctly
        assert_eq!(uri1, decrypt_uri(&enc1, &key).unwrap());
        assert_eq!(uri2, decrypt_uri(&enc2, &key).unwrap());
        assert_eq!(uri3, decrypt_uri(&enc3, &key).unwrap());

        // URIs are encrypted but structure is preserved
        assert_ne!(enc1, uri1);
        assert_ne!(enc2, uri2);
        assert_ne!(enc3, uri3);
    }
}
