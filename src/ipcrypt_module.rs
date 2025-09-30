//! IPCrypt module for encrypting and decrypting IP addresses
//!
//! This module provides format-preserving encryption for both IPv4 and IPv6 addresses
//! using the IPCrypt-PFX algorithm. The encrypted addresses maintain their network
//! prefix relationships, which is useful for analytics and network analysis.

use anyhow::{anyhow, Result};
use ipcrypt2::IpcryptPfx;
use std::net::IpAddr;

/// IP cipher wrapper for reusable cipher instances
pub struct IpCipher {
    cipher: IpcryptPfx,
}

impl IpCipher {
    /// Create a new IP cipher from a key
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            return Err(anyhow!("Key must be 32 bytes (64 hex characters)"));
        }

        let key_array: [u8; 32] = key
            .try_into()
            .map_err(|_| anyhow!("Failed to convert key to array"))?;

        Ok(Self {
            cipher: IpcryptPfx::new(key_array),
        })
    }

    /// Encrypt an IP address
    pub fn encrypt(&self, ip_str: &str) -> Result<String> {
        let ip: IpAddr = ip_str
            .parse()
            .map_err(|e| anyhow!("Invalid IP address: {}", e))?;

        let encrypted = self
            .cipher
            .encrypt_ipaddr(ip)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        Ok(encrypted.to_string())
    }

    /// Decrypt an IP address
    pub fn decrypt(&self, ip_str: &str) -> Result<String> {
        let ip: IpAddr = ip_str
            .parse()
            .map_err(|e| anyhow!("Invalid IP address: {}", e))?;

        let decrypted = self
            .cipher
            .decrypt_ipaddr(ip)
            .map_err(|e| anyhow!("Decryption failed: {}", e))?;

        Ok(decrypted.to_string())
    }
}

/// Encrypt an IP address using format-preserving encryption
///
/// # Arguments
/// * `ip_str` - The IP address to encrypt (IPv4 or IPv6)
/// * `key` - 32-byte encryption key
///
/// # Returns
/// Encrypted IP address as a string
///
/// # Errors
/// Returns an error if the IP address is invalid or the key is not 32 bytes
pub fn encrypt_ip(ip_str: &str, key: &[u8]) -> Result<String> {
    let cipher = IpCipher::new(key)?;
    cipher.encrypt(ip_str)
}

/// Decrypt an encrypted IP address
///
/// # Arguments
/// * `ip_str` - The encrypted IP address to decrypt
/// * `key` - 32-byte decryption key (must match the encryption key)
///
/// # Returns
/// Decrypted IP address as a string
///
/// # Errors
/// Returns an error if the encrypted IP is invalid or the key is not 32 bytes
pub fn decrypt_ip(ip_str: &str, key: &[u8]) -> Result<String> {
    let cipher = IpCipher::new(key)?;
    cipher.decrypt(ip_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_encrypt_decrypt() {
        // Key must have different halves for IpcryptPfx
        let key_hex = "0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210";
        let key = hex::decode(key_hex).unwrap();
        let ip = "192.168.1.1";

        let encrypted = encrypt_ip(ip, &key).unwrap();
        let decrypted = decrypt_ip(&encrypted, &key).unwrap();

        assert_eq!(ip, decrypted);
    }

    #[test]
    fn test_ipv6_encrypt_decrypt() {
        // Key must have different halves for IpcryptPfx
        let key_hex = "0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210";
        let key = hex::decode(key_hex).unwrap();
        let ip = "2001:db8::1";

        let encrypted = encrypt_ip(ip, &key).unwrap();
        let decrypted = decrypt_ip(&encrypted, &key).unwrap();

        assert_eq!(ip, decrypted);
    }

    #[test]
    fn test_prefix_preservation_ipv4() {
        // Key must have different halves for IpcryptPfx
        let key_hex = "0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210";
        let key = hex::decode(key_hex).unwrap();

        // IPs in same /24 should have same prefix after encryption
        let ip1 = "192.168.1.1";
        let ip2 = "192.168.1.2";
        let ip3 = "192.168.2.1";

        let encrypted1 = encrypt_ip(ip1, &key).unwrap();
        let encrypted2 = encrypt_ip(ip2, &key).unwrap();
        let encrypted3 = encrypt_ip(ip3, &key).unwrap();

        // Parse encrypted IPs to check prefix preservation
        let enc_ip1: IpAddr = encrypted1.parse().unwrap();
        let enc_ip2: IpAddr = encrypted2.parse().unwrap();
        let enc_ip3: IpAddr = encrypted3.parse().unwrap();

        if let (IpAddr::V4(e1), IpAddr::V4(e2), IpAddr::V4(e3)) = (enc_ip1, enc_ip2, enc_ip3) {
            let octets1 = e1.octets();
            let octets2 = e2.octets();
            let octets3 = e3.octets();

            // First 3 octets should match for ip1 and ip2 (same /24)
            assert_eq!(octets1[0..3], octets2[0..3]);

            // First 2 octets should differ between ip1 and ip3 (different /24)
            assert_ne!(octets1[2], octets3[2]);
        } else {
            panic!("Expected IPv4 addresses");
        }
    }
}
