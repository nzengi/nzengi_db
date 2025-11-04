//! Hash functions
//!
//! This module provides hash functions for cryptographic operations.
//!
//! # Example
//!
//! ```rust
//! use nzengi_db::crypto::HashUtils;
//!
//! // SHA-256 hash
//! let hash = HashUtils::sha256("Hello, World!");
//!
//! // Blake2b hash
//! let blake2_hash = HashUtils::blake2b("Hello, World!");
//!
//! // Hash to field element
//! let field = HashUtils::hash_to_field("Hello, World!");
//! ```

use blake2::{Blake2b512, Digest as Blake2Digest};
use halo2_proofs::halo2curves::bn256::Fr as Field;
use hex;
use sha2::{Digest, Sha256};

/// Hash utilities
///
/// Provides methods for computing cryptographic hashes.
pub struct HashUtils;

impl HashUtils {
    /// Compute SHA-256 hash of input data
    ///
    /// # Arguments
    /// * `data` - Input data to hash
    ///
    /// # Returns
    /// Hex-encoded SHA-256 hash string
    ///
    /// # Example
    /// ```
    /// use nzengi_db::crypto::HashUtils;
    ///
    /// let hash = HashUtils::sha256("Hello, World!");
    /// println!("SHA-256: {}", hash);
    /// ```
    pub fn sha256(data: &str) -> String {
        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, data.as_bytes());
        hex::encode(Digest::finalize(hasher))
    }

    /// Compute SHA-256 hash of bytes
    ///
    /// # Arguments
    /// * `data` - Input bytes to hash
    ///
    /// # Returns
    /// Hex-encoded SHA-256 hash string
    pub fn sha256_bytes(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, data);
        hex::encode(Digest::finalize(hasher))
    }

    /// Compute Blake2b hash of input data
    ///
    /// # Arguments
    /// * `data` - Input data to hash
    ///
    /// # Returns
    /// Hex-encoded Blake2b hash string
    ///
    /// # Example
    /// ```
    /// use nzengi_db::crypto::HashUtils;
    ///
    /// let hash = HashUtils::blake2b("Hello, World!");
    /// println!("Blake2b: {}", hash);
    /// ```
    pub fn blake2b(data: &str) -> String {
        let mut hasher = Blake2b512::new();
        Blake2Digest::update(&mut hasher, data.as_bytes());
        hex::encode(Blake2Digest::finalize(hasher))
    }

    /// Compute Blake2b hash of bytes
    ///
    /// # Arguments
    /// * `data` - Input bytes to hash
    ///
    /// # Returns
    /// Hex-encoded Blake2b hash string
    pub fn blake2b_bytes(data: &[u8]) -> String {
        let mut hasher = Blake2b512::new();
        Blake2Digest::update(&mut hasher, data);
        hex::encode(Blake2Digest::finalize(hasher))
    }

    /// Hash string to field element
    ///
    /// This method hashes a string using SHA-256 and converts the result
    /// to a field element. Only the first 31 bytes of the hash are used
    /// to ensure it fits in the 254-bit field.
    ///
    /// # Arguments
    /// * `data` - Input string to hash
    ///
    /// # Returns
    /// Field element representation of the hash
    ///
    /// # Example
    /// ```
    /// use nzengi_db::crypto::HashUtils;
    ///
    /// let field = HashUtils::hash_to_field("Hello, World!");
    /// ```
    pub fn hash_to_field(data: &str) -> Field {
        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, data.as_bytes());
        let hash = Digest::finalize(hasher);

        // Take first 31 bytes to fit in field (254-bit field, 31 bytes = 248 bits)
        let mut bytes = [0u8; 32];
        bytes[1..32].copy_from_slice(&hash[..31]);

        // Convert to field element
        Field::from_bytes(&bytes).unwrap_or(Field::zero())
    }

    /// Hash bytes to field element
    ///
    /// # Arguments
    /// * `data` - Input bytes to hash
    ///
    /// # Returns
    /// Field element representation of the hash
    pub fn hash_bytes_to_field(data: &[u8]) -> Field {
        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, data);
        let hash = Digest::finalize(hasher);

        // Take first 31 bytes to fit in field
        let mut bytes = [0u8; 32];
        bytes[1..32].copy_from_slice(&hash[..31]);

        // Convert to field element
        Field::from_bytes(&bytes).unwrap_or(Field::zero())
    }

    /// Compute commitment hash from multiple commitments
    ///
    /// This method computes a hash of multiple commitment values,
    /// useful for creating a global database commitment hash.
    ///
    /// # Arguments
    /// * `commitments` - Vector of commitment byte vectors
    ///
    /// # Returns
    /// Hex-encoded hash string
    pub fn hash_commitments(commitments: &[Vec<u8>]) -> String {
        let mut hasher = Sha256::new();
        for commitment in commitments {
            Digest::update(&mut hasher, commitment);
        }
        hex::encode(Digest::finalize(hasher))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let hash = HashUtils::sha256("Hello, World!");
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 64); // SHA-256 produces 32 bytes = 64 hex chars
    }

    #[test]
    fn test_sha256_bytes() {
        let data = b"Hello, World!";
        let hash = HashUtils::sha256_bytes(data);
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_blake2b() {
        let hash = HashUtils::blake2b("Hello, World!");
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 128); // Blake2b-512 produces 64 bytes = 128 hex chars
    }

    #[test]
    fn test_blake2b_bytes() {
        let data = b"Hello, World!";
        let hash = HashUtils::blake2b_bytes(data);
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 128);
    }

    #[test]
    fn test_hash_to_field() {
        let field = HashUtils::hash_to_field("Hello, World!");
        // Field should be non-zero for non-empty input
        assert_ne!(field, Field::zero());
    }

    #[test]
    fn test_hash_bytes_to_field() {
        let data = b"Hello, World!";
        let field = HashUtils::hash_bytes_to_field(data);
        assert_ne!(field, Field::zero());
    }

    #[test]
    fn test_hash_commitments() {
        let commitments = vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8]];
        let hash = HashUtils::hash_commitments(&commitments);
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_hash_consistency() {
        // Same input should produce same hash
        let hash1 = HashUtils::sha256("test");
        let hash2 = HashUtils::sha256("test");
        assert_eq!(hash1, hash2);
    }
}
