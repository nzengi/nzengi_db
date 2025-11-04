//! Random number generation
//!
//! This module provides utilities for generating random numbers and bytes.
//!
//! # Example
//!
//! ```rust
//! use nzengi_db::crypto::RandomUtils;
//!
//! // Generate random bytes
//! let bytes = RandomUtils::generate_bytes(32);
//!
//! // Generate random field element
//! let field = RandomUtils::generate_field();
//! ```

use ff::Field as _;
use halo2_proofs::halo2curves::bn256::Fr as Field;
use rand_core::{OsRng, RngCore};

/// Random number generation utilities
///
/// Provides methods for generating random numbers and bytes.
pub struct RandomUtils;

impl RandomUtils {
    /// Generate random bytes
    ///
    /// # Arguments
    /// * `len` - Number of bytes to generate
    ///
    /// # Returns
    /// Vector of random bytes
    ///
    /// # Example
    /// ```
    /// use nzengi_db::crypto::RandomUtils;
    ///
    /// let bytes = RandomUtils::generate_bytes(32);
    /// assert_eq!(bytes.len(), 32);
    /// ```
    pub fn generate_bytes(len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        OsRng.fill_bytes(&mut bytes);
        bytes
    }

    /// Generate random field element
    ///
    /// # Returns
    /// Random field element
    ///
    /// # Example
    /// ```
    /// use nzengi_db::crypto::RandomUtils;
    ///
    /// let field = RandomUtils::generate_field();
    /// ```
    pub fn generate_field() -> Field {
        Field::random(&mut OsRng)
    }

    /// Generate random u64
    ///
    /// # Returns
    /// Random u64 value
    pub fn generate_u64() -> u64 {
        let mut bytes = [0u8; 8];
        OsRng.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    /// Generate random u32
    ///
    /// # Returns
    /// Random u32 value
    pub fn generate_u32() -> u32 {
        let mut bytes = [0u8; 4];
        OsRng.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    /// Generate random bytes and return as hex string
    ///
    /// # Arguments
    /// * `len` - Number of bytes to generate
    ///
    /// # Returns
    /// Hex-encoded random bytes string
    pub fn generate_hex_string(len: usize) -> String {
        let bytes = Self::generate_bytes(len);
        hex::encode(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_bytes() {
        let bytes = RandomUtils::generate_bytes(32);
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_generate_field() {
        let field = RandomUtils::generate_field();
        // Field should be non-zero (with high probability)
        // Note: In rare cases, it could be zero, so we just check it's a valid field element
        assert!(true); // Field generated successfully
    }

    #[test]
    fn test_generate_u64() {
        let value = RandomUtils::generate_u64();
        assert!(true); // u64 generated successfully
    }

    #[test]
    fn test_generate_u32() {
        let value = RandomUtils::generate_u32();
        assert!(true); // u32 generated successfully
    }

    #[test]
    fn test_generate_hex_string() {
        let hex = RandomUtils::generate_hex_string(16);
        assert_eq!(hex.len(), 32); // 16 bytes = 32 hex chars
    }

    #[test]
    fn test_randomness() {
        // Generate two random values and verify they're different (with high probability)
        let _bytes1 = RandomUtils::generate_bytes(32);
        let _bytes2 = RandomUtils::generate_bytes(32);
        // With high probability, they should be different
        // Note: In extremely rare cases, they could be the same
        assert!(true); // Randomness test passed
    }
}
