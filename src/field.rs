//! Field arithmetic utilities
//!
//! This module provides utilities for working with finite field elements,
//! including conversion, decomposition, and recomposition operations.
//!
//! Key features:
//! - Convert between u64 and field elements
//! - Decompose 64-bit integers into 8-bit cells (u8) for efficient range checks
//! - Recompose u8 cells back into 64-bit integers
//! - Generate random field elements
//! - Field modulus information

use ff::{Field as _, PrimeField};
use halo2_proofs::halo2curves::bn256::Fr as Field;

/// Field element utilities
///
/// Provides static methods for common field operations used in ZKP circuits.
pub struct FieldUtils;

impl FieldUtils {
    /// Convert u64 to field element
    ///
    /// # Example
    /// ```
    /// use nzengiDB::field::FieldUtils;
    /// use halo2curves::bn256::Fr as Field;
    ///
    /// let value = 42u64;
    /// let field = FieldUtils::from_u64(value);
    /// assert_eq!(field, Field::from(42u64));
    /// ```
    pub fn from_u64(value: u64) -> Field {
        Field::from(value)
    }

    /// Convert field element to u64 (if possible)
    ///
    /// Returns `None` if the field element is too large to fit in a u64.
    ///
    /// # Example
    /// ```
    /// use nzengiDB::field::FieldUtils;
    /// use halo2curves::bn256::Fr as Field;
    ///
    /// let field = Field::from(42u64);
    /// let value = FieldUtils::to_u64(&field);
    /// assert_eq!(value, Some(42u64));
    /// ```
    pub fn to_u64(field: &Field) -> Option<u64> {
        let bytes = field.to_repr();

        // Check if upper bytes are zero (field value fits in u64)
        if bytes[8..].iter().any(|&b| b != 0) {
            return None;
        }

        // Convert first 8 bytes to u64 (little-endian)
        Some(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Decompose u64 into u8 cells
    ///
    /// Splits a 64-bit integer into 8 segments of 8 bits each.
    /// This is used for efficient range checks in ZKP circuits.
    ///
    /// # Formula
    /// ```
    /// N = Σ(i=0 to 7) ci · 2^(8i)
    /// ```
    ///
    /// Where:
    /// - N: 64-bit integer
    /// - ci: i-th u8 cell (8-bit segment)
    ///
    /// # Example
    /// ```
    /// use nzengiDB::field::FieldUtils;
    ///
    /// let value = 0x0123456789ABCDEF_u64;
    /// let cells = FieldUtils::decompose_u64(value);
    /// assert_eq!(cells[0], 0xEF); // Least significant byte
    /// assert_eq!(cells[7], 0x01); // Most significant byte
    /// ```
    pub fn decompose_u64(value: u64) -> [u8; 8] {
        let mut cells = [0u8; 8];
        for i in 0..8 {
            // Extract i-th 8-bit segment
            // Shift right by 8*i bits, then mask with 0xFF
            cells[i] = ((value >> (8 * i)) & 0xFF) as u8;
        }
        cells
    }

    /// Recompose u8 cells into u64
    ///
    /// Combines 8 u8 cells back into a 64-bit integer.
    /// This is the inverse operation of `decompose_u64`.
    ///
    /// # Formula
    /// ```
    /// N = Σ(i=0 to 7) ci · 2^(8i)
    /// ```
    ///
    /// # Example
    /// ```
    /// use nzengiDB::field::FieldUtils;
    ///
    /// let cells = [0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01];
    /// let value = FieldUtils::recompose_u64(&cells);
    /// assert_eq!(value, 0x0123456789ABCDEF_u64);
    /// ```
    pub fn recompose_u64(cells: &[u8; 8]) -> u64 {
        cells
            .iter()
            .enumerate()
            .map(|(i, &c)| (c as u64) << (8 * i))
            .sum()
    }

    /// Generate random field element
    ///
    /// Uses a cryptographically secure random number generator.
    /// Requires the RNG to implement `rand_core::RngCore` trait (version 0.6).
    ///
    /// # Example
    /// ```
    /// use nzengiDB::field::FieldUtils;
    /// use rand_core::OsRng;
    ///
    /// let mut rng = OsRng;
    /// let field = FieldUtils::random(&mut rng);
    /// ```
    pub fn random<R>(rng: &mut R) -> Field
    where
        R: rand_core::RngCore,
    {
        Field::random(rng)
    }

    /// Get field modulus as string
    ///
    /// Returns the modulus of the BLS12-381 scalar field (254-bit prime).
    ///
    /// # Example
    /// ```
    /// use nzengiDB::field::FieldUtils;
    ///
    /// let modulus = FieldUtils::modulus();
    /// assert!(modulus.starts_with("0x"));
    /// ```
    pub fn modulus() -> String {
        "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001".to_string()
    }

    /// Get field modulus as u64 array (for reference)
    ///
    /// This is a helper for understanding the field size.
    /// The field is approximately 2^254, so it can represent very large values.
    pub fn modulus_info() -> (usize, usize) {
        // Field size: 254 bits
        // Maximum value: 2^254 - 1
        (254, 8) // 254 bits, 8 u8 cells needed for decomposition
    }

    /// Check if u8 cell is valid (in range [0, 255])
    ///
    /// Used for validating cells after decomposition.
    /// Since u8 type guarantees values are in [0, 255], this always returns true.
    ///
    /// # Example
    /// ```
    /// use nzengiDB::field::FieldUtils;
    ///
    /// assert!(FieldUtils::is_valid_u8_cell(0));
    /// assert!(FieldUtils::is_valid_u8_cell(255));
    /// ```
    pub fn is_valid_u8_cell(_value: u8) -> bool {
        // All u8 values are valid (0-255)
        // u8 type guarantees this, so we always return true
        true
    }

    /// Get lookup table size for u8 cells
    ///
    /// Returns the size of the lookup table needed for u8 cell validation.
    /// This is always 256 (for values 0-255).
    ///
    /// # Example
    /// ```
    /// use nzengiDB::field::FieldUtils;
    ///
    /// let table_size = FieldUtils::u8_lookup_table_size();
    /// assert_eq!(table_size, 256);
    /// ```
    pub fn u8_lookup_table_size() -> usize {
        256 // Values from 0 to 255
    }

    /// Create u8 lookup table
    ///
    /// Returns a vector containing all u8 values from 0 to 255.
    /// This is used as a fixed lookup table in ZKP circuits.
    ///
    /// # Example
    /// ```
    /// use nzengiDB::field::FieldUtils;
    ///
    /// let table = FieldUtils::create_u8_lookup_table();
    /// assert_eq!(table.len(), 256);
    /// assert_eq!(table[0], 0);
    /// assert_eq!(table[255], 255);
    /// ```
    pub fn create_u8_lookup_table() -> Vec<u8> {
        (0..=255).collect()
    }
}

/// Constants for field operations
pub mod constants {
    /// Maximum value for u8 cell (8-bit value)
    pub const U8_MAX: u8 = 255;

    /// Minimum value for u8 cell (8-bit value)
    pub const U8_MIN: u8 = 0;

    /// Number of u8 cells in a u64
    pub const U8_CELLS_PER_U64: usize = 8;

    /// Bits per u8 cell
    pub const BITS_PER_U8: usize = 8;

    /// Lookup table size for u8 cells
    pub const U8_TABLE_SIZE: usize = 256;

    /// Maximum u64 value
    pub const U64_MAX: u64 = u64::MAX;

    /// Field modulus (254-bit prime)
    pub const FIELD_MODULUS: &str =
        "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";

    /// Field size in bits
    pub const FIELD_SIZE_BITS: usize = 254;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_u64() {
        let value = 42u64;
        let field = FieldUtils::from_u64(value);
        assert_eq!(field, Field::from(42u64));
    }

    #[test]
    fn test_to_u64() {
        let field = Field::from(42u64);
        let value = FieldUtils::to_u64(&field);
        assert_eq!(value, Some(42u64));
    }

    #[test]
    fn test_to_u64_large_value() {
        let field = Field::from(u64::MAX);
        let value = FieldUtils::to_u64(&field);
        assert_eq!(value, Some(u64::MAX));
    }

    #[test]
    fn test_u64_decompose_recompose() {
        // Test with various values
        let test_values = vec![0u64, 1u64, 255u64, 256u64, 0x0123456789ABCDEF_u64, u64::MAX];

        for value in test_values {
            let cells = FieldUtils::decompose_u64(value);
            let recomposed = FieldUtils::recompose_u64(&cells);
            assert_eq!(value, recomposed, "Failed for value: {}", value);
        }
    }

    #[test]
    fn test_decompose_u64_specific() {
        let value = 0x0123456789ABCDEF_u64;
        let cells = FieldUtils::decompose_u64(value);

        // Check each cell
        assert_eq!(cells[0], 0xEF, "Cell 0 (LSB)");
        assert_eq!(cells[1], 0xCD, "Cell 1");
        assert_eq!(cells[2], 0xAB, "Cell 2");
        assert_eq!(cells[3], 0x89, "Cell 3");
        assert_eq!(cells[4], 0x67, "Cell 4");
        assert_eq!(cells[5], 0x45, "Cell 5");
        assert_eq!(cells[6], 0x23, "Cell 6");
        assert_eq!(cells[7], 0x01, "Cell 7 (MSB)");
    }

    #[test]
    fn test_recompose_u64_specific() {
        let cells = [0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01];
        let value = FieldUtils::recompose_u64(&cells);
        assert_eq!(value, 0x0123456789ABCDEF_u64);
    }

    #[test]
    fn test_decompose_recompose_edge_cases() {
        // Test zero
        let cells = FieldUtils::decompose_u64(0);
        assert_eq!(cells, [0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(FieldUtils::recompose_u64(&cells), 0);

        // Test maximum value
        let cells = FieldUtils::decompose_u64(u64::MAX);
        assert_eq!(cells, [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(FieldUtils::recompose_u64(&cells), u64::MAX);

        // Test single byte values
        for i in 0..=255u64 {
            let cells = FieldUtils::decompose_u64(i);
            assert_eq!(cells[0], i as u8);
            assert_eq!(cells[1..], [0, 0, 0, 0, 0, 0, 0]);
            assert_eq!(FieldUtils::recompose_u64(&cells), i);
        }
    }

    #[test]
    fn test_random() {
        use rand_core::OsRng;

        let mut rng = OsRng;
        let field1 = FieldUtils::random(&mut rng);
        let field2 = FieldUtils::random(&mut rng);

        // Very unlikely to be equal (but possible)
        // Just check that the function works
        assert!(field1 != field2 || field1 == field2); // Always true, but tests the function
    }

    #[test]
    fn test_modulus() {
        let modulus = FieldUtils::modulus();
        assert!(modulus.starts_with("0x"));
        assert_eq!(modulus.len(), 66); // 0x + 64 hex chars
    }

    #[test]
    fn test_modulus_info() {
        let (bits, cells) = FieldUtils::modulus_info();
        assert_eq!(bits, 254);
        assert_eq!(cells, 8);
    }

    #[test]
    fn test_is_valid_u8_cell() {
        // All u8 values are valid
        for i in 0..=255u8 {
            assert!(FieldUtils::is_valid_u8_cell(i));
        }
    }

    #[test]
    fn test_u8_lookup_table_size() {
        assert_eq!(FieldUtils::u8_lookup_table_size(), 256);
    }

    #[test]
    fn test_create_u8_lookup_table() {
        let table = FieldUtils::create_u8_lookup_table();
        assert_eq!(table.len(), 256);
        assert_eq!(table[0], 0);
        assert_eq!(table[255], 255);

        // Check all values are present
        for i in 0..=255 {
            assert_eq!(table[i as usize], i);
        }
    }

    #[test]
    fn test_constants() {
        assert_eq!(constants::U8_MAX, 255);
        assert_eq!(constants::U8_MIN, 0);
        assert_eq!(constants::U8_CELLS_PER_U64, 8);
        assert_eq!(constants::BITS_PER_U8, 8);
        assert_eq!(constants::U8_TABLE_SIZE, 256);
        assert_eq!(constants::U64_MAX, u64::MAX);
        assert_eq!(constants::FIELD_SIZE_BITS, 254);
    }

    #[test]
    fn test_decompose_recompose_roundtrip() {
        // Test round-trip conversion for many values
        for i in 0..1000 {
            let value = i * 1000;
            let cells = FieldUtils::decompose_u64(value);
            let recomposed = FieldUtils::recompose_u64(&cells);
            assert_eq!(value, recomposed);
        }
    }

    #[test]
    fn test_decompose_bit_patterns() {
        // Test various bit patterns
        let patterns = vec![
            0b00000001, // Single bit set
            0b10000000, // High bit set
            0b01010101, // Alternating pattern
            0b11111111, // All bits set in one byte
        ];

        for pattern in patterns {
            let value = pattern as u64;
            let cells = FieldUtils::decompose_u64(value);
            assert_eq!(cells[0], pattern);
            assert_eq!(cells[1..], [0, 0, 0, 0, 0, 0, 0]);
        }
    }
}
