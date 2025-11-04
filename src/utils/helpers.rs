//! Helper functions
//!
//! This module provides common utility functions used throughout the codebase.
//!
//! # Example
//!
//! ```rust
//! use nzengi_db::utils::Helpers;
//!
//! // Format bytes
//! let formatted = Helpers::format_bytes(1024);
//! println!("Size: {}", formatted); // "1.00 KB"
//!
//! // Format duration
//! let formatted = Helpers::format_duration(1234);
//! println!("Time: {}", formatted); // "1.23s"
//! ```

use std::time::Duration;

/// Helper functions
///
/// Provides common utility functions.
pub struct Helpers;

impl Helpers {
    /// Format bytes to human-readable string
    ///
    /// # Arguments
    /// * `bytes` - Number of bytes
    ///
    /// # Returns
    /// Formatted string (e.g., "1.00 KB", "1.50 MB")
    ///
    /// # Example
    /// ```
    /// use nzengi_db::utils::Helpers;
    ///
    /// let formatted = Helpers::format_bytes(1024);
    /// assert_eq!(formatted, "1.00 KB");
    /// ```
    pub fn format_bytes(bytes: u64) -> String {
        const KB: u64 = 1024;
        const MB: u64 = KB * 1024;
        const GB: u64 = MB * 1024;
        const TB: u64 = GB * 1024;

        if bytes >= TB {
            format!("{:.2} TB", bytes as f64 / TB as f64)
        } else if bytes >= GB {
            format!("{:.2} GB", bytes as f64 / GB as f64)
        } else if bytes >= MB {
            format!("{:.2} MB", bytes as f64 / MB as f64)
        } else if bytes >= KB {
            format!("{:.2} KB", bytes as f64 / KB as f64)
        } else {
            format!("{} B", bytes)
        }
    }

    /// Format duration to human-readable string
    ///
    /// # Arguments
    /// * `nanos` - Duration in nanoseconds
    ///
    /// # Returns
    /// Formatted string (e.g., "1.23s", "500ms")
    ///
    /// # Example
    /// ```
    /// use nzengi_db::utils::Helpers;
    ///
    /// let formatted = Helpers::format_duration(1_234_000_000);
    /// assert!(formatted.contains("s"));
    /// ```
    pub fn format_duration(nanos: u64) -> String {
        let duration = Duration::from_nanos(nanos);
        let seconds = duration.as_secs();
        let millis = duration.as_millis();

        if seconds >= 1 {
            let subsec_nanos = duration.subsec_nanos();
            let total_seconds = seconds as f64 + subsec_nanos as f64 / 1_000_000_000.0;
            format!("{:.2}s", total_seconds)
        } else if millis >= 1 {
            format!("{}ms", millis)
        } else {
            format!("{}ns", nanos)
        }
    }

    /// Format duration from Duration struct
    ///
    /// # Arguments
    /// * `duration` - Duration struct
    ///
    /// # Returns
    /// Formatted string
    pub fn format_duration_from(duration: Duration) -> String {
        Self::format_duration(duration.as_nanos() as u64)
    }

    /// Pad vector to specified length
    ///
    /// # Arguments
    /// * `vec` - Vector to pad
    /// * `len` - Target length
    /// * `value` - Value to pad with
    ///
    /// # Returns
    /// Padded vector
    pub fn pad_to_length<T: Clone>(vec: Vec<T>, len: usize, value: T) -> Vec<T> {
        let mut result = vec;
        while result.len() < len {
            result.push(value.clone());
        }
        result.truncate(len);
        result
    }

    /// Truncate vector to specified length
    ///
    /// # Arguments
    /// * `vec` - Vector to truncate
    /// * `len` - Target length
    ///
    /// # Returns
    /// Truncated vector
    pub fn truncate_to_length<T>(vec: Vec<T>, len: usize) -> Vec<T> {
        let mut result = vec;
        result.truncate(len);
        result
    }

    /// Check if a number is a power of 2
    ///
    /// # Arguments
    /// * `n` - Number to check
    ///
    /// # Returns
    /// `true` if n is a power of 2, `false` otherwise
    pub fn is_power_of_2(n: u64) -> bool {
        n != 0 && (n & (n - 1)) == 0
    }

    /// Calculate log2 of a number (must be power of 2)
    ///
    /// # Arguments
    /// * `n` - Number (must be power of 2)
    ///
    /// # Returns
    /// `Some(log2)` if n is power of 2, `None` otherwise
    pub fn log2(n: u64) -> Option<u32> {
        if !Self::is_power_of_2(n) {
            return None;
        }

        let mut log = 0;
        let mut temp = n;
        while temp > 1 {
            temp >>= 1;
            log += 1;
        }
        Some(log)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_format_bytes() {
        assert_eq!(Helpers::format_bytes(0), "0 B");
        assert_eq!(Helpers::format_bytes(1024), "1.00 KB");
        assert_eq!(Helpers::format_bytes(1024 * 1024), "1.00 MB");
    }

    #[test]
    fn test_format_duration() {
        let formatted = Helpers::format_duration(1_000_000_000);
        assert!(formatted.contains("s"));

        let formatted = Helpers::format_duration(500_000_000);
        assert!(formatted.contains("ms") || formatted.contains("s"));
    }

    #[test]
    fn test_format_duration_from() {
        let duration = Duration::from_secs(1);
        let formatted = Helpers::format_duration_from(duration);
        assert!(formatted.contains("s"));
    }

    #[test]
    fn test_pad_to_length() {
        let vec = vec![1, 2, 3];
        let padded = Helpers::pad_to_length(vec, 5, 0);
        assert_eq!(padded.len(), 5);
        assert_eq!(padded, vec![1, 2, 3, 0, 0]);
    }

    #[test]
    fn test_truncate_to_length() {
        let vec = vec![1, 2, 3, 4, 5];
        let truncated = Helpers::truncate_to_length(vec, 3);
        assert_eq!(truncated.len(), 3);
        assert_eq!(truncated, vec![1, 2, 3]);
    }

    #[test]
    fn test_is_power_of_2() {
        assert!(Helpers::is_power_of_2(1));
        assert!(Helpers::is_power_of_2(2));
        assert!(Helpers::is_power_of_2(4));
        assert!(Helpers::is_power_of_2(8));
        assert!(Helpers::is_power_of_2(16));
        assert!(!Helpers::is_power_of_2(3));
        assert!(!Helpers::is_power_of_2(5));
        assert!(!Helpers::is_power_of_2(6));
    }

    #[test]
    fn test_log2() {
        assert_eq!(Helpers::log2(1), Some(0));
        assert_eq!(Helpers::log2(2), Some(1));
        assert_eq!(Helpers::log2(4), Some(2));
        assert_eq!(Helpers::log2(8), Some(3));
        assert_eq!(Helpers::log2(16), Some(4));
        assert_eq!(Helpers::log2(3), None);
        assert_eq!(Helpers::log2(5), None);
    }
}
