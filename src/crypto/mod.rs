//! Cryptographic primitives module
//!
//! This module provides cryptographic functionality including:
//! - Hash functions (SHA-256, Blake2)
//! - Random number generation
//! - Cryptographic utilities
//!
//! # Example
//!
//! ```rust
//! use nzengi_db::crypto::{HashUtils, RandomUtils};
//!
//! // Hash data
//! let hash = HashUtils::sha256("Hello, World!");
//! println!("SHA-256 hash: {}", hash);
//!
//! // Generate random bytes
//! let random_bytes = RandomUtils::generate_bytes(32);
//! ```

pub mod hash;
pub mod random;

// Re-export main types for convenience
pub use hash::HashUtils;
pub use random::RandomUtils;
