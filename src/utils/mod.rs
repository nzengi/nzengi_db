//! Utilities module
//!
//! This module provides utility functions for common operations:
//! - Helper functions
//! - Logging utilities
//! - Common utilities
//!
//! # Example
//!
//! ```rust
//! use nzengi_db::utils::{Logger, Helpers};
//!
//! // Initialize logger
//! Logger::init();
//!
//! // Log message
//! Logger::info("Application started");
//!
//! // Helper function
//! let formatted = Helpers::format_bytes(1024);
//! ```

pub mod helpers;
pub mod logger;

// Re-export main types for convenience
pub use helpers::Helpers;
pub use logger::Logger;
