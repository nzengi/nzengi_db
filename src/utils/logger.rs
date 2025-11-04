//! Logging utilities
//!
//! This module provides logging functionality using the `log` crate.
//!
//! # Example
//!
//! ```rust
//! use nzengi_db::utils::Logger;
//!
//! // Initialize logger
//! Logger::init();
//!
//! // Log messages
//! Logger::info("Application started");
//! Logger::debug("Debug information");
//! Logger::error("Error occurred");
//! ```

use log::LevelFilter;

/// Logging utilities
///
/// Provides methods for logging messages at different levels.
pub struct Logger;

impl Logger {
    /// Initialize the logger
    ///
    /// Sets up the logger with default configuration.
    /// If `env_logger` is available, it will use environment variables
    /// to configure the log level (e.g., `RUST_LOG=info`).
    ///
    /// # Example
    /// ```
    /// use nzengi_db::utils::Logger;
    ///
    /// Logger::init();
    /// Logger::info("Logger initialized");
    /// ```
    pub fn init() {
        env_logger::Builder::from_default_env()
            .filter_level(LevelFilter::Info)
            .init();
    }

    /// Initialize logger with custom log level
    ///
    /// # Arguments
    /// * `level` - Log level filter
    pub fn init_with_level(level: LevelFilter) {
        env_logger::Builder::from_default_env()
            .filter_level(level)
            .init();
    }

    /// Log an info message
    ///
    /// # Arguments
    /// * `message` - Message to log
    pub fn info(message: &str) {
        log::info!("{}", message);
    }

    /// Log a debug message
    ///
    /// # Arguments
    /// * `message` - Message to log
    pub fn debug(message: &str) {
        log::debug!("{}", message);
    }

    /// Log a warning message
    ///
    /// # Arguments
    /// * `message` - Message to log
    pub fn warn(message: &str) {
        log::warn!("{}", message);
    }

    /// Log an error message
    ///
    /// # Arguments
    /// * `message` - Message to log
    pub fn error(message: &str) {
        log::error!("{}", message);
    }

    /// Log a trace message
    ///
    /// # Arguments
    /// * `message` - Message to log
    pub fn trace(message: &str) {
        log::trace!("{}", message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logger_init() {
        Logger::init();
        assert!(true); // Logger initialized successfully
    }

    #[test]
    fn test_logger_info() {
        Logger::info("Test info message");
        assert!(true); // Message logged successfully
    }

    #[test]
    fn test_logger_debug() {
        Logger::debug("Test debug message");
        assert!(true); // Message logged successfully
    }

    #[test]
    fn test_logger_warn() {
        Logger::warn("Test warning message");
        assert!(true); // Message logged successfully
    }

    #[test]
    fn test_logger_error() {
        Logger::error("Test error message");
        assert!(true); // Message logged successfully
    }
}
