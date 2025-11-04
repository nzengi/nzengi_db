//! API layer module
//!
//! This module provides HTTP/REST API functionality for nzengi_db.
//! It is only available when the `api` feature is enabled.
//!
//! # Example
//!
//! ```rust,no_run
//! use nzengi_db::api::{ApiServer, ApiClient};
//!
//! // Start API server
//! let server = ApiServer::new("127.0.0.1:8080".parse().unwrap());
//! server.start().await?;
//!
//! // Use API client
//! let client = ApiClient::new("http://127.0.0.1:8080");
//! let result = client.execute_query("SELECT COUNT(*) FROM lineitem").await?;
//! ```

#[cfg(feature = "api")]
pub mod client;
#[cfg(feature = "api")]
pub mod server;

// Re-export main types when API feature is enabled
#[cfg(feature = "api")]
pub use client::ApiClient;
#[cfg(feature = "api")]
pub use server::ApiServer;
