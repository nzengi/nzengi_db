//! API client
//!
//! This module provides HTTP client functionality for interacting with the API server.
//!
//! # Example
//!
//! ```rust,no_run
//! use nzengi_db::api::ApiClient;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = ApiClient::new("http://127.0.0.1:8080");
//!
//!     // Execute query
//!     let response = client.execute_query("SELECT COUNT(*) FROM lineitem").await?;
//!     println!("Result: {:?}", response.result);
//!
//!     // Verify proof
//!     let valid = client.verify_proof(&response.proof, &response.public_inputs).await?;
//!     println!("Proof valid: {}", valid);
//!
//!     Ok(())
//! }
//! ```

#[cfg(feature = "api")]
use crate::api::server::{
    ExecuteQueryRequest, ExecuteQueryResponse, VerifyProofRequest, VerifyProofResponse,
};
#[cfg(feature = "api")]
use serde_json;

/// API client
///
/// Provides methods for interacting with the nzengi_db API server.
#[cfg(feature = "api")]
pub struct ApiClient {
    /// Base URL of the API server
    base_url: String,
}

#[cfg(feature = "api")]
impl ApiClient {
    /// Create a new API client
    ///
    /// # Arguments
    /// * `base_url` - Base URL of the API server (e.g., "http://127.0.0.1:8080")
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
        }
    }

    /// Execute a query
    ///
    /// # Arguments
    /// * `query` - SQL query string
    ///
    /// # Returns
    /// `Ok(ExecuteQueryResponse)` if successful, `Err` otherwise
    pub async fn execute_query(
        &self,
        query: &str,
    ) -> Result<ExecuteQueryResponse, Box<dyn std::error::Error>> {
        let client = reqwest::Client::new();
        let url = format!("{}/query", self.base_url);

        let request = ExecuteQueryRequest {
            query: query.to_string(),
        };

        let response = client.post(&url).json(&request).send().await?;

        if !response.status().is_success() {
            return Err(format!("API request failed: {}", response.status()).into());
        }

        let result: ExecuteQueryResponse = response.json().await?;
        Ok(result)
    }

    /// Verify a proof
    ///
    /// # Arguments
    /// * `proof` - Proof bytes (hex-encoded)
    /// * `public_inputs` - Public inputs (hex-encoded)
    ///
    /// # Returns
    /// `Ok(bool)` if verification succeeds, `Err` otherwise
    pub async fn verify_proof(
        &self,
        proof: &str,
        public_inputs: &[String],
    ) -> Result<bool, Box<dyn std::error::Error>> {
        #[cfg(feature = "reqwest")]
        {
            let client = reqwest::Client::new();
            let url = format!("{}/verify", self.base_url);

            let request = VerifyProofRequest {
                proof: proof.to_string(),
                public_inputs: public_inputs.to_vec(),
            };

            let response = client.post(&url).json(&request).send().await?;

            if !response.status().is_success() {
                return Err(format!("API request failed: {}", response.status()).into());
            }

            let result: VerifyProofResponse = response.json().await?;
            Ok(result.valid)
        }
        #[cfg(not(feature = "reqwest"))]
        Err("reqwest feature not enabled".into())
    }

    /// Health check
    ///
    /// # Returns
    /// `Ok(())` if server is healthy, `Err` otherwise
    pub async fn health_check(&self) -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(feature = "reqwest")]
        {
            let client = reqwest::Client::new();
            let url = format!("{}/health", self.base_url);

            let response = client.get(&url).send().await?;

            if !response.status().is_success() {
                return Err(format!("Health check failed: {}", response.status()).into());
            }

            Ok(())
        }
        #[cfg(not(feature = "reqwest"))]
        Err("reqwest feature not enabled".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "api")]
    #[test]
    fn test_api_client_new() {
        let client = ApiClient::new("http://127.0.0.1:8080");
        assert_eq!(client.base_url, "http://127.0.0.1:8080");
    }
}
