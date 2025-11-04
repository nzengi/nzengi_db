//! NzengiDB: Efficient Non-interactive Zero-Knowledge Proofs for SQL Queries
//!
//! This library provides a database system that uses zero-knowledge proofs
//! to ensure both data confidentiality and query result provability.
//!
//! # Example
//!
//! ```no_run
//! use nzengi_db::*;
//!
//! // Create query executor
//! let executor = QueryExecutor::new(database, params, commitment);
//!
//! // Execute query with proof generation
//! let (result, proof) = executor.execute("SELECT COUNT(*) FROM lineitem WHERE l_quantity > 10")?;
//!
//! // Verify proof
//! let verifier = Verifier::new(params);
//! assert!(verifier.verify(&proof, &commitment)?);
//! ```

// Re-export main types (when implemented)
// pub use types::{Table, Column, Row, Value, QueryResult, Proof};
// pub use commitment::DatabaseCommitment;
// pub use query::QueryExecutor;
// pub use proof::{Prover, Verifier};

/// NzengiDB version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// Main modules
pub mod commitment;
pub mod field;
pub mod types;

pub mod circuit;
pub mod crypto;
pub mod database;
pub mod gates;
pub mod proof;
pub mod query;
pub mod utils;

#[cfg(feature = "api")]
pub mod api;
