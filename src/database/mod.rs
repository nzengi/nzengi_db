//! Database management module
//!
//! This module provides functionality for managing database schemas, storage,
//! and data loading.
//!
//! The database management module consists of:
//! - `schema`: Schema management and validation
//! - `storage`: Database storage and persistence
//! - `loader`: Data loading from files
//! - `tpch`: TPC-H benchmark data support
//!
//! # Overview
//!
//! The database management system enables:
//! - Schema definition and validation
//! - Database persistence (save/load)
//! - Data loading from various formats
//! - TPC-H benchmark data generation
//!
//! # Example
//!
//! ```rust
//! use nzengi_db::database::{Database, Schema, DataLoader};
//!
//! // Create database with schema
//! let schema = Schema::new("mydb".to_string());
//! let mut db = Database::new(schema);
//!
//! // Load data
//! let loader = DataLoader::new();
//! loader.load_table(&mut db, "lineitem.csv")?;
//!
//! // Save database
//! db.save("mydb.json")?;
//! ```

pub mod loader;
pub mod schema;
pub mod storage;
pub mod tpch;

// Re-export main types for convenience
pub use loader::DataLoader;
pub use schema::{Database, Schema};
pub use storage::DatabaseStorage;
pub use tpch::TPCHData;
