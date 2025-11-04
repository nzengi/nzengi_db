//! Database commitment module
//!
//! This module provides functionality for creating cryptographic commitments
//! to database tables using the Inner Product Argument (IPA) protocol.
//!
//! The commitment module consists of:
//! - `ipa`: IPA protocol implementation for vector commitments
//! - `database`: Database-level commitment operations
//!
//! # Overview
//!
//! Database commitments allow the prover to commit to a database state
//! without revealing the actual data. This enables:
//! - Proof that queries were executed on the correct database
//! - Verification of database authenticity
//! - Immutable database state tracking
//!
//! # IPA Protocol
//!
//! The Inner Product Argument (IPA) protocol is used for:
//! - Proving time: O(n) linear with circuit size
//! - Verification time: O(log n) logarithmic
//! - Proof size: O(log n) logarithmic
//! - Works on 254-bit prime field
//! - No trusted setup required
//!
//! # Database Commitment
//!
//! A database commitment is a cryptographic representation of a database state,
//! enabling proof of properties about the data without revealing the data itself.
//! This allows the prover to include evidence in the proof that the query was
//! indeed processed on the committed database.
//!
//! # Example
//!
//! ```rust
//! use nzengi_db::commitment::*;
//! use nzengi_db::types::Table;
//!
//! // Generate parameters (one-time process)
//! let params = IPAParams::new(16); // 2^16 = 65536 max rows
//!
//! // Create database commitment
//! let tables = vec![/* your tables */];
//! let commitment = DatabaseCommitment::commit_database(&tables, &params);
//!
//! // Verify commitment
//! assert!(commitment.verify(&params));
//!
//! // Get commitment hash (for blockchain/immutable storage)
//! println!("Commitment hash: {}", commitment.commitment_hash);
//! ```
//!
//! # Performance
//!
//! Database commitment time (for TPC-H benchmark):
//!
//! | Database Size | Time (seconds) |
//! |---------------|----------------|
//! | 60k Rows      | 2.89           |
//! | 120k Rows     | 5.53           |
//! | 240k Rows     | 10.94          |
//!
//! # Public Parameters
//!
//! Public parameters generation (one-time process):
//!
//! | Max Rows (2^k) | Time (seconds) |
//! |----------------|----------------|
//! | 2^15           | 104            |
//! | 2^16           | 221            |
//! | 2^17           | 410            |
//! | 2^18           | 832            |
//!
//! Once generated, these parameters can be reused for all queries
//! as long as the circuit size doesn't exceed the maximum.

pub mod database;
pub mod ipa;

// Re-export main types for convenience
pub use database::{ColumnCommitment, DatabaseCommitment, TableCommitment};
pub use ipa::{IPAParams, VectorCommitment};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Column, DataType, Row, Table, Value};

    #[test]
    fn test_commitment_workflow() {
        // Create a simple table
        let table = Table {
            name: "test_table".to_string(),
            columns: vec![
                Column::new("id".to_string(), DataType::Integer),
                Column::new("value".to_string(), DataType::Integer),
            ],
            rows: vec![
                Row::new(vec![Value::Integer(1), Value::Integer(10)]),
                Row::new(vec![Value::Integer(2), Value::Integer(20)]),
            ],
        };

        // Generate parameters (small k for testing)
        let params = IPAParams::new(10); // 2^10 = 1024 max rows

        // Create database commitment
        let commitment = DatabaseCommitment::commit_database(&[table], &params);

        // Verify commitment
        assert!(commitment.verify(&params));

        // Check commitment hash exists
        assert!(!commitment.commitment_hash.is_empty());
    }

    #[test]
    fn test_table_commitment_access() {
        let table = Table {
            name: "users".to_string(),
            columns: vec![Column::new("id".to_string(), DataType::Integer)],
            rows: vec![Row::new(vec![Value::Integer(1)])],
        };

        let params = IPAParams::new(10);
        let commitment = DatabaseCommitment::commit_database(&[table], &params);

        // Get table commitment
        let table_commitment = commitment.get_table_commitment("users");
        assert!(table_commitment.is_some());

        let table_commitment = table_commitment.unwrap();
        assert_eq!(table_commitment.table_name, "users");
        assert_eq!(table_commitment.column_commitments.len(), 1);
    }

    #[test]
    fn test_multiple_tables_commitment() {
        let table1 = Table {
            name: "table1".to_string(),
            columns: vec![Column::new("col1".to_string(), DataType::Integer)],
            rows: vec![Row::new(vec![Value::Integer(1)])],
        };

        let table2 = Table {
            name: "table2".to_string(),
            columns: vec![Column::new("col2".to_string(), DataType::Integer)],
            rows: vec![Row::new(vec![Value::Integer(2)])],
        };

        let params = IPAParams::new(10);
        let commitment = DatabaseCommitment::commit_database(&[table1, table2], &params);

        assert_eq!(commitment.table_commitments.len(), 2);
        assert!(commitment.get_table_commitment("table1").is_some());
        assert!(commitment.get_table_commitment("table2").is_some());
    }
}
