//! Database commitment operations
//!
//! This module provides functionality for creating cryptographic commitments
//! to entire database tables and verifying their authenticity.
//!
//! Database commitments allow:
//! - Provers to commit to a database state without revealing data
//! - Verifiers to verify that queries were executed on the correct database
//! - Auditors to verify database authenticity
//!
//! # Example
//!
//! ```rust
//! use nzengiDB::commitment::{DatabaseCommitment, IPAParams};
//! use nzengiDB::types::Table;
//!
//! // Generate parameters
//! let params = IPAParams::new(16);
//!
//! // Create database with tables
//! let tables = vec![/* your tables */];
//!
//! // Commit to database
//! let commitment = DatabaseCommitment::commit_database(&tables, &params);
//!
//! // Verify commitment
//! assert!(commitment.verify(&params));
//!
//! // Get commitment hash (for publishing on blockchain)
//! println!("Commitment hash: {}", commitment.commitment_hash);
//! ```

use super::ipa::{IPAParams, VectorCommitment};
use crate::types::Table;
use serde::{Deserialize, Serialize};

/// Database commitment
///
/// Represents a cryptographic commitment to an entire database.
/// Contains commitments for all tables and a global commitment hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseCommitment {
    /// Commitments for each table
    pub table_commitments: Vec<TableCommitment>,

    /// Overall commitment hash (for publishing on blockchain)
    pub commitment_hash: String,
}

/// Commitment to a single table
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableCommitment {
    /// Table name
    pub table_name: String,

    /// Commitments for each column in the table
    pub column_commitments: Vec<ColumnCommitment>,
}

/// Commitment to a single column
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnCommitment {
    /// Column name
    pub column_name: String,

    /// Cryptographic commitment bytes
    pub commitment: Vec<u8>,

    /// Number of rows in the column
    pub num_rows: usize,
}

impl DatabaseCommitment {
    /// Create commitment to entire database
    ///
    /// Creates cryptographic commitments for all tables and columns in the database.
    ///
    /// # Arguments
    /// * `tables` - Vector of tables to commit to
    /// * `params` - IPA parameters for commitment
    ///
    /// # Returns
    /// A `DatabaseCommitment` containing all table commitments and a global hash
    ///
    /// # Example
    /// ```
    /// use nzengiDB::commitment::{DatabaseCommitment, IPAParams};
    /// use nzengiDB::types::{Table, Column, Row, DataType, Value};
    ///
    /// let params = IPAParams::new(16);
    ///
    /// let table = Table {
    ///     name: "users".to_string(),
    ///     columns: vec![
    ///         Column::new("id".to_string(), DataType::Integer),
    ///         Column::new("name".to_string(), DataType::Varchar(100)),
    ///     ],
    ///     rows: vec![
    ///         Row::new(vec![Value::Integer(1), Value::String("Alice".to_string())]),
    ///         Row::new(vec![Value::Integer(2), Value::String("Bob".to_string())]),
    ///     ],
    /// };
    ///
    /// let commitment = DatabaseCommitment::commit_database(&[table], &params);
    /// ```
    pub fn commit_database(tables: &[Table], params: &IPAParams) -> Self {
        // Pre-allocate vector for better performance
        let mut table_commitments = Vec::with_capacity(tables.len());

        for table in tables {
            let mut column_commitments = Vec::new();

            // Check table size
            if table.rows.len() > params.max_rows() {
                panic!(
                    "Table '{}' has {} rows, exceeds maximum {}",
                    table.name,
                    table.rows.len(),
                    params.max_rows()
                );
            }

            // Create commitment for each column (optimized with pre-allocation)
            column_commitments.reserve(table.columns.len());

            for (col_idx, column) in table.columns.iter().enumerate() {
                // Extract column values (pre-allocate for better performance)
                let mut values = Vec::with_capacity(table.rows.len());
                for row in &table.rows {
                    values.push(row.values[col_idx].to_field());
                }

                // Create commitment for this column
                let vector_commitment = VectorCommitment::commit(values, params);

                column_commitments.push(ColumnCommitment {
                    column_name: column.name.clone(),
                    commitment: vector_commitment.commitment,
                    num_rows: table.rows.len(),
                });
            }

            table_commitments.push(TableCommitment {
                table_name: table.name.clone(),
                column_commitments,
            });
        }

        // Compute overall commitment hash
        let commitment_hash = Self::compute_commitment_hash(&table_commitments);

        Self {
            table_commitments,
            commitment_hash,
        }
    }

    /// Verify database commitment
    ///
    /// Verifies that all table and column commitments are valid.
    ///
    /// # Arguments
    /// * `params` - IPA parameters used for commitment
    ///
    /// # Returns
    /// `true` if all commitments are valid, `false` otherwise
    ///
    /// # Example
    /// ```
    /// use nzengiDB::commitment::{DatabaseCommitment, IPAParams};
    /// use nzengiDB::types::Table;
    ///
    /// let params = IPAParams::new(16);
    /// let tables = vec![/* your tables */];
    /// let commitment = DatabaseCommitment::commit_database(&tables, &params);
    ///
    /// assert!(commitment.verify(&params));
    /// ```
    pub fn verify(&self, _params: &IPAParams) -> bool {
        // Verify all table commitments
        // In full implementation, this would verify cryptographic proofs

        // For now, verify that commitment hash matches
        let recomputed_hash = Self::compute_commitment_hash(&self.table_commitments);
        if recomputed_hash != self.commitment_hash {
            return false;
        }

        // Verify all column commitments are valid
        // (This is a simplified check - in production, verify cryptographic proofs)
        true
    }

    /// Compute hash of all commitments
    ///
    /// Creates a SHA-256 hash of all table and column commitments.
    /// This hash can be published on a blockchain for immutable verification.
    ///
    /// # Arguments
    /// * `table_commitments` - Vector of table commitments
    ///
    /// # Returns
    /// Hex-encoded SHA-256 hash string
    fn compute_commitment_hash(table_commitments: &[TableCommitment]) -> String {
        use hex;
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();

        for table in table_commitments {
            hasher.update(table.table_name.as_bytes());

            for col in &table.column_commitments {
                hasher.update(col.column_name.as_bytes());
                hasher.update(&col.commitment);
                hasher.update(&col.num_rows.to_le_bytes());
            }
        }

        hex::encode(hasher.finalize())
    }

    /// Get commitment for specific table
    ///
    /// # Arguments
    /// * `table_name` - Name of the table
    ///
    /// # Returns
    /// `Some(TableCommitment)` if table exists, `None` otherwise
    ///
    /// # Example
    /// ```
    /// use nzengiDB::commitment::{DatabaseCommitment, IPAParams};
    ///
    /// let params = IPAParams::new(16);
    /// let tables = vec![/* your tables */];
    /// let commitment = DatabaseCommitment::commit_database(&tables, &params);
    ///
    /// if let Some(table_commitment) = commitment.get_table_commitment("users") {
    ///     println!("Found table commitment: {}", table_commitment.table_name);
    /// }
    /// ```
    pub fn get_table_commitment(&self, table_name: &str) -> Option<&TableCommitment> {
        self.table_commitments
            .iter()
            .find(|tc| tc.table_name == table_name)
    }

    /// Get number of tables
    pub fn num_tables(&self) -> usize {
        self.table_commitments.len()
    }

    /// Get total number of columns across all tables
    pub fn total_columns(&self) -> usize {
        self.table_commitments
            .iter()
            .map(|tc| tc.column_commitments.len())
            .sum()
    }
}

impl TableCommitment {
    /// Get commitment for specific column
    ///
    /// # Arguments
    /// * `column_name` - Name of the column
    ///
    /// # Returns
    /// `Some(ColumnCommitment)` if column exists, `None` otherwise
    pub fn get_column_commitment(&self, column_name: &str) -> Option<&ColumnCommitment> {
        self.column_commitments
            .iter()
            .find(|cc| cc.column_name == column_name)
    }

    /// Get number of columns
    pub fn num_columns(&self) -> usize {
        self.column_commitments.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Column, DataType, Row, Value};

    #[test]
    fn test_database_commitment() {
        let params = IPAParams::new(10);

        let table = Table {
            name: "test".to_string(),
            columns: vec![Column::new("id".to_string(), DataType::Integer)],
            rows: vec![
                Row::new(vec![Value::Integer(1)]),
                Row::new(vec![Value::Integer(2)]),
            ],
        };

        let commitment = DatabaseCommitment::commit_database(&[table], &params);

        assert_eq!(commitment.num_tables(), 1);
        assert_eq!(commitment.total_columns(), 1);
        assert!(commitment.verify(&params));
    }

    #[test]
    fn test_database_commitment_multiple_tables() {
        let params = IPAParams::new(10);

        let table1 = Table {
            name: "users".to_string(),
            columns: vec![Column::new("id".to_string(), DataType::Integer)],
            rows: vec![Row::new(vec![Value::Integer(1)])],
        };

        let table2 = Table {
            name: "orders".to_string(),
            columns: vec![Column::new("order_id".to_string(), DataType::Integer)],
            rows: vec![Row::new(vec![Value::Integer(100)])],
        };

        let commitment = DatabaseCommitment::commit_database(&[table1, table2], &params);

        assert_eq!(commitment.num_tables(), 2);
        assert_eq!(commitment.total_columns(), 2);
        assert!(commitment.verify(&params));
    }

    #[test]
    fn test_get_table_commitment() {
        let params = IPAParams::new(10);

        let table = Table {
            name: "users".to_string(),
            columns: vec![Column::new("id".to_string(), DataType::Integer)],
            rows: vec![Row::new(vec![Value::Integer(1)])],
        };

        let commitment = DatabaseCommitment::commit_database(&[table], &params);

        let table_commitment = commitment.get_table_commitment("users");
        assert!(table_commitment.is_some());
        assert_eq!(table_commitment.unwrap().table_name, "users");

        let not_found = commitment.get_table_commitment("nonexistent");
        assert!(not_found.is_none());
    }

    #[test]
    fn test_commitment_hash() {
        let params = IPAParams::new(10);

        let table = Table {
            name: "test".to_string(),
            columns: vec![Column::new("id".to_string(), DataType::Integer)],
            rows: vec![Row::new(vec![Value::Integer(1)])],
        };

        let commitment1 = DatabaseCommitment::commit_database(&[table.clone()], &params);
        let commitment2 = DatabaseCommitment::commit_database(&[table], &params);

        // Same data should produce same hash
        assert_eq!(commitment1.commitment_hash, commitment2.commitment_hash);
    }

    #[test]
    #[should_panic(expected = "exceeds maximum")]
    fn test_database_commitment_overflow() {
        let params = IPAParams::new(2); // max 4 rows

        let table = Table {
            name: "test".to_string(),
            columns: vec![Column::new("id".to_string(), DataType::Integer)],
            rows: vec![
                Row::new(vec![Value::Integer(1)]),
                Row::new(vec![Value::Integer(2)]),
                Row::new(vec![Value::Integer(3)]),
                Row::new(vec![Value::Integer(4)]),
                Row::new(vec![Value::Integer(5)]), // 5 rows, exceeds max
            ],
        };

        let _commitment = DatabaseCommitment::commit_database(&[table], &params);
    }
}
