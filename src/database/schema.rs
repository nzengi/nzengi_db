//! Database schema management
//!
//! This module provides functionality for managing database schemas,
//! including table definitions and validation.
//!
//! # Example
//!
//! ```rust
//! use nzengi_db::database::{Database, Schema};
//! use nzengi_db::types::{Table, Column, DataType};
//!
//! // Create schema
//! let mut schema = Schema::new("mydb".to_string());
//!
//! // Add table
//! let table = Table::new(
//!     "lineitem".to_string(),
//!     vec![
//!         Column::new("l_quantity".to_string(), DataType::Integer),
//!         Column::new("l_extendedprice".to_string(), DataType::Decimal),
//!     ],
//! );
//! schema.add_table(table)?;
//!
//! // Create database
//! let db = Database::new(schema);
//! ```

use crate::types::Table;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Database schema
///
/// Represents the schema of a database, including all table definitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schema {
    /// Database name
    pub name: String,

    /// Table definitions (name -> table)
    pub tables: HashMap<String, Table>,
}

impl Schema {
    /// Create a new database schema
    ///
    /// # Arguments
    /// * `name` - Database name
    pub fn new(name: String) -> Self {
        Self {
            name,
            tables: HashMap::new(),
        }
    }

    /// Add a table to the schema
    ///
    /// # Arguments
    /// * `table` - Table to add
    ///
    /// # Returns
    /// `Ok(())` if successful, `Err` if table already exists
    pub fn add_table(&mut self, table: Table) -> Result<(), Box<dyn std::error::Error>> {
        if self.tables.contains_key(&table.name) {
            return Err(format!("Table {} already exists", table.name).into());
        }
        self.tables.insert(table.name.clone(), table);
        Ok(())
    }

    /// Get a table by name
    ///
    /// # Arguments
    /// * `name` - Table name
    ///
    /// # Returns
    /// `Some(Table)` if found, `None` otherwise
    pub fn get_table(&self, name: &str) -> Option<&Table> {
        self.tables.get(name)
    }

    /// Get a mutable reference to a table
    ///
    /// # Arguments
    /// * `name` - Table name
    ///
    /// # Returns
    /// `Some(&mut Table)` if found, `None` otherwise
    pub fn get_table_mut(&mut self, name: &str) -> Option<&mut Table> {
        self.tables.get_mut(name)
    }

    /// Validate the schema
    ///
    /// Checks that all tables have valid column definitions.
    ///
    /// # Returns
    /// `Ok(())` if valid, `Err` otherwise
    pub fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        for (name, table) in &self.tables {
            if table.columns.is_empty() {
                return Err(format!("Table {} has no columns", name).into());
            }

            // Check for duplicate column names
            let mut column_names = std::collections::HashSet::new();
            for column in &table.columns {
                if !column_names.insert(&column.name) {
                    return Err(
                        format!("Table {} has duplicate column: {}", name, column.name).into(),
                    );
                }
            }

            // Validate that all rows match the schema
            for (row_idx, row) in table.rows.iter().enumerate() {
                if row.values.len() != table.columns.len() {
                    return Err(format!(
                        "Table {} row {} has {} values but schema has {} columns",
                        name,
                        row_idx,
                        row.values.len(),
                        table.columns.len()
                    )
                    .into());
                }
            }
        }

        Ok(())
    }

    /// Get all table names
    pub fn table_names(&self) -> Vec<String> {
        self.tables.keys().cloned().collect()
    }
}

/// Database
///
/// Represents a complete database with schema and data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Database {
    /// Database schema
    pub schema: Schema,
}

impl Database {
    /// Create a new database
    ///
    /// # Arguments
    /// * `schema` - Database schema
    pub fn new(schema: Schema) -> Self {
        Self { schema }
    }

    /// Get a table by name
    ///
    /// # Arguments
    /// * `name` - Table name
    ///
    /// # Returns
    /// `Some(&Table)` if found, `None` otherwise
    pub fn get_table(&self, name: &str) -> Option<&Table> {
        self.schema.get_table(name)
    }

    /// Get a mutable reference to a table
    ///
    /// # Arguments
    /// * `name` - Table name
    ///
    /// # Returns
    /// `Some(&mut Table)` if found, `None` otherwise
    pub fn get_table_mut(&mut self, name: &str) -> Option<&mut Table> {
        self.schema.get_table_mut(name)
    }

    /// Validate the database
    ///
    /// Validates both schema and data.
    ///
    /// # Returns
    /// `Ok(())` if valid, `Err` otherwise
    pub fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.schema.validate()
    }

    /// Get all table names
    pub fn table_names(&self) -> Vec<String> {
        self.schema.table_names()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Column, DataType};

    #[test]
    fn test_schema_new() {
        let schema = Schema::new("testdb".to_string());
        assert_eq!(schema.name, "testdb");
        assert!(schema.tables.is_empty());
    }

    #[test]
    fn test_schema_add_table() {
        let mut schema = Schema::new("testdb".to_string());
        let table = Table::new(
            "lineitem".to_string(),
            vec![Column::new("l_quantity".to_string(), DataType::Integer)],
        );
        assert!(schema.add_table(table).is_ok());
        assert_eq!(schema.tables.len(), 1);
    }

    #[test]
    fn test_schema_add_duplicate_table() {
        let mut schema = Schema::new("testdb".to_string());
        let table = Table::new(
            "lineitem".to_string(),
            vec![Column::new("l_quantity".to_string(), DataType::Integer)],
        );
        schema.add_table(table.clone()).unwrap();
        assert!(schema.add_table(table).is_err());
    }

    #[test]
    fn test_schema_validate() {
        let mut schema = Schema::new("testdb".to_string());
        let table = Table::new(
            "lineitem".to_string(),
            vec![Column::new("l_quantity".to_string(), DataType::Integer)],
        );
        schema.add_table(table).unwrap();
        assert!(schema.validate().is_ok());
    }

    #[test]
    fn test_database_new() {
        let schema = Schema::new("testdb".to_string());
        let db = Database::new(schema);
        assert_eq!(db.schema.name, "testdb");
    }

    #[test]
    fn test_database_validate() {
        let mut schema = Schema::new("testdb".to_string());
        let table = Table::new(
            "lineitem".to_string(),
            vec![Column::new("l_quantity".to_string(), DataType::Integer)],
        );
        schema.add_table(table).unwrap();
        let db = Database::new(schema);
        assert!(db.validate().is_ok());
    }
}
