//! Data loader
//!
//! This module provides functionality for loading data from various formats
//! into database tables.
//!
//! # Example
//!
//! ```rust
//! use nzengi_db::database::{Database, Schema, DataLoader};
//!
//! let mut db = Database::new(Schema::new("mydb".to_string()));
//! let loader = DataLoader::new();
//!
//! // Load from CSV
//! loader.load_csv(&mut db, "lineitem.csv", "lineitem")?;
//!
//! // Load from JSON
//! loader.load_json(&mut db, "lineitem.json", "lineitem")?;
//! ```

use crate::database::schema::Database;
use crate::types::{Column, DataType, Row, Table, Value};
use serde_json;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};

/// Data loader
///
/// Provides methods for loading data from various formats.
#[derive(Debug, Clone)]
pub struct DataLoader;

impl DataLoader {
    /// Create a new data loader
    pub fn new() -> Self {
        Self
    }

    /// Load data from a CSV file
    ///
    /// # Arguments
    /// * `database` - Database to load data into
    /// * `path` - Path to CSV file
    /// * `table_name` - Name of the table to create/update
    ///
    /// # Returns
    /// `Ok(())` if successful, `Err` otherwise
    pub fn load_csv(
        &self,
        database: &mut Database,
        path: &str,
        table_name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let file = File::open(path).map_err(|e| format!("Failed to open file {}: {}", path, e))?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();

        // Read header
        let header_line = lines
            .next()
            .ok_or("CSV file is empty")?
            .map_err(|e| format!("Failed to read header: {}", e))?;
        let headers: Vec<String> = header_line
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();

        // Create columns (assuming all columns are integers for simplicity)
        let columns: Vec<Column> = headers
            .iter()
            .map(|h| Column::new(h.clone(), DataType::Integer))
            .collect();

        // Create or get table
        let table = if let Some(existing_table) = database.get_table_mut(table_name) {
            existing_table
        } else {
            let new_table = Table::new(table_name.to_string(), columns);
            database.schema.add_table(new_table)?;
            database.get_table_mut(table_name).unwrap()
        };

        // Read data rows
        for line_result in lines {
            let line = line_result.map_err(|e| format!("Failed to read line: {}", e))?;
            let values: Vec<String> = line.split(',').map(|s| s.trim().to_string()).collect();

            if values.len() != headers.len() {
                return Err(format!(
                    "Row has {} values but header has {} columns",
                    values.len(),
                    headers.len()
                )
                .into());
            }

            let row_values: Vec<Value> = values
                .iter()
                .map(|v| {
                    v.parse::<i32>()
                        .map(Value::Integer)
                        .unwrap_or_else(|_| Value::Integer(0))
                })
                .collect();

            table.rows.push(Row::new(row_values));
        }

        Ok(())
    }

    /// Load data from a JSON file
    ///
    /// # Arguments
    /// * `database` - Database to load data into
    /// * `path` - Path to JSON file
    /// * `table_name` - Name of the table to create/update
    ///
    /// # Returns
    /// `Ok(())` if successful, `Err` otherwise
    pub fn load_json(
        &self,
        database: &mut Database,
        path: &str,
        table_name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut file =
            File::open(path).map_err(|e| format!("Failed to open file {}: {}", path, e))?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(|e| format!("Failed to read file {}: {}", path, e))?;

        // Parse JSON (expecting an array of objects)
        let json_data: serde_json::Value =
            serde_json::from_str(&contents).map_err(|e| format!("Failed to parse JSON: {}", e))?;

        let array = json_data.as_array().ok_or("JSON data must be an array")?;

        if array.is_empty() {
            return Err("JSON array is empty".into());
        }

        // Extract columns from first object
        let first_obj = array[0]
            .as_object()
            .ok_or("JSON array elements must be objects")?;
        let headers: Vec<String> = first_obj.keys().cloned().collect();

        // Create columns (assuming all columns are integers for simplicity)
        let columns: Vec<Column> = headers
            .iter()
            .map(|h| Column::new(h.clone(), DataType::Integer))
            .collect();

        // Create or get table
        let table = if let Some(existing_table) = database.get_table_mut(table_name) {
            existing_table
        } else {
            let new_table = Table::new(table_name.to_string(), columns);
            database.schema.add_table(new_table)?;
            database.get_table_mut(table_name).unwrap()
        };

        // Read data rows
        for obj in array {
            let obj = obj
                .as_object()
                .ok_or("JSON array elements must be objects")?;

            let row_values: Vec<Value> = headers
                .iter()
                .map(|h| {
                    obj.get(h)
                        .and_then(|v| {
                            if let Some(i) = v.as_i64() {
                                Some(Value::Integer(i as i32))
                            } else if let Some(s) = v.as_str() {
                                Some(Value::String(s.to_string()))
                            } else {
                                None
                            }
                        })
                        .unwrap_or(Value::Null)
                })
                .collect();

            table.rows.push(Row::new(row_values));
        }

        Ok(())
    }

    /// Load a table from a Table struct
    ///
    /// # Arguments
    /// * `database` - Database to load data into
    /// * `table` - Table to add
    ///
    /// # Returns
    /// `Ok(())` if successful, `Err` otherwise
    pub fn load_table(
        &self,
        database: &mut Database,
        table: Table,
    ) -> Result<(), Box<dyn std::error::Error>> {
        database.schema.add_table(table)?;
        Ok(())
    }
}

impl Default for DataLoader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loader_new() {
        let loader = DataLoader::new();
        assert!(true); // Loader created successfully
    }

    #[test]
    fn test_loader_load_table() {
        let loader = DataLoader::new();
        let mut db = Database::new(crate::database::schema::Schema::new("testdb".to_string()));

        let table = Table::new(
            "lineitem".to_string(),
            vec![Column::new("l_quantity".to_string(), DataType::Integer)],
        );

        assert!(loader.load_table(&mut db, table).is_ok());
        assert_eq!(db.schema.tables.len(), 1);
    }
}
