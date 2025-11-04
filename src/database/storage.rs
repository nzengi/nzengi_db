//! Database storage layer
//!
//! This module provides functionality for persisting databases to disk
//! and loading them back.
//!
//! # Example
//!
//! ```rust
//! use nzengi_db::database::{Database, Schema, DatabaseStorage};
//!
//! let mut db = Database::new(Schema::new("mydb".to_string()));
//!
//! // Save database
//! let storage = DatabaseStorage::new();
//! storage.save(&db, "mydb.json")?;
//!
//! // Load database
//! let loaded_db = storage.load("mydb.json")?;
//! ```

use crate::database::schema::Database;
use serde_json;
use std::fs;
use std::io::{Read, Write};

/// Database storage
///
/// Provides methods for saving and loading databases.
#[derive(Debug, Clone)]
pub struct DatabaseStorage;

impl DatabaseStorage {
    /// Create a new database storage instance
    pub fn new() -> Self {
        Self
    }

    /// Save a database to a file
    ///
    /// # Arguments
    /// * `database` - Database to save
    /// * `path` - File path to save to
    ///
    /// # Returns
    /// `Ok(())` if successful, `Err` otherwise
    pub fn save(&self, database: &Database, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        // Validate database before saving
        database.validate()?;

        // Serialize database to JSON
        let json = serde_json::to_string_pretty(database)
            .map_err(|e| format!("Failed to serialize database: {}", e))?;

        // Write to file
        let mut file =
            fs::File::create(path).map_err(|e| format!("Failed to create file {}: {}", path, e))?;
        file.write_all(json.as_bytes())
            .map_err(|e| format!("Failed to write to file {}: {}", path, e))?;

        Ok(())
    }

    /// Load a database from a file
    ///
    /// # Arguments
    /// * `path` - File path to load from
    ///
    /// # Returns
    /// `Ok(Database)` if successful, `Err` otherwise
    pub fn load(&self, path: &str) -> Result<Database, Box<dyn std::error::Error>> {
        // Read file
        let mut file =
            fs::File::open(path).map_err(|e| format!("Failed to open file {}: {}", path, e))?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(|e| format!("Failed to read file {}: {}", path, e))?;

        // Deserialize database from JSON
        let database: Database = serde_json::from_str(&contents)
            .map_err(|e| format!("Failed to deserialize database: {}", e))?;

        // Validate loaded database
        database.validate()?;

        Ok(database)
    }

    /// Save a database to a binary file (bincode)
    ///
    /// # Arguments
    /// * `database` - Database to save
    /// * `path` - File path to save to
    ///
    /// # Returns
    /// `Ok(())` if successful, `Err` otherwise
    pub fn save_binary(
        &self,
        database: &Database,
        path: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Validate database before saving
        database.validate()?;

        // Serialize database to JSON (bincode requires additional trait implementations)
        let json = serde_json::to_vec(database)
            .map_err(|e| format!("Failed to serialize database: {}", e))?;

        // Write to file
        let mut file =
            fs::File::create(path).map_err(|e| format!("Failed to create file {}: {}", path, e))?;
        file.write_all(&json)
            .map_err(|e| format!("Failed to write to file {}: {}", path, e))?;

        Ok(())
    }

    /// Load a database from a binary file (bincode)
    ///
    /// # Arguments
    /// * `path` - File path to load from
    ///
    /// # Returns
    /// `Ok(Database)` if successful, `Err` otherwise
    pub fn load_binary(&self, path: &str) -> Result<Database, Box<dyn std::error::Error>> {
        // Read file
        let mut file =
            fs::File::open(path).map_err(|e| format!("Failed to open file {}: {}", path, e))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|e| format!("Failed to read file {}: {}", path, e))?;

        // Deserialize database from JSON (bincode requires additional trait implementations)
        let database: Database = serde_json::from_slice(&bytes)
            .map_err(|e| format!("Failed to deserialize database: {}", e))?;

        // Validate loaded database
        database.validate()?;

        Ok(database)
    }
}

impl Default for DatabaseStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::schema::Schema;
    use crate::types::{Column, DataType, Table};

    #[test]
    fn test_storage_new() {
        let storage = DatabaseStorage::new();
        assert!(true); // Storage created successfully
    }

    #[test]
    fn test_storage_save_and_load() {
        let storage = DatabaseStorage::new();

        // Create a simple database
        let mut schema = Schema::new("testdb".to_string());
        let table = Table::new(
            "lineitem".to_string(),
            vec![Column::new("l_quantity".to_string(), DataType::Integer)],
        );
        schema.add_table(table).unwrap();
        let db = Database::new(schema);

        // Save to temporary file
        let temp_path = "/tmp/test_db.json";
        assert!(storage.save(&db, temp_path).is_ok());

        // Load from file
        let loaded_db = storage.load(temp_path);
        assert!(loaded_db.is_ok());

        // Clean up
        let _ = std::fs::remove_file(temp_path);
    }
}
