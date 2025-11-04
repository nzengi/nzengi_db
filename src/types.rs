//! Core types for database operations
//!
//! This module defines the core data structures used throughout nzengiDB:
//! - Tables, columns, and rows
//! - SQL data types and values
//! - Query results and proofs

use halo2_proofs::halo2curves::bn256::Fr as Field;
use serde::{Deserialize, Serialize};

/// Database table representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Table {
    /// Table name
    pub name: String,

    /// Column definitions
    pub columns: Vec<Column>,

    /// Data rows
    pub rows: Vec<Row>,
}

impl Table {
    /// Create a new empty table
    pub fn new(name: String, columns: Vec<Column>) -> Self {
        Self {
            name,
            columns,
            rows: Vec::new(),
        }
    }

    /// Get number of rows
    pub fn num_rows(&self) -> usize {
        self.rows.len()
    }

    /// Get number of columns
    pub fn num_columns(&self) -> usize {
        self.columns.len()
    }

    /// Get column by name
    pub fn get_column(&self, name: &str) -> Option<&Column> {
        self.columns.iter().find(|c| c.name == name)
    }
}

/// Column definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Column {
    /// Column name
    pub name: String,

    /// Data type
    pub data_type: DataType,
}

impl Column {
    /// Create a new column
    pub fn new(name: String, data_type: DataType) -> Self {
        Self { name, data_type }
    }
}

/// SQL data types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DataType {
    /// 32-bit integer
    Integer,

    /// 64-bit integer
    BigInt,

    /// Decimal number (stored as fixed-point integer)
    Decimal,

    /// Variable-length string
    Varchar(usize),

    /// Date (Unix timestamp)
    Date,

    /// Boolean value
    Boolean,
}

/// Database row
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Row {
    /// Row values
    pub values: Vec<Value>,
}

impl Row {
    /// Create a new row
    pub fn new(values: Vec<Value>) -> Self {
        Self { values }
    }

    /// Get value at column index
    pub fn get_value(&self, index: usize) -> Option<&Value> {
        self.values.get(index)
    }

    /// Get value by column name (requires table reference)
    pub fn get_value_by_name(&self, table: &Table, column_name: &str) -> Option<&Value> {
        let col_index = table.columns.iter().position(|c| c.name == column_name)?;
        self.values.get(col_index)
    }
}

/// SQL value types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Value {
    /// 32-bit integer
    Integer(i32),

    /// 64-bit integer
    BigInt(i64),

    /// Decimal number (stored as fixed-point integer)
    Decimal(i64),

    /// String value
    String(String),

    /// Date value (Unix timestamp)
    Date(u64),

    /// Boolean value
    Boolean(bool),

    /// NULL value
    Null,
}

impl Value {
    /// Convert value to field element
    ///
    /// This is used when converting SQL values to field elements for ZKP circuits.
    /// String values are hashed to fit in the field.
    pub fn to_field(&self) -> Field {
        match self {
            Value::Integer(v) => {
                // Convert signed to unsigned, handling negative values
                if *v < 0 {
                    // For negative values, use two's complement representation
                    Field::from((*v as u32) as u64)
                } else {
                    Field::from(*v as u64)
                }
            }
            Value::BigInt(v) => {
                if *v < 0 {
                    Field::from((*v as u64) as u64)
                } else {
                    Field::from(*v as u64)
                }
            }
            Value::Decimal(v) => Field::from(*v as u64),
            Value::Date(v) => Field::from(*v),
            Value::Boolean(b) => Field::from(if *b { 1u64 } else { 0u64 }),
            Value::String(s) => {
                // Hash string to field element
                Self::string_to_field(s)
            }
            Value::Null => Field::zero(),
        }
    }

    /// Hash string to field element
    ///
    /// Strings are hashed using SHA-256 to fit within the field size.
    /// Only the first 31 bytes of the hash are used to ensure it fits in the field.
    fn string_to_field(s: &str) -> Field {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(s.as_bytes());
        let hash = hasher.finalize();

        // Take first 31 bytes to fit in field (254-bit field, 31 bytes = 248 bits)
        let mut bytes = [0u8; 32];
        bytes[1..32].copy_from_slice(&hash[..31]);

        // Convert to field element
        // Note: This may fail if the bytes don't form a valid field element
        // In production, we might want to handle this more gracefully
        Field::from_bytes(&bytes).unwrap_or(Field::zero())
    }

    /// Convert from field element (for integer types only)
    ///
    /// This is a helper for converting field elements back to integer values.
    /// Note: This only works for integer types, not for strings (which are hashed).
    pub fn from_field(field: &Field, data_type: &DataType) -> Option<Self> {
        // Convert field to bytes
        let bytes = field.to_bytes();

        // Convert to u64 (little-endian)
        let value = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);

        match data_type {
            DataType::Integer => Some(Value::Integer(value as i32)),
            DataType::BigInt => Some(Value::BigInt(value as i64)),
            DataType::Decimal => Some(Value::Decimal(value as i64)),
            DataType::Date => Some(Value::Date(value)),
            DataType::Boolean => Some(Value::Boolean(value != 0)),
            DataType::Varchar(_) => None, // Cannot recover string from hash
        }
    }
}

/// Query result
///
/// Contains the result of a SQL query execution along with column names.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    /// Column names in the result
    pub columns: Vec<String>,

    /// Result rows
    pub rows: Vec<Row>,
}

impl QueryResult {
    /// Create a new empty query result
    pub fn new(columns: Vec<String>) -> Self {
        Self {
            columns,
            rows: Vec::new(),
        }
    }

    /// Add a row to the result
    pub fn add_row(&mut self, row: Row) {
        self.rows.push(row);
    }

    /// Get number of rows
    pub fn num_rows(&self) -> usize {
        self.rows.len()
    }

    /// Get number of columns
    pub fn num_columns(&self) -> usize {
        self.columns.len()
    }
}

/// Zero-knowledge proof
///
/// Contains the proof bytes and public inputs for verification.
#[derive(Debug, Clone)]
pub struct Proof {
    /// Serialized proof bytes
    pub proof_bytes: Vec<u8>,

    /// Public inputs (for verification)
    pub public_inputs: Vec<Field>,
}

impl Proof {
    /// Create a new proof
    pub fn new(proof_bytes: Vec<u8>, public_inputs: Vec<Field>) -> Self {
        Self {
            proof_bytes,
            public_inputs,
        }
    }

    /// Get proof size in bytes
    pub fn size(&self) -> usize {
        self.proof_bytes.len()
    }

    /// Serialize proof to JSON (for debugging)
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

// Serialization for Proof (for JSON export)
impl Serialize for Proof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("Proof", 2)?;
        state.serialize_field("proof_bytes", &hex::encode(&self.proof_bytes))?;
        state.serialize_field(
            "public_inputs",
            &self
                .public_inputs
                .iter()
                .map(|f| hex::encode(f.to_bytes()))
                .collect::<Vec<_>>(),
        )?;
        state.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_table_creation() {
        let columns = vec![
            Column::new("id".to_string(), DataType::Integer),
            Column::new("name".to_string(), DataType::Varchar(100)),
        ];
        let table = Table::new("users".to_string(), columns);

        assert_eq!(table.name, "users");
        assert_eq!(table.num_columns(), 2);
        assert_eq!(table.num_rows(), 0);
    }

    #[test]
    fn test_value_to_field() {
        // Test Integer
        let int_val = Value::Integer(42);
        let field = int_val.to_field();
        assert_eq!(field, Field::from(42u64));

        // Test BigInt
        let bigint_val = Value::BigInt(1234567890);
        let field = bigint_val.to_field();
        assert_eq!(field, Field::from(1234567890u64));

        // Test Boolean
        let bool_val = Value::Boolean(true);
        let field = bool_val.to_field();
        assert_eq!(field, Field::from(1u64));

        let bool_val = Value::Boolean(false);
        let field = bool_val.to_field();
        assert_eq!(field, Field::from(0u64));

        // Test Null
        let null_val = Value::Null;
        let field = null_val.to_field();
        assert_eq!(field, Field::zero());
    }

    #[test]
    fn test_value_from_field() {
        let field = Field::from(42u64);

        // Test Integer
        let value = Value::from_field(&field, &DataType::Integer).unwrap();
        assert_eq!(value, Value::Integer(42));

        // Test Boolean
        let value = Value::from_field(&field, &DataType::Boolean).unwrap();
        assert_eq!(value, Value::Boolean(true));

        let field = Field::from(0u64);
        let value = Value::from_field(&field, &DataType::Boolean).unwrap();
        assert_eq!(value, Value::Boolean(false));
    }

    #[test]
    fn test_query_result() {
        let mut result = QueryResult::new(vec!["id".to_string(), "name".to_string()]);

        result.add_row(Row::new(vec![
            Value::Integer(1),
            Value::String("Alice".to_string()),
        ]));

        result.add_row(Row::new(vec![
            Value::Integer(2),
            Value::String("Bob".to_string()),
        ]));

        assert_eq!(result.num_columns(), 2);
        assert_eq!(result.num_rows(), 2);
    }

    #[test]
    fn test_row_get_value() {
        let table = Table::new(
            "users".to_string(),
            vec![
                Column::new("id".to_string(), DataType::Integer),
                Column::new("name".to_string(), DataType::Varchar(100)),
            ],
        );

        let row = Row::new(vec![Value::Integer(1), Value::String("Alice".to_string())]);

        // Test by index
        assert_eq!(row.get_value(0), Some(&Value::Integer(1)));
        assert_eq!(row.get_value(1), Some(&Value::String("Alice".to_string())));

        // Test by name
        assert_eq!(
            row.get_value_by_name(&table, "id"),
            Some(&Value::Integer(1))
        );
        assert_eq!(
            row.get_value_by_name(&table, "name"),
            Some(&Value::String("Alice".to_string()))
        );
    }
}
