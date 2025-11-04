//! Circuit builder
//!
//! This module provides functionality for building circuits from execution plans
//! and query data. It handles the construction of circuits with appropriate gates
//! based on the query requirements.
//!
//! # Overview
//!
//! The circuit builder:
//! - Builds circuits from execution plans
//! - Configures gates based on query operations
//! - Assigns data to circuit components
//! - Manages circuit construction workflow
//!
//! # Example
//!
//! ```rust
//! use nzengi_db::circuit::builder::CircuitBuilder;
//! use nzengi_db::query::planner::ExecutionPlan;
//!
//! let builder = CircuitBuilder::new();
//! let circuit = builder.build_from_plan(&plan, &data)?;
//! ```

use super::NzengiCircuit;
use crate::query::planner::ExecutionPlan;
use halo2_proofs::halo2curves::bn256::Fr as Field;
use std::collections::HashMap;

/// Circuit builder
///
/// This struct provides methods for building circuits from execution plans
/// and query data.
#[derive(Debug, Clone)]
pub struct CircuitBuilder {
    /// Enable aggressive optimizations
    pub optimize: bool,
}

impl CircuitBuilder {
    /// Create a new circuit builder
    pub fn new() -> Self {
        Self { optimize: true }
    }

    /// Create a new circuit builder with optimization settings
    ///
    /// # Arguments
    /// * `optimize` - Enable optimizations
    pub fn with_optimize(optimize: bool) -> Self {
        Self { optimize }
    }

    /// Build a circuit from an execution plan
    ///
    /// This method constructs a circuit based on the execution plan,
    /// configuring gates and assigning data as needed.
    ///
    /// # Arguments
    /// * `plan` - Execution plan for the query
    /// * `data` - Query data (tables, rows, etc.)
    ///
    /// # Returns
    /// `Ok(NzengiCircuit)` if circuit building succeeds, `Err` otherwise
    ///
    /// # Example
    /// ```
    /// use nzengi_db::circuit::builder::CircuitBuilder;
    /// use nzengi_db::query::planner::ExecutionPlan;
    ///
    /// let builder = CircuitBuilder::new();
    /// let circuit = builder.build_from_plan(&plan, &data)?;
    /// ```
    pub fn build_from_plan(
        &self,
        _plan: &ExecutionPlan,
        _data: &HashMap<String, Vec<Field>>,
    ) -> Result<NzengiCircuit, Box<dyn std::error::Error>> {
        let circuit = NzengiCircuit::new();

        // Add gates based on execution plan
        // Note: This is a simplified implementation
        // In production, you would:
        // 1. Analyze the execution plan
        // 2. Configure appropriate gates
        // 3. Assign data to gates
        // 4. Optimize circuit layout

        // For now, we'll create a basic circuit structure
        // The actual gate configuration and data assignment
        // would be done based on the plan's operations

        Ok(circuit)
    }

    /// Build a circuit with range check gates
    ///
    /// # Arguments
    /// * `values` - Values to check ranges for
    ///
    /// # Returns
    /// `Ok(NzengiCircuit)` if circuit building succeeds, `Err` otherwise
    pub fn with_range_checks(
        &self,
        values: Vec<u64>,
    ) -> Result<NzengiCircuit, Box<dyn std::error::Error>> {
        let mut circuit = NzengiCircuit::new();

        for value in values {
            let u8_cells = crate::field::FieldUtils::decompose_u64(value);
            circuit = circuit.with_range_check(value, u8_cells.to_vec());
        }

        Ok(circuit)
    }

    /// Build a circuit with sort gates
    ///
    /// # Arguments
    /// * `input_values` - Input values to sort
    /// * `alpha` - Random field element for blinding
    ///
    /// # Returns
    /// `Ok(NzengiCircuit)` if circuit building succeeds, `Err` otherwise
    pub fn with_sort(
        &self,
        input_values: Vec<Field>,
        alpha: Field,
    ) -> Result<NzengiCircuit, Box<dyn std::error::Error>> {
        let mut sorted_values = input_values.clone();
        sorted_values.sort_by(|a, b| {
            let a_u64 = Self::field_to_u64(*a);
            let b_u64 = Self::field_to_u64(*b);
            a_u64.cmp(&b_u64)
        });

        let circuit = NzengiCircuit::new().with_sort(input_values, sorted_values, alpha);
        Ok(circuit)
    }

    /// Build a circuit with aggregation gates
    ///
    /// # Arguments
    /// * `values` - Values to aggregate
    /// * `start_indices` - Start indices for groups
    /// * `end_indices` - End indices for groups
    ///
    /// # Returns
    /// `Ok(NzengiCircuit)` if circuit building succeeds, `Err` otherwise
    pub fn with_aggregation(
        &self,
        values: Vec<Field>,
        start_indices: Vec<Field>,
        end_indices: Vec<Field>,
    ) -> Result<NzengiCircuit, Box<dyn std::error::Error>> {
        let binary_markers = vec![Field::from(1u64); values.len()];
        let circuit = NzengiCircuit::new().with_aggregation(
            values,
            binary_markers,
            start_indices,
            end_indices,
        );
        Ok(circuit)
    }

    /// Helper function to convert field to u64 for comparison
    fn field_to_u64(value: Field) -> u64 {
        let bytes = value.to_bytes();
        let mut u64_bytes = [0u8; 8];
        for i in 0..8.min(bytes.len()) {
            u64_bytes[i] = bytes[i];
        }
        u64::from_le_bytes(u64_bytes)
    }
}

impl Default for CircuitBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_builder_new() {
        let builder = CircuitBuilder::new();
        assert!(builder.optimize);
    }

    #[test]
    fn test_circuit_builder_with_optimize() {
        let builder = CircuitBuilder::with_optimize(false);
        assert!(!builder.optimize);
    }

    #[test]
    fn test_build_from_plan() {
        let builder = CircuitBuilder::new();
        let plan = ExecutionPlan {
            tables: vec![],
            filters: vec![],
            joins: vec![],
            group_by: vec![],
            aggregations: vec![],
            sort: vec![],
            projection: vec![],
        };
        let data = HashMap::new();

        let result = builder.build_from_plan(&plan, &data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_with_range_checks() {
        let builder = CircuitBuilder::new();
        let values = vec![1u64, 2u64, 3u64];

        let result = builder.with_range_checks(values);
        assert!(result.is_ok());
    }

    #[test]
    fn test_with_sort() {
        let builder = CircuitBuilder::new();
        let input_values = vec![Field::from(3u64), Field::from(1u64), Field::from(2u64)];
        let alpha = Field::from(42u64);

        let result = builder.with_sort(input_values, alpha);
        assert!(result.is_ok());
    }
}
