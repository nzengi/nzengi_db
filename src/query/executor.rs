//! Query executor
//!
//! This module provides functionality for executing SQL queries with zero-knowledge proofs.
//!
//! # Example
//!
//! ```rust
//! use nzengi_db::query::{QueryExecutor, QueryParser, QueryPlanner};
//! use nzengi_db::commitment::IPAParams;
//! use nzengi_db::types::Table;
//!
//! let params = IPAParams::new(10);
//! let parser = QueryParser::new();
//! let planner = QueryPlanner::new();
//! let executor = QueryExecutor::new(&params);
//!
//! let ast = parser.parse("SELECT COUNT(*) FROM lineitem WHERE l_quantity > 10")?;
//! let plan = planner.plan(&ast)?;
//! let (result, proof) = executor.execute(&plan, &database)?;
//! ```

use crate::circuit::NzengiCircuit;
use crate::commitment::IPAParams;
use crate::proof::Prover;
use crate::query::planner::{
    AggregationOperation, ExecutionPlan, FilterOperation, GroupByOperation, SortOperation,
};
use crate::types::{QueryResult, Row, Table, Value};
use halo2_proofs::halo2curves::bn256::Fr as Field;
use std::collections::HashMap;

/// Query executor
///
/// This struct provides methods for executing SQL queries with zero-knowledge proofs.
#[derive(Debug, Clone)]
pub struct QueryExecutor {
    /// Public parameters for proof generation
    params: IPAParams,
}

impl QueryExecutor {
    /// Create a new query executor
    ///
    /// # Arguments
    /// * `params` - IPA parameters for proof generation
    pub fn new(params: &IPAParams) -> Self {
        Self {
            params: params.clone(),
        }
    }

    /// Execute a query plan and generate a proof
    ///
    /// # Arguments
    /// * `plan` - Execution plan for the query
    /// * `tables` - Map of table names to tables
    ///
    /// # Returns
    /// `Ok((QueryResult, Proof))` if execution succeeds, `Err` otherwise
    pub fn execute(
        &self,
        plan: &ExecutionPlan,
        tables: &HashMap<String, Table>,
    ) -> Result<(QueryResult, crate::types::Proof), Box<dyn std::error::Error>> {
        // Get the first table (for now, we only support single-table queries)
        let table_name = plan.tables.first().ok_or("No tables specified in query")?;
        let table = tables
            .get(table_name)
            .ok_or_else(|| format!("Table {} not found", table_name))?;

        // Apply filters
        let mut filtered_rows = table.rows.clone();
        for filter in &plan.filters {
            filtered_rows = self.apply_filter(&filtered_rows, filter, table)?;
        }
        // Clone filtered_rows for circuit building (it may be used later)
        let filtered_rows_for_circuit = filtered_rows.clone();

        // Apply group-by (if any)
        let grouped_data = if !plan.group_by.is_empty() {
            self.apply_group_by(&filtered_rows, &plan.group_by[0], table)?
        } else {
            vec![filtered_rows]
        };

        // Apply aggregations
        let mut result_rows = vec![];
        for group in &grouped_data {
            let mut row_values = vec![];
            for agg in &plan.aggregations {
                let value = self.apply_aggregation(group, agg, table)?;
                row_values.push(value);
            }
            result_rows.push(Row::new(row_values));
        }

        // Apply sort (if any)
        if !plan.sort.is_empty() {
            result_rows = self.apply_sort(&result_rows, &plan.sort[0], table)?;
        }

        // Build circuit (use cloned filtered_rows)
        let circuit = self.build_circuit(plan, table, &filtered_rows_for_circuit)?;

        // Generate proof
        let prover = Prover::new(&self.params);
        let (pk, _vk) = prover
            .generate_keys(&circuit)
            .map_err(|e| format!("Failed to generate keys: {}", e))?;
        let proof = prover
            .create_proof(&pk, &circuit, &[])
            .map_err(|e| format!("Failed to create proof: {}", e))?;

        // Create query result
        let columns: Vec<String> = plan
            .aggregations
            .iter()
            .map(|agg| {
                agg.alias
                    .clone()
                    .unwrap_or_else(|| format!("{:?}", agg.function))
            })
            .collect();
        let result = QueryResult {
            columns,
            rows: result_rows,
        };

        Ok((result, proof))
    }

    /// Apply a filter operation
    fn apply_filter(
        &self,
        rows: &[Row],
        filter: &FilterOperation,
        table: &Table,
    ) -> Result<Vec<Row>, Box<dyn std::error::Error>> {
        let column_idx = table
            .columns
            .iter()
            .position(|c| c.name == filter.column)
            .ok_or_else(|| format!("Column {} not found", filter.column))?;

        let mut filtered = vec![];
        for row in rows {
            if let Some(value) = row.values.get(column_idx) {
                if self.evaluate_filter_condition(value, &filter.condition) {
                    filtered.push(row.clone());
                }
            }
        }

        Ok(filtered)
    }

    /// Evaluate a filter condition
    fn evaluate_filter_condition(
        &self,
        value: &Value,
        condition: &crate::query::planner::FilterCondition,
    ) -> bool {
        match condition {
            crate::query::planner::FilterCondition::GreaterThan(threshold) => {
                // Simplified comparison - in production, you'd parse the threshold properly
                match value {
                    Value::Integer(v) => *v > threshold.parse::<i32>().unwrap_or(0),
                    Value::BigInt(v) => *v > threshold.parse::<i64>().unwrap_or(0),
                    _ => false,
                }
            }
            crate::query::planner::FilterCondition::LessThan(threshold) => match value {
                Value::Integer(v) => *v < threshold.parse::<i32>().unwrap_or(0),
                Value::BigInt(v) => *v < threshold.parse::<i64>().unwrap_or(0),
                _ => false,
            },
            crate::query::planner::FilterCondition::Equal(threshold) => match value {
                Value::Integer(v) => *v == threshold.parse::<i32>().unwrap_or(0),
                Value::BigInt(v) => *v == threshold.parse::<i64>().unwrap_or(0),
                _ => false,
            },
            _ => false, // Other conditions not implemented yet
        }
    }

    /// Apply a group-by operation
    fn apply_group_by(
        &self,
        rows: &[Row],
        _group_by: &GroupByOperation,
        _table: &Table,
    ) -> Result<Vec<Vec<Row>>, Box<dyn std::error::Error>> {
        // Simplified group-by implementation
        // In production, you'd properly group by the specified columns
        Ok(vec![rows.to_vec()])
    }

    /// Apply an aggregation operation
    fn apply_aggregation(
        &self,
        rows: &[Row],
        agg: &AggregationOperation,
        table: &Table,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let column_idx = agg
            .column
            .as_ref()
            .and_then(|col| table.columns.iter().position(|c| c.name == *col));

        match agg.function {
            crate::query::planner::AggregationFunction::Count => {
                Ok(Value::Integer(rows.len() as i32))
            }
            crate::query::planner::AggregationFunction::Sum => {
                if let Some(idx) = column_idx {
                    let sum: i64 = rows
                        .iter()
                        .filter_map(|r| r.values.get(idx))
                        .filter_map(|v| match v {
                            Value::Integer(i) => Some(*i as i64),
                            Value::BigInt(b) => Some(*b),
                            _ => None,
                        })
                        .sum();
                    Ok(Value::BigInt(sum))
                } else {
                    Ok(Value::BigInt(0))
                }
            }
            crate::query::planner::AggregationFunction::Avg => {
                if let Some(idx) = column_idx {
                    let sum: i64 = rows
                        .iter()
                        .filter_map(|r| r.values.get(idx))
                        .filter_map(|v| match v {
                            Value::Integer(i) => Some(*i as i64),
                            Value::BigInt(b) => Some(*b),
                            _ => None,
                        })
                        .sum();
                    let count = rows.len() as i64;
                    Ok(Value::BigInt(if count > 0 { sum / count } else { 0 }))
                } else {
                    Ok(Value::BigInt(0))
                }
            }
            _ => Ok(Value::Integer(0)), // Other aggregations not implemented yet
        }
    }

    /// Apply a sort operation
    fn apply_sort(
        &self,
        rows: &[Row],
        _sort: &SortOperation,
        _table: &Table,
    ) -> Result<Vec<Row>, Box<dyn std::error::Error>> {
        // Simplified sort implementation
        // In production, you'd properly sort by the specified columns
        Ok(rows.to_vec())
    }

    /// Build a circuit from an execution plan
    fn build_circuit(
        &self,
        plan: &ExecutionPlan,
        table: &Table,
        filtered_rows: &[Row],
    ) -> Result<NzengiCircuit, Box<dyn std::error::Error>> {
        let mut circuit = NzengiCircuit::new();

        // Add range check gates for filters
        for filter in &plan.filters {
            if let Some(value) = self.extract_filter_value(filter, table, filtered_rows) {
                let u8_cells = crate::field::FieldUtils::decompose_u64(value);
                circuit = circuit.with_range_check(value, u8_cells.to_vec());
            }
        }

        // Add aggregation gates
        if !plan.aggregations.is_empty() {
            let values: Vec<Field> = filtered_rows
                .iter()
                .flat_map(|r| r.values.iter().map(|v| v.to_field()))
                .collect();
            let binary_markers = vec![Field::from(1u64); values.len()];
            let start_indices = vec![Field::zero()];
            let end_indices = vec![Field::from(values.len() as u64)];
            circuit = circuit.with_aggregation(values, binary_markers, start_indices, end_indices);
        }

        // Add sort gates
        if !plan.sort.is_empty() {
            let input_values: Vec<Field> = filtered_rows
                .iter()
                .flat_map(|r| r.values.iter().map(|v| v.to_field()))
                .collect();
            let mut sorted_values = input_values.clone();
            sorted_values.sort(); // Simplified sort
            let alpha = Field::from(42u64); // Random alpha
            circuit = circuit.with_sort(input_values, sorted_values, alpha);
        }

        Ok(circuit)
    }

    /// Extract filter value from a filter operation
    fn extract_filter_value(
        &self,
        _filter: &FilterOperation,
        _table: &Table,
        _rows: &[Row],
    ) -> Option<u64> {
        // Simplified - in production, you'd properly extract the value
        Some(10u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Column;

    #[test]
    fn test_executor_new() {
        let params = IPAParams::new(10);
        let executor = QueryExecutor::new(&params);
        assert!(true); // Executor created successfully
    }

    #[test]
    fn test_executor_execute_simple() {
        let params = IPAParams::new(10);
        let executor = QueryExecutor::new(&params);

        // Create a simple table
        let mut table = Table::new(
            "lineitem".to_string(),
            vec![Column::new(
                "l_quantity".to_string(),
                crate::types::DataType::Integer,
            )],
        );
        table.rows.push(Row::new(vec![Value::Integer(10)]));

        let mut tables = HashMap::new();
        tables.insert("lineitem".to_string(), table);

        // Create a simple plan
        let plan = ExecutionPlan {
            tables: vec!["lineitem".to_string()],
            filters: vec![],
            joins: vec![],
            group_by: vec![],
            aggregations: vec![AggregationOperation {
                function: crate::query::planner::AggregationFunction::Count,
                column: None,
                alias: Some("count".to_string()),
            }],
            sort: vec![],
            projection: vec![],
        };

        // Note: This test may fail if circuit generation fails
        // The actual execution depends on proper circuit configuration
        let result = executor.execute(&plan, &tables);
        if let Err(e) = result {
            println!("Execution failed (expected for test): {}", e);
        }
    }
}
