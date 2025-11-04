//! Circuit configuration
//!
//! This module provides the circuit configuration structure that defines
//! which gates are enabled and how columns are allocated.
//!
//! # Overview
//!
//! The circuit configuration:
//! - Allocates advice and fixed columns
//! - Configures custom gates
//! - Manages column assignments
//! - Enables/disables gates dynamically

use crate::gates::{
    AggregationConfig, BitwiseRangeCheckConfig, GroupByConfig, JoinConfig, SortConfig,
};
use halo2_proofs::halo2curves::bn256::Fr as Field;
use halo2_proofs::plonk::*;

/// Configuration for nzengi circuit
///
/// This struct contains all gate configurations for the circuit.
#[derive(Debug, Clone)]
pub struct CircuitConfig {
    /// Range check gate configuration
    pub range_check: Option<BitwiseRangeCheckConfig>,

    /// Sort gate configuration
    pub sort: Option<SortConfig>,

    /// Group-by gate configuration
    pub group_by: Option<GroupByConfig>,

    /// Join gate configuration
    pub join: Option<JoinConfig>,

    /// Aggregation gate configuration
    pub aggregation: Option<AggregationConfig>,
}

impl CircuitConfig {
    /// Create a new circuit configuration
    ///
    /// # Arguments
    /// * `meta` - Constraint system metadata
    /// * `enable_range_check` - Enable range check gate
    /// * `enable_sort` - Enable sort gate
    /// * `enable_group_by` - Enable group-by gate
    /// * `enable_join` - Enable join gate
    /// * `enable_aggregation` - Enable aggregation gate
    ///
    /// # Returns
    /// `CircuitConfig` with configured gates
    pub fn new(
        meta: &mut ConstraintSystem<Field>,
        enable_range_check: bool,
        enable_sort: bool,
        enable_group_by: bool,
        enable_join: bool,
        enable_aggregation: bool,
    ) -> Self {
        // Calculate total number of advice columns needed
        // Range check: 9 columns (1 value + 8 u8 cells)
        // Sort: 4 columns (input, output, z, alpha)
        // Group-by: 5 columns (sorted, start_idx, end_idx, binary_marker, helper_p)
        // Join: 6 columns (t1_join, t2_join, result_t1_join, result_t2_join, sorted_union, z)
        // Aggregation: 8 columns (value, binary_marker, accumulator, start_idx, end_idx, sum, count, avg)

        let mut total_columns = 0;
        if enable_range_check {
            total_columns += 9;
        }
        if enable_sort {
            total_columns += 4;
        }
        if enable_group_by {
            total_columns += 5;
        }
        if enable_join {
            total_columns += 6;
        }
        if enable_aggregation {
            total_columns += 8;
        }

        // Create advice columns
        let advice_columns: Vec<Column<Advice>> =
            (0..total_columns).map(|_| meta.advice_column()).collect();

        // Lookup tables use TableColumn, not fixed columns
        // No need to create fixed columns for range check lookup table

        // Configure gates
        let mut col_idx = 0;

        // Range check gate
        let range_check = if enable_range_check {
            let advice = &advice_columns[col_idx..col_idx + 9];
            // Range check gate now uses TableColumn internally, no fixed columns needed
            col_idx += 9;
            Some(BitwiseRangeCheckConfig::configure(meta, advice, &[]))
        } else {
            None
        };

        // Sort gate
        let sort = if enable_sort {
            let advice = &advice_columns[col_idx..col_idx + 4];
            col_idx += 4;
            Some(SortConfig::configure(meta, advice))
        } else {
            None
        };

        // Group-by gate
        let group_by = if enable_group_by {
            let advice = &advice_columns[col_idx..col_idx + 5];
            col_idx += 5;
            Some(GroupByConfig::configure(meta, advice))
        } else {
            None
        };

        // Join gate
        let join = if enable_join {
            let advice = &advice_columns[col_idx..col_idx + 6];
            col_idx += 6;
            Some(JoinConfig::configure(meta, advice))
        } else {
            None
        };

        // Aggregation gate
        let aggregation = if enable_aggregation {
            let advice = &advice_columns[col_idx..col_idx + 8];
            Some(AggregationConfig::configure(meta, advice))
        } else {
            None
        };

        Self {
            range_check,
            sort,
            group_by,
            join,
            aggregation,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_config_new() {
        let mut meta = ConstraintSystem::<Field>::default();
        let config = CircuitConfig::new(&mut meta, true, true, true, true, true);

        assert!(
            config.range_check.is_some(),
            "Range check should be enabled"
        );
        assert!(config.sort.is_some(), "Sort should be enabled");
        assert!(config.group_by.is_some(), "Group-by should be enabled");
        assert!(config.join.is_some(), "Join should be enabled");
        assert!(
            config.aggregation.is_some(),
            "Aggregation should be enabled"
        );
    }

    #[test]
    fn test_circuit_config_selective() {
        let mut meta = ConstraintSystem::<Field>::default();
        let config = CircuitConfig::new(&mut meta, true, false, false, false, false);

        assert!(
            config.range_check.is_some(),
            "Range check should be enabled"
        );
        assert!(config.sort.is_none(), "Sort should be disabled");
        assert!(config.group_by.is_none(), "Group-by should be disabled");
        assert!(config.join.is_none(), "Join should be disabled");
        assert!(
            config.aggregation.is_none(),
            "Aggregation should be disabled"
        );
    }
}
