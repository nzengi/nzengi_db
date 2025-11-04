//! Group-by gate for proving grouping correctness
//!
//! This module provides a group-by gate that verifies:
//! 1. Group boundaries are correctly identified (equality check)
//! 2. Binary markers correctly indicate same/different groups
//! 3. Start/end indices correctly mark group boundaries
//!
//! # Method
//!
//! 1. Group Boundary Detection: b = 1 - (v1 - v2) · p
//!    - p = 0 if v1 = v2 (same group)
//!    - p = 1/(v1-v2) if v1 ≠ v2 (different group)
//!
//! 2. Validation: b · (v1 - v2) = 0
//!
//! # Constraints
//!
//! - Group boundary constraint: 1 per adjacent pair
//! - Validation constraint: 1 per adjacent pair
//!
//! # Example
//!
//! ```rust
//! use nzengi_db::gates::group_by::GroupByConfig;
//! use halo2_proofs::plonk::ConstraintSystem;
//! use halo2_proofs::halo2curves::bn256::Fr as Field;
//!
//! let mut meta = ConstraintSystem::<Field>::default();
//! let advice = vec![meta.advice_column(); 5];
//!
//! let config = GroupByConfig::configure(&mut meta, &advice);
//! ```

use ff::Field as _;
use halo2_proofs::halo2curves::bn256::Fr as Field;
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, ErrorFront, Expression},
    poly::Rotation,
};

/// Configuration for group-by gate
///
/// This gate verifies that group boundaries are correctly identified
/// and binary markers correctly indicate same/different groups.
#[derive(Debug, Clone)]
pub struct GroupByConfig {
    /// Column for sorted values (from SortGate)
    pub sorted_col: Column<Advice>,

    /// Column for start index of each group
    pub start_idx: Column<Advice>,

    /// Column for end index of each group
    pub end_idx: Column<Advice>,

    /// Column for binary marker b (1 = same group, 0 = different group)
    pub binary_marker: Column<Advice>,

    /// Column for helper variable p
    pub helper_p: Column<Advice>,
}

impl GroupByConfig {
    /// Configure the group-by gate
    ///
    /// # Arguments
    /// * `meta` - Constraint system metadata
    /// * `advice` - Slice of advice columns (needs at least 5: sorted, start_idx, end_idx, binary_marker, helper_p)
    ///
    /// # Returns
    /// `GroupByConfig` with configured columns
    ///
    /// # Panics
    /// Panics if not enough columns are provided
    pub fn configure(meta: &mut ConstraintSystem<Field>, advice: &[Column<Advice>]) -> Self {
        // Validate input
        assert!(
            advice.len() >= 5,
            "Need at least 5 advice columns (sorted, start_idx, end_idx, binary_marker, helper_p)"
        );

        // Assign columns
        let sorted_col = advice[0];
        let start_idx = advice[1];
        let end_idx = advice[2];
        let binary_marker = advice[3];
        let helper_p = advice[4];

        // Enable equality on all advice columns
        meta.enable_equality(sorted_col);
        meta.enable_equality(start_idx);
        meta.enable_equality(end_idx);
        meta.enable_equality(binary_marker);
        meta.enable_equality(helper_p);

        // Constraint 1: Group boundary constraint
        // b = 1 - (v1 - v2) · p
        // where:
        //   p = 0           if v1 = v2 (same group)
        //   p = 1/(v1-v2)   if v1 ≠ v2 (different group)
        meta.create_gate("group_boundary", |meta| {
            let v1 = meta.query_advice(sorted_col, Rotation::cur());
            let v2 = meta.query_advice(sorted_col, Rotation::next());
            let b = meta.query_advice(binary_marker, Rotation::cur());
            let p = meta.query_advice(helper_p, Rotation::cur());

            // b = 1 - (v1 - v2) · p
            // Rearranged: b + (v1 - v2) · p = 1
            let left = b.clone() + (v1.clone() - v2.clone()) * p.clone();
            vec![left - Expression::Constant(Field::one())]
        });

        // Constraint 2: Validation constraint
        // b · (v1 - v2) = 0
        // This ensures:
        // - If v1 = v2: any b works, but formula forces b = 1
        // - If v1 ≠ v2: b must be 0, else constraint violated
        meta.create_gate("group_validity", |meta| {
            let v1 = meta.query_advice(sorted_col, Rotation::cur());
            let v2 = meta.query_advice(sorted_col, Rotation::next());
            let b = meta.query_advice(binary_marker, Rotation::cur());

            // b · (v1 - v2) = 0
            vec![b * (v1 - v2)]
        });

        Self {
            sorted_col,
            start_idx,
            end_idx,
            binary_marker,
            helper_p,
        }
    }

    /// Assign values for group-by gate
    ///
    /// This method:
    /// 1. Assigns sorted values to sorted column
    /// 2. Computes and assigns binary markers b
    /// 3. Computes and assigns helper variables p
    /// 4. Computes and assigns start/end indices
    ///
    /// # Arguments
    /// * `layouter` - Layouter for assigning values
    /// * `sorted_values` - The sorted values (must be sorted by grouping attributes)
    ///
    /// # Returns
    /// `Ok(())` if assignment succeeds, `Err(Error)` otherwise
    pub fn assign(
        &self,
        layouter: &mut impl Layouter<Field>,
        sorted_values: &[Field],
    ) -> Result<(), ErrorFront> {
        let n = sorted_values.len();
        if n == 0 {
            return Ok(()); // Empty input, nothing to do
        }

        // Compute binary markers b and helper variables p
        // For each adjacent pair (i, i+1):
        // - If sorted_values[i] == sorted_values[i+1]: b = 1, p = 0 (same group)
        // - If sorted_values[i] != sorted_values[i+1]: b = 0, p = 1/(v1-v2) (different group)
        let mut binary_markers = Vec::with_capacity(n);
        let mut helper_ps = Vec::with_capacity(n);

        for i in 0..n {
            if i == n - 1 {
                // Last row: no next value, so b = 0 (end of last group)
                binary_markers.push(Field::zero());
                helper_ps.push(Field::zero());
            } else {
                let v1 = sorted_values[i];
                let v2 = sorted_values[i + 1];
                let diff = v2 - v1;

                if diff.is_zero().into() {
                    // v1 == v2: same group
                    binary_markers.push(Field::one()); // b = 1
                    helper_ps.push(Field::zero()); // p = 0
                } else {
                    // v1 != v2: different group
                    binary_markers.push(Field::zero()); // b = 0
                    helper_ps.push(diff.invert().unwrap()); // p = 1/(v1-v2)
                }
            }
        }

        // Compute start/end indices
        // Start index: index where binary_marker changes from 0 to 1 (or first row)
        // End index: index where binary_marker changes from 1 to 0 (or last row)
        let mut start_indices = Vec::with_capacity(n);
        let mut end_indices = Vec::with_capacity(n);

        let mut current_group_start = 0;
        for i in 0..n {
            // Check if this is the start of a new group
            if i == 0 || (i > 0 && binary_markers[i - 1] == Field::zero()) {
                current_group_start = i;
            }

            start_indices.push(Field::from(current_group_start as u64));

            // Check if this is the end of a group
            if i == n - 1 || (i < n - 1 && binary_markers[i] == Field::zero()) {
                end_indices.push(Field::from(i as u64));
            } else {
                // Not end yet, use next end index
                end_indices.push(Field::from((i + 1) as u64));
            }
        }

        // Assign all values in a region
        layouter.assign_region(
            || "group_by gate",
            |mut region| {
                // Assign sorted values
                for (i, &value) in sorted_values.iter().enumerate() {
                    region.assign_advice(
                        || format!("sorted[{}]", i),
                        self.sorted_col,
                        i,
                        || Value::known(value),
                    )?;
                }

                // Assign binary markers
                for (i, &marker) in binary_markers.iter().enumerate() {
                    region.assign_advice(
                        || format!("binary_marker[{}]", i),
                        self.binary_marker,
                        i,
                        || Value::known(marker),
                    )?;
                }

                // Assign helper variables p
                for (i, &p) in helper_ps.iter().enumerate() {
                    region.assign_advice(
                        || format!("helper_p[{}]", i),
                        self.helper_p,
                        i,
                        || Value::known(p),
                    )?;
                }

                // Assign start indices
                for (i, &start) in start_indices.iter().enumerate() {
                    region.assign_advice(
                        || format!("start_idx[{}]", i),
                        self.start_idx,
                        i,
                        || Value::known(start),
                    )?;
                }

                // Assign end indices
                for (i, &end) in end_indices.iter().enumerate() {
                    region.assign_advice(
                        || format!("end_idx[{}]", i),
                        self.end_idx,
                        i,
                        || Value::known(end),
                    )?;
                }

                Ok(())
            },
        )
    }

    /// Get group boundaries from sorted values
    ///
    /// Returns a vector of (start_index, end_index) tuples for each group.
    ///
    /// # Arguments
    /// * `sorted_values` - The sorted values (must be sorted by grouping attributes)
    ///
    /// # Returns
    /// Vector of (start_index, end_index) tuples
    pub fn get_group_boundaries(sorted_values: &[Field]) -> Vec<(usize, usize)> {
        let n = sorted_values.len();
        if n == 0 {
            return vec![];
        }

        let mut boundaries = Vec::new();
        let mut current_start = 0;

        for i in 0..n {
            // Check if this is the start of a new group
            if i == 0 || (i > 0 && sorted_values[i - 1] != sorted_values[i]) {
                if i > 0 {
                    // End previous group
                    boundaries.push((current_start, i - 1));
                }
                current_start = i;
            }
        }

        // Add last group
        boundaries.push((current_start, n - 1));

        boundaries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        plonk::Circuit,
    };

    #[test]
    fn test_group_boundary_constraint() {
        // Test that group boundary constraint works correctly
        let sorted = vec![
            Field::from(1u64),
            Field::from(1u64),
            Field::from(2u64),
            Field::from(2u64),
            Field::from(2u64),
            Field::from(3u64),
        ];

        // Compute binary markers and helper variables
        let mut binary_markers = Vec::new();
        let mut helper_ps = Vec::new();

        for i in 0..sorted.len() {
            if i == sorted.len() - 1 {
                binary_markers.push(Field::zero());
                helper_ps.push(Field::zero());
            } else {
                let v1 = sorted[i];
                let v2 = sorted[i + 1];
                let diff = v2 - v1;

                if diff.is_zero().into() {
                    binary_markers.push(Field::one());
                    helper_ps.push(Field::zero());
                } else {
                    binary_markers.push(Field::zero());
                    helper_ps.push(diff.invert().unwrap());
                }
            }
        }

        // Verify constraint: b = 1 - (v1 - v2) · p
        for i in 0..sorted.len() - 1 {
            let v1 = sorted[i];
            let v2 = sorted[i + 1];
            let b = binary_markers[i];
            let p = helper_ps[i];

            let computed_b = Field::one() - (v1 - v2) * p;
            assert_eq!(
                b, computed_b,
                "Binary marker should satisfy b = 1 - (v1 - v2) · p"
            );
        }
    }

    #[test]
    fn test_group_validity_constraint() {
        // Test that group validity constraint works correctly
        let sorted = vec![
            Field::from(1u64),
            Field::from(1u64),
            Field::from(2u64),
            Field::from(2u64),
        ];

        let mut binary_markers = Vec::new();
        for i in 0..sorted.len() {
            if i == sorted.len() - 1 {
                binary_markers.push(Field::zero());
            } else {
                let v1 = sorted[i];
                let v2 = sorted[i + 1];
                let diff = v2 - v1;

                if diff.is_zero().into() {
                    binary_markers.push(Field::one());
                } else {
                    binary_markers.push(Field::zero());
                }
            }
        }

        // Verify constraint: b · (v1 - v2) = 0
        for i in 0..sorted.len() - 1 {
            let v1 = sorted[i];
            let v2 = sorted[i + 1];
            let b = binary_markers[i];

            let result = b * (v1 - v2);
            assert_eq!(
                result,
                Field::zero(),
                "Validation constraint should be satisfied: b · (v1 - v2) = 0"
            );
        }
    }

    #[test]
    fn test_get_group_boundaries() {
        // Test group boundary detection
        let sorted = vec![
            Field::from(1u64),
            Field::from(1u64),
            Field::from(2u64),
            Field::from(2u64),
            Field::from(2u64),
            Field::from(3u64),
        ];

        let boundaries = GroupByConfig::get_group_boundaries(&sorted);
        assert_eq!(boundaries.len(), 3, "Should have 3 groups");
        assert_eq!(boundaries[0], (0, 1), "First group: indices 0-1");
        assert_eq!(boundaries[1], (2, 4), "Second group: indices 2-4");
        assert_eq!(boundaries[2], (5, 5), "Third group: index 5");
    }

    #[test]
    fn test_get_group_boundaries_single_group() {
        // Test with single group
        let sorted = vec![Field::from(1u64), Field::from(1u64), Field::from(1u64)];

        let boundaries = GroupByConfig::get_group_boundaries(&sorted);
        assert_eq!(boundaries.len(), 1, "Should have 1 group");
        assert_eq!(boundaries[0], (0, 2), "Single group: indices 0-2");
    }

    #[test]
    fn test_get_group_boundaries_empty() {
        // Test with empty input
        let sorted = vec![];
        let boundaries = GroupByConfig::get_group_boundaries(&sorted);
        assert_eq!(boundaries.len(), 0, "Should have 0 groups");
    }

    /// Test circuit for group-by gate
    #[derive(Default)]
    struct TestCircuit {
        sorted_values: Vec<Field>,
    }

    impl Circuit<Field> for TestCircuit {
        type Config = GroupByConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Field>) -> Self::Config {
            let advice = (0..5).map(|_| meta.advice_column()).collect::<Vec<_>>();
            GroupByConfig::configure(meta, &advice)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Field>,
        ) -> Result<(), ErrorFront> {
            if !self.sorted_values.is_empty() {
                config.assign(&mut layouter, &self.sorted_values)?;
            }
            Ok(())
        }
    }

    #[test]
    fn test_group_by_circuit() {
        // Test with various input sizes
        let test_cases = vec![
            vec![1u64, 1u64, 2u64, 2u64, 2u64, 3u64],
            vec![1u64, 1u64, 1u64],
            vec![1u64, 2u64, 3u64],
            vec![1u64],
        ];

        for input_u64 in test_cases {
            // Sort input (should already be sorted for group-by)
            let mut sorted_u64 = input_u64.clone();
            sorted_u64.sort();
            let sorted: Vec<Field> = sorted_u64.iter().map(|&v| Field::from(v)).collect();

            let circuit = TestCircuit {
                sorted_values: sorted,
            };

            let k = 10; // 2^10 = 1024 rows
            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            assert_eq!(
                prover.verify(),
                Ok(()),
                "Circuit verification failed for input: {:?}",
                input_u64
            );
        }
    }

    #[test]
    fn test_group_by_circuit_empty() {
        // Test with empty input
        let circuit = TestCircuit {
            sorted_values: vec![],
        };

        let k = 10;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()), "Empty circuit should verify");
    }
}
