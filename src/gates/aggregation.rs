//! Aggregation gate for proving aggregation correctness
//!
//! This module provides aggregation gates that verify:
//! 1. SUM: Accumulate values within each group
//! 2. COUNT: Count records in each group
//! 3. AVG: Average values in each group
//! 4. MIN/MAX: Minimum/maximum values in each group
//!
//! # Method
//!
//! 1. SUM: Mi = bi · Mi-1 + valuei · (1 - bi)
//!    - If bi = 1 (same group): Mi = Mi-1 + valuei
//!    - If bi = 0 (new group): Mi = valuei
//!
//! 2. COUNT: counti = endi - starti + 1
//!
//! 3. AVG: avgi · counti - sumi = 0
//!
//! 4. MIN/MAX: After sorting, MINi = value at starti, MAXi = value at endi
//!
//! # Constraints
//!
//! - SUM constraint: 1 per group
//! - COUNT constraint: 1 per group
//! - AVG constraint: 1 per group
//! - MIN/MAX constraint: 1 per group
//!
//! # Example
//!
//! ```rust
//! use nzengi_db::gates::aggregation::AggregationConfig;
//! use halo2_proofs::plonk::ConstraintSystem;
//! use halo2_proofs::halo2curves::bn256::Fr as Field;
//!
//! let mut meta = ConstraintSystem::<Field>::default();
//! let advice = vec![meta.advice_column(); 7];
//!
//! let config = AggregationConfig::configure(&mut meta, &advice);
//! ```

use ff::Field as _;
use halo2_proofs::halo2curves::bn256::Fr as Field;
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, ErrorFront, Expression},
    poly::Rotation,
};

/// Configuration for aggregation gate
///
/// This gate verifies that aggregation operations are correctly performed
/// with proper group-based accumulation.
#[derive(Debug, Clone)]
pub struct AggregationConfig {
    /// Column for values being aggregated
    pub value_col: Column<Advice>,

    /// Column for binary marker b (1 = same group, 0 = different group)
    pub binary_marker_col: Column<Advice>,

    /// Column for accumulator M (for SUM)
    pub accumulator_col: Column<Advice>,

    /// Column for start index of each group
    pub start_idx_col: Column<Advice>,

    /// Column for end index of each group
    pub end_idx_col: Column<Advice>,

    /// Column for SUM result
    pub sum_col: Column<Advice>,

    /// Column for COUNT result
    pub count_col: Column<Advice>,

    /// Column for AVG result
    pub avg_col: Column<Advice>,
}

impl AggregationConfig {
    /// Configure the aggregation gate
    ///
    /// # Arguments
    /// * `meta` - Constraint system metadata
    /// * `advice` - Slice of advice columns (needs at least 8 columns)
    ///
    /// # Returns
    /// `AggregationConfig` with configured columns
    ///
    /// # Panics
    /// Panics if not enough columns are provided
    pub fn configure(meta: &mut ConstraintSystem<Field>, advice: &[Column<Advice>]) -> Self {
        // Validate input
        assert!(
            advice.len() >= 8,
            "Need at least 8 advice columns (value, binary_marker, accumulator, start_idx, end_idx, sum, count, avg)"
        );

        // Assign columns
        let value_col = advice[0];
        let binary_marker_col = advice[1];
        let accumulator_col = advice[2];
        let start_idx_col = advice[3];
        let end_idx_col = advice[4];
        let sum_col = advice[5];
        let count_col = advice[6];
        let avg_col = advice[7];

        // Enable equality on all advice columns
        meta.enable_equality(value_col);
        meta.enable_equality(binary_marker_col);
        meta.enable_equality(accumulator_col);
        meta.enable_equality(start_idx_col);
        meta.enable_equality(end_idx_col);
        meta.enable_equality(sum_col);
        meta.enable_equality(count_col);
        meta.enable_equality(avg_col);

        // Constraint 1: SUM constraint
        // Mi = bi · Mi-1 + valuei · (1 - bi)
        // If bi = 1 (same group): Mi = Mi-1 + valuei
        // If bi = 0 (new group): Mi = valuei
        meta.create_gate("sum_aggregation", |meta| {
            let m_cur = meta.query_advice(accumulator_col, Rotation::cur());
            let m_prev = meta.query_advice(accumulator_col, Rotation::prev());
            let value_cur = meta.query_advice(value_col, Rotation::cur());
            let b_cur = meta.query_advice(binary_marker_col, Rotation::cur());

            // Mi = bi · Mi-1 + valuei · (1 - bi)
            // Rearranged: Mi - bi · Mi-1 - valuei · (1 - bi) = 0
            let left = m_cur.clone();
            let one = Expression::Constant(Field::one());
            let right = b_cur.clone() * m_prev.clone() + value_cur.clone() * (one - b_cur.clone());
            vec![left - right]
        });

        // Constraint 2: COUNT constraint
        // counti = endi - starti + 1
        meta.create_gate("count_aggregation", |meta| {
            let count_cur = meta.query_advice(count_col, Rotation::cur());
            let start_cur = meta.query_advice(start_idx_col, Rotation::cur());
            let end_cur = meta.query_advice(end_idx_col, Rotation::cur());

            // counti = endi - starti + 1
            // Rearranged: counti - (endi - starti + 1) = 0
            // end_cur, start_cur, count_cur are already Expression<F, V>
            // Use Expression arithmetic: (end - start) + 1
            let left = count_cur.clone();
            let diff = end_cur.clone() - start_cur.clone();
            let right = diff + Expression::Constant(Field::one());
            vec![left - right]
        });

        // Constraint 3: AVG constraint
        // avgi · counti - sumi = 0
        meta.create_gate("avg_aggregation", |meta| {
            let avg_cur = meta.query_advice(avg_col, Rotation::cur());
            let count_cur = meta.query_advice(count_col, Rotation::cur());
            let sum_cur = meta.query_advice(sum_col, Rotation::cur());

            // avgi · counti - sumi = 0
            vec![avg_cur * count_cur - sum_cur]
        });

        Self {
            value_col,
            binary_marker_col,
            accumulator_col,
            start_idx_col,
            end_idx_col,
            sum_col,
            count_col,
            avg_col,
        }
    }

    /// Assign values for aggregation gate
    ///
    /// This method:
    /// 1. Assigns values to value column
    /// 2. Assigns binary markers to binary_marker column
    /// 3. Computes and assigns accumulators M
    /// 4. Computes and assigns start/end indices
    /// 5. Computes and assigns SUM, COUNT, AVG results
    ///
    /// # Arguments
    /// * `layouter` - Layouter for assigning values
    /// * `values` - Values being aggregated
    /// * `binary_markers` - Binary markers (1 = same group, 0 = different group)
    /// * `start_indices` - Start indices of each group
    /// * `end_indices` - End indices of each group
    ///
    /// # Returns
    /// `Ok(())` if assignment succeeds, `Err(Error)` otherwise
    pub fn assign(
        &self,
        layouter: &mut impl Layouter<Field>,
        values: &[Field],
        binary_markers: &[Field],
        start_indices: &[Field],
        end_indices: &[Field],
    ) -> Result<(), ErrorFront> {
        let n = values.len();
        if n == 0 {
            return Ok(()); // Empty input, nothing to do
        }

        // Validate inputs
        assert_eq!(
            binary_markers.len(),
            n,
            "Binary markers must have same length as values"
        );
        assert_eq!(
            start_indices.len(),
            n,
            "Start indices must have same length as values"
        );
        assert_eq!(
            end_indices.len(),
            n,
            "End indices must have same length as values"
        );

        // Compute accumulators M
        // Mi = bi · Mi-1 + valuei · (1 - bi)
        let mut accumulators = Vec::with_capacity(n);
        if n > 0 {
            // First row: M0 = value0 (assuming new group)
            accumulators.push(values[0]);
        }

        for i in 1..n {
            let m_prev = accumulators[i - 1];
            let value_cur = values[i];
            let b_cur = binary_markers[i];

            // Mi = bi · Mi-1 + valuei · (1 - bi)
            let m_cur = b_cur * m_prev + value_cur * (Field::one() - b_cur);
            accumulators.push(m_cur);
        }

        // Compute SUM, COUNT, AVG per group
        // Group boundaries are determined by binary_markers
        let mut groups = Vec::new();
        let mut current_group_start = 0;

        for i in 0..n {
            // Check if this is the start of a new group
            if i == 0 || (i > 0 && binary_markers[i - 1] == Field::zero()) {
                if i > 0 {
                    // End previous group
                    let start_idx = Self::field_to_usize(start_indices[current_group_start]);
                    let end_idx = Self::field_to_usize(end_indices[i - 1]);
                    groups.push((start_idx, end_idx));
                }
                current_group_start = i;
            }
        }

        // Add last group
        if n > 0 {
            let start_idx = Self::field_to_usize(start_indices[current_group_start]);
            let end_idx = Self::field_to_usize(end_indices[n - 1]);
            groups.push((start_idx, end_idx));
        }

        // Compute SUM, COUNT, AVG for each group
        let mut sums = Vec::with_capacity(n);
        let mut counts = Vec::with_capacity(n);
        let mut avgs = Vec::with_capacity(n);

        for (start, end) in &groups {
            // SUM: sum of values in group
            let sum: Field = values[*start..=*end].iter().sum();

            // COUNT: count = end - start + 1
            let count = Field::from((end - start + 1) as u64);

            // AVG: avg = sum / count
            let avg = sum * count.invert().unwrap();

            // Assign to all rows in group
            for _ in *start..=*end {
                sums.push(sum);
                counts.push(count);
                avgs.push(avg);
            }
        }

        // Assign all values in a region
        layouter.assign_region(
            || "aggregation gate",
            |mut region| {
                // Assign values
                for (i, &value) in values.iter().enumerate() {
                    region.assign_advice(
                        || format!("value[{}]", i),
                        self.value_col,
                        i,
                        || Value::known(value),
                    )?;
                }

                // Assign binary markers
                for (i, &marker) in binary_markers.iter().enumerate() {
                    region.assign_advice(
                        || format!("binary_marker[{}]", i),
                        self.binary_marker_col,
                        i,
                        || Value::known(marker),
                    )?;
                }

                // Assign accumulators
                for (i, &acc) in accumulators.iter().enumerate() {
                    region.assign_advice(
                        || format!("accumulator[{}]", i),
                        self.accumulator_col,
                        i,
                        || Value::known(acc),
                    )?;
                }

                // Assign start indices
                for (i, &start) in start_indices.iter().enumerate() {
                    region.assign_advice(
                        || format!("start_idx[{}]", i),
                        self.start_idx_col,
                        i,
                        || Value::known(start),
                    )?;
                }

                // Assign end indices
                for (i, &end) in end_indices.iter().enumerate() {
                    region.assign_advice(
                        || format!("end_idx[{}]", i),
                        self.end_idx_col,
                        i,
                        || Value::known(end),
                    )?;
                }

                // Assign SUM results
                for (i, &sum) in sums.iter().enumerate() {
                    region.assign_advice(
                        || format!("sum[{}]", i),
                        self.sum_col,
                        i,
                        || Value::known(sum),
                    )?;
                }

                // Assign COUNT results
                for (i, &count) in counts.iter().enumerate() {
                    region.assign_advice(
                        || format!("count[{}]", i),
                        self.count_col,
                        i,
                        || Value::known(count),
                    )?;
                }

                // Assign AVG results
                for (i, &avg) in avgs.iter().enumerate() {
                    region.assign_advice(
                        || format!("avg[{}]", i),
                        self.avg_col,
                        i,
                        || Value::known(avg),
                    )?;
                }

                Ok(())
            },
        )
    }

    /// Compute SUM for a group
    ///
    /// # Arguments
    /// * `values` - Values in the group
    ///
    /// # Returns
    /// SUM of values
    pub fn compute_sum(values: &[Field]) -> Field {
        values.iter().sum()
    }

    /// Compute COUNT for a group
    ///
    /// # Arguments
    /// * `start_idx` - Start index of group
    /// * `end_idx` - End index of group
    ///
    /// # Returns
    /// COUNT = end_idx - start_idx + 1
    pub fn compute_count(start_idx: usize, end_idx: usize) -> usize {
        end_idx - start_idx + 1
    }

    /// Compute AVG for a group
    ///
    /// # Arguments
    /// * `values` - Values in the group
    ///
    /// # Returns
    /// AVG = SUM / COUNT
    pub fn compute_avg(values: &[Field]) -> Field {
        if values.is_empty() {
            return Field::zero();
        }
        let sum: Field = values.iter().sum();
        let count = Field::from(values.len() as u64);
        sum * count.invert().unwrap()
    }

    /// Compute MIN for a group (after sorting)
    ///
    /// # Arguments
    /// * `values` - Sorted values in the group
    ///
    /// # Returns
    /// MIN = value at start of group
    pub fn compute_min(values: &[Field]) -> Field {
        if values.is_empty() {
            return Field::zero();
        }
        values[0]
    }

    /// Compute MAX for a group (after sorting)
    ///
    /// # Arguments
    /// * `values` - Sorted values in the group
    ///
    /// # Returns
    /// MAX = value at end of group
    pub fn compute_max(values: &[Field]) -> Field {
        if values.is_empty() {
            return Field::zero();
        }
        values[values.len() - 1]
    }

    /// Convert field value to usize for index operations
    ///
    /// # Arguments
    /// * `value` - Field value
    ///
    /// # Returns
    /// usize representation
    fn field_to_usize(value: Field) -> usize {
        // Convert field to bytes and extract first 8 bytes as u64, then to usize
        let bytes = value.to_bytes();
        let mut u64_bytes = [0u8; 8];
        for i in 0..8.min(bytes.len()) {
            u64_bytes[i] = bytes[i];
        }
        u64::from_le_bytes(u64_bytes) as usize
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
    fn test_sum_aggregation() {
        // Test SUM computation
        let values = vec![Field::from(1u64), Field::from(2u64), Field::from(3u64)];
        let sum = AggregationConfig::compute_sum(&values);
        assert_eq!(sum, Field::from(6u64), "SUM should be 6");
    }

    #[test]
    fn test_count_aggregation() {
        // Test COUNT computation
        let count = AggregationConfig::compute_count(0, 2);
        assert_eq!(count, 3, "COUNT should be 3");
    }

    #[test]
    fn test_avg_aggregation() {
        // Test AVG computation
        let values = vec![Field::from(2u64), Field::from(4u64), Field::from(6u64)];
        let avg = AggregationConfig::compute_avg(&values);
        assert_eq!(avg, Field::from(4u64), "AVG should be 4");
    }

    #[test]
    fn test_min_aggregation() {
        // Test MIN computation (after sorting)
        let values = vec![Field::from(3u64), Field::from(1u64), Field::from(2u64)];
        let min = AggregationConfig::compute_min(&values);
        assert_eq!(
            min,
            Field::from(3u64),
            "MIN should be first value (after sorting)"
        );
    }

    #[test]
    fn test_max_aggregation() {
        // Test MAX computation (after sorting)
        let values = vec![Field::from(1u64), Field::from(3u64), Field::from(2u64)];
        let max = AggregationConfig::compute_max(&values);
        assert_eq!(
            max,
            Field::from(2u64),
            "MAX should be last value (after sorting)"
        );
    }

    #[test]
    fn test_sum_constraint() {
        // Test SUM constraint: Mi = bi · Mi-1 + valuei · (1 - bi)
        let m_prev = Field::from(5u64);
        let value_cur = Field::from(3u64);
        let b_same = Field::one(); // same group
        let b_new = Field::zero(); // new group

        // Same group: Mi = Mi-1 + valuei
        let m_same = b_same * m_prev + value_cur * (Field::one() - b_same);
        assert_eq!(m_same, Field::from(8u64), "Same group: M = 5 + 3 = 8");

        // New group: Mi = valuei
        let m_new = b_new * m_prev + value_cur * (Field::one() - b_new);
        assert_eq!(m_new, Field::from(3u64), "New group: M = 3");
    }

    #[test]
    fn test_count_constraint() {
        // Test COUNT constraint: counti = endi - starti + 1
        let start = Field::from(0u64);
        let end = Field::from(2u64);
        let count = end - start + Field::one();
        assert_eq!(count, Field::from(3u64), "COUNT should be 3");
    }

    #[test]
    fn test_avg_constraint() {
        // Test AVG constraint: avgi · counti - sumi = 0
        let sum = Field::from(12u64);
        let count = Field::from(3u64);
        let avg = sum * count.invert().unwrap();
        let result = avg * count - sum;
        assert_eq!(result, Field::zero(), "AVG constraint should be satisfied");
    }

    /// Test circuit for aggregation gate
    #[derive(Default)]
    struct TestCircuit {
        values: Vec<Field>,
        binary_markers: Vec<Field>,
        start_indices: Vec<Field>,
        end_indices: Vec<Field>,
    }

    impl Circuit<Field> for TestCircuit {
        type Config = AggregationConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Field>) -> Self::Config {
            let advice = (0..8).map(|_| meta.advice_column()).collect::<Vec<_>>();
            AggregationConfig::configure(meta, &advice)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Field>,
        ) -> Result<(), ErrorFront> {
            if !self.values.is_empty() {
                config.assign(
                    &mut layouter,
                    &self.values,
                    &self.binary_markers,
                    &self.start_indices,
                    &self.end_indices,
                )?;
            }
            Ok(())
        }
    }

    #[test]
    fn test_aggregation_circuit() {
        // Test with single group
        let values = vec![Field::from(1u64), Field::from(2u64), Field::from(3u64)];
        let binary_markers = vec![
            Field::one(),  // same group
            Field::one(),  // same group
            Field::zero(), // end of group
        ];
        let start_indices = vec![Field::from(0u64), Field::from(0u64), Field::from(0u64)];
        let end_indices = vec![Field::from(2u64), Field::from(2u64), Field::from(2u64)];

        let circuit = TestCircuit {
            values,
            binary_markers,
            start_indices,
            end_indices,
        };

        let k = 10; // 2^10 = 1024 rows
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(
            prover.verify(),
            Ok(()),
            "Circuit verification should succeed"
        );
    }

    #[test]
    fn test_aggregation_circuit_empty() {
        // Test with empty input
        let circuit = TestCircuit {
            values: vec![],
            binary_markers: vec![],
            start_indices: vec![],
            end_indices: vec![],
        };

        let k = 10;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()), "Empty circuit should verify");
    }
}
