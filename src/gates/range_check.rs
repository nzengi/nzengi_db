//! Range check gate using bitwise decomposition
//!
//! This module provides a range check gate that verifies 64-bit integers
//! are within valid range using bitwise decomposition into u8 cells.
//!
//! # Method
//!
//! 1. Decompose 64-bit integer into 8 u8 cells (8-bit segments)
//! 2. Verify each u8 cell is in [0, 255] via lookup table
//! 3. Verify decomposition: value = Σ(i=0 to 7) u8_cells[i] * 2^(8i)
//!
//! # Constraints
//!
//! - Decomposition constraint: 1 per integer
//! - Lookup constraints: 8 per integer (one per u8 cell)
//!
//! # Example
//!
//! ```rust
//! use nzengi_db::gates::range_check::BitwiseRangeCheckConfig;
//! use halo2_proofs::plonk::ConstraintSystem;
//! use halo2_proofs::halo2curves::bn256::Fr as Field;
//!
//! let mut meta = ConstraintSystem::<Field>::default();
//! let advice = vec![meta.advice_column(); 9];
//! let fixed = vec![meta.fixed_column(); 1];
//!
//! let config = BitwiseRangeCheckConfig::configure(&mut meta, &advice, &fixed);
//! ```

use crate::field::FieldUtils;
use halo2_proofs::halo2curves::bn256::Fr as Field;
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, ErrorFront, Fixed, TableColumn},
    poly::Rotation,
};

/// Configuration for bitwise range check gate
///
/// This gate verifies that a 64-bit integer can be decomposed into
/// 8 u8 cells, each of which is in the range [0, 255].
#[derive(Debug, Clone)]
pub struct BitwiseRangeCheckConfig {
    /// Column for the original 64-bit value
    pub value: Column<Advice>,

    /// Columns for the 8 u8 cells (8-bit segments)
    pub u8_cells: [Column<Advice>; 8],

    /// TableColumn for the lookup table [0..255]
    pub u8_table: TableColumn,
}

impl BitwiseRangeCheckConfig {
    /// Configure the bitwise range check gate
    ///
    /// # Arguments
    /// * `meta` - Constraint system metadata
    /// * `advice` - Slice of advice columns (needs at least 9: 1 value + 8 cells)
    /// * `fixed` - Slice of fixed columns (needs at least 1 for lookup table)
    ///
    /// # Returns
    /// `BitwiseRangeCheckConfig` with configured columns
    ///
    /// # Panics
    /// Panics if not enough columns are provided
    pub fn configure(
        meta: &mut ConstraintSystem<Field>,
        advice: &[Column<Advice>],
        _fixed: &[Column<Fixed>],
    ) -> Self {
        // Validate input
        assert!(
            advice.len() >= 9,
            "Need at least 9 advice columns (1 value + 8 u8 cells)"
        );

        // Assign columns
        let value = advice[0];
        let u8_cells = [
            advice[1], advice[2], advice[3], advice[4], advice[5], advice[6], advice[7], advice[8],
        ];
        // In Halo2, lookup tables use TableColumn, not Column<Fixed>
        let u8_table = meta.lookup_table_column();

        // Enable equality on all advice columns
        meta.enable_equality(value);
        for &col in &u8_cells {
            meta.enable_equality(col);
        }

        // Constraint 1: Decomposition constraint
        // value = Σ(i=0 to 7) u8_cells[i] * 2^(8i)
        meta.create_gate("u64_decomposition", |meta| {
            let value = meta.query_advice(value, Rotation::cur());
            let cells: Vec<_> = u8_cells
                .iter()
                .map(|&col| meta.query_advice(col, Rotation::cur()))
                .collect();

            // Compute: Σ(i=0 to 7) cells[i] * 2^(8i)
            let mut recomposed = cells[0].clone();
            for i in 1..8 {
                let multiplier = Field::from(1u64 << (8 * i));
                recomposed = recomposed + cells[i].clone() * multiplier;
            }

            // Constraint: value - recomposed = 0
            vec![value - recomposed]
        });

        // Constraint 2: Lookup constraints for each u8 cell
        // Each u8 cell must be in [0, 255] via lookup table
        // In Halo2, lookup takes (input_expr, TableColumn) pairs
        meta.lookup("u8_range", |meta| {
            u8_cells
                .iter()
                .map(|&col| {
                    let cell = meta.query_advice(col, Rotation::cur());
                    (cell, u8_table)
                })
                .collect()
        });

        Self {
            value,
            u8_cells,
            u8_table,
        }
    }

    /// Assign a 64-bit value with decomposition
    ///
    /// This method:
    /// 1. Decomposes the value into 8 u8 cells
    /// 2. Assigns the original value to the value column
    /// 3. Assigns each u8 cell to its respective column
    ///
    /// # Arguments
    /// * `layouter` - Layouter for assigning values
    /// * `value` - The 64-bit integer to decompose and assign
    ///
    /// # Returns
    /// `Ok(())` if assignment succeeds, `Err(Error)` otherwise
    pub fn assign(
        &self,
        layouter: &mut impl Layouter<Field>,
        value: u64,
    ) -> Result<(), ErrorFront> {
        // Decompose value into u8 cells
        let cells = FieldUtils::decompose_u64(value);

        // Assign value and cells in a region
        layouter.assign_region(
            || "bitwise range check",
            |mut region| {
                // Assign original 64-bit value
                region.assign_advice(
                    || "value",
                    self.value,
                    0,
                    || Value::known(Field::from(value)),
                )?;

                // Assign each u8 cell
                for (i, &cell) in cells.iter().enumerate() {
                    region.assign_advice(
                        || format!("u8_cell[{}]", i),
                        self.u8_cells[i],
                        0,
                        || Value::known(Field::from(cell as u64)),
                    )?;
                }

                Ok(())
            },
        )
    }

    /// Load the u8 lookup table into the fixed column
    ///
    /// This method assigns values [0..255] to the fixed column
    /// for use in lookup constraints.
    ///
    /// # Arguments
    /// * `layouter` - Layouter for assigning fixed values
    ///
    /// # Returns
    /// `Ok(())` if assignment succeeds, `Err(Error)` otherwise
    pub fn load_lookup_table(&self, layouter: &mut impl Layouter<Field>) -> Result<(), ErrorFront> {
        // Get lookup table from FieldUtils
        let table = FieldUtils::create_u8_lookup_table();
        assert_eq!(
            table.len(),
            FieldUtils::u8_lookup_table_size(),
            "Lookup table size mismatch"
        );

        // In Halo2, lookup tables are assigned using assign_table
        layouter.assign_table(
            || "u8 lookup table",
            |mut table_layouter| {
                for (i, &val) in table.iter().enumerate() {
                    table_layouter.assign_cell(
                        || format!("u8_table[{}]", i),
                        self.u8_table,
                        i,
                        || Value::known(Field::from(val as u64)),
                    )?;
                }
                Ok(())
            },
        )
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
    fn test_decomposition_recomposition() {
        // Test that decompose and recompose are inverse operations
        let test_values = vec![
            0u64,
            1u64,
            255u64,
            256u64,
            65535u64,
            0x0123456789ABCDEF_u64,
            u64::MAX,
        ];

        for &value in &test_values {
            let cells = FieldUtils::decompose_u64(value);
            let recomposed = FieldUtils::recompose_u64(&cells);
            assert_eq!(
                value, recomposed,
                "Decomposition/recomposition failed for value {}",
                value
            );
        }
    }

    #[test]
    fn test_u8_lookup_table() {
        // Test lookup table creation
        let table = FieldUtils::create_u8_lookup_table();
        assert_eq!(table.len(), 256, "Lookup table should have 256 entries");
        assert_eq!(table[0], 0, "First entry should be 0");
        assert_eq!(table[255], 255, "Last entry should be 255");

        // Test that all values are in range [0, 255]
        for (i, &val) in table.iter().enumerate() {
            assert_eq!(val, i as u8, "Table entry {} should be {}", i, i);
            assert!(val <= 255, "Table entry should be <= 255");
        }
    }

    /// Test circuit for range check gate
    #[derive(Default)]
    struct TestCircuit {
        value: u64,
    }

    impl Circuit<Field> for TestCircuit {
        type Config = BitwiseRangeCheckConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Field>) -> Self::Config {
            let advice = (0..9).map(|_| meta.advice_column()).collect::<Vec<_>>();
            let fixed = vec![meta.fixed_column()];

            BitwiseRangeCheckConfig::configure(meta, &advice, &fixed)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Field>,
        ) -> Result<(), ErrorFront> {
            // Load lookup table
            config.load_lookup_table(&mut layouter)?;

            // Assign value with decomposition
            config.assign(&mut layouter, self.value)?;

            Ok(())
        }
    }

    #[test]
    fn test_range_check_circuit() {
        // Test with various values
        let test_values = vec![0u64, 1u64, 255u64, 256u64, 65535u64, 0x0123456789ABCDEF_u64];

        for value in test_values {
            let circuit = TestCircuit { value };
            let k = 10; // 2^10 = 1024 rows
            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            assert_eq!(
                prover.verify(),
                Ok(()),
                "Circuit verification failed for value {}",
                value
            );
        }
    }

    #[test]
    fn test_range_check_circuit_max_value() {
        // Test with maximum u64 value
        let circuit = TestCircuit { value: u64::MAX };
        let k = 10;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(
            prover.verify(),
            Ok(()),
            "Circuit verification failed for u64::MAX"
        );
    }
}
