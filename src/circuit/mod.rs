//! PLONKish circuit structure with custom gates integration
//!
//! This module provides the main circuit structure that integrates all custom gates
//! for SQL query verification using zero-knowledge proofs.
//!
//! # Architecture
//!
//! The circuit structure follows PLONKish design principles:
//! - Fixed columns: Constants and lookup tables
//! - Advice columns: Private witness values and intermediate computations
//! - Instance columns: Public inputs/outputs
//!
//! # Custom Gates Integration
//!
//! The circuit integrates the following custom gates:
//! - Range Check Gate: Bitwise decomposition for range validation
//! - Sort Gate: Permutation and sortedness checks
//! - Group-By Gate: Group boundary detection and validation
//! - Join Gate: Deduplication, disjointness, and join predicate validation
//! - Aggregation Gate: SUM, COUNT, AVG, MIN, MAX operations
//!
//! # Example
//!
//! ```rust
//! use nzengi_db::circuit::NzengiCircuit;
//! use halo2_proofs::plonk::Circuit;
//!
//! let circuit = NzengiCircuit::default();
//! let k = 10; // 2^10 = 1024 rows
//! let prover = MockProver::run(k, &circuit, vec![]).unwrap();
//! assert_eq!(prover.verify(), Ok(()));
//! ```

pub mod builder;
pub mod config;
pub mod layouter;

// Re-export main types for convenience
pub use builder::CircuitBuilder;
pub use config::CircuitConfig;
pub use layouter::CircuitLayouter;

use halo2_proofs::halo2curves::bn256::Fr as Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, ErrorFront},
};

/// Nzengi circuit for SQL query verification
///
/// This circuit integrates all custom gates for proving SQL query correctness.
#[derive(Default, Debug, Clone)]
pub struct NzengiCircuit {
    /// Circuit configuration
    _config: Option<config::CircuitConfig>,

    /// Range check data (optional)
    range_check_data: Option<(u64, Vec<u8>)>,

    /// Sort data (optional)
    sort_data: Option<(Vec<Field>, Vec<Field>, Field)>,

    /// Group-by data (optional)
    group_by_data: Option<Vec<Field>>,

    /// Join data (optional)
    join_data: Option<(Vec<Field>, Vec<Field>, Vec<(Field, Field)>)>,

    /// Aggregation data (optional)
    aggregation_data: Option<(Vec<Field>, Vec<Field>, Vec<Field>, Vec<Field>)>,
}

impl NzengiCircuit {
    /// Create a new empty circuit
    pub fn new() -> Self {
        Self::default()
    }

    /// Set range check data
    pub fn with_range_check(mut self, value: u64, u8_cells: Vec<u8>) -> Self {
        self.range_check_data = Some((value, u8_cells));
        self
    }

    /// Set sort data
    pub fn with_sort(
        mut self,
        input_values: Vec<Field>,
        sorted_values: Vec<Field>,
        alpha: Field,
    ) -> Self {
        self.sort_data = Some((input_values, sorted_values, alpha));
        self
    }

    /// Set group-by data
    pub fn with_group_by(mut self, sorted_values: Vec<Field>) -> Self {
        self.group_by_data = Some(sorted_values);
        self
    }

    /// Set join data
    pub fn with_join(
        mut self,
        t1_join_values: Vec<Field>,
        t2_join_values: Vec<Field>,
        join_results: Vec<(Field, Field)>,
    ) -> Self {
        self.join_data = Some((t1_join_values, t2_join_values, join_results));
        self
    }

    /// Set aggregation data
    pub fn with_aggregation(
        mut self,
        values: Vec<Field>,
        binary_markers: Vec<Field>,
        start_indices: Vec<Field>,
        end_indices: Vec<Field>,
    ) -> Self {
        self.aggregation_data = Some((values, binary_markers, start_indices, end_indices));
        self
    }
}

impl Circuit<Field> for NzengiCircuit {
    type Config = config::CircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::new()
    }

    fn configure(meta: &mut ConstraintSystem<Field>) -> Self::Config {
        // Determine which gates to enable based on data availability
        // In a real implementation, this would be determined by query analysis
        let enable_range_check = true;
        let enable_sort = true;
        let enable_group_by = true;
        let enable_join = true;
        let enable_aggregation = true;

        config::CircuitConfig::new(
            meta,
            enable_range_check,
            enable_sort,
            enable_group_by,
            enable_join,
            enable_aggregation,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Field>,
    ) -> Result<(), ErrorFront> {
        // Assign range check gate
        if let (Some(range_check_config), Some((value, _u8_cells))) =
            (&config.range_check, &self.range_check_data)
        {
            range_check_config.load_lookup_table(&mut layouter)?;
            range_check_config.assign(&mut layouter, *value)?;
        }

        // Assign sort gate
        if let (Some(sort_config), Some((input_values, sorted_values, alpha))) =
            (&config.sort, &self.sort_data)
        {
            sort_config.assign(&mut layouter, input_values, sorted_values, *alpha)?;
        }

        // Assign group-by gate
        if let (Some(group_by_config), Some(sorted_values)) =
            (&config.group_by, &self.group_by_data)
        {
            group_by_config.assign(&mut layouter, sorted_values)?;
        }

        // Assign join gate
        if let (Some(join_config), Some((t1_join_values, t2_join_values, join_results))) =
            (&config.join, &self.join_data)
        {
            join_config.assign(&mut layouter, t1_join_values, t2_join_values, join_results)?;
        }

        // Assign aggregation gate
        if let (
            Some(aggregation_config),
            Some((values, binary_markers, start_indices, end_indices)),
        ) = (&config.aggregation, &self.aggregation_data)
        {
            aggregation_config.assign(
                &mut layouter,
                values,
                binary_markers,
                start_indices,
                end_indices,
            )?;
        }

        Ok(())
    }
}
