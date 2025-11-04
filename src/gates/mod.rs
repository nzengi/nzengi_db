//! Custom gates for SQL operations
//!
//! This module provides custom gates for various SQL operations:
//! - Range check: Verify values are within a specified range
//! - Sort: Prove sorting correctness
//! - Group-by: Prove grouping correctness
//! - Join: Prove join correctness
//! - Aggregation: Prove aggregation function correctness

pub mod aggregation;
pub mod group_by;
pub mod join;
pub mod range_check;
pub mod sort;

// Re-export main types for convenience
pub use aggregation::AggregationConfig;
pub use group_by::GroupByConfig;
pub use join::JoinConfig;
pub use range_check::BitwiseRangeCheckConfig;
pub use sort::SortConfig;
