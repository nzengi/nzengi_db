//! Query processing module
//!
//! This module provides functionality for parsing, planning, and executing SQL queries
//! using zero-knowledge proofs.
//!
//! The query processing module consists of:
//! - `parser`: SQL query parsing into AST
//! - `planner`: Query execution planning (gate selection)
//! - `executor`: Query execution with circuit building
//!
//! # Overview
//!
//! The query processing system enables:
//! - SQL query parsing using sqlparser
//! - Execution plan generation
//! - Circuit building from execution plans
//! - Query execution with proof generation
//!
//! # Workflow
//!
//! 1. **Parse**: Parse SQL query into AST
//! 2. **Plan**: Generate execution plan (which gates to use)
//! 3. **Optimize**: Optimize execution plan (filter pushdown, join reordering, etc.)
//! 4. **Build**: Build circuit from execution plan
//! 5. **Execute**: Execute query on database
//! 6. **Prove**: Generate proof for query execution
//!
//! # Example
//!
//! ```rust
//! use nzengi_db::query::{QueryParser, QueryPlanner, QueryOptimizer, QueryExecutor};
//! use nzengi_db::commitment::IPAParams;
//!
//! let params = IPAParams::new(10);
//! let parser = QueryParser::new();
//! let planner = QueryPlanner::new();
//! let optimizer = QueryOptimizer::new();
//! let executor = QueryExecutor::new(&params);
//!
//! // Parse query
//! let ast = parser.parse("SELECT COUNT(*) FROM lineitem WHERE l_quantity > 10")?;
//!
//! // Plan execution
//! let plan = planner.plan(&ast)?;
//!
//! // Optimize plan
//! let (optimized_plan, stats) = optimizer.optimize(&plan)?;
//!
//! // Execute query
//! let (result, proof) = executor.execute(&optimized_plan, &database)?;
//! ```

pub mod executor;
pub mod optimizer;
pub mod parser;
pub mod planner;

// Re-export main types for convenience
pub use executor::QueryExecutor;
pub use optimizer::{OptimizationStats, QueryOptimizer};
pub use parser::QueryParser;
pub use planner::{ExecutionPlan, QueryPlanner};
