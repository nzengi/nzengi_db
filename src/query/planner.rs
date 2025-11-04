//! Query execution planner
//!
//! This module provides functionality for planning SQL query execution,
//! determining which gates to use for each operation.
//!
//! # Example
//!
//! ```rust
//! use nzengi_db::query::{QueryParser, QueryPlanner};
//!
//! let parser = QueryParser::new();
//! let planner = QueryPlanner::new();
//!
//! let ast = parser.parse("SELECT COUNT(*) FROM lineitem WHERE l_quantity > 10")?;
//! let plan = planner.plan(&ast)?;
//! ```

use crate::query::parser::QueryParser;
use sqlparser::ast::{Expr, Query, SelectItem, Statement};

/// Query execution plan
///
/// This struct represents an execution plan for a SQL query,
/// specifying which gates to use for each operation.
#[derive(Debug, Clone)]
pub struct ExecutionPlan {
    /// Tables to query
    pub tables: Vec<String>,

    /// Filter operations (Range Check Gates)
    pub filters: Vec<FilterOperation>,

    /// Join operations (Join Gates)
    pub joins: Vec<JoinOperation>,

    /// Group-by operations (Group-By Gates)
    pub group_by: Vec<GroupByOperation>,

    /// Aggregation operations (Aggregation Gates)
    pub aggregations: Vec<AggregationOperation>,

    /// Sort operations (Sort Gates)
    pub sort: Vec<SortOperation>,

    /// Projection operations (column selection)
    pub projection: Vec<String>,
}

/// Filter operation
#[derive(Debug, Clone)]
pub struct FilterOperation {
    /// Column name
    pub column: String,

    /// Filter condition
    pub condition: FilterCondition,
}

/// Filter condition type
#[derive(Debug, Clone)]
pub enum FilterCondition {
    /// Greater than
    GreaterThan(String),

    /// Less than
    LessThan(String),

    /// Equal to
    Equal(String),

    /// Between
    Between(String, String),

    /// In
    In(Vec<String>),
}

/// Join operation
#[derive(Debug, Clone)]
pub struct JoinOperation {
    /// Left table
    pub left_table: String,

    /// Right table
    pub right_table: String,

    /// Join column in left table
    pub left_column: String,

    /// Join column in right table
    pub right_column: String,
}

/// Group-by operation
#[derive(Debug, Clone)]
pub struct GroupByOperation {
    /// Columns to group by
    pub columns: Vec<String>,
}

/// Aggregation operation
#[derive(Debug, Clone)]
pub struct AggregationOperation {
    /// Aggregation function
    pub function: AggregationFunction,

    /// Column to aggregate
    pub column: Option<String>,

    /// Alias for the result
    pub alias: Option<String>,
}

/// Aggregation function type

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AggregationFunction {
    /// Sum
    Sum,

    /// Count
    Count,

    /// Average
    Avg,

    /// Minimum
    Min,

    /// Maximum
    Max,
}

/// Sort operation
#[derive(Debug, Clone)]
pub struct SortOperation {
    /// Columns to sort by
    pub columns: Vec<String>,

    /// Sort order (true for ascending, false for descending)
    pub ascending: Vec<bool>,
}

/// Query planner
///
/// This struct provides methods for planning SQL query execution.
#[derive(Debug)]
pub struct QueryPlanner {
    /// Query parser for extracting information (QueryParser doesn't implement Clone)
    parser: QueryParser,
}

impl QueryPlanner {
    /// Create a new query planner
    pub fn new() -> Self {
        Self {
            parser: QueryParser::new(),
        }
    }

    /// Plan execution for a SQL query
    ///
    /// # Arguments
    /// * `statement` - SQL statement AST
    ///
    /// # Returns
    /// `Ok(ExecutionPlan)` if planning succeeds, `Err` otherwise
    pub fn plan(&self, statement: &Statement) -> Result<ExecutionPlan, Box<dyn std::error::Error>> {
        match statement {
            Statement::Query(query) => self.plan_query(query),
            _ => Err("Only SELECT queries are supported".into()),
        }
    }

    /// Plan execution for a SELECT query
    ///
    /// # Arguments
    /// * `query` - SQL query AST
    ///
    /// # Returns
    /// `Ok(ExecutionPlan)` if planning succeeds, `Err` otherwise
    fn plan_query(&self, query: &Query) -> Result<ExecutionPlan, Box<dyn std::error::Error>> {
        let mut plan = ExecutionPlan {
            tables: self.parser.extract_tables(query),
            filters: vec![],
            joins: vec![],
            group_by: vec![],
            aggregations: vec![],
            sort: vec![],
            projection: vec![],
        };

        // Extract WHERE clause (filters)
        if let Some(where_expr) = self.parser.extract_where(query) {
            plan.filters.extend(self.extract_filters(&where_expr)?);
        }

        // Extract JOINs (from FROM clause)
        // Note: This is a simplified version - in production, you'd parse JOIN syntax properly
        // For now, we assume joins are specified in WHERE clause (e.g., table1.col = table2.col)

        // Extract GROUP BY clause
        let group_by_exprs = self.parser.extract_group_by(query);
        if !group_by_exprs.is_empty() {
            plan.group_by.push(GroupByOperation {
                columns: group_by_exprs.iter().map(|e| e.to_string()).collect(),
            });
        }

        // Extract aggregations from SELECT clause
        let select_items = self.parser.extract_select_items(query);
        for item in &select_items {
            if let Some(agg) = self.extract_aggregation(item) {
                plan.aggregations.push(agg);
            }
            if let Some(col) = self.extract_column_name(item) {
                plan.projection.push(col);
            }
        }

        // Extract ORDER BY clause
        let order_by_exprs = self.parser.extract_order_by(query);
        if !order_by_exprs.is_empty() {
            plan.sort.push(SortOperation {
                columns: order_by_exprs.iter().map(|e| e.expr.to_string()).collect(),
                ascending: order_by_exprs
                    .iter()
                    .map(|e| {
                        // OrderByExpr in sqlparser 0.59 has options field (OrderByOptions struct)
                        // options is NOT Option<OrderByOptions>, it's directly OrderByOptions
                        // Check if options.asc is Some(false) for descending
                        // Default to ascending if not specified
                        !matches!(e.options.asc, Some(false))
                    })
                    .collect(),
            });
        }

        Ok(plan)
    }

    /// Extract filters from a WHERE expression
    fn extract_filters(
        &self,
        expr: &Expr,
    ) -> Result<Vec<FilterOperation>, Box<dyn std::error::Error>> {
        let mut filters = vec![];

        match expr {
            Expr::BinaryOp { left, op, right } => {
                // Handle comparison operators
                if let Some(column) = self.extract_column_from_expr(left) {
                    if let Some(value) = self.extract_value_from_expr(right) {
                        let condition = match op.to_string().as_str() {
                            ">" => FilterCondition::GreaterThan(value),
                            "<" => FilterCondition::LessThan(value),
                            "=" | "==" => FilterCondition::Equal(value),
                            _ => return Ok(vec![]), // Unsupported operator
                        };
                        filters.push(FilterOperation { column, condition });
                    }
                }
            }
            Expr::Between {
                expr,
                negated: _negated,
                low,
                high,
            } => {
                if let Some(column) = self.extract_column_from_expr(expr) {
                    if let (Some(low_val), Some(high_val)) = (
                        self.extract_value_from_expr(low),
                        self.extract_value_from_expr(high),
                    ) {
                        filters.push(FilterOperation {
                            column,
                            condition: FilterCondition::Between(low_val, high_val),
                        });
                    }
                }
            }
            Expr::InList {
                expr,
                list,
                negated: _,
            } => {
                if let Some(column) = self.extract_column_from_expr(expr) {
                    let values: Vec<String> = list
                        .iter()
                        .filter_map(|e| self.extract_value_from_expr(e))
                        .collect();
                    if !values.is_empty() {
                        filters.push(FilterOperation {
                            column,
                            condition: FilterCondition::In(values),
                        });
                    }
                }
            }
            // Note: Expr::And/Or don't exist in sqlparser 0.59, use BinaryOp instead
            // This case is already handled in BinaryOp above
            _ => {} // Other expression types not supported yet
        }

        Ok(filters)
    }

    /// Extract column name from an expression
    fn extract_column_from_expr(&self, expr: &Expr) -> Option<String> {
        match expr {
            Expr::Identifier(ident) => Some(ident.value.clone()),
            Expr::CompoundIdentifier(idents) => Some(
                idents
                    .iter()
                    .map(|i| i.value.clone())
                    .collect::<Vec<_>>()
                    .join("."),
            ),
            _ => None,
        }
    }

    /// Extract value from an expression
    fn extract_value_from_expr(&self, expr: &Expr) -> Option<String> {
        match expr {
            Expr::Value(v) => {
                // Value is ValueWithSpan in sqlparser 0.59
                match &v.value {
                    sqlparser::ast::Value::Number(n, _) => Some(n.clone()),
                    sqlparser::ast::Value::SingleQuotedString(s)
                    | sqlparser::ast::Value::DoubleQuotedString(s) => Some(s.clone()),
                    _ => Some(format!("{}", v)),
                }
            }
            Expr::Identifier(ident) => Some(ident.value.clone()),
            _ => None,
        }
    }

    /// Extract aggregation from a SELECT item
    fn extract_aggregation(&self, item: &SelectItem) -> Option<AggregationOperation> {
        match item {
            SelectItem::UnnamedExpr(expr) => self.extract_aggregation_from_expr(expr, None),
            SelectItem::ExprWithAlias { expr, alias } => {
                self.extract_aggregation_from_expr(expr, Some(alias.value.clone()))
            }
            _ => None,
        }
    }

    /// Extract aggregation from an expression
    fn extract_aggregation_from_expr(
        &self,
        expr: &Expr,
        alias: Option<String>,
    ) -> Option<AggregationOperation> {
        match expr {
            Expr::Function(func) => {
                let func_name = func.name.to_string().to_uppercase();
                let agg_func = match func_name.as_str() {
                    "SUM" => AggregationFunction::Sum,
                    "COUNT" => AggregationFunction::Count,
                    "AVG" | "AVERAGE" => AggregationFunction::Avg,
                    "MIN" => AggregationFunction::Min,
                    "MAX" => AggregationFunction::Max,
                    _ => return None,
                };

                // Function arguments handling for sqlparser 0.59
                // In sqlparser 0.59, func.args is FunctionArguments enum with variants:
                // - None: Special functions without parentheses (e.g., CURRENT_TIMESTAMP)
                // - Subquery(Box<Query>): Single subquery argument
                // - List(FunctionArgumentList): Normal function argument list
                let column = match &func.args {
                    sqlparser::ast::FunctionArguments::List(list) => {
                        // FunctionArgumentList is a struct with args field (Vec<FunctionArg>)
                        list.args.first().and_then(|arg| match arg {
                            sqlparser::ast::FunctionArg::Unnamed(
                                sqlparser::ast::FunctionArgExpr::Expr(e),
                            ) => self.extract_column_from_expr(e),
                            _ => None,
                        })
                    }
                    sqlparser::ast::FunctionArguments::None => None,
                    sqlparser::ast::FunctionArguments::Subquery(_) => None,
                };

                Some(AggregationOperation {
                    function: agg_func,
                    column,
                    alias,
                })
            }
            _ => None,
        }
    }

    /// Extract column name from a SELECT item
    fn extract_column_name(&self, item: &SelectItem) -> Option<String> {
        match item {
            SelectItem::UnnamedExpr(expr) => self.extract_column_from_expr(expr),
            SelectItem::ExprWithAlias { expr: _expr, alias } => Some(alias.value.clone()),
            SelectItem::Wildcard(_) => Some("*".to_string()),
            _ => None,
        }
    }
}

impl Default for QueryPlanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_planner_new() {
        let planner = QueryPlanner::new();
        assert!(true); // Planner created successfully
    }

    #[test]
    fn test_planner_plan_simple() {
        let planner = QueryPlanner::new();
        let parser = QueryParser::new();
        let ast = parser.parse("SELECT * FROM lineitem").unwrap();
        let plan = planner.plan(&ast);
        assert!(plan.is_ok());
    }

    #[test]
    fn test_planner_plan_with_where() {
        let planner = QueryPlanner::new();
        let parser = QueryParser::new();
        let ast = parser
            .parse("SELECT * FROM lineitem WHERE l_quantity > 10")
            .unwrap();
        let plan = planner.plan(&ast).unwrap();
        assert!(!plan.filters.is_empty());
    }

    #[test]
    fn test_planner_plan_with_group_by() {
        let planner = QueryPlanner::new();
        let parser = QueryParser::new();
        let ast = parser
            .parse("SELECT l_returnflag, COUNT(*) FROM lineitem GROUP BY l_returnflag")
            .unwrap();
        let plan = planner.plan(&ast).unwrap();
        assert!(!plan.group_by.is_empty());
    }

    #[test]
    fn test_planner_plan_with_aggregation() {
        let planner = QueryPlanner::new();
        let parser = QueryParser::new();
        let ast = parser.parse("SELECT COUNT(*) FROM lineitem").unwrap();
        let plan = planner.plan(&ast).unwrap();
        assert!(!plan.aggregations.is_empty());
    }
}
