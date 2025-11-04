//! SQL query parser
//!
//! This module provides functionality for parsing SQL queries into Abstract Syntax Trees (AST)
//! using the sqlparser library.
//!
//! # Example
//!
//! ```rust
//! use nzengi_db::query::QueryParser;
//!
//! let parser = QueryParser::new();
//! let ast = parser.parse("SELECT COUNT(*) FROM lineitem WHERE l_quantity > 10")?;
//! ```

use sqlparser::ast::{Expr, GroupByExpr, Query, SelectItem, SetExpr, Statement};
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser;

/// SQL query parser
///
/// This struct provides methods for parsing SQL queries into ASTs.
#[derive(Debug)]
pub struct QueryParser {
    /// SQL dialect to use for parsing (GenericDialect doesn't implement Clone)
    dialect: GenericDialect,
}

impl QueryParser {
    /// Create a new query parser
    pub fn new() -> Self {
        Self {
            dialect: GenericDialect {},
        }
    }

    /// Parse a SQL query string into an AST
    ///
    /// # Arguments
    /// * `query` - SQL query string
    ///
    /// # Returns
    /// `Ok(Statement)` if parsing succeeds, `Err` otherwise
    ///
    /// # Example
    /// ```
    /// use nzengi_db::query::QueryParser;
    ///
    /// let parser = QueryParser::new();
    /// let ast = parser.parse("SELECT COUNT(*) FROM lineitem WHERE l_quantity > 10")?;
    /// ```
    pub fn parse(&self, query: &str) -> Result<Statement, Box<dyn std::error::Error>> {
        // In sqlparser 0.59, use Parser::parse_sql static method
        // See: https://docs.rs/sqlparser/0.59.0/sqlparser/index.html
        let ast = Parser::parse_sql(&self.dialect, query)
            .map_err(|e| format!("Failed to parse SQL query: {}", e))?;

        if ast.len() != 1 {
            return Err("Expected exactly one SQL statement".into());
        }

        Ok(ast.into_iter().next().unwrap())
    }

    /// Parse a SQL query and extract the SELECT statement
    ///
    /// # Arguments
    /// * `query` - SQL query string
    ///
    /// # Returns
    /// `Ok(Query)` if parsing succeeds, `Err` otherwise
    pub fn parse_select(&self, query: &str) -> Result<Query, Box<dyn std::error::Error>> {
        let statement = self.parse(query)?;

        match statement {
            Statement::Query(query) => Ok(*query),
            _ => Err("Expected SELECT query".into()),
        }
    }

    /// Extract SELECT items from a query
    ///
    /// # Arguments
    /// * `query` - SQL query AST
    ///
    /// # Returns
    /// Vector of SELECT items
    pub fn extract_select_items(&self, query: &Query) -> Vec<SelectItem> {
        match &*query.body {
            SetExpr::Select(select) => select.projection.clone(),
            _ => vec![],
        }
    }

    /// Extract FROM clause from a query
    ///
    /// # Arguments
    /// * `query` - SQL query AST
    ///
    /// # Returns
    /// Vector of table names
    pub fn extract_tables(&self, query: &Query) -> Vec<String> {
        match &*query.body {
            SetExpr::Select(select) => select
                .from
                .iter()
                .map(|table| table.relation.to_string())
                .collect(),
            _ => vec![],
        }
    }

    /// Extract WHERE clause from a query
    ///
    /// # Arguments
    /// * `query` - SQL query AST
    ///
    /// # Returns
    /// Optional WHERE expression
    pub fn extract_where(&self, query: &Query) -> Option<Expr> {
        match &*query.body {
            SetExpr::Select(select) => select.selection.clone(),
            _ => None,
        }
    }

    /// Extract GROUP BY clause from a query
    ///
    /// # Arguments
    /// * `query` - SQL query AST
    ///
    /// # Returns
    /// Vector of GROUP BY expressions
    pub fn extract_group_by(&self, query: &Query) -> Vec<Expr> {
        match &*query.body {
            SetExpr::Select(select) => match &select.group_by {
                GroupByExpr::Expressions(exprs, _) => exprs.clone(),
                GroupByExpr::All(_) => Vec::new(),
            },
            _ => vec![],
        }
    }

    /// Extract ORDER BY clause from a query
    ///
    /// # Arguments
    /// * `query` - SQL query AST
    ///
    /// # Returns
    /// Vector of ORDER BY expressions
    pub fn extract_order_by(&self, query: &Query) -> Vec<sqlparser::ast::OrderByExpr> {
        // In sqlparser 0.59, query.order_by is Option<OrderBy>
        // OrderBy is a struct with kind: OrderByKind and interpolate: Option<Interpolate>
        // OrderByKind enum contains Vec<OrderByExpr> in Expression variant
        query
            .order_by
            .as_ref()
            .map(|order_by| {
                // Match on OrderByKind enum to extract Vec<OrderByExpr>
                // OrderByKind::All is a tuple variant with OrderByOptions
                // OrderByKind::Expressions is a tuple variant with Vec<OrderByExpr>
                match &order_by.kind {
                    sqlparser::ast::OrderByKind::All(_) => vec![],
                    sqlparser::ast::OrderByKind::Expressions(exprs) => exprs.clone(),
                }
            })
            .unwrap_or_default()
    }
}

impl Default for QueryParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parser_new() {
        let parser = QueryParser::new();
        assert!(true); // Parser created successfully
    }

    #[test]
    fn test_parser_parse_simple() {
        let parser = QueryParser::new();
        let result = parser.parse("SELECT * FROM lineitem");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parser_parse_select() {
        let parser = QueryParser::new();
        let result = parser.parse_select("SELECT COUNT(*) FROM lineitem WHERE l_quantity > 10");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parser_extract_tables() {
        let parser = QueryParser::new();
        let query = parser.parse_select("SELECT * FROM lineitem").unwrap();
        let tables = parser.extract_tables(&query);
        assert_eq!(tables.len(), 1);
        assert!(tables[0].contains("lineitem"));
    }

    #[test]
    fn test_parser_extract_where() {
        let parser = QueryParser::new();
        let query = parser
            .parse_select("SELECT * FROM lineitem WHERE l_quantity > 10")
            .unwrap();
        let where_clause = parser.extract_where(&query);
        assert!(where_clause.is_some());
    }

    #[test]
    fn test_parser_extract_group_by() {
        let parser = QueryParser::new();
        let query = parser
            .parse_select("SELECT l_returnflag, COUNT(*) FROM lineitem GROUP BY l_returnflag")
            .unwrap();
        let group_by = parser.extract_group_by(&query);
        assert!(!group_by.is_empty());
    }

    #[test]
    fn test_parser_extract_order_by() {
        let parser = QueryParser::new();
        let query = parser
            .parse_select("SELECT * FROM lineitem ORDER BY l_returnflag")
            .unwrap();
        let order_by = parser.extract_order_by(&query);
        assert!(!order_by.is_empty());
    }
}
