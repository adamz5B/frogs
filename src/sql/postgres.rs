use std::collections::HashMap;

use async_trait::async_trait;
use sqlx::postgres::{PgPoolOptions, PgRow};
use sqlx::{Column, Row, TypeInfo};

use super::{SqlDriver, SqlError, SqlRow, SqlValue};
use crate::config::ConnectionConfig;

#[derive(Debug)]
pub struct PostgresDriver {
    pool: sqlx::PgPool,
}

impl PostgresDriver {
    pub async fn connect(config: &ConnectionConfig) -> Result<Self, SqlError> {
        let url = build_connection_url(config)?;
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .map_err(|e| SqlError::ConnectionFailed(e.to_string()))?;
        Ok(Self { pool })
    }
}

#[async_trait]
impl SqlDriver for PostgresDriver {
    async fn query(
        &self,
        script: &str,
        params: &HashMap<String, SqlValue>,
    ) -> Result<Vec<SqlRow>, SqlError> {
        let (translated, param_order) = translate_named_params(script);

        let mut query = sqlx::query(&translated);
        for name in &param_order {
            let value = params.get(name).cloned().unwrap_or(SqlValue::Null);
            query = match value {
                SqlValue::Null => query.bind(Option::<String>::None),
                SqlValue::Bool(b) => query.bind(b),
                SqlValue::Int(n) => query.bind(n),
                SqlValue::Float(f) => query.bind(f),
                SqlValue::Text(s) => query.bind(s),
                SqlValue::Timestamp(ts) => query.bind(ts),
            };
        }

        let rows = query
            .fetch_all(&self.pool)
            .await
            .map_err(|e| SqlError::QueryFailed(e.to_string()))?;

        rows.iter().map(convert_row).collect()
    }
}

fn build_connection_url(config: &ConnectionConfig) -> Result<String, SqlError> {
    let get_str = |key: &str| -> Option<String> {
        config.settings.get(key).and_then(|v| v.as_str()).map(str::to_string)
    };

    let host = get_str("host").unwrap_or_else(|| "localhost".to_string());
    let port = config
        .settings
        .get("port")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(5432);
    let database = get_str("database")
        .ok_or_else(|| SqlError::ConnectionFailed("missing 'database' in connection settings".into()))?;
    let user = get_str("user").unwrap_or_else(|| "postgres".to_string());
    let password = match get_str("passwordEnv") {
        Some(env_name) => std::env::var(&env_name).unwrap_or_default(),
        None => String::new(),
    };

    Ok(format!("postgres://{user}:{password}@{host}:{port}/{database}"))
}

/// Rewrites `:name` placeholders (as authored in `datasources/sql/*.sql`
/// files) into Postgres's positional `$1, $2, ...` syntax, returning the
/// rewritten SQL plus which parameter name each positional slot binds —
/// a repeated `:name` reuses the same `$N`. Postgres's `::type` cast
/// operator is recognized and left alone rather than misread as a param
/// named `type`. This is a plain textual scan, not a SQL parser — script
/// files are trusted, hand-authored config, not untrusted input, so that's
/// an intentional scope limit rather than an oversight.
fn translate_named_params(script: &str) -> (String, Vec<String>) {
    let bytes = script.as_bytes();
    let mut output = String::with_capacity(script.len());
    let mut order: Vec<String> = Vec::new();
    let mut i = 0;

    while i < bytes.len() {
        let c = bytes[i] as char;

        if c == ':' && i + 1 < bytes.len() && bytes[i + 1] as char == ':' {
            output.push_str("::");
            i += 2;
            continue;
        }

        if c == ':' && i + 1 < bytes.len() && (bytes[i + 1] as char == '_' || (bytes[i + 1] as char).is_alphabetic())
        {
            let start = i + 1;
            let mut end = start;
            while end < bytes.len() && ((bytes[end] as char == '_') || (bytes[end] as char).is_alphanumeric()) {
                end += 1;
            }
            let name = &script[start..end];
            let position = match order.iter().position(|n| n == name) {
                Some(pos) => pos + 1,
                None => {
                    order.push(name.to_string());
                    order.len()
                }
            };
            output.push('$');
            output.push_str(&position.to_string());
            i = end;
            continue;
        }

        output.push(c);
        i += 1;
    }

    (output, order)
}

fn convert_row(row: &PgRow) -> Result<SqlRow, SqlError> {
    let mut out = SqlRow::new();
    for (i, column) in row.columns().iter().enumerate() {
        let type_name = column.type_info().name();
        let value = match type_name {
            "BOOL" => row.try_get::<Option<bool>, _>(i).map(|v| v.map(SqlValue::Bool)),
            "INT2" => row
                .try_get::<Option<i16>, _>(i)
                .map(|v| v.map(|n| SqlValue::Int(n as i64))),
            "INT4" => row
                .try_get::<Option<i32>, _>(i)
                .map(|v| v.map(|n| SqlValue::Int(n as i64))),
            "INT8" => row.try_get::<Option<i64>, _>(i).map(|v| v.map(SqlValue::Int)),
            "FLOAT4" => row
                .try_get::<Option<f32>, _>(i)
                .map(|v| v.map(|n| SqlValue::Float(n as f64))),
            "FLOAT8" => row.try_get::<Option<f64>, _>(i).map(|v| v.map(SqlValue::Float)),
            "TEXT" | "VARCHAR" | "BPCHAR" | "NAME" => {
                row.try_get::<Option<String>, _>(i).map(|v| v.map(SqlValue::Text))
            }
            "TIMESTAMP" | "TIMESTAMPTZ" => row
                .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>(i)
                .map(|v| v.map(SqlValue::Timestamp)),
            other => {
                return Err(SqlError::QueryFailed(format!(
                    "column '{}' has unsupported Postgres type '{other}'",
                    column.name()
                )));
            }
        };
        let value = value.map_err(|e| SqlError::QueryFailed(format!("column '{}': {e}", column.name())))?;
        out.insert(column.name().to_string(), value.unwrap_or(SqlValue::Null));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translates_a_single_named_param() {
        let (sql, order) = translate_named_params("SELECT * FROM cars WHERE vin = :vin");
        assert_eq!(sql, "SELECT * FROM cars WHERE vin = $1");
        assert_eq!(order, vec!["vin"]);
    }

    #[test]
    fn reuses_position_for_a_repeated_param() {
        let (sql, order) = translate_named_params("WHERE maker = :maker AND (:maker IS NOT NULL)");
        assert_eq!(sql, "WHERE maker = $1 AND ($1 IS NOT NULL)");
        assert_eq!(order, vec!["maker"]);
    }

    #[test]
    fn assigns_distinct_positions_in_order_of_first_appearance() {
        let (sql, order) = translate_named_params("WHERE maker = :maker AND model = :model");
        assert_eq!(sql, "WHERE maker = $1 AND model = $2");
        assert_eq!(order, vec!["maker", "model"]);
    }

    #[test]
    fn does_not_mistake_a_postgres_type_cast_for_a_param() {
        let (sql, order) = translate_named_params("SELECT amount::numeric FROM pricing WHERE id = :id");
        assert_eq!(sql, "SELECT amount::numeric FROM pricing WHERE id = $1");
        assert_eq!(order, vec!["id"]);
    }

    /// Real round-trip test against a live Postgres instance — not run by
    /// default since this dev environment has neither Docker nor a local
    /// Postgres. To run it: start a Postgres instance, then
    /// `DATABASE_URL_TEST=postgres://user:pass@localhost:5432/db cargo test --features postgres -- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn queries_a_real_postgres_instance() {
        let url = std::env::var("DATABASE_URL_TEST")
            .expect("set DATABASE_URL_TEST to a reachable Postgres connection string to run this test");
        let pool = sqlx::PgPool::connect(&url).await.expect("failed to connect");
        let driver = PostgresDriver { pool };

        sqlx::query("CREATE TEMP TABLE frogs_smoke_test (vin TEXT, year INT4)")
            .execute(&driver.pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO frogs_smoke_test (vin, year) VALUES ('1HGCM82633A004352', 2003)")
            .execute(&driver.pool)
            .await
            .unwrap();

        let mut params = HashMap::new();
        params.insert("vin".to_string(), SqlValue::Text("1HGCM82633A004352".to_string()));
        let rows = driver
            .query("SELECT vin, year FROM frogs_smoke_test WHERE vin = :vin", &params)
            .await
            .expect("query should succeed");

        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].get("vin"),
            Some(&SqlValue::Text("1HGCM82633A004352".to_string()))
        );
        assert_eq!(rows[0].get("year"), Some(&SqlValue::Int(2003)));
    }
}
