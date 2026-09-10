use std::collections::HashMap;

use async_trait::async_trait;
use sqlx::mysql::{MySqlPoolOptions, MySqlRow};
use sqlx::{Column, Row, TypeInfo};

use super::{SqlDriver, SqlError, SqlRow, SqlValue, sql_value_to_json};
use crate::config::ConnectionConfig;

#[derive(Debug)]
pub struct MySqlDriver {
    pool: sqlx::MySqlPool,
}

impl MySqlDriver {
    pub async fn connect(config: &ConnectionConfig) -> Result<Self, SqlError> {
        let url = build_connection_url(config)?;
        let pool = MySqlPoolOptions::new()
            .max_connections(super::DEFAULT_POOL_MAX_CONNECTIONS)
            .connect(&url)
            .await
            .map_err(|e| SqlError::ConnectionFailed(e.to_string()))?;
        Ok(Self { pool })
    }
}

#[async_trait]
impl SqlDriver for MySqlDriver {
    async fn query(&self, script: &str, params: &HashMap<String, SqlValue>) -> Result<Vec<SqlRow>, SqlError> {
        let (translated, order) = translate_named_params(script);

        let mut query = sqlx::query(&translated);
        for name in &order {
            let value = params.get(name).cloned().unwrap_or(SqlValue::Null);
            query = match value {
                SqlValue::Null => query.bind(Option::<String>::None),
                SqlValue::Bool(b) => query.bind(b),
                SqlValue::Int(n) => query.bind(n),
                SqlValue::Float(f) => query.bind(f),
                SqlValue::Text(s) => query.bind(s),
                SqlValue::Timestamp(ts) => query.bind(ts),
                // MySQL/MariaDB has no array column/parameter type at all
                // (unlike Postgres — see `postgres::bind_array`) — this
                // mirrors sqlite.rs's own JSON-encoded-text fallback exactly,
                // not postgres.rs's native-array path.
                SqlValue::Array(items) => query.bind(serde_json::Value::Array(items.iter().map(sql_value_to_json).collect()).to_string()),
            };
        }

        let rows = query.fetch_all(&self.pool).await.map_err(classify_query_error)?;

        rows.iter().map(convert_row).collect()
    }
}

/// Classifies a real query failure by sqlx's own portable `ErrorKind` —
/// not by hand-parsing MySQL's own error code — so a unique/foreign-key/
/// not-null/check constraint violation becomes `SqlError::ConstraintViolation`
/// (classifies to `datasource.sql.constraint_violation`) instead of the
/// generic `QueryFailed` every other query error still falls back to.
fn classify_query_error(e: sqlx::Error) -> SqlError {
    use sqlx::error::ErrorKind;
    match e.as_database_error().map(|db| db.kind()) {
        Some(ErrorKind::UniqueViolation | ErrorKind::ForeignKeyViolation | ErrorKind::NotNullViolation | ErrorKind::CheckViolation) => {
            SqlError::ConstraintViolation(e.to_string())
        }
        _ => SqlError::QueryFailed(e.to_string()),
    }
}

fn build_connection_url(config: &ConnectionConfig) -> Result<String, SqlError> {
    let get_str = |key: &str| -> Option<String> { config.settings.get(key).and_then(|v| v.as_str()).map(str::to_string) };

    let host = get_str("host").unwrap_or_else(|| "localhost".to_string());
    let port = config.settings.get("port").and_then(serde_json::Value::as_u64).unwrap_or(3306);
    let database = get_str("database").ok_or_else(|| SqlError::ConnectionFailed("missing 'database' in connection settings".into()))?;
    // MySQL's conventional default admin user is "root" — unlike Postgres's
    // own default of "postgres" (see `postgres::build_connection_url`).
    let user = get_str("user").unwrap_or_else(|| "root".to_string());
    let password = match get_str("passwordEnv") {
        Some(env_name) => std::env::var(&env_name).unwrap_or_default(),
        None => String::new(),
    };

    Ok(format!("mysql://{user}:{password}@{host}:{port}/{database}"))
}

/// Rewrites `:name` placeholders into MySQL's positional `?` syntax,
/// returning the rewritten SQL plus which parameter name each `?` binds, in
/// order. Adapted from `sqlite.rs`'s own version: like SQLite (and unlike
/// Postgres's `$N`), a plain `?` can't be reused by number, so every `?`
/// needs its own bind call — a repeated `:name` becomes a separate `?` bound
/// to the same value again, rather than one shared slot. `::` is still
/// recognized (a type-cast operator in Postgres, not in MySQL) purely so a
/// script copy-pasted from a Postgres connection behaves the same either way.
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

        if c == ':' && i + 1 < bytes.len() && (bytes[i + 1] as char == '_' || (bytes[i + 1] as char).is_alphabetic()) {
            let start = i + 1;
            let mut end = start;
            while end < bytes.len() && ((bytes[end] as char == '_') || (bytes[end] as char).is_alphanumeric()) {
                end += 1;
            }
            output.push('?');
            order.push(script[start..end].to_string());
            i = end;
            continue;
        }

        output.push(c);
        i += 1;
    }

    (output, order)
}

/// Column type names are taken from sqlx-mysql 0.8's own source
/// (`protocol::text::column::ColumnType::name`), not guessed or observed
/// against a live server — this dev environment has no MySQL instance
/// available. Two things confirmed directly from that source rather than
/// assumed: `TINYINT(1)` really is reported as a distinct type name,
/// `"BOOLEAN"`, separate from plain `"TINYINT"` (which stays `SqlValue::Int`
/// here) — so the width-1 boolean convention doesn't need guessing at either.
/// `"INT"` is what a real `INT`/`INTEGER` column reports (MySQL has no
/// separate "INTEGER" name at the wire level), but `"INTEGER"` is matched
/// too in case a future sqlx version or a MariaDB-specific path ever reports
/// it that way.
fn convert_row(row: &MySqlRow) -> Result<SqlRow, SqlError> {
    let mut out = SqlRow::new();
    for (i, column) in row.columns().iter().enumerate() {
        let type_name = column.type_info().name();
        let value = match type_name {
            "BOOLEAN" => row.try_get::<Option<bool>, _>(i).map(|v| v.map(SqlValue::Bool)),
            "TINYINT" => row.try_get::<Option<i8>, _>(i).map(|v| v.map(|n| SqlValue::Int(n as i64))),
            "SMALLINT" => row.try_get::<Option<i16>, _>(i).map(|v| v.map(|n| SqlValue::Int(n as i64))),
            "INT" | "INTEGER" => row.try_get::<Option<i32>, _>(i).map(|v| v.map(|n| SqlValue::Int(n as i64))),
            "BIGINT" => row.try_get::<Option<i64>, _>(i).map(|v| v.map(SqlValue::Int)),
            "FLOAT" => row.try_get::<Option<f32>, _>(i).map(|v| v.map(|n| SqlValue::Float(n as f64))),
            "DOUBLE" => row.try_get::<Option<f64>, _>(i).map(|v| v.map(SqlValue::Float)),
            "VARCHAR" | "CHAR" | "TEXT" => row.try_get::<Option<String>, _>(i).map(|v| v.map(SqlValue::Text)),
            "DATETIME" | "TIMESTAMP" => row.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>(i).map(|v| v.map(SqlValue::Timestamp)),
            other => {
                return Err(SqlError::QueryFailed(format!("column '{}' has unsupported MySQL type '{other}'", column.name())));
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
        assert_eq!(sql, "SELECT * FROM cars WHERE vin = ?");
        assert_eq!(order, vec!["vin"]);
    }

    /// Unlike Postgres's `$N` (which reuses one positional slot for a
    /// repeated `:name`), MySQL's plain `?` can't be reused by number — a
    /// repeated `:name` must become a *separate* `?` bound to the same value
    /// again, exactly like `sqlite.rs`'s
    /// `a_repeated_param_becomes_a_separate_placeholder_per_occurrence`.
    /// Deliberately not asserting the postgres.rs shape (one `$1` reused,
    /// `order == ["maker"]`) — that would be the wrong behavior here.
    #[test]
    fn a_repeated_param_becomes_a_separate_placeholder_per_occurrence() {
        let (sql, order) = translate_named_params("WHERE maker = :maker AND (:maker IS NOT NULL)");
        assert_eq!(sql, "WHERE maker = ? AND (? IS NOT NULL)");
        assert_eq!(order, vec!["maker", "maker"]);
    }

    #[test]
    fn assigns_distinct_positions_in_order_of_first_appearance() {
        let (sql, order) = translate_named_params("WHERE maker = :maker AND model = :model");
        assert_eq!(sql, "WHERE maker = ? AND model = ?");
        assert_eq!(order, vec!["maker", "model"]);
    }

    #[test]
    fn does_not_mistake_a_postgres_type_cast_for_a_param() {
        let (sql, order) = translate_named_params("SELECT amount::numeric FROM pricing WHERE id = :id");
        assert_eq!(sql, "SELECT amount::numeric FROM pricing WHERE id = ?");
        assert_eq!(order, vec!["id"]);
    }

    fn config_with(settings: &[(&str, serde_json::Value)]) -> ConnectionConfig {
        ConnectionConfig {
            driver: "mysql".to_string(),
            settings: settings.iter().map(|(k, v)| (k.to_string(), v.clone())).collect(),
        }
    }

    #[test]
    fn missing_database_is_a_clear_connection_error() {
        let config = config_with(&[]);
        let err = build_connection_url(&config).expect_err("missing 'database' must fail, not build a broken URL");
        assert!(matches!(err, SqlError::ConnectionFailed(_)));
        assert!(err.to_string().contains("database"));
    }

    #[test]
    fn defaults_host_port_and_user_when_not_configured() {
        let config = config_with(&[("database", serde_json::json!("vehicles"))]);
        let url = build_connection_url(&config).unwrap();
        assert_eq!(url, "mysql://root:@localhost:3306/vehicles");
    }

    #[test]
    fn uses_explicit_host_port_user_and_database() {
        let config = config_with(&[
            ("host", serde_json::json!("db.internal")),
            ("port", serde_json::json!(3307)),
            ("user", serde_json::json!("app")),
            ("database", serde_json::json!("vehicles")),
        ]);
        let url = build_connection_url(&config).unwrap();
        assert_eq!(url, "mysql://app:@db.internal:3307/vehicles");
    }

    #[test]
    fn resolves_the_password_from_the_named_env_var() {
        // SAFETY: this test doesn't run concurrently with anything else
        // that reads/writes this specific env var.
        unsafe {
            std::env::set_var("FROGS_TEST_MYSQL_PASSWORD", "s3cret");
        }
        let config = config_with(&[
            ("database", serde_json::json!("vehicles")),
            ("passwordEnv", serde_json::json!("FROGS_TEST_MYSQL_PASSWORD")),
        ]);
        let url = build_connection_url(&config).unwrap();
        assert_eq!(url, "mysql://root:s3cret@localhost:3306/vehicles");
    }

    #[test]
    fn an_unset_password_env_var_falls_back_to_an_empty_password_not_an_error() {
        let config = config_with(&[
            ("database", serde_json::json!("vehicles")),
            ("passwordEnv", serde_json::json!("FROGS_TEST_MYSQL_PASSWORD_DEFINITELY_UNSET")),
        ]);
        let url = build_connection_url(&config).unwrap();
        assert_eq!(url, "mysql://root:@localhost:3306/vehicles");
    }

    /// Real round-trip test against a live MySQL/MariaDB instance — not run
    /// by default since this dev environment has neither Docker nor a local
    /// MySQL server. To run it: start a MySQL/MariaDB instance, then
    /// `DATABASE_URL_TEST_MYSQL=mysql://user:pass@localhost:3306/db cargo test --features mysql -- --ignored`.
    /// A distinct env var from Postgres's `DATABASE_URL_TEST` so both live
    /// suites can be configured to coexist in the same CI run.
    ///
    /// Deliberately *not* a temporary table: `driver.pool` is a connection
    /// *pool* (`MySqlDriver::connect`, `max_connections(5)`), and MySQL's
    /// own `CREATE TEMPORARY TABLE` is scoped to the single session that
    /// created it — the follow-up `INSERT`/`SELECT` can easily land on a
    /// different physical connection than the one that ran the `CREATE`,
    /// where the temporary table simply doesn't exist. A real table, dropped
    /// both before (in case a previous run panicked before cleanup) and
    /// after, avoids that trap — same reasoning as postgres.rs's own
    /// `queries_a_real_postgres_instance`.
    #[tokio::test]
    #[ignore]
    async fn queries_a_real_mysql_instance() {
        let url = std::env::var("DATABASE_URL_TEST_MYSQL").expect("set DATABASE_URL_TEST_MYSQL to a reachable MySQL/MariaDB connection string to run this test");
        let pool = sqlx::MySqlPool::connect(&url).await.expect("failed to connect");
        let driver = MySqlDriver { pool };

        sqlx::query("DROP TABLE IF EXISTS frogs_smoke_test").execute(&driver.pool).await.unwrap();
        sqlx::query("CREATE TABLE frogs_smoke_test (vin TEXT, year INT)").execute(&driver.pool).await.unwrap();
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
        assert_eq!(rows[0].get("vin"), Some(&SqlValue::Text("1HGCM82633A004352".to_string())));
        assert_eq!(rows[0].get("year"), Some(&SqlValue::Int(2003)));

        sqlx::query("DROP TABLE frogs_smoke_test").execute(&driver.pool).await.unwrap();
    }

    /// MySQL/MariaDB has no native array column/parameter type at all (see
    /// `query`'s own `SqlValue::Array` arm) — a JSON array parameter always
    /// binds as JSON-encoded text instead, proven genuinely queryable via
    /// MySQL's own `JSON_LENGTH`, not just that it doesn't error. Mirrors
    /// sqlite.rs's `an_array_parameter_binds_as_json_text_and_is_queryable_via_json_each`,
    /// substituting `JSON_LENGTH` for `json_each` since MySQL has no
    /// equivalent table-valued JSON-array-expansion function built the same
    /// way SQLite's does.
    #[tokio::test]
    #[ignore]
    async fn an_array_parameter_binds_as_json_text_and_is_queryable_via_json_length() {
        let url = std::env::var("DATABASE_URL_TEST_MYSQL").expect("set DATABASE_URL_TEST_MYSQL to a reachable MySQL/MariaDB connection string to run this test");
        let pool = sqlx::MySqlPool::connect(&url).await.expect("failed to connect");
        let driver = MySqlDriver { pool };

        let mut params = HashMap::new();
        params.insert("ids".to_string(), SqlValue::Array(vec![SqlValue::Int(1), SqlValue::Int(2), SqlValue::Int(3)]));
        let rows = driver
            .query("SELECT JSON_LENGTH(:ids) AS n", &params)
            .await
            .expect("a JSON-array-typed parameter should be queryable via JSON_LENGTH");

        assert_eq!(rows[0].get("n"), Some(&SqlValue::Int(3)));
    }

    /// The point of `classify_query_error` existing at all: a real unique-
    /// constraint violation against a real MySQL/MariaDB instance classifies
    /// as `ConstraintViolation`, not the generic `QueryFailed` every other
    /// query error still falls back to. Proves the claimed copy-paste
    /// correctness against `postgres.rs`'s/`sqlite.rs`'s own versions
    /// against a real MySQL error, rather than just trusting it.
    #[tokio::test]
    #[ignore]
    async fn a_unique_constraint_violation_classifies_distinctly() {
        let url = std::env::var("DATABASE_URL_TEST_MYSQL").expect("set DATABASE_URL_TEST_MYSQL to a reachable MySQL/MariaDB connection string to run this test");
        let pool = sqlx::MySqlPool::connect(&url).await.expect("failed to connect");
        let driver = MySqlDriver { pool };

        sqlx::query("DROP TABLE IF EXISTS frogs_constraint_test").execute(&driver.pool).await.unwrap();
        sqlx::query("CREATE TABLE frogs_constraint_test (vin VARCHAR(64) UNIQUE)")
            .execute(&driver.pool)
            .await
            .unwrap();

        let mut params = HashMap::new();
        params.insert("vin".to_string(), SqlValue::Text("1HGCM82633A004352".to_string()));
        driver
            .query("INSERT INTO frogs_constraint_test (vin) VALUES (:vin)", &params)
            .await
            .expect("the first insert should succeed");

        let err = driver
            .query("INSERT INTO frogs_constraint_test (vin) VALUES (:vin)", &params)
            .await
            .expect_err("a duplicate value against a UNIQUE column must fail");

        assert!(matches!(err, SqlError::ConstraintViolation(_)), "expected ConstraintViolation, got {err:?}");

        sqlx::query("DROP TABLE frogs_constraint_test").execute(&driver.pool).await.unwrap();
    }
}
