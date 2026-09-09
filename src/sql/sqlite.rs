use std::collections::HashMap;

use async_trait::async_trait;
use sqlx::sqlite::{SqliteColumn, SqliteConnectOptions, SqlitePoolOptions, SqliteRow};
use sqlx::{Column, Row, TypeInfo, ValueRef};

use super::{SqlDriver, SqlError, SqlRow, SqlValue, sql_value_to_json};
use crate::config::ConnectionConfig;

#[derive(Debug)]
pub struct SqliteDriver {
    pool: sqlx::SqlitePool,
}

impl SqliteDriver {
    pub async fn connect(config: &ConnectionConfig) -> Result<Self, SqlError> {
        let database = config
            .settings
            .get("database")
            .and_then(|v| v.as_str())
            .ok_or_else(|| SqlError::ConnectionFailed("missing 'database' (a file path, or ':memory:') in connection settings".into()))?;

        let is_memory = database == ":memory:";
        let options = if is_memory {
            SqliteConnectOptions::new().in_memory(true)
        } else {
            SqliteConnectOptions::new().filename(database).create_if_missing(true)
        };

        // SQLite serializes writes internally regardless of pool size, so a
        // large pool doesn't buy write concurrency the way it does for
        // Postgres — kept modest rather than reusing the same default. A
        // `:memory:` database is further pinned to exactly one connection:
        // each new connection to `:memory:` gets its own *separate*,
        // otherwise-empty database, so pooling would silently scatter
        // queries across unrelated in-memory databases.
        let pool = SqlitePoolOptions::new()
            .max_connections(if is_memory { 1 } else { super::DEFAULT_POOL_MAX_CONNECTIONS })
            .connect_with(options)
            .await
            .map_err(|e| SqlError::ConnectionFailed(e.to_string()))?;

        Ok(Self { pool })
    }
}

#[async_trait]
impl SqlDriver for SqliteDriver {
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
                // SQLite has no native array parameter type at all, unlike
                // Postgres (see `postgres::bind_array`) — always the same
                // JSON-encoded-text fallback `json_value_to_sql_value` used
                // for every array before native binding existed anywhere.
                SqlValue::Array(items) => query.bind(serde_json::Value::Array(items.iter().map(sql_value_to_json).collect()).to_string()),
            };
        }

        let rows = query.fetch_all(&self.pool).await.map_err(classify_query_error)?;

        rows.iter().map(convert_row).collect()
    }
}

/// Classifies a real query failure by sqlx's own portable `ErrorKind` —
/// not by hand-parsing SQLite's own result code — so a unique/foreign-key/
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

/// Rewrites `:name` placeholders into SQLite's positional `?` syntax,
/// returning the rewritten SQL plus which parameter name each `?` binds, in
/// order. Unlike Postgres's `$N`, a plain `?` can't be reused by number —
/// sqlx's SQLite backend rejects named placeholders outright at runtime
/// ("unsupported SQL parameter format"), so every `?` needs its own bind
/// call — a repeated `:name` becomes a separate `?` bound to the same value
/// again, rather than one shared slot. `::` is still recognized (a
/// type-cast operator in Postgres, not in SQLite) purely so a script
/// copy-pasted from a Postgres connection behaves the same either way.
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

fn convert_row(row: &SqliteRow) -> Result<SqlRow, SqlError> {
    let mut out = SqlRow::new();
    for (i, column) in row.columns().iter().enumerate() {
        // `column.type_info()` reflects SQLite's *declared* column type
        // (`sqlite3_column_decltype`) — real for an actual table column
        // (e.g. `year INTEGER`), but always "NULL" for a computed/literal
        // expression with no table backing it (`SELECT 1 AS x`), regardless
        // of that expression's real value. For that case, fall back to the
        // *value's own* runtime storage class instead (`sqlite3_column_type`,
        // via `try_get_raw`) — the only place that information is available.
        let declared = column.type_info().name();
        let value = if declared == "NULL" {
            let raw = row.try_get_raw(i).map_err(|e| SqlError::QueryFailed(format!("column '{}': {e}", column.name())))?;
            decode_column(row, i, column, raw.type_info().name())?
        } else {
            decode_column(row, i, column, declared)?
        };
        out.insert(column.name().to_string(), value);
    }
    Ok(out)
}

fn decode_column(row: &SqliteRow, i: usize, column: &SqliteColumn, type_name: &str) -> Result<SqlValue, SqlError> {
    let value = match type_name {
        "BOOLEAN" => row.try_get::<Option<bool>, _>(i).map(|v| v.map(SqlValue::Bool)),
        "INTEGER" => row.try_get::<Option<i64>, _>(i).map(|v| v.map(SqlValue::Int)),
        "REAL" => row.try_get::<Option<f64>, _>(i).map(|v| v.map(SqlValue::Float)),
        "TEXT" => row.try_get::<Option<String>, _>(i).map(|v| v.map(SqlValue::Text)),
        "DATETIME" => row.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>(i).map(|v| v.map(SqlValue::Timestamp)),
        "NULL" => Ok(None),
        other => {
            return Err(SqlError::QueryFailed(format!("column '{}' has unsupported SQLite type '{other}'", column.name())));
        }
    };
    value
        .map(|opt| opt.unwrap_or(SqlValue::Null))
        .map_err(|e| SqlError::QueryFailed(format!("column '{}': {e}", column.name())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConnectionConfig;

    /// A computed/literal `SELECT` — no `CREATE TABLE` at all — is a
    /// realistic way to back a zero-setup mock endpoint (e.g. standing in
    /// for an upstream service in a test, without seeding any actual data).
    /// It's also what caught a real bug: SQLite reports "NULL" as the
    /// *declared* type for a column with no backing table column,
    /// regardless of its actual value, which made every field in a query
    /// like this silently decode as `SqlValue::Null` until `convert_row`
    /// was fixed to fall back to the value's own runtime type in that case.
    #[tokio::test]
    async fn decodes_a_literal_select_with_no_backing_table() {
        let driver = SqliteDriver::connect(&memory_config()).await.unwrap();
        let rows = driver
            .query("SELECT 24500.126 AS amount, 'usd' AS currency", &HashMap::new())
            .await
            .expect("a literal SELECT needs no table at all");

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("amount"), Some(&SqlValue::Float(24500.126)));
        assert_eq!(rows[0].get("currency"), Some(&SqlValue::Text("usd".to_string())));
    }

    fn memory_config() -> ConnectionConfig {
        let mut settings = HashMap::new();
        settings.insert("database".to_string(), serde_json::Value::String(":memory:".to_string()));
        ConnectionConfig {
            driver: "sqlite".to_string(),
            settings,
        }
    }

    /// A real round-trip test, not `#[ignore]`d — unlike Postgres, an
    /// in-memory SQLite database needs no external service at all, so
    /// there's no reason this can't run in CI/every `cargo test`.
    #[tokio::test]
    async fn queries_a_real_in_memory_database() {
        let driver = SqliteDriver::connect(&memory_config()).await.expect("connect should succeed");

        sqlx::query("CREATE TABLE cars (vin TEXT, year INTEGER, price REAL, active BOOLEAN)")
            .execute(&driver.pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO cars (vin, year, price, active) VALUES ('1HGCM82633A004352', 2003, 4500.5, 1)")
            .execute(&driver.pool)
            .await
            .unwrap();

        let mut params = HashMap::new();
        params.insert("vin".to_string(), SqlValue::Text("1HGCM82633A004352".to_string()));
        let rows = driver
            .query("SELECT vin, year, price, active FROM cars WHERE vin = :vin", &params)
            .await
            .expect("query should succeed");

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("vin"), Some(&SqlValue::Text("1HGCM82633A004352".to_string())));
        assert_eq!(rows[0].get("year"), Some(&SqlValue::Int(2003)));
        assert_eq!(rows[0].get("price"), Some(&SqlValue::Float(4500.5)));
        assert_eq!(rows[0].get("active"), Some(&SqlValue::Bool(true)));
    }

    /// SQLite has no native array parameter type — `SqlValue::Array` always
    /// binds as JSON-encoded text, queryable via SQLite's own `json_each`
    /// table-valued function to prove it's genuinely usable JSON on the
    /// other end, not just an opaque blob.
    #[tokio::test]
    async fn an_array_parameter_binds_as_json_text_and_is_queryable_via_json_each() {
        let driver = SqliteDriver::connect(&memory_config()).await.unwrap();

        let mut params = HashMap::new();
        params.insert("ids".to_string(), SqlValue::Array(vec![SqlValue::Int(1), SqlValue::Int(2), SqlValue::Int(3)]));
        let rows = driver
            .query("SELECT COUNT(*) AS n FROM json_each(:ids)", &params)
            .await
            .expect("a JSON-array-typed parameter should be queryable via json_each");

        assert_eq!(rows[0].get("n"), Some(&SqlValue::Int(3)));
    }

    /// The point of `classify_query_error` existing at all: a real unique-
    /// constraint violation against a real `:memory:` database classifies
    /// as `ConstraintViolation`, not the generic `QueryFailed` every other
    /// query error still falls back to.
    #[tokio::test]
    async fn a_unique_constraint_violation_classifies_distinctly() {
        let driver = SqliteDriver::connect(&memory_config()).await.unwrap();
        sqlx::query("CREATE TABLE cars (vin TEXT UNIQUE)").execute(&driver.pool).await.unwrap();

        let mut params = HashMap::new();
        params.insert("vin".to_string(), SqlValue::Text("1HGCM82633A004352".to_string()));
        driver
            .query("INSERT INTO cars (vin) VALUES (:vin)", &params)
            .await
            .expect("the first insert should succeed");

        let err = driver
            .query("INSERT INTO cars (vin) VALUES (:vin)", &params)
            .await
            .expect_err("a duplicate value against a UNIQUE column must fail");

        assert!(matches!(err, SqlError::ConstraintViolation(_)), "expected ConstraintViolation, got {err:?}");
    }

    /// An ordinary bad-SQL failure (not a constraint violation at all) must
    /// still classify as the generic `QueryFailed` — proves
    /// `classify_query_error` doesn't over-eagerly reclassify everything.
    #[tokio::test]
    async fn an_ordinary_query_failure_is_not_misclassified_as_a_constraint_violation() {
        let driver = SqliteDriver::connect(&memory_config()).await.unwrap();
        let err = driver
            .query("SELECT * FROM a_table_that_does_not_exist", &HashMap::new())
            .await
            .expect_err("querying a nonexistent table must fail");

        assert!(
            matches!(err, SqlError::QueryFailed(_)),
            "expected the ordinary QueryFailed classification, got {err:?}"
        );
    }

    #[tokio::test]
    async fn query_with_no_matching_row_returns_empty() {
        let driver = SqliteDriver::connect(&memory_config()).await.unwrap();
        sqlx::query("CREATE TABLE cars (vin TEXT)").execute(&driver.pool).await.unwrap();

        let rows = driver.query("SELECT vin FROM cars WHERE vin = :vin", &HashMap::new()).await.unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn translates_named_params_to_positional_question_marks() {
        let (sql, order) = translate_named_params("WHERE maker = :maker AND model = :model");
        assert_eq!(sql, "WHERE maker = ? AND model = ?");
        assert_eq!(order, vec!["maker", "model"]);
    }

    #[test]
    fn a_repeated_param_becomes_a_separate_placeholder_per_occurrence() {
        let (sql, order) = translate_named_params("WHERE maker = :maker AND (:maker IS NOT NULL)");
        assert_eq!(sql, "WHERE maker = ? AND (? IS NOT NULL)");
        assert_eq!(order, vec!["maker", "maker"]);
    }

    #[test]
    fn does_not_mistake_a_postgres_type_cast_for_a_param() {
        let (sql, order) = translate_named_params("SELECT amount::numeric FROM pricing WHERE id = :id");
        assert_eq!(sql, "SELECT amount::numeric FROM pricing WHERE id = ?");
        assert_eq!(order, vec!["id"]);
    }

    #[tokio::test]
    async fn missing_database_setting_is_a_clear_connection_error() {
        let config = ConnectionConfig {
            driver: "sqlite".to_string(),
            settings: HashMap::new(),
        };
        let err = SqliteDriver::connect(&config).await.expect_err("missing 'database' should fail to connect");
        assert!(matches!(err, SqlError::ConnectionFailed(_)));
    }
}
