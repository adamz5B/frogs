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
            .max_connections(super::DEFAULT_POOL_MAX_CONNECTIONS)
            .acquire_timeout(std::time::Duration::from_secs(super::DEFAULT_POOL_ACQUIRE_TIMEOUT_SECS))
            .connect(&url)
            .await
            .map_err(|e| SqlError::ConnectionFailed(e.to_string()))?;
        Ok(Self { pool })
    }
}

#[async_trait]
impl SqlDriver for PostgresDriver {
    async fn query(&self, script: &str, params: &HashMap<String, SqlValue>) -> Result<Vec<SqlRow>, SqlError> {
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
                SqlValue::Array(items) => bind_array(query, items),
            };
        }

        let rows = query.fetch_all(&self.pool).await.map_err(classify_query_error)?;

        rows.iter().map(convert_row).collect()
    }
}

/// Classifies a real query failure by sqlx's own portable `ErrorKind` —
/// not by hand-parsing Postgres's SQLSTATE code — so a unique/foreign-key/
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

/// Binds a `SqlValue::Array` as a real native Postgres array parameter when
/// every element is the same scalar kind sqlx already knows how to encode
/// as one (`int8[]`/`float8[]`/`bool[]`/`text[]`) — an empty array binds as
/// `text[]`, arbitrarily, since there's no element to infer a type from.
/// Anything else (mixed element types, or elements this doesn't model —
/// nested arrays, timestamps) falls back to the same JSON-encoded-text
/// shape `json_value_to_sql_value` used for *every* array before this
/// function existed, rather than erroring on the harder cases.
fn bind_array<'q>(
    query: sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>,
    items: Vec<SqlValue>,
) -> sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments> {
    if items.is_empty() {
        return query.bind(Vec::<String>::new());
    }
    if items.iter().all(|v| matches!(v, SqlValue::Int(_))) {
        let values: Vec<i64> = items.into_iter().map(|v| if let SqlValue::Int(n) = v { n } else { unreachable!() }).collect();
        return query.bind(values);
    }
    if items.iter().all(|v| matches!(v, SqlValue::Float(_))) {
        let values: Vec<f64> = items.into_iter().map(|v| if let SqlValue::Float(f) = v { f } else { unreachable!() }).collect();
        return query.bind(values);
    }
    if items.iter().all(|v| matches!(v, SqlValue::Bool(_))) {
        let values: Vec<bool> = items.into_iter().map(|v| if let SqlValue::Bool(b) = v { b } else { unreachable!() }).collect();
        return query.bind(values);
    }
    if items.iter().all(|v| matches!(v, SqlValue::Text(_))) {
        let values: Vec<String> = items.into_iter().map(|v| if let SqlValue::Text(s) = v { s } else { unreachable!() }).collect();
        return query.bind(values);
    }
    let json_text = serde_json::Value::Array(items.iter().map(super::sql_value_to_json).collect()).to_string();
    query.bind(json_text)
}

fn build_connection_url(config: &ConnectionConfig) -> Result<String, SqlError> {
    let get_str = |key: &str| -> Option<String> { config.settings.get(key).and_then(|v| v.as_str()).map(str::to_string) };

    let host = get_str("host").unwrap_or_else(|| "localhost".to_string());
    let port = config.settings.get("port").and_then(serde_json::Value::as_u64).unwrap_or(5432);
    let database = get_str("database").ok_or_else(|| SqlError::ConnectionFailed("missing 'database' in connection settings".into()))?;
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
    let mut output = String::with_capacity(script.len());
    let mut order: Vec<String> = Vec::new();
    let mut chars = script.char_indices().peekable();

    while let Some((i, c)) = chars.next() {
        if c == ':' {
            if chars.peek().map(|&(_, next)| next) == Some(':') {
                chars.next();
                output.push_str("::");
                continue;
            }
            // `i` is the colon, which is ASCII, so `i + 1` is always a
            // character boundary. The scan itself never advances by raw index:
            // the only way forward is `chars.next()`, so no index arithmetic
            // can stall the loop or land mid-character.
            if let Some((name, end)) = super::ascii_param_name_at(script, i + 1) {
                let position = match order.iter().position(|n| n == name) {
                    Some(pos) => pos + 1,
                    None => {
                        order.push(name.to_string());
                        order.len()
                    }
                };
                output.push('$');
                output.push_str(&position.to_string());
                while chars.peek().is_some_and(|&(j, _)| j < end) {
                    chars.next();
                }
                continue;
            }
        }

        output.push(c);
    }

    (output, order)
}

fn convert_row(row: &PgRow) -> Result<SqlRow, SqlError> {
    let mut out = SqlRow::new();
    for (i, column) in row.columns().iter().enumerate() {
        let type_name = column.type_info().name();
        let value = match type_name {
            "BOOL" => row.try_get::<Option<bool>, _>(i).map(|v| v.map(SqlValue::Bool)),
            "INT2" => row.try_get::<Option<i16>, _>(i).map(|v| v.map(|n| SqlValue::Int(n as i64))),
            "INT4" => row.try_get::<Option<i32>, _>(i).map(|v| v.map(|n| SqlValue::Int(n as i64))),
            "INT8" => row.try_get::<Option<i64>, _>(i).map(|v| v.map(SqlValue::Int)),
            "FLOAT4" => row.try_get::<Option<f32>, _>(i).map(|v| v.map(|n| SqlValue::Float(n as f64))),
            "FLOAT8" => row.try_get::<Option<f64>, _>(i).map(|v| v.map(SqlValue::Float)),
            "TEXT" | "VARCHAR" | "BPCHAR" | "NAME" => row.try_get::<Option<String>, _>(i).map(|v| v.map(SqlValue::Text)),
            "TIMESTAMP" | "TIMESTAMPTZ" => row.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>(i).map(|v| v.map(SqlValue::Timestamp)),
            other => {
                return Err(SqlError::QueryFailed(format!("column '{}' has unsupported Postgres type '{other}'", column.name())));
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

    /// Runs a synchronous, potentially-hanging call on its own thread with a
    /// hard deadline — a infinite-loop regression in `translate_named_params`
    /// (the single worst-case outcome called out for this fix) must fail
    /// this test loudly rather than hang the whole `cargo test` run forever.
    fn run_with_timeout<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(std::time::Duration::from_secs(2))
            .expect("translate_named_params did not return within 2s — likely an infinite-loop regression in the char-advance logic")
    }

    /// Previously panicked: a byte-wise scan that reinterpreted the lead
    /// byte of 'é' as alphabetic could stop mid-character and slice at a
    /// non-char-boundary. Run under a watchdog since the specifically
    /// called-out worst-case regression here is an infinite loop, not just
    /// a panic.
    #[test]
    fn a_colon_immediately_followed_by_a_multibyte_character_does_not_panic_or_hang() {
        let (sql, order) = run_with_timeout(|| translate_named_params("SELECT 1 -- :é"));
        assert_eq!(
            sql, "SELECT 1 -- :é",
            "no identifier starts right after the colon, so the text passes through unchanged"
        );
        assert!(order.is_empty());
    }

    /// Previously panicked for the same reason as the comment case above —
    /// this is the "real placeholder immediately followed by non-ASCII"
    /// shape (`:idé`), not just a bare colon in prose.
    #[test]
    fn a_placeholder_name_truncated_by_a_trailing_non_ascii_character_binds_only_its_ascii_prefix() {
        let (sql, order) = run_with_timeout(|| translate_named_params("SELECT :idé FROM t"));
        assert_eq!(sql, "SELECT $1é FROM t");
        assert_eq!(order, vec!["id"]);
    }

    /// Previously corrupted: non-ASCII passthrough text was being
    /// re-encoded as Latin-1 (`'José'` became `'JosÃ©'` in the SQL actually
    /// sent). `char_indices`/`String::push(char)` can't reproduce that bug —
    /// pinned here as a regression test, run under the same watchdog since
    /// this is exactly the "ordinary passthrough text, must return promptly"
    /// case called out for this fix.
    #[test]
    fn non_ascii_passthrough_text_round_trips_byte_identically_not_latin1_corrupted() {
        let (sql, order) = run_with_timeout(|| translate_named_params("SELECT 'José' AS n WHERE x = :x"));
        assert_eq!(sql, "SELECT 'José' AS n WHERE x = $1");
        assert_eq!(order, vec!["x"]);
    }

    /// Pins the `::`-is-a-cast-operator direction explicitly: a `::name`
    /// with nothing before the first colon is still read as a (two-colon)
    /// cast marker followed by literal text, not a placeholder named `name`
    /// — empty order, not `["name"]`.
    #[test]
    fn a_double_colon_prefix_is_a_cast_marker_not_a_placeholder() {
        let (sql, order) = translate_named_params("::name");
        assert_eq!(sql, "::name");
        assert!(order.is_empty());
    }

    fn config_with(settings: &[(&str, serde_json::Value)]) -> ConnectionConfig {
        ConnectionConfig {
            driver: "postgres".to_string(),
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
        assert_eq!(url, "postgres://postgres:@localhost:5432/vehicles");
    }

    #[test]
    fn uses_explicit_host_port_user_and_database() {
        let config = config_with(&[
            ("host", serde_json::json!("db.internal")),
            ("port", serde_json::json!(6543)),
            ("user", serde_json::json!("app")),
            ("database", serde_json::json!("vehicles")),
        ]);
        let url = build_connection_url(&config).unwrap();
        assert_eq!(url, "postgres://app:@db.internal:6543/vehicles");
    }

    #[test]
    fn resolves_the_password_from_the_named_env_var() {
        // SAFETY: this test doesn't run concurrently with anything else
        // that reads/writes this specific env var.
        unsafe {
            std::env::set_var("FROGS_TEST_PG_PASSWORD", "s3cret");
        }
        let config = config_with(&[
            ("database", serde_json::json!("vehicles")),
            ("passwordEnv", serde_json::json!("FROGS_TEST_PG_PASSWORD")),
        ]);
        let url = build_connection_url(&config).unwrap();
        assert_eq!(url, "postgres://postgres:s3cret@localhost:5432/vehicles");
    }

    #[test]
    fn an_unset_password_env_var_falls_back_to_an_empty_password_not_an_error() {
        let config = config_with(&[
            ("database", serde_json::json!("vehicles")),
            ("passwordEnv", serde_json::json!("FROGS_TEST_PG_PASSWORD_DEFINITELY_UNSET")),
        ]);
        let url = build_connection_url(&config).unwrap();
        assert_eq!(url, "postgres://postgres:@localhost:5432/vehicles");
    }

    /// Real round-trip test against a live Postgres instance — not run by
    /// default since this dev environment has neither Docker nor a local
    /// Postgres. To run it: start a Postgres instance, then
    /// `DATABASE_URL_TEST=postgres://user:pass@localhost:5432/db cargo test --features postgres -- --ignored`.
    ///
    /// Deliberately *not* `CREATE TEMP TABLE`: a temp table is scoped to
    /// the single session that created it, but `driver.pool` is a
    /// connection *pool* (`PostgresDriver::connect`, `max_connections(5)`)
    /// — the follow-up `INSERT`/`SELECT` can easily land on a different
    /// physical connection than the one that ran the `CREATE`, where the
    /// temp table simply doesn't exist. A real table, dropped both before
    /// (in case a previous run panicked before cleanup) and after, avoids
    /// that trap.
    #[tokio::test]
    #[ignore]
    async fn queries_a_real_postgres_instance() {
        let url = std::env::var("DATABASE_URL_TEST").expect("set DATABASE_URL_TEST to a reachable Postgres connection string to run this test");
        let pool = sqlx::PgPool::connect(&url).await.expect("failed to connect");
        let driver = PostgresDriver { pool };

        sqlx::query("DROP TABLE IF EXISTS frogs_smoke_test").execute(&driver.pool).await.unwrap();
        sqlx::query("CREATE TABLE frogs_smoke_test (vin TEXT, year INT4)")
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
        assert_eq!(rows[0].get("vin"), Some(&SqlValue::Text("1HGCM82633A004352".to_string())));
        assert_eq!(rows[0].get("year"), Some(&SqlValue::Int(2003)));

        sqlx::query("DROP TABLE frogs_smoke_test").execute(&driver.pool).await.unwrap();
    }

    /// A homogeneous scalar array binds as a real native Postgres array
    /// (`= ANY($1)`, not a JSON-text blob a script would have to
    /// `json_array_elements()` its way through) — the actual point of
    /// `bind_array` existing at all. Same env-var-gated `#[ignore]`
    /// convention as the smoke test above.
    #[tokio::test]
    #[ignore]
    async fn an_array_parameter_binds_as_a_real_postgres_array() {
        let url = std::env::var("DATABASE_URL_TEST").expect("set DATABASE_URL_TEST to a reachable Postgres connection string to run this test");
        let pool = sqlx::PgPool::connect(&url).await.expect("failed to connect");
        let driver = PostgresDriver { pool };

        let mut params = HashMap::new();
        params.insert("ids".to_string(), SqlValue::Array(vec![SqlValue::Int(1), SqlValue::Int(2), SqlValue::Int(3)]));
        let rows = driver
            .query("SELECT unnest(:ids::int8[]) AS id ORDER BY id", &params)
            .await
            .expect("a homogeneous int array should bind as a real Postgres array, queryable via unnest");

        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].get("id"), Some(&SqlValue::Int(1)));
        assert_eq!(rows[1].get("id"), Some(&SqlValue::Int(2)));
        assert_eq!(rows[2].get("id"), Some(&SqlValue::Int(3)));
    }

    /// A mixed-type array has no single native Postgres array type to bind
    /// as, so it falls back to the same JSON-encoded-text shape every array
    /// used before native binding existed — proven queryable via Postgres's
    /// own `jsonb_array_length`, not just that it doesn't error.
    #[tokio::test]
    #[ignore]
    async fn a_mixed_type_array_parameter_falls_back_to_json_text() {
        let url = std::env::var("DATABASE_URL_TEST").expect("set DATABASE_URL_TEST to a reachable Postgres connection string to run this test");
        let pool = sqlx::PgPool::connect(&url).await.expect("failed to connect");
        let driver = PostgresDriver { pool };

        let mut params = HashMap::new();
        params.insert("mixed".to_string(), SqlValue::Array(vec![SqlValue::Int(1), SqlValue::Text("two".to_string())]));
        let rows = driver
            .query("SELECT jsonb_array_length(:mixed::jsonb) AS n", &params)
            .await
            .expect("a mixed-type array should still bind as valid JSON text");

        assert_eq!(rows[0].get("n"), Some(&SqlValue::Int(2)));
    }

    /// The point of `classify_query_error` existing at all: a real unique-
    /// constraint violation against a real Postgres instance classifies as
    /// `ConstraintViolation`, not the generic `QueryFailed` every other
    /// query error still falls back to.
    #[tokio::test]
    #[ignore]
    async fn a_unique_constraint_violation_classifies_distinctly() {
        let url = std::env::var("DATABASE_URL_TEST").expect("set DATABASE_URL_TEST to a reachable Postgres connection string to run this test");
        let pool = sqlx::PgPool::connect(&url).await.expect("failed to connect");
        let driver = PostgresDriver { pool };

        sqlx::query("DROP TABLE IF EXISTS frogs_constraint_test").execute(&driver.pool).await.unwrap();
        sqlx::query("CREATE TABLE frogs_constraint_test (vin TEXT UNIQUE)")
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

    /// The point of `DEFAULT_POOL_ACQUIRE_TIMEOUT_SECS` existing at all
    /// (see `docs/frogs-source-call-timeout.md`): wrapping a real query in
    /// `tokio::time::timeout` and letting it elapse must not poison the
    /// shared connection pool out from under every other caller. A
    /// `pg_sleep(2)` call, bounded by a much shorter `tokio::time::timeout`
    /// (the same wrapper `endpoint::resolve::run_sql_source` applies around
    /// an ordinary source's real call), is left to keep running on its own
    /// connection after we stop awaiting it — an immediately following
    /// ordinary `SELECT 1` on the very same driver/pool must still succeed,
    /// proving the pool handed back a healthy connection rather than one
    /// stuck mid-query or otherwise wedged.
    #[tokio::test]
    #[ignore]
    async fn a_timed_out_query_does_not_poison_the_shared_connection_pool() {
        let url = std::env::var("DATABASE_URL_TEST").expect("set DATABASE_URL_TEST to a reachable Postgres connection string to run this test");
        let pool = sqlx::PgPool::connect(&url).await.expect("failed to connect");
        let driver = PostgresDriver { pool };

        let empty_params = HashMap::new();
        let slow_query = driver.query("SELECT pg_sleep(2)", &empty_params);
        let outcome = tokio::time::timeout(std::time::Duration::from_millis(100), slow_query).await;
        assert!(outcome.is_err(), "the 2-second pg_sleep must not complete within the 100ms bound");

        // The same driver, same pool, immediately afterwards — if the timed-
        // out call above left the pool in a bad state (e.g. a connection
        // that's still mid-query and never returned), this would hang or
        // fail instead of returning promptly.
        let rows = driver
            .query("SELECT 1 AS one", &empty_params)
            .await
            .expect("an ordinary query on the same pool must still succeed after a prior call timed out");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("one"), Some(&SqlValue::Int(1)));
    }
}
