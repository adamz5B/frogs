use std::collections::HashMap;

use async_trait::async_trait;
use tiberius::ColumnType;

use super::{SqlDriver, SqlError, SqlRow, SqlValue, sql_value_to_json};
use crate::config::ConnectionConfig;

pub struct MssqlDriver {
    pool: deadpool_tiberius::Pool,
}

/// Hand-written rather than `#[derive(Debug)]`: `deadpool_tiberius::Manager`
/// (the pool's own type parameter) holds a `Box<dyn Fn(...)>` internally and
/// has no `Debug` impl of its own, so `deadpool_tiberius::Pool` doesn't
/// implement `Debug` either — required regardless, since `SqlDriver: Debug`.
impl std::fmt::Debug for MssqlDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MssqlDriver").finish_non_exhaustive()
    }
}

/// Pure connection settings pulled out of `connections.json`, kept separate
/// from `deadpool_tiberius::Manager` itself (unlike `postgres`/`mysql`'s own
/// URL-string equivalent) so `build_connection_settings` is unit-testable
/// without constructing a real `Manager`/`Pool` — `deadpool-tiberius`'s
/// builder isn't URL-based, and there's no cheap way to build one without
/// actually dialing a server.
struct MssqlConnectionSettings {
    host: String,
    port: u16,
    database: String,
    user: String,
    password: String,
}

/// Same shape/semantics as `postgres::build_connection_url`/
/// `mysql::build_connection_url` — `host`/`port`/`user`/`passwordEnv` all
/// default the same way — with one deliberate difference: a missing
/// `database` is NOT a hard error here. `deadpool-tiberius` itself defaults
/// an unset database to `"master"`, which is a perfectly usable target for
/// e.g. `frogs validate`'s connectivity check; forcing every project to name
/// one up front the way Postgres/MySQL do buys nothing extra, since `master`
/// always exists on a real SQL Server instance.
fn build_connection_settings(config: &ConnectionConfig) -> Result<MssqlConnectionSettings, SqlError> {
    let get_str = |key: &str| -> Option<String> { config.settings.get(key).and_then(|v| v.as_str()).map(str::to_string) };

    let host = get_str("host").unwrap_or_else(|| "localhost".to_string());
    let port = config.settings.get("port").and_then(serde_json::Value::as_u64).unwrap_or(1433) as u16;
    let database = get_str("database").unwrap_or_else(|| "master".to_string());
    // SQL Server's conventional admin login — unlike Postgres's "postgres" or
    // MySQL/MariaDB's "root" (see each driver's own `build_connection_url`).
    let user = get_str("user").unwrap_or_else(|| "sa".to_string());
    let password = match get_str("passwordEnv") {
        Some(env_name) => std::env::var(&env_name).unwrap_or_default(),
        None => String::new(),
    };

    Ok(MssqlConnectionSettings {
        host,
        port,
        database,
        user,
        password,
    })
}

impl MssqlDriver {
    /// `.trust_cert()` is called unconditionally: SQL Server requires an
    /// encrypted connection by default, and most dev/self-signed instances
    /// (including the CI service container this driver is tested against)
    /// have no real CA chain a client could validate against. This trades
    /// away certificate *authentication* while keeping the transport itself
    /// encrypted — the same trade-off Postgres's/MySQL's own default TLS
    /// posture in this project already makes (see `postgres`'s/`mysql`'s
    /// `tls-rustls` sqlx feature: encrypted-in-transit, not CA-verified by
    /// default), not a new or weaker one introduced specifically for MSSQL.
    pub async fn connect(config: &ConnectionConfig) -> Result<Self, SqlError> {
        let settings = build_connection_settings(config)?;
        let pool = deadpool_tiberius::Manager::new()
            .host(&settings.host)
            .port(settings.port)
            .database(&settings.database)
            .basic_authentication(&settings.user, &settings.password)
            .max_size(super::DEFAULT_POOL_MAX_CONNECTIONS as usize)
            .trust_cert()
            .create_pool()
            .map_err(|e| SqlError::ConnectionFailed(e.to_string()))?;
        Ok(Self { pool })
    }
}

#[async_trait]
impl SqlDriver for MssqlDriver {
    async fn query(&self, script: &str, params: &HashMap<String, SqlValue>) -> Result<Vec<SqlRow>, SqlError> {
        let (translated, param_order) = translate_named_params(script);

        let mut client = self.pool.get().await.map_err(|e| SqlError::ConnectionFailed(e.to_string()))?;

        let mut query = tiberius::Query::new(translated);
        for name in &param_order {
            let value = params.get(name).cloned().unwrap_or(SqlValue::Null);
            match value {
                SqlValue::Null => query.bind(Option::<String>::None),
                SqlValue::Bool(b) => query.bind(b),
                SqlValue::Int(n) => query.bind(n),
                SqlValue::Float(f) => query.bind(f),
                SqlValue::Text(s) => query.bind(s),
                SqlValue::Timestamp(ts) => query.bind(ts),
                // T-SQL has no native array parameter type at all (unlike
                // Postgres — see `postgres::bind_array`) — same JSON-encoded-
                // text fallback `mysql.rs`/`sqlite.rs` already use.
                SqlValue::Array(items) => query.bind(serde_json::Value::Array(items.iter().map(sql_value_to_json).collect()).to_string()),
            };
        }

        let rows = query
            .query(&mut client)
            .await
            .map_err(classify_query_error)?
            .into_first_result()
            .await
            .map_err(classify_query_error)?;

        rows.iter().map(convert_row).collect()
    }
}

/// Hand-rolled, unlike `postgres.rs`/`mysql.rs`'s own `classify_query_error`
/// — there's no shared `sqlx::error::ErrorKind` to lean on here, since this
/// driver doesn't go through sqlx at all. `tiberius::error::Error::code()`
/// returns the server's own numeric error code when the error actually
/// originated from the server (`None` for a purely local/transport failure).
/// `2627`/`2601` are SQL Server's own codes for a unique-constraint/unique-
/// index violation, `547` for a foreign-key-or-check-constraint violation,
/// `515` for a NOT NULL violation — the closest MSSQL equivalent to sqlx's
/// portable `ErrorKind::{UniqueViolation, ForeignKeyViolation, NotNullViolation, CheckViolation}`.
fn classify_query_error(e: tiberius::error::Error) -> SqlError {
    match e.code() {
        Some(2627) | Some(2601) | Some(547) | Some(515) => SqlError::ConstraintViolation(e.to_string()),
        _ => SqlError::QueryFailed(e.to_string()),
    }
}

/// Rewrites `:name` placeholders into T-SQL's positional `@P1, @P2, ...`
/// syntax, returning the rewritten SQL plus which parameter name each `@PN`
/// binds — a repeated `:name` reuses the same `@PN`, since T-SQL parameters
/// (like Postgres's `$N`) are reusable by position. Adapted from
/// `postgres::translate_named_params`, but with the `::`-cast lookahead
/// branch dropped entirely: T-SQL has no such operator (casts go through
/// `CAST`/`CONVERT`), so there's nothing here for it to misread.
fn translate_named_params(script: &str) -> (String, Vec<String>) {
    let bytes = script.as_bytes();
    let mut output = String::with_capacity(script.len());
    let mut order: Vec<String> = Vec::new();
    let mut i = 0;

    while i < bytes.len() {
        let c = bytes[i] as char;

        if c == ':' && i + 1 < bytes.len() && (bytes[i + 1] as char == '_' || (bytes[i + 1] as char).is_alphabetic()) {
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
            output.push_str("@P");
            output.push_str(&position.to_string());
            i = end;
            continue;
        }

        output.push(c);
        i += 1;
    }

    (output, order)
}

/// `ColumnType` is a real enum (`tiberius::ColumnType`), not a string like
/// Postgres's/MySQL's own `TypeInfo::name()` — matched directly rather than
/// via a name lookup. `Bit`/`Bitn` both decode to the same `ColumnData::Bit`
/// at runtime (the `n` suffix only distinguishes a nullable wire encoding
/// from a fixed one — real, nullable columns report the `n`-suffixed variant
/// almost universally), so both map to `Bool`; same reasoning covers
/// `Datetime`/`Datetime4`/`Datetimen`/`Datetime2` all mapping to `Timestamp`
/// via `NaiveDateTime` — read as `chrono::DateTime<Utc>` directly would
/// reject the two legacy `datetime`/`smalldatetime` shapes, since tiberius's
/// own `FromSql` impl for `DateTime<Utc>` only accepts `DateTime2`/
/// `DateTimeOffset` data, not the older `datetime`/`smalldatetime` wire
/// format — so this reads as timezone-naive first and assumes UTC, the same
/// convention `postgres.rs`'s/`sqlite.rs`'s own `convert_row` already uses
/// for a timestamp column with no real timezone attached.
fn convert_row(row: &tiberius::Row) -> Result<SqlRow, SqlError> {
    let mut out = SqlRow::new();
    for column in row.columns() {
        let name = column.name();
        let value = match column.column_type() {
            ColumnType::Bit | ColumnType::Bitn => row.try_get::<bool, _>(name).map(|v| v.map(SqlValue::Bool)),
            ColumnType::Int1 => row.try_get::<u8, _>(name).map(|v| v.map(|n| SqlValue::Int(n as i64))),
            ColumnType::Int2 => row.try_get::<i16, _>(name).map(|v| v.map(|n| SqlValue::Int(n as i64))),
            ColumnType::Int4 => row.try_get::<i32, _>(name).map(|v| v.map(|n| SqlValue::Int(n as i64))),
            ColumnType::Int8 => row.try_get::<i64, _>(name).map(|v| v.map(SqlValue::Int)),
            ColumnType::Float4 => row.try_get::<f32, _>(name).map(|v| v.map(|n| SqlValue::Float(n as f64))),
            ColumnType::Float8 => row.try_get::<f64, _>(name).map(|v| v.map(SqlValue::Float)),
            ColumnType::BigVarChar | ColumnType::BigChar | ColumnType::NVarchar | ColumnType::NChar | ColumnType::Text | ColumnType::NText => {
                row.try_get::<&str, _>(name).map(|v| v.map(|s| SqlValue::Text(s.to_string())))
            }
            ColumnType::Datetime4 | ColumnType::Datetime | ColumnType::Datetimen | ColumnType::Datetime2 => row
                .try_get::<chrono::NaiveDateTime, _>(name)
                .map(|v| v.map(|naive| SqlValue::Timestamp(chrono::DateTime::from_naive_utc_and_offset(naive, chrono::Utc)))),
            other => {
                return Err(SqlError::QueryFailed(format!("column '{name}' has unsupported MSSQL type '{other:?}'")));
            }
        };
        let value = value.map_err(|e| SqlError::QueryFailed(format!("column '{name}': {e}")))?;
        out.insert(name.to_string(), value.unwrap_or(SqlValue::Null));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translates_a_single_named_param() {
        let (sql, order) = translate_named_params("SELECT * FROM cars WHERE vin = :vin");
        assert_eq!(sql, "SELECT * FROM cars WHERE vin = @P1");
        assert_eq!(order, vec!["vin"]);
    }

    #[test]
    fn reuses_position_for_a_repeated_param() {
        let (sql, order) = translate_named_params("WHERE maker = :maker AND (:maker IS NOT NULL)");
        assert_eq!(sql, "WHERE maker = @P1 AND (@P1 IS NOT NULL)");
        assert_eq!(order, vec!["maker"]);
    }

    #[test]
    fn assigns_distinct_positions_in_order_of_first_appearance() {
        let (sql, order) = translate_named_params("WHERE maker = :maker AND model = :model");
        assert_eq!(sql, "WHERE maker = @P1 AND model = @P2");
        assert_eq!(order, vec!["maker", "model"]);
    }

    /// `postgres.rs`'s/`mysql.rs`'s own translators special-case a `::` pair
    /// so a real Postgres type cast (`amount::numeric`) is never misread as
    /// a param named `numeric` — a branch this driver's own doc comment
    /// says was dropped entirely, since T-SQL has no cast operator to
    /// protect. This pins down that the drop is actually safe for realistic
    /// T-SQL input rather than just "the branch happens to not exist": a
    /// bare `::` pair that isn't immediately followed by an identifier
    /// character (here, an IPv6 literal — the one place a real script is
    /// likely to contain a literal `::`) passes straight through unchanged,
    /// because this scanner (like Postgres's and MySQL's own) only ever
    /// starts a param match right after a `:` when the very next character
    /// is a letter or underscore — a digit or quote right after doesn't
    /// qualify, so nothing here mistakes it for the start of a param name.
    #[test]
    fn a_bare_double_colon_not_followed_by_an_identifier_passes_through_unchanged() {
        let (sql, order) = translate_named_params("SELECT * FROM hosts WHERE ip = '::1' AND id = :id");
        assert_eq!(sql, "SELECT * FROM hosts WHERE ip = '::1' AND id = @P1");
        assert_eq!(order, vec!["id"]);
    }

    fn config_with(settings: &[(&str, serde_json::Value)]) -> ConnectionConfig {
        ConnectionConfig {
            driver: "mssql".to_string(),
            settings: settings.iter().map(|(k, v)| (k.to_string(), v.clone())).collect(),
        }
    }

    #[test]
    fn a_missing_database_defaults_to_master_rather_than_erroring() {
        let config = config_with(&[]);
        let settings = build_connection_settings(&config).expect("a missing database must not be a hard error, unlike postgres/mysql");
        assert_eq!(settings.database, "master");
    }

    #[test]
    fn defaults_host_port_and_user_when_not_configured() {
        let config = config_with(&[]);
        let settings = build_connection_settings(&config).unwrap();
        assert_eq!(settings.host, "localhost");
        assert_eq!(settings.port, 1433);
        assert_eq!(settings.user, "sa");
        assert_eq!(settings.password, "");
    }

    #[test]
    fn uses_explicit_host_port_user_and_database() {
        let config = config_with(&[
            ("host", serde_json::json!("db.internal")),
            ("port", serde_json::json!(1434)),
            ("user", serde_json::json!("app")),
            ("database", serde_json::json!("vehicles")),
        ]);
        let settings = build_connection_settings(&config).unwrap();
        assert_eq!(settings.host, "db.internal");
        assert_eq!(settings.port, 1434);
        assert_eq!(settings.user, "app");
        assert_eq!(settings.database, "vehicles");
    }

    #[test]
    fn resolves_the_password_from_the_named_env_var() {
        // SAFETY: this test doesn't run concurrently with anything else
        // that reads/writes this specific env var.
        unsafe {
            std::env::set_var("FROGS_TEST_MSSQL_PASSWORD", "s3cret");
        }
        let config = config_with(&[("passwordEnv", serde_json::json!("FROGS_TEST_MSSQL_PASSWORD"))]);
        let settings = build_connection_settings(&config).unwrap();
        assert_eq!(settings.password, "s3cret");
    }

    #[test]
    fn an_unset_password_env_var_falls_back_to_an_empty_password_not_an_error() {
        let config = config_with(&[("passwordEnv", serde_json::json!("FROGS_TEST_MSSQL_PASSWORD_DEFINITELY_UNSET"))]);
        let settings = build_connection_settings(&config).unwrap();
        assert_eq!(settings.password, "");
    }

    /// Builds a `ConnectionConfig` from discrete `MSSQL_TEST_*` env vars
    /// rather than one connection-string env var (unlike Postgres's/MySQL's
    /// own `DATABASE_URL_TEST`/`DATABASE_URL_TEST_MYSQL`) — `deadpool-tiberius`'s
    /// own builder is field-based, not URL-based, so there's no single
    /// connection-string shape to hand it in the first place. Only the
    /// password is required to be set explicitly; every other field defaults
    /// the same way a real `connections.json` entry would (see
    /// `build_connection_settings`'s own defaults), so a bare `MSSQL_TEST_PASSWORD=...`
    /// against a local default-instance SQL Server is enough to run these.
    fn config_from_env() -> ConnectionConfig {
        const PASSWORD_ENV: &str = "MSSQL_TEST_PASSWORD";
        std::env::var(PASSWORD_ENV)
            .expect("set MSSQL_TEST_PASSWORD (and optionally MSSQL_TEST_HOST/MSSQL_TEST_PORT/MSSQL_TEST_DATABASE/MSSQL_TEST_USER) to a reachable SQL Server instance to run this test");
        let host = std::env::var("MSSQL_TEST_HOST").unwrap_or_else(|_| "localhost".to_string());
        let port = std::env::var("MSSQL_TEST_PORT").ok().and_then(|v| v.parse::<u64>().ok()).unwrap_or(1433);
        let database = std::env::var("MSSQL_TEST_DATABASE").unwrap_or_else(|_| "master".to_string());
        let user = std::env::var("MSSQL_TEST_USER").unwrap_or_else(|_| "sa".to_string());

        config_with(&[
            ("host", serde_json::json!(host)),
            ("port", serde_json::json!(port)),
            ("database", serde_json::json!(database)),
            ("user", serde_json::json!(user)),
            ("passwordEnv", serde_json::json!(PASSWORD_ENV)),
        ])
    }

    /// Real round-trip test against a live SQL Server instance — not run by
    /// default since this dev environment has no MSSQL server available. To
    /// run it: start a SQL Server instance, then
    /// `MSSQL_TEST_PASSWORD=<sa password> cargo test --locked --features mssql -- --ignored`
    /// (add `MSSQL_TEST_HOST`/`MSSQL_TEST_PORT`/`MSSQL_TEST_DATABASE`/`MSSQL_TEST_USER`
    /// to point anywhere other than a default local instance's `master` DB).
    ///
    /// Deliberately not a temporary table (`#temp`), for the same reason
    /// `postgres.rs`'s/`mysql.rs`'s own live tests use a real one: SQL
    /// Server's local `#temp` tables are scoped to the single session that
    /// created them, but `driver.pool` is a connection pool — the follow-up
    /// `INSERT`/`SELECT` can easily land on a different physical connection
    /// than the one that ran the `CREATE`, where the temp table simply
    /// doesn't exist.
    #[tokio::test]
    #[ignore]
    async fn queries_a_real_mssql_instance() {
        let config = config_from_env();
        let driver = MssqlDriver::connect(&config).await.expect("failed to connect");

        driver.query("DROP TABLE IF EXISTS frogs_mssql_smoke_test", &HashMap::new()).await.unwrap();
        driver
            .query("CREATE TABLE frogs_mssql_smoke_test (vin VARCHAR(64), year INT)", &HashMap::new())
            .await
            .unwrap();
        driver
            .query("INSERT INTO frogs_mssql_smoke_test (vin, year) VALUES ('1HGCM82633A004352', 2003)", &HashMap::new())
            .await
            .unwrap();

        let mut params = HashMap::new();
        params.insert("vin".to_string(), SqlValue::Text("1HGCM82633A004352".to_string()));
        let rows = driver
            .query("SELECT vin, year FROM frogs_mssql_smoke_test WHERE vin = :vin", &params)
            .await
            .expect("query should succeed");

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("vin"), Some(&SqlValue::Text("1HGCM82633A004352".to_string())));
        assert_eq!(rows[0].get("year"), Some(&SqlValue::Int(2003)));

        driver.query("DROP TABLE frogs_mssql_smoke_test", &HashMap::new()).await.unwrap();
    }

    /// The point of `classify_query_error` existing at all: a real unique-
    /// constraint violation against a real SQL Server instance classifies
    /// as `ConstraintViolation` (via its hand-rolled 2627/2601/547/515
    /// error-code mapping — there's no shared `sqlx::ErrorKind` free ride
    /// here, unlike `postgres.rs`'s/`mysql.rs`'s own version of this same
    /// test), not the generic `QueryFailed` every other query error still
    /// falls back to. Same env-var gating as `queries_a_real_mssql_instance`.
    #[tokio::test]
    #[ignore]
    async fn a_unique_constraint_violation_classifies_distinctly() {
        let config = config_from_env();
        let driver = MssqlDriver::connect(&config).await.expect("failed to connect");

        driver.query("DROP TABLE IF EXISTS frogs_mssql_constraint_test", &HashMap::new()).await.unwrap();
        driver
            .query("CREATE TABLE frogs_mssql_constraint_test (vin VARCHAR(64) UNIQUE)", &HashMap::new())
            .await
            .unwrap();

        let mut params = HashMap::new();
        params.insert("vin".to_string(), SqlValue::Text("1HGCM82633A004352".to_string()));
        driver
            .query("INSERT INTO frogs_mssql_constraint_test (vin) VALUES (:vin)", &params)
            .await
            .expect("the first insert should succeed");

        let err = driver
            .query("INSERT INTO frogs_mssql_constraint_test (vin) VALUES (:vin)", &params)
            .await
            .expect_err("a duplicate value against a UNIQUE column must fail");

        assert!(matches!(err, SqlError::ConstraintViolation(_)), "expected ConstraintViolation, got {err:?}");

        driver.query("DROP TABLE frogs_mssql_constraint_test", &HashMap::new()).await.unwrap();
    }
}
