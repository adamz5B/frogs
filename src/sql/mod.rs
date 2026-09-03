#[cfg(feature = "postgres")]
pub mod postgres;
#[cfg(feature = "sqlite")]
pub mod sqlite;

use std::collections::HashMap;
use std::fmt;

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::config::ConnectionConfig;

/// A driver-agnostic value, used both for bound query parameters and for
/// fields decoded out of a returned row.
#[derive(Debug, Clone, PartialEq)]
pub enum SqlValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Text(String),
    Timestamp(DateTime<Utc>),
}

/// One row of a query result, keyed by column name — matches how the
/// (not-yet-built) response-mapping layer will address fields, e.g.
/// `sources.car.vin`.
pub type SqlRow = HashMap<String, SqlValue>;

#[derive(Debug)]
pub enum SqlError {
    ConnectionFailed(String),
    QueryFailed(String),
}

impl fmt::Display for SqlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SqlError::ConnectionFailed(msg) => write!(f, "connection failed: {msg}"),
            SqlError::QueryFailed(msg) => write!(f, "query failed: {msg}"),
        }
    }
}

impl std::error::Error for SqlError {}

/// Converts one decoded row value into plain JSON — shared by endpoint
/// source resolution and security verifier execution, both of which need
/// a SQL row as a `serde_json::Value` (a response field to map, or a
/// `validIf` check to evaluate).
pub fn sql_value_to_json(value: &SqlValue) -> Value {
    match value {
        SqlValue::Null => Value::Null,
        SqlValue::Bool(b) => Value::Bool(*b),
        SqlValue::Int(n) => Value::Number((*n).into()),
        SqlValue::Float(f) => serde_json::Number::from_f64(*f).map(Value::Number).unwrap_or(Value::Null),
        SqlValue::Text(s) => Value::String(s.clone()),
        SqlValue::Timestamp(ts) => Value::String(ts.to_rfc3339()),
    }
}

/// The inverse of `sql_value_to_json` — converts a JSON value pulled out of
/// a request body into a bindable parameter. An array or object doesn't fit
/// `SqlValue`'s flat scalar shape, so it's JSON-encoded as text rather than
/// silently dropped to `Null`; native array-typed parameter binding (the
/// design doc's own array-passthrough case) is a distinct, more deliberate
/// feature, not this function's job.
pub fn json_value_to_sql_value(value: &Value) -> SqlValue {
    match value {
        Value::Null => SqlValue::Null,
        Value::Bool(b) => SqlValue::Bool(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                SqlValue::Int(i)
            } else if let Some(f) = n.as_f64() {
                SqlValue::Float(f)
            } else {
                SqlValue::Null
            }
        }
        Value::String(s) => SqlValue::Text(s.clone()),
        Value::Array(_) | Value::Object(_) => SqlValue::Text(value.to_string()),
    }
}

/// The internal abstraction boundary every compiled-in driver adapts to.
/// `connections.json`'s `"driver"` field selects which implementation runs
/// at startup — same mechanism regardless of whether it resolves to
/// `sqlx`/postgres, `tiberius`, `rusqlite`, or eventually `odbc-api`.
#[async_trait::async_trait]
pub trait SqlDriver: Send + Sync + std::fmt::Debug {
    /// Runs `script` (a driver-native SQL string using `:name` placeholders,
    /// as authored in `datasources/sql/<connection>/*.sql`) with `params`
    /// bound by name, returning every row of the result set.
    async fn query(&self, script: &str, params: &HashMap<String, SqlValue>) -> Result<Vec<SqlRow>, SqlError>;
}

/// Connects one entry to a compiled-in driver implementation. A connection
/// whose `"driver"` isn't compiled into this binary fails immediately with
/// a message telling the user which Cargo feature would need to be enabled —
/// matching the design doc's "startup validation" requirement, rather than
/// failing confusingly on the first query. Shared by `connect_all` (fails
/// fast on the first bad connection — the right posture for actually
/// starting the server) and `try_connect_each` (tries every connection
/// independently — what `frogs validate` needs instead).
async fn connect_one(name: &str, conn: &ConnectionConfig) -> Result<Box<dyn SqlDriver>, SqlError> {
    match conn.driver.as_str() {
        #[cfg(feature = "postgres")]
        "postgres" => Ok(Box::new(postgres::PostgresDriver::connect(conn).await?)),
        #[cfg(feature = "sqlite")]
        "sqlite" => Ok(Box::new(sqlite::SqliteDriver::connect(conn).await?)),
        other => Err(SqlError::ConnectionFailed(format!(
            "connection '{name}' uses driver '{other}', which isn't compiled into this binary \
             (rebuild with `--features {other}` or use a build that includes it)"
        ))),
    }
}

/// Connects every entry in `connections.json`. Fails fast on the first bad
/// connection — `frogs run` has no use for a half-connected set of drivers,
/// so there's no reason to keep trying the rest once one has already failed.
pub async fn connect_all(connections: &HashMap<String, ConnectionConfig>) -> Result<HashMap<String, Box<dyn SqlDriver>>, SqlError> {
    let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
    for (name, conn) in connections {
        drivers.insert(name.clone(), connect_one(name, conn).await?);
    }
    Ok(drivers)
}

/// Tries every connection independently, collecting each one's own
/// pass/fail result instead of stopping at the first failure — a full
/// picture of what's broken in one pass, which is what `frogs validate`
/// needs; `connect_all`'s fail-fast posture would only ever report the
/// first problem found.
pub async fn try_connect_each(connections: &HashMap<String, ConnectionConfig>) -> Vec<(String, Result<(), SqlError>)> {
    let mut results = Vec::new();
    for (name, conn) in connections {
        results.push((name.clone(), connect_one(name, conn).await.map(|_driver| ())));
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConnectionConfig;

    /// "mssql" has no match arm at all in `connect_all` regardless of which
    /// `--features` this test binary happens to be built with, so this
    /// exercises the fallback branch deterministically rather than depending
    /// on which drivers are compiled in.
    #[tokio::test]
    async fn a_driver_not_compiled_into_this_binary_fails_startup_with_a_clear_message() {
        let mut connections = HashMap::new();
        connections.insert(
            "primary".to_string(),
            ConnectionConfig {
                driver: "mssql".to_string(),
                settings: HashMap::new(),
            },
        );

        let err = connect_all(&connections)
            .await
            .expect_err("a connection whose driver isn't compiled in must fail startup, not be silently skipped");

        let message = err.to_string();
        assert!(message.contains("primary"), "message should name the failing connection: {message}");
        assert!(message.contains("mssql"), "message should name the unsupported driver: {message}");
        assert!(message.contains("--features mssql"), "message should say how to fix it: {message}");
    }

    #[tokio::test]
    async fn no_connections_configured_is_not_an_error() {
        let connections = HashMap::new();
        let drivers = connect_all(&connections).await.expect("an empty connections map is a valid, if unusual, project");
        assert!(drivers.is_empty());
    }

    #[tokio::test]
    async fn try_connect_each_reports_every_connection_not_just_the_first_failure() {
        let mut connections = HashMap::new();
        connections.insert(
            "primary".to_string(),
            ConnectionConfig {
                driver: "mssql".to_string(),
                settings: HashMap::new(),
            },
        );
        connections.insert(
            "secondary".to_string(),
            ConnectionConfig {
                driver: "oracle".to_string(),
                settings: HashMap::new(),
            },
        );

        let results = try_connect_each(&connections).await;
        assert_eq!(results.len(), 2, "both connections must be attempted, not just the first");

        let by_name: HashMap<&str, &Result<(), SqlError>> = results.iter().map(|(name, result)| (name.as_str(), result)).collect();
        assert!(by_name["primary"].is_err());
        assert!(by_name["secondary"].is_err());
    }

    #[tokio::test]
    async fn try_connect_each_of_an_empty_map_is_an_empty_report() {
        let results = try_connect_each(&HashMap::new()).await;
        assert!(results.is_empty());
    }

    #[test]
    fn json_scalars_round_trip_through_sql_value() {
        assert_eq!(json_value_to_sql_value(&Value::Null), SqlValue::Null);
        assert_eq!(json_value_to_sql_value(&Value::Bool(true)), SqlValue::Bool(true));
        assert_eq!(json_value_to_sql_value(&serde_json::json!(42)), SqlValue::Int(42));
        assert_eq!(json_value_to_sql_value(&serde_json::json!(1.5)), SqlValue::Float(1.5));
        assert_eq!(json_value_to_sql_value(&Value::String("hi".to_string())), SqlValue::Text("hi".to_string()));
    }

    #[test]
    fn a_json_array_or_object_is_encoded_as_text_rather_than_dropped() {
        let array = serde_json::json!([1, 2, 3]);
        assert_eq!(json_value_to_sql_value(&array), SqlValue::Text("[1,2,3]".to_string()));

        let object = serde_json::json!({ "a": 1 });
        assert_eq!(json_value_to_sql_value(&object), SqlValue::Text(r#"{"a":1}"#.to_string()));
    }
}
