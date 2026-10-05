#[cfg(feature = "mssql")]
pub mod mssql;
#[cfg(feature = "mysql")]
pub mod mysql;
#[cfg(feature = "oracle")]
pub mod oracle;
#[cfg(feature = "postgres")]
pub mod postgres;
// Always compiled in — SQLite is a base feature, not optional. See
// Cargo.toml's `[features]` block.
pub mod sqlite;

use std::collections::HashMap;
use std::fmt;

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::config::ConnectionConfig;

/// A driver-agnostic value, used both for bound query parameters and for
/// fields decoded out of a returned row. `Array` is a *bound-parameter-only*
/// concept — no driver ever decodes a returned column into it (array-typed
/// columns aren't supported on read at all, see each driver's own
/// `convert_row`); it exists so a JSON array from a request body can bind as
/// a real native array parameter where the driver supports one, rather than
/// always falling back to JSON-encoded text.
#[derive(Debug, Clone, PartialEq)]
pub enum SqlValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Text(String),
    Timestamp(DateTime<Utc>),
    Array(Vec<SqlValue>),
}

/// One row of a query result, keyed by column name — matches how the
/// (not-yet-built) response-mapping layer will address fields, e.g.
/// `sources.car.vin`.
pub type SqlRow = HashMap<String, SqlValue>;

#[derive(Debug)]
pub enum SqlError {
    ConnectionFailed(String),
    QueryFailed(String),
    /// A unique/foreign-key/not-null/check constraint violation —
    /// classified separately from an ordinary `QueryFailed` via the
    /// driver's own portable `sqlx::error::ErrorKind`, not by pattern-
    /// matching a driver-specific SQLSTATE/result code (see each driver's
    /// own `classify_query_error`).
    ConstraintViolation(String),
}

impl fmt::Display for SqlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SqlError::ConnectionFailed(msg) => write!(f, "connection failed: {msg}"),
            SqlError::QueryFailed(msg) => write!(f, "query failed: {msg}"),
            SqlError::ConstraintViolation(msg) => write!(f, "constraint violation: {msg}"),
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
        // Never actually produced by a driver decoding a real row (see this
        // variant's own doc comment) — defined for completeness/symmetry,
        // not a path any driver exercises today.
        SqlValue::Array(items) => Value::Array(items.iter().map(sql_value_to_json).collect()),
    }
}

/// The inverse of `sql_value_to_json` — converts a JSON value pulled out of
/// a request body into a bindable parameter. A JSON array becomes
/// `SqlValue::Array`, which each driver then binds as a real native array
/// parameter where it can (Postgres, when every element is the same
/// scalar kind) and falls back to JSON-encoded text otherwise (always, for
/// SQLite — it has no native array parameter type at all). An object
/// doesn't fit `SqlValue`'s shape either way, so it's JSON-encoded as text
/// rather than silently dropped to `Null`.
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
        Value::Array(items) => SqlValue::Array(items.iter().map(json_value_to_sql_value).collect()),
        Value::Object(_) => SqlValue::Text(value.to_string()),
    }
}

/// The ASCII `:name` placeholder identifier starting at `start` — which is
/// the index of the first byte *after* a `:`, **not** the colon's own index.
/// Returns `(name, index_just_past_the_name)`, or `None` if there's no
/// identifier there at all.
///
/// Deliberately knows nothing about `::`. Whether a doubled colon is a cast
/// operator to skip whole (Postgres/SQLite/MySQL/Oracle) or just two colons
/// whose *second* one starts a real placeholder (MSSQL, which has no `::`
/// operator — `"::name"` really does translate to `":@P1"` binding `name`)
/// is a per-driver decision each caller already makes in its own loop.
/// Folding it in here would silently drop MSSQL's placeholder count and
/// shift every later `@PN` number, which on a dedup driver can bind a value
/// to the wrong placeholder.
///
/// Classification is ASCII-only (`is_ascii_alphabetic`/`is_ascii_alphanumeric`),
/// not `char::is_alphabetic` applied to one byte: a UTF-8 lead byte such as
/// `0xC3` reinterpreted as a `char` is `'Ã'`, which *is* alphanumeric —
/// which is how the previous byte-wise scan could stop in the middle of a
/// character and panic slicing `script`. Both returned bounds are ASCII byte
/// positions, so the returned slice is always on a character boundary, and a
/// `start` that happens to land on a continuation byte returns `None`
/// (a continuation byte is neither `_` nor ASCII-alphabetic) rather than
/// panicking.
pub(crate) fn ascii_param_name_at(script: &str, start: usize) -> Option<(&str, usize)> {
    let bytes = script.as_bytes();
    let first = *bytes.get(start)?;
    if first != b'_' && !first.is_ascii_alphabetic() {
        return None;
    }
    let mut end = start + 1;
    while end < bytes.len() && (bytes[end] == b'_' || bytes[end].is_ascii_alphanumeric()) {
        end += 1;
    }
    Some((&script[start..end], end))
}

/// Every distinct `:name` placeholder in `script` whose identifier is
/// immediately followed by a non-ASCII byte — i.e. where
/// `ascii_param_name_at` stopped early and the name it extracted is only a
/// *prefix* of what the author probably wrote (`:idé` → `id`). Every driver
/// binds an unrecognized name as a silent `SqlValue::Null`
/// (`params.get(name).cloned().unwrap_or(SqlValue::Null)`), which for the
/// common `(:x IS NULL OR col = :x)` nullable-filter idiom quietly widens a
/// filter instead of failing — so this is reported rather than left silent.
///
/// A `:` followed *directly* by a non-ASCII character (`-- :é`) is **not**
/// reported: no identifier is extracted, nothing is bound, and the text
/// passes through literally — flagging that would just be noise for prose in
/// a comment. Driver-agnostic, so it may over-report a `::`-cast immediately
/// followed by a non-ASCII identifier on a driver that skips `::` whole;
/// over-reporting a warning is acceptable here, under-reporting is not.
pub(crate) fn truncated_placeholder_names(script: &str) -> Vec<String> {
    let bytes = script.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b':' {
            i += 1;
            continue;
        }
        match ascii_param_name_at(script, i + 1) {
            Some((name, end)) => {
                if bytes.get(end).is_some_and(|b| !b.is_ascii()) && !out.iter().any(|n| n == name) {
                    out.push(name.to_string());
                }
                i = end;
            }
            None => i += 1,
        }
    }
    out
}

/// The pool size both drivers actually configure (see `postgres.rs`/
/// `sqlite.rs`'s own `.max_connections(...)` calls) — pulled out to one
/// named constant so `pool_capacity`'s ceiling reasoning below can't
/// silently drift out of sync with what a real connection really gets.
pub const DEFAULT_POOL_MAX_CONNECTIONS: u32 = 5;

/// How long a driver waits for a free pool connection before giving up —
/// sqlx's own implicit default, stated explicitly in each `PoolOptions`
/// chain (`postgres.rs`/`mysql.rs`/`sqlite.rs`) so it can't drift silently
/// and so its relationship to the source-call timeout is visible. It sits
/// deliberately *above* `config::server`'s 10s
/// `default_source_call_timeout_ms`: an ordinary source's own call bound
/// should normally elapse first, so a hung query is reported as
/// `datasource.sql.timeout` rather than as pool starvation on whichever
/// unlucky later request happened to wait 30s for a connection. The two
/// failure modes stay temporally distinguishable in logs instead of racing
/// at the same value. `mssql.rs`/`oracle.rs` use a different pooling crate
/// and have no `PoolOptions` to apply this to.
pub const DEFAULT_POOL_ACQUIRE_TIMEOUT_SECS: u64 = 30;

/// The real pool capacity `connect_one` would give this connection,
/// without actually connecting — used by `endpoint::validate_nested_many`'s
/// `maxConcurrency` ceiling so a nested-many source can't be configured to
/// claim more concurrent connections than its own connection's pool could
/// ever satisfy. `None` for a driver this binary doesn't recognize at all;
/// callers skip that specific check in that case (see `validate_nested_many`'s
/// own doc comment — the same "unknown connection" gap already exists
/// elsewhere and isn't newly invented here).
pub fn pool_capacity(conn: &ConnectionConfig) -> Option<u32> {
    match conn.driver.as_str() {
        "sqlite" => {
            // Mirrors `sqlite::SqliteDriver::connect`'s own in-memory
            // special case exactly — a `:memory:` database is pinned to
            // exactly one real connection, regardless of this constant.
            let is_memory = conn.settings.get("database").and_then(|v| v.as_str()) == Some(":memory:");
            Some(if is_memory { 1 } else { DEFAULT_POOL_MAX_CONNECTIONS })
        }
        "postgres" => Some(DEFAULT_POOL_MAX_CONNECTIONS),
        "mysql" => Some(DEFAULT_POOL_MAX_CONNECTIONS),
        "mssql" => Some(DEFAULT_POOL_MAX_CONNECTIONS),
        "oracle" => Some(DEFAULT_POOL_MAX_CONNECTIONS),
        _ => None,
    }
}

/// The internal abstraction boundary every compiled-in driver adapts to.
/// `connections.json`'s `"driver"` field selects which implementation runs
/// at startup — same mechanism regardless of whether it resolves to
/// `sqlx`/postgres, `tiberius`, `rusqlite`, or eventually `odbc-api`.
// `async_trait`'s macro expansion redundantly tags the generated method with
// `#[must_use]` even though it already returns a must_use pinned boxed
// future — a newer clippy flags that as `double_must_use`. The redundancy is
// in the macro's own expansion, not anything we can fix here.
#[allow(clippy::double_must_use)]
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
        #[cfg(feature = "mysql")]
        "mysql" => Ok(Box::new(mysql::MySqlDriver::connect(conn).await?)),
        #[cfg(feature = "mssql")]
        "mssql" => Ok(Box::new(mssql::MssqlDriver::connect(conn).await?)),
        #[cfg(feature = "oracle")]
        "oracle" => Ok(Box::new(oracle::OracleDriver::connect(conn).await?)),
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

    /// "nosuchdriver" has no match arm at all in `connect_all` regardless of
    /// which `--features` this test binary happens to be built with (unlike
    /// "mssql"/"oracle", which now do — see `mssql.rs`/`oracle.rs`), so this
    /// exercises the fallback branch deterministically rather than depending
    /// on which drivers are compiled in.
    #[tokio::test]
    async fn a_driver_not_compiled_into_this_binary_fails_startup_with_a_clear_message() {
        let mut connections = HashMap::new();
        connections.insert(
            "primary".to_string(),
            ConnectionConfig {
                driver: "nosuchdriver".to_string(),
                settings: HashMap::new(),
            },
        );

        let err = connect_all(&connections)
            .await
            .expect_err("a connection whose driver isn't compiled in must fail startup, not be silently skipped");

        let message = err.to_string();
        assert!(message.contains("primary"), "message should name the failing connection: {message}");
        assert!(message.contains("nosuchdriver"), "message should name the unsupported driver: {message}");
        assert!(message.contains("--features nosuchdriver"), "message should say how to fix it: {message}");
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
                driver: "nosuchdriver".to_string(),
                settings: HashMap::new(),
            },
        );
        // A second, distinct guaranteed-uncompiled-driver placeholder (not
        // "oracle" — that's a real, compilable driver now, see `oracle.rs`)
        // so this genuinely proves two independently-failing connections are
        // both reported, rather than the same string's failure counted twice.
        connections.insert(
            "secondary".to_string(),
            ConnectionConfig {
                driver: "nosuchdriver2".to_string(),
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
    fn a_json_object_is_encoded_as_text_rather_than_dropped() {
        let object = serde_json::json!({ "a": 1 });
        assert_eq!(json_value_to_sql_value(&object), SqlValue::Text(r#"{"a":1}"#.to_string()));
    }

    #[test]
    fn a_json_array_becomes_a_native_sql_value_array_not_text() {
        let array = serde_json::json!([1, 2, 3]);
        assert_eq!(
            json_value_to_sql_value(&array),
            SqlValue::Array(vec![SqlValue::Int(1), SqlValue::Int(2), SqlValue::Int(3)])
        );
    }

    #[test]
    fn a_nested_array_converts_recursively() {
        let array = serde_json::json!([[1, 2], ["a"]]);
        assert_eq!(
            json_value_to_sql_value(&array),
            SqlValue::Array(vec![
                SqlValue::Array(vec![SqlValue::Int(1), SqlValue::Int(2)]),
                SqlValue::Array(vec![SqlValue::Text("a".to_string())]),
            ])
        );
    }

    #[test]
    fn sql_value_array_round_trips_back_to_json() {
        let value = SqlValue::Array(vec![SqlValue::Int(1), SqlValue::Text("x".to_string())]);
        assert_eq!(sql_value_to_json(&value), serde_json::json!([1, "x"]));
    }

    #[test]
    fn ascii_param_name_at_extracts_a_plain_ascii_name() {
        assert_eq!(ascii_param_name_at("vin", 0), Some(("vin", 3)));
    }

    #[test]
    fn ascii_param_name_at_allows_a_leading_underscore() {
        assert_eq!(ascii_param_name_at("_private", 0), Some(("_private", 8)));
    }

    #[test]
    fn ascii_param_name_at_includes_trailing_digits() {
        assert_eq!(ascii_param_name_at("id2", 0), Some(("id2", 3)));
    }

    #[test]
    fn ascii_param_name_at_returns_none_when_start_is_past_the_end_of_the_string() {
        assert_eq!(ascii_param_name_at("abc", 10), None);
        assert_eq!(
            ascii_param_name_at("abc", 3),
            None,
            "start exactly at the end (one past the last byte) is also out of range"
        );
    }

    #[test]
    fn ascii_param_name_at_returns_none_when_start_is_on_a_digit() {
        // A digit can never start an identifier — mirrors every driver's own
        // `:5foo`-isn't-a-param-name assumption.
        assert_eq!(ascii_param_name_at(":5foo", 1), None);
    }

    #[test]
    fn ascii_param_name_at_returns_none_without_panicking_on_a_utf8_lead_byte() {
        // 'é' encodes as the two bytes 0xC3 0xA9 — byte 0 is the lead byte.
        // A byte-wise scan that reinterpreted this as a char would see it as
        // alphabetic and try to slice mid-character; this must instead just
        // report "no identifier here" without ever panicking.
        let script = "é";
        assert_eq!(ascii_param_name_at(script, 0), None);
    }

    #[test]
    fn ascii_param_name_at_returns_none_without_panicking_on_a_utf8_continuation_byte() {
        // Byte 1 of 'é' is the continuation byte 0xA9 — not a valid char
        // boundary at all. The old byte-wise scan panicked slicing here;
        // this must return None without ever constructing a slice.
        let script = "é";
        assert_eq!(ascii_param_name_at(script, 1), None);
    }

    #[test]
    fn ascii_param_name_at_stops_cleanly_at_a_multibyte_character_boundary() {
        // "idé": 'i' and 'd' are each one ASCII byte, so byte offset 2 is
        // exactly where the (multi-byte) 'é' starts — a real character
        // boundary, confirming the returned name/end never straddles one.
        let script = "idé";
        assert!(script.is_char_boundary(2));
        assert_eq!(ascii_param_name_at(script, 0), Some(("id", 2)));
    }

    #[test]
    fn truncated_placeholder_names_extracts_the_ascii_prefix_before_a_non_ascii_byte() {
        assert_eq!(truncated_placeholder_names("SELECT :idé"), vec!["id".to_string()]);
    }

    #[test]
    fn truncated_placeholder_names_does_not_report_a_bare_colon_followed_directly_by_non_ascii() {
        // No identifier is extracted at all here (the char right after `:`
        // isn't ASCII-alphabetic/`_`), so there's nothing to call "truncated"
        // — this is prose in a comment, not a misnamed placeholder.
        assert_eq!(truncated_placeholder_names("-- :é"), Vec::<String>::new());
    }

    #[test]
    fn truncated_placeholder_names_reports_nothing_for_an_all_ascii_script() {
        assert_eq!(truncated_placeholder_names("WHERE a = :id"), Vec::<String>::new());
    }

    #[test]
    fn truncated_placeholder_names_dedupes_the_same_truncated_name_appearing_twice() {
        assert_eq!(truncated_placeholder_names("SELECT :idé, :idé"), vec!["id".to_string()]);
    }
}
