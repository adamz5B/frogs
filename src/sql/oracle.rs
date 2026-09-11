//! Oracle SQL driver, backed by `oracle-rs` (a pure-Rust TNS protocol
//! implementation — no OCI/Instant Client) plus `deadpool-oracle` for
//! pooling. Architecturally closest to `mssql.rs`: neither goes through
//! sqlx, both wrap a driver-specific pool type directly. See Cargo.toml's
//! own dependency comment for why this crate pair was picked over Oracle's
//! official `oracledb` crate.
//!
//! ## Bind-parameter translation
//!
//! `oracle-rs` 0.1.7 has no dedicated bind-by-name-with-reuse mode for plain
//! SQL statements, despite Oracle's native OCI layer nominally supporting
//! one. Confirmed by reading `Statement::parse_bind_variables` in its own
//! source (`src/statement.rs`): for `StatementType::Query`/`Dml` statements
//! it pushes *every* textual occurrence of a `:name` placeholder into
//! `bind_info_list` unconditionally (its own comment: "allow duplicates
//! otherwise" — deduplication by name only happens for `StatementType::PlSql`
//! blocks). `Connection::execute`/`query` then binds the caller-supplied
//! `&[Value]` slice to that list purely positionally — `execute_query_with_params`/
//! `execute_dml_with_params` just forward `params.to_vec()` into the wire
//! message unchanged, with no name-based matching at all. So a `:name`
//! placeholder repeated twice in one statement needs the *same* value
//! supplied twice in the slice, once per occurrence — not once. That's why
//! `translate_named_params` below returns one entry per textual *occurrence*
//! (not deduplicated by name), even though the emitted SQL text reuses the
//! same bare `:N` number for a repeated name — that reuse is purely cosmetic
//! (in case the translated SQL is ever logged), since oracle-rs's own parser
//! doesn't care whether the numbers match, only that a value is supplied for
//! every occurrence it finds.
//!
//! ## Transactions
//!
//! Unlike every other driver in this project, an Oracle session is not
//! autocommit by default at the wire-protocol level: `oracle-rs`'s own
//! `Connection::execute` always runs DML with `auto_commit: false` (see its
//! `ExecuteOptions::for_dml(false)`, and its own crate-level doc example,
//! which calls `conn.commit()` explicitly after every DML `execute`). `query`
//! below does the same — an explicit `commit()` after a successful non-SELECT
//! statement, since `SqlDriver::query` has no separate transaction-boundary
//! API for a caller to do this itself.

use std::collections::HashMap;

use async_trait::async_trait;
use chrono::{Datelike, Timelike};
use oracle_rs::types::OracleTimestamp;
use oracle_rs::{Config, OracleType, Row as OracleRow, Statement, StatementType, Value as OracleValue};

use super::{SqlDriver, SqlError, SqlRow, SqlValue, sql_value_to_json};
use crate::config::ConnectionConfig;

pub struct OracleDriver {
    pool: deadpool_oracle::Pool,
}

/// Hand-written rather than `#[derive(Debug)]`, for the same reason as
/// `mssql.rs`'s own `MssqlDriver`: `deadpool_oracle::Pool` is a
/// `deadpool::managed::Pool<OracleConnectionManager>`, and
/// `OracleConnectionManager` (the pool's manager type) has no `Debug` impl
/// of its own — required regardless, since `SqlDriver: Debug`.
impl std::fmt::Debug for OracleDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OracleDriver").finish_non_exhaustive()
    }
}

/// Pure connection settings pulled out of `connections.json`, kept separate
/// from `deadpool_oracle`'s own `Config`/`PoolBuilder` construction — same
/// reason as `mssql::MssqlConnectionSettings`: unit-testable without
/// actually dialing a server.
struct OracleConnectionSettings {
    host: String,
    port: u16,
    service_name: String,
    user: String,
    password: String,
}

/// `serviceName` (camelCase, matching `passwordEnv`/`apiRoot`'s own
/// convention) and `user` are both hard-required, unlike every other
/// driver's own `build_connection_url`/`build_connection_settings`:
///
/// - An Oracle listener has no usable default service name/SID the way
///   Postgres/MySQL/SQL Server have a default database — connecting to
///   *something* by default (`build_connect_string`) would silently target
///   whatever the listener happens to resolve an empty/absent service to,
///   which isn't a safe guess to make on a project's behalf.
/// - There's no universally-safe Oracle admin account to fall back to the
///   way `mssql.rs` defaults to `"sa"`: Oracle's own conventional admin
///   accounts (`SYS`, `SYSTEM`) carry elevated privileges that shouldn't be
///   silently assumed for an unconfigured connection.
fn build_connection_settings(config: &ConnectionConfig) -> Result<OracleConnectionSettings, SqlError> {
    let get_str = |key: &str| -> Option<String> { config.settings.get(key).and_then(|v| v.as_str()).map(str::to_string) };

    let host = get_str("host").unwrap_or_else(|| "localhost".to_string());
    let port = config.settings.get("port").and_then(serde_json::Value::as_u64).unwrap_or(1521) as u16;
    let service_name = get_str("serviceName")
        .ok_or_else(|| SqlError::ConnectionFailed("connection is missing required 'serviceName' setting (no default is safe to assume)".to_string()))?;
    let user = get_str("user").ok_or_else(|| SqlError::ConnectionFailed("connection is missing required 'user' setting (no default is safe to assume)".to_string()))?;
    let password = match get_str("passwordEnv") {
        Some(env_name) => std::env::var(&env_name).unwrap_or_default(),
        None => String::new(),
    };

    Ok(OracleConnectionSettings {
        host,
        port,
        service_name,
        user,
        password,
    })
}

impl OracleDriver {
    /// # TLS posture (deliberate scope cut — plaintext by default)
    ///
    /// `oracle-rs` 0.1.7 exposes `Config::with_tls()` (encrypts via TCPS,
    /// verifying the server certificate against the system/public root CA
    /// store) and, on its `TlsConfig`, a `danger_accept_invalid_certs()`
    /// builder method that looks like a direct equivalent of `mssql.rs`'s
    /// own `.trust_cert()` ("encrypt the transport, don't require a trusted
    /// CA chain"). It is not: reading `transport::tls::TlsConfig::build_client_config`
    /// (the function that actually builds the `rustls::ClientConfig` used
    /// for the handshake) shows the `verify_server` flag that
    /// `danger_accept_invalid_certs()` sets is never consulted there —
    /// `build_client_config` always calls
    /// `ClientConfig::builder().with_root_certificates(root_store)`, which
    /// performs full certificate-chain verification against whichever root
    /// store was configured (the system/public roots, absent an explicit CA
    /// cert or wallet), regardless of `verify_server`. In this crate version,
    /// there is no working "encrypted but unverified" posture: enabling TLS
    /// against a self-signed or internal-CA Oracle instance (the normal case
    /// for a dev/CI/on-prem deployment, and exactly what this driver's own
    /// live-instance testing targets) fails certificate verification with no
    /// available bypass short of an Oracle wallet or a custom CA cert file —
    /// both out of scope for this pass.
    ///
    /// Given that, this build connects to Oracle in **plaintext** by default
    /// (`oracle_rs::Config`'s own default `TlsMode::Disable`) — a deliberate,
    /// documented scope cut, not a silent omission. A future pass adding real
    /// wallet/CA-cert configuration should revisit this doc comment.
    pub async fn connect(config: &ConnectionConfig) -> Result<Self, SqlError> {
        let settings = build_connection_settings(config)?;
        let oracle_config = Config::new(settings.host, settings.port, settings.service_name, settings.user, settings.password);
        let pool = deadpool_oracle::PoolBuilder::new(oracle_config)
            .max_size(super::DEFAULT_POOL_MAX_CONNECTIONS as usize)
            .build()
            .map_err(|e| SqlError::ConnectionFailed(e.to_string()))?;
        Ok(Self { pool })
    }
}

#[async_trait]
impl SqlDriver for OracleDriver {
    async fn query(&self, script: &str, params: &HashMap<String, SqlValue>) -> Result<Vec<SqlRow>, SqlError> {
        let (translated, occurrences) = translate_named_params(script);
        let values: Vec<OracleValue> = occurrences
            .iter()
            .map(|name| sql_value_to_oracle_value(params.get(name).cloned().unwrap_or(SqlValue::Null)))
            .collect();

        let conn = self.pool.get().await.map_err(|e| SqlError::ConnectionFailed(e.to_string()))?;

        let result = conn.execute(&translated, &values).await.map_err(classify_query_error)?;

        // See this module's own doc comment ("Transactions"): a SELECT is
        // read-only, so committing after it would just be a wasted
        // round-trip — everything else needs an explicit commit to persist.
        if Statement::new(translated.as_str()).statement_type() != StatementType::Query {
            conn.commit().await.map_err(classify_query_error)?;
        }

        result.rows.iter().map(|row| convert_row(&result.columns, row)).collect()
    }
}

/// oracle-rs's own `Error::OracleError { code, .. }` exposes the server's
/// real numeric ORA error code directly — confirmed against its source
/// (`connection.rs`'s `parse_error_response`, which reads the wire
/// protocol's numeric error number straight off the packet and stores it
/// verbatim as `code`, e.g. ORA-00001 arrives as `code: 1`, not as a string
/// needing parsing). This matches on that numeric code directly rather than
/// `Error`'s `Display` text — the safer of the two paths the design review
/// required: a numeric match can't be fooled by a bound, request-derived
/// value that happens to *contain* an ORA-code-looking substring the way a
/// text match against `Error::to_string()` could be. 1 = unique constraint
/// (ORA-00001), 2291/2292 = FK violation (ORA-02291/ORA-02292), 1400 = NOT
/// NULL violation (ORA-01400), 2290 = CHECK violation (ORA-02290). Any other
/// code, or any non-`OracleError` variant (a connection/protocol/local
/// failure with no server-side ORA code at all), falls through to the
/// generic `QueryFailed` — never guessed at.
///
/// ## Known `oracle-rs` 0.1.7 limitation: a real UNIQUE violation doesn't
/// reach this function as `code: 1`
///
/// Confirmed live against a real `gvenzl/oracle-free:23-slim` instance: a
/// genuine duplicate-key `INSERT` against a `UNIQUE` column doesn't surface
/// as `Error::OracleError { code: 1, .. }` at all. Instead, it trips
/// `execute_dml_with_params`'s internal MARKER-packet reset-recovery path
/// (`connection.rs`), and after that reset sequence hits EOF, oracle-rs
/// synthesizes a *generic* `Error::OracleError { code: 0, message: "Server
/// rejected the operation and closed the connection. This may happen when
/// binding a temporary LOB..." }` — a message that's actively misleading
/// here (no LOB is involved in a plain `VARCHAR2` unique-key insert), and a
/// `code: 0` that carries no real ORA-error information at all. The
/// connection itself is not actually broken (a follow-up query on the same
/// connection succeeds immediately), but by the time the error reaches this
/// function the real ORA-00001 code has already been lost — this is a bug in
/// `oracle-rs` 0.1.7 itself, not something this driver's own code can
/// recover.
///
/// This function deliberately does **not** treat `code: 0` (or the specific
/// wording of that synthesized message) as a probable `ConstraintViolation`.
/// That signal isn't authoritative: the exact same reset/EOF/`code: 0` path
/// could just as easily be triggered by a NOT NULL or CHECK violation, or by
/// a completely unrelated server-side rejection — promoting a non-
/// authoritative signal to `ConstraintViolation` is exactly the over-eager
/// guessing this project's own "fail clearly rather than guess" principle
/// (see `docs/frogs-additional-sql-drivers.md`) and the design review's
/// warning against loose/unanchored error-classification both rule out. So,
/// for now, a real Oracle UNIQUE/NOT NULL/FK/CHECK violation reached through
/// this specific reset path classifies as the generic `QueryFailed` rather
/// than `ConstraintViolation` — an honest limitation, not a silent one.
/// Re-check this against a newer `oracle-rs` release before assuming it's
/// still needed; if a future version surfaces the real code instead of
/// resetting the connection, the numeric match above should already handle
/// it correctly with no further changes here.
fn classify_query_error(e: oracle_rs::Error) -> SqlError {
    match &e {
        oracle_rs::Error::OracleError {
            code: 1 | 2291 | 2292 | 1400 | 2290,
            ..
        } => SqlError::ConstraintViolation(e.to_string()),
        _ => SqlError::QueryFailed(e.to_string()),
    }
}

/// Rewrites `:name` placeholders into Oracle's bare numbered bind syntax
/// (`:1`, `:2`, ...), returning the rewritten SQL plus one entry *per textual
/// occurrence* of a placeholder (not deduplicated by name) — see this
/// module's own doc comment ("Bind-parameter translation") for why the
/// occurrence list, unlike `mssql.rs`'s/`postgres.rs`'s equivalent, isn't
/// collapsed to one entry per unique name: oracle-rs needs exactly one bound
/// value per occurrence it parses out of the SQL text, regardless of whether
/// two occurrences share a name. The emitted `:N` numbering still reuses the
/// same number for a repeated name, purely for readability if this SQL is
/// ever logged — adapted from `postgres::translate_named_params`'s
/// character-scanning approach, including its `::`-cast lookahead (Oracle's
/// PL/SQL has no `::` cast operator, but a script copy-pasted from a
/// Postgres connection should still behave the same either way).
fn translate_named_params(script: &str) -> (String, Vec<String>) {
    let bytes = script.as_bytes();
    let mut output = String::with_capacity(script.len());
    let mut first_seen: Vec<String> = Vec::new();
    let mut occurrences: Vec<String> = Vec::new();
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
            let name = &script[start..end];
            let position = match first_seen.iter().position(|n| n == name) {
                Some(pos) => pos + 1,
                None => {
                    first_seen.push(name.to_string());
                    first_seen.len()
                }
            };
            output.push(':');
            output.push_str(&position.to_string());
            occurrences.push(name.to_string());
            i = end;
            continue;
        }

        output.push(c);
        i += 1;
    }

    (output, occurrences)
}

/// Binds each `SqlValue` variant to the closest native `oracle-rs` `Value`.
/// `Array` has no Oracle native equivalent bindable generically across
/// arbitrary column types — same JSON-encoded-text fallback `mysql.rs`/
/// `mssql.rs`/`sqlite.rs` already use, rather than `oracle_rs::Value::Json`
/// (which targets Oracle's own native JSON column type specifically, not a
/// generic bind target).
fn sql_value_to_oracle_value(value: SqlValue) -> OracleValue {
    match value {
        SqlValue::Null => OracleValue::Null,
        SqlValue::Bool(b) => OracleValue::Boolean(b),
        SqlValue::Int(n) => OracleValue::Integer(n),
        SqlValue::Float(f) => OracleValue::Float(f),
        SqlValue::Text(s) => OracleValue::String(s),
        SqlValue::Timestamp(ts) => OracleValue::Timestamp(OracleTimestamp {
            year: ts.date_naive().year(),
            month: ts.date_naive().month() as u8,
            day: ts.date_naive().day() as u8,
            hour: ts.time().hour() as u8,
            minute: ts.time().minute() as u8,
            second: ts.time().second() as u8,
            microsecond: ts.time().nanosecond() / 1_000,
            tz_hour_offset: 0,
            tz_minute_offset: 0,
        }),
        SqlValue::Array(items) => OracleValue::String(sql_value_to_json(&SqlValue::Array(items)).to_string()),
    }
}

/// Converts one decoded row. Matched against the column's *declared* Oracle
/// type (`ColumnInfo::oracle_type`, from the server's own describe metadata)
/// rather than the decoded `Value` variant, mirroring `mssql.rs`'s own
/// `convert_row` (matched against `tiberius::ColumnType`) — the declared
/// type is the stable, documented contract; the runtime `Value` shape is an
/// implementation detail of how oracle-rs happens to decode it.
///
/// `NUMBER`/`BINARY_INTEGER` → `SqlValue::Int` when the value is a whole
/// number that fits in `i64`, else `SqlValue::Float` — a deliberate
/// precision-loss risk for a `NUMBER` wider than an `f64` can represent
/// exactly, accepted here since `SqlValue` has no arbitrary-precision
/// decimal variant at all (every other driver in this project makes the same
/// trade-off for its own wide-numeric type).
///
/// This branch matches `OracleValue::String` first, not `Integer`/`Number` —
/// confirmed live against a real `gvenzl/oracle-free:23-slim` instance (a
/// plain `SELECT` against a `NUMBER(10)` column returned `String("2003")`,
/// not `Integer`/`Number`): **`oracle-rs` 0.1.7's actual row-decoding path
/// for `Connection::execute`/`query`** (`connection.rs`'s own
/// `parse_column_value`) hardcodes its `OracleType::Number` arm to
/// `Ok(Value::String(num.value))` unconditionally. The `Value::Integer`/
/// `Value::Number` variants this doc comment originally assumed `NUMBER`
/// would decode to only come from a *different*, apparently-dead decoder in
/// `row.rs` (`RowDataDecoder::decode_number`) that this crate's own
/// `execute`/`query` path never actually calls. This is a real discrepancy
/// inside `oracle-rs` 0.1.7 itself, not a bug in this driver — the
/// `Integer`/`Number` arms below are kept (rather than deleted) purely as
/// forward-compatible dead code in case a future `oracle-rs` release starts
/// actually using its own `row.rs` decoder; re-check this comment against
/// that release's source before assuming the `String` arm is still needed.
///
/// `CLOB` is deliberately *not* mapped to `Text` despite the plan's original
/// intent to treat it the same as `VARCHAR2`/`CHAR`: reading oracle-rs's own
/// row-decoding path (`row.rs`'s `decode_column_value`) shows `CLOB`/`BLOB`
/// columns fetched through the plain `query()`/`execute()` API this driver
/// uses come back as `Value::Lob(LobValue::locator(..))` — an out-of-band
/// locator, not inlined text or bytes. Materializing the actual LOB content
/// needs additional locator-fetch round-trips (`oracle-rs`'s own
/// `LobOpMessage` machinery) this pass doesn't implement, so `CLOB`/`BLOB`
/// both fall into the same loud-error bucket as every other unsupported
/// type below, rather than silently returning a locator's internal bytes as
/// if they were the column's real text.
///
/// `TIMESTAMP WITH (LOCAL) TIME ZONE` are excluded from the `TIMESTAMP`/
/// `DATE` case for the same fail-closed reason: unlike `DATE`/plain
/// `TIMESTAMP` (which genuinely carry no timezone information, so reading
/// them as timezone-naive and assuming UTC — the same convention
/// `postgres.rs`'s/`mssql.rs`'s own `convert_row` already use — loses
/// nothing), a `TIMESTAMP WITH TIME ZONE` column carries a real per-row
/// offset; silently discarding it under the same "assume UTC" convention
/// could misrepresent an actual non-UTC timestamp rather than just leaving
/// out information that was never there.
fn convert_row(columns: &[oracle_rs::ColumnInfo], row: &OracleRow) -> Result<SqlRow, SqlError> {
    let mut out = SqlRow::new();
    for (index, column) in columns.iter().enumerate() {
        let name = &column.name;
        let raw = row.get(index).cloned().unwrap_or(OracleValue::Null);
        let value = match column.oracle_type {
            OracleType::Varchar | OracleType::Char | OracleType::Long => match raw {
                OracleValue::Null => SqlValue::Null,
                OracleValue::String(s) => SqlValue::Text(s),
                other => return Err(SqlError::QueryFailed(format!("column '{name}': expected Oracle string data, got {other:?}"))),
            },
            OracleType::Number | OracleType::BinaryInteger => match raw {
                OracleValue::Null => SqlValue::Null,
                OracleValue::String(s) => match s.parse::<i64>() {
                    Ok(i) => SqlValue::Int(i),
                    Err(_) => s
                        .parse::<f64>()
                        .map(SqlValue::Float)
                        .map_err(|_| SqlError::QueryFailed(format!("column '{name}': Oracle NUMBER value '{s}' is not a valid number")))?,
                },
                // Not the path this crate version actually takes (see this
                // function's own doc comment) — kept for forward
                // compatibility only.
                OracleValue::Integer(i) => SqlValue::Int(i),
                OracleValue::Number(n) => SqlValue::Float(n.to_f64().map_err(|e| SqlError::QueryFailed(format!("column '{name}': {e}")))?),
                other => return Err(SqlError::QueryFailed(format!("column '{name}': expected Oracle numeric data, got {other:?}"))),
            },
            OracleType::Date => match raw {
                OracleValue::Null => SqlValue::Null,
                OracleValue::Date(d) => {
                    let naive_date = chrono::NaiveDate::from_ymd_opt(d.year, d.month as u32, d.day as u32)
                        .ok_or_else(|| SqlError::QueryFailed(format!("column '{name}': invalid Oracle DATE value")))?;
                    let naive_time = chrono::NaiveTime::from_hms_opt(d.hour as u32, d.minute as u32, d.second as u32)
                        .ok_or_else(|| SqlError::QueryFailed(format!("column '{name}': invalid Oracle DATE value")))?;
                    SqlValue::Timestamp(chrono::DateTime::from_naive_utc_and_offset(naive_date.and_time(naive_time), chrono::Utc))
                }
                other => return Err(SqlError::QueryFailed(format!("column '{name}': expected Oracle DATE data, got {other:?}"))),
            },
            OracleType::Timestamp => match raw {
                OracleValue::Null => SqlValue::Null,
                OracleValue::Timestamp(ts) => {
                    let naive_date = chrono::NaiveDate::from_ymd_opt(ts.year, ts.month as u32, ts.day as u32)
                        .ok_or_else(|| SqlError::QueryFailed(format!("column '{name}': invalid Oracle TIMESTAMP value")))?;
                    let naive_time = chrono::NaiveTime::from_hms_micro_opt(ts.hour as u32, ts.minute as u32, ts.second as u32, ts.microsecond)
                        .ok_or_else(|| SqlError::QueryFailed(format!("column '{name}': invalid Oracle TIMESTAMP value")))?;
                    SqlValue::Timestamp(chrono::DateTime::from_naive_utc_and_offset(naive_date.and_time(naive_time), chrono::Utc))
                }
                other => return Err(SqlError::QueryFailed(format!("column '{name}': expected Oracle TIMESTAMP data, got {other:?}"))),
            },
            other_type => {
                return Err(SqlError::QueryFailed(format!("column '{name}' has unsupported Oracle type '{other_type:?}'")));
            }
        };
        out.insert(name.clone(), value);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translates_a_single_named_param() {
        let (sql, occurrences) = translate_named_params("SELECT * FROM cars WHERE vin = :vin");
        assert_eq!(sql, "SELECT * FROM cars WHERE vin = :1");
        assert_eq!(occurrences, vec!["vin"]);
    }

    /// Unlike `mssql.rs`'s/`postgres.rs`'s own equivalent test (which asserts
    /// a *single* order entry for a repeated name, since those drivers bind
    /// by reusable position), this asserts one entry *per textual
    /// occurrence* — the whole point of this module's own "Bind-parameter
    /// translation" doc comment: oracle-rs's own `Statement::parse_bind_variables`
    /// pushes a bind slot for every occurrence of a placeholder it finds in
    /// `Query`/`Dml` SQL text, so `oracle.rs`'s translator has to supply a
    /// value for each occurrence too, even though the emitted SQL text
    /// cosmetically reuses the same `:1` number for both.
    #[test]
    fn a_repeated_named_param_produces_one_occurrence_entry_per_textual_use_not_deduplicated_by_name() {
        let (sql, occurrences) = translate_named_params("WHERE maker = :maker AND (:maker IS NOT NULL)");
        assert_eq!(sql, "WHERE maker = :1 AND (:1 IS NOT NULL)");
        assert_eq!(occurrences, vec!["maker", "maker"]);
    }

    #[test]
    fn assigns_distinct_numbers_in_order_of_first_appearance_for_distinct_params() {
        let (sql, occurrences) = translate_named_params("WHERE maker = :maker AND model = :model");
        assert_eq!(sql, "WHERE maker = :1 AND model = :2");
        assert_eq!(occurrences, vec!["maker", "model"]);
    }

    /// Mirrors `postgres.rs`'s own `does_not_mistake_a_postgres_type_cast_for_a_param`
    /// test: this module's own doc comment says the `::`-cast lookahead was
    /// kept (unlike `mssql.rs`, which dropped it since T-SQL has no such
    /// operator) specifically so a script copy-pasted from a Postgres
    /// connection still behaves the same, even though Oracle's own PL/SQL
    /// has no `::` cast operator of its own to protect.
    #[test]
    fn a_double_colon_pair_is_not_mistaken_for_the_start_of_a_param_name() {
        let (sql, occurrences) = translate_named_params("SELECT amount::numeric FROM pricing WHERE id = :id");
        assert_eq!(sql, "SELECT amount::numeric FROM pricing WHERE id = :1");
        assert_eq!(occurrences, vec!["id"]);
    }

    fn config_with(settings: &[(&str, serde_json::Value)]) -> ConnectionConfig {
        ConnectionConfig {
            driver: "oracle".to_string(),
            settings: settings.iter().map(|(k, v)| (k.to_string(), v.clone())).collect(),
        }
    }

    #[test]
    fn defaults_host_and_port_when_not_configured() {
        let config = config_with(&[("serviceName", serde_json::json!("FREEPDB1")), ("user", serde_json::json!("system"))]);
        let settings = build_connection_settings(&config).unwrap();
        assert_eq!(settings.host, "localhost");
        assert_eq!(settings.port, 1521);
        assert_eq!(settings.password, "");
    }

    #[test]
    fn uses_explicit_host_and_port_when_configured() {
        let config = config_with(&[
            ("host", serde_json::json!("db.internal")),
            ("port", serde_json::json!(1522)),
            ("serviceName", serde_json::json!("FREEPDB1")),
            ("user", serde_json::json!("system")),
        ]);
        let settings = build_connection_settings(&config).unwrap();
        assert_eq!(settings.host, "db.internal");
        assert_eq!(settings.port, 1522);
    }

    /// Unlike every other driver's own `build_connection_settings`/
    /// `build_connection_url` (which all default a missing database/service
    /// name to something usable), a missing `serviceName` here is a hard
    /// error — see this module's own doc comment on `build_connection_settings`
    /// for why no default is safe to assume for Oracle specifically.
    #[test]
    fn a_missing_service_name_is_a_hard_error_with_no_default() {
        let config = config_with(&[("user", serde_json::json!("system"))]);
        let err = match build_connection_settings(&config) {
            Err(e) => e,
            Ok(_) => panic!("serviceName has no safe default and must be required"),
        };
        let SqlError::ConnectionFailed(msg) = err else {
            unreachable!("build_connection_settings only ever returns ConnectionFailed")
        };
        assert!(msg.contains("serviceName"), "error message should name the missing setting, got: {msg}");
    }

    /// Same reasoning as the missing-`serviceName` case above, but for
    /// `user`: unlike `mssql.rs`'s own default of `"sa"`, there's no
    /// universally-safe Oracle admin account to fall back to (see this
    /// module's own doc comment).
    #[test]
    fn a_missing_user_is_a_hard_error_with_no_default() {
        let config = config_with(&[("serviceName", serde_json::json!("FREEPDB1"))]);
        let err = match build_connection_settings(&config) {
            Err(e) => e,
            Ok(_) => panic!("user has no safe default and must be required"),
        };
        let SqlError::ConnectionFailed(msg) = err else {
            unreachable!("build_connection_settings only ever returns ConnectionFailed")
        };
        assert!(msg.contains("user"), "error message should name the missing setting, got: {msg}");
    }

    #[test]
    fn resolves_the_password_from_the_named_env_var() {
        // SAFETY: this test doesn't run concurrently with anything else
        // that reads/writes this specific env var.
        unsafe {
            std::env::set_var("FROGS_TEST_ORACLE_PASSWORD", "s3cret");
        }
        let config = config_with(&[
            ("serviceName", serde_json::json!("FREEPDB1")),
            ("user", serde_json::json!("system")),
            ("passwordEnv", serde_json::json!("FROGS_TEST_ORACLE_PASSWORD")),
        ]);
        let settings = build_connection_settings(&config).unwrap();
        assert_eq!(settings.password, "s3cret");
    }

    #[test]
    fn an_unset_password_env_var_falls_back_to_an_empty_password_not_an_error() {
        let config = config_with(&[
            ("serviceName", serde_json::json!("FREEPDB1")),
            ("user", serde_json::json!("system")),
            ("passwordEnv", serde_json::json!("FROGS_TEST_ORACLE_PASSWORD_DEFINITELY_UNSET")),
        ]);
        let settings = build_connection_settings(&config).unwrap();
        assert_eq!(settings.password, "");
    }

    #[test]
    fn a_completely_unset_password_env_key_also_defaults_to_an_empty_password() {
        let config = config_with(&[("serviceName", serde_json::json!("FREEPDB1")), ("user", serde_json::json!("system"))]);
        let settings = build_connection_settings(&config).unwrap();
        assert_eq!(settings.password, "");
    }

    /// Builds a `ConnectionConfig` from discrete `ORACLE_TEST_*` env vars,
    /// same shape as `mssql.rs`'s own `config_from_env` — `deadpool-oracle`'s
    /// own config is field-based, not URL-based, so there's no single
    /// connection-string shape to hand it in the first place. Only the
    /// password is required to be set explicitly to gate these tests; every
    /// other field defaults to a value that matches the
    /// `gvenzl/oracle-free:23-slim` Docker image's own defaults (host/port
    /// for a locally-published container, `FREEPDB1`'s the image's own
    /// default pluggable database, `system` its own default admin user).
    fn config_from_env() -> ConnectionConfig {
        const PASSWORD_ENV: &str = "ORACLE_TEST_PASSWORD";
        std::env::var(PASSWORD_ENV).expect(
            "set ORACLE_TEST_PASSWORD (and optionally ORACLE_TEST_HOST/ORACLE_TEST_PORT/ORACLE_TEST_SERVICE_NAME/ORACLE_TEST_USER) to a reachable Oracle instance to run this test",
        );
        let host = std::env::var("ORACLE_TEST_HOST").unwrap_or_else(|_| "localhost".to_string());
        let port = std::env::var("ORACLE_TEST_PORT").ok().and_then(|v| v.parse::<u64>().ok()).unwrap_or(1521);
        let service_name = std::env::var("ORACLE_TEST_SERVICE_NAME").unwrap_or_else(|_| "FREEPDB1".to_string());
        let user = std::env::var("ORACLE_TEST_USER").unwrap_or_else(|_| "system".to_string());

        config_with(&[
            ("host", serde_json::json!(host)),
            ("port", serde_json::json!(port)),
            ("serviceName", serde_json::json!(service_name)),
            ("user", serde_json::json!(user)),
            ("passwordEnv", serde_json::json!(PASSWORD_ENV)),
        ])
    }

    /// Runs an idempotent `DROP TABLE <name>` via Oracle's own idiomatic
    /// "drop if exists" idiom: Oracle has no `DROP TABLE IF EXISTS` syntax at
    /// all, so the conventional workaround is a PL/SQL block that attempts
    /// the drop and swallows exactly ORA-00942 ("table or view does not
    /// exist"), re-raising anything else. Verified against a real
    /// `gvenzl/oracle-free:23-slim` instance during this test's own
    /// development.
    async fn drop_table_if_exists(driver: &OracleDriver, table: &str) {
        let script = format!("BEGIN EXECUTE IMMEDIATE 'DROP TABLE {table}'; EXCEPTION WHEN OTHERS THEN IF SQLCODE != -942 THEN RAISE; END IF; END;");
        driver.query(&script, &HashMap::new()).await.expect("drop-if-exists block should never itself fail");
    }

    /// Real round-trip test against a live Oracle instance — not run by
    /// default since this dev environment has no Oracle server available. To
    /// run it: start an Oracle instance (e.g.
    /// `docker run -d -p 1521:1521 --env-file <file with ORACLE_PASSWORD=...> gvenzl/oracle-free:23-slim`),
    /// then `ORACLE_TEST_PASSWORD=<that password> cargo test --locked --features oracle -- --ignored`
    /// (add `ORACLE_TEST_HOST`/`ORACLE_TEST_PORT`/`ORACLE_TEST_SERVICE_NAME`/`ORACLE_TEST_USER`
    /// to point anywhere other than a default local `gvenzl/oracle-free` container).
    ///
    /// Deliberately not a Postgres-style temp table: Oracle's own private
    /// temporary tables are also session-scoped, and `driver.pool` is a
    /// connection pool — the follow-up `INSERT`/`SELECT` could easily land on
    /// a different physical connection than the one that ran the `CREATE`,
    /// same reasoning `mssql.rs`'s own live test documents.
    ///
    /// Column keys are asserted in `UPPERCASE` — verified against a real
    /// `gvenzl/oracle-free:23-slim` instance during this test's own
    /// development: Oracle folds an unquoted identifier to uppercase in its
    /// data dictionary (the opposite convention from Postgres, which folds
    /// to lowercase), and `convert_row` reports a column's name exactly as
    /// the server's own describe metadata gives it, unmodified — this isn't
    /// a driver bug, just Oracle's own well-known identifier-folding
    /// behavior showing up in `SqlRow`'s keys.
    #[tokio::test]
    #[ignore]
    async fn queries_a_real_oracle_instance() {
        let config = config_from_env();
        let driver = OracleDriver::connect(&config).await.expect("failed to connect");

        drop_table_if_exists(&driver, "frogs_oracle_smoke_test").await;
        driver
            .query("CREATE TABLE frogs_oracle_smoke_test (vin VARCHAR2(64), car_year NUMBER(10))", &HashMap::new())
            .await
            .unwrap();

        let mut insert_params = HashMap::new();
        insert_params.insert("vin".to_string(), SqlValue::Text("1HGCM82633A004352".to_string()));
        insert_params.insert("car_year".to_string(), SqlValue::Int(2003));
        driver
            .query("INSERT INTO frogs_oracle_smoke_test (vin, car_year) VALUES (:vin, :car_year)", &insert_params)
            .await
            .unwrap();

        let mut select_params = HashMap::new();
        select_params.insert("vin".to_string(), SqlValue::Text("1HGCM82633A004352".to_string()));
        let rows = driver
            .query("SELECT vin, car_year FROM frogs_oracle_smoke_test WHERE vin = :vin", &select_params)
            .await
            .expect("query should succeed");

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("VIN"), Some(&SqlValue::Text("1HGCM82633A004352".to_string())));
        assert_eq!(rows[0].get("CAR_YEAR"), Some(&SqlValue::Int(2003)));

        driver.query("DROP TABLE frogs_oracle_smoke_test", &HashMap::new()).await.unwrap();
    }

    /// Pins down `classify_query_error`'s own documented, deliberate
    /// `oracle-rs` 0.1.7 limitation (see that function's doc comment,
    /// "Known `oracle-rs` 0.1.7 limitation") rather than the originally-hoped-
    /// for behavior: a real duplicate-key `INSERT` against a `UNIQUE` column
    /// does *not* reach `classify_query_error` as `Error::OracleError { code:
    /// 1, .. }` at all — `execute_dml_with_params` trips its own internal
    /// MARKER-packet reset-recovery path first, which synthesizes a non-
    /// authoritative `code: 0` with a misleading LOB-mentioning message by
    /// the time the error surfaces here, so it classifies as the generic
    /// `SqlError::QueryFailed` every other unclassifiable query error already
    /// falls back to, not `ConstraintViolation`.
    ///
    /// This was deliberately *not* special-cased into a `ConstraintViolation`
    /// promotion: `code: 0` carries no real ORA-error information, and the
    /// exact same reset/EOF path could equally be triggered by a NOT NULL or
    /// CHECK violation, or something unrelated entirely — pattern-matching a
    /// non-authoritative signal into a specific classification is exactly
    /// the over-eager guessing this project's own error-classification
    /// design review rules out elsewhere (see `classify_query_error`'s own
    /// doc comment for the full reasoning). A connection-liveness probe
    /// right after the failure (confirmed by hand during this test's own
    /// development: a follow-up `SELECT` on the same connection succeeds
    /// immediately) doesn't help either — it proves the connection didn't
    /// die, not *which* server-side error actually occurred.
    ///
    /// If a future `oracle-rs` release stops needing the MARKER-reset path
    /// for this case and starts surfacing the real ORA-00001 code, this test
    /// should start failing (`QueryFailed` where `ConstraintViolation` is now
    /// achievable) — at that point, flip this back to asserting
    /// `ConstraintViolation`, the same shape `mssql.rs`'s/`postgres.rs`'s own
    /// equivalent test already asserts today.
    #[tokio::test]
    #[ignore]
    async fn a_unique_constraint_violation_currently_falls_back_to_query_failed_a_documented_oracle_rs_limitation() {
        let config = config_from_env();
        let driver = OracleDriver::connect(&config).await.expect("failed to connect");

        drop_table_if_exists(&driver, "frogs_oracle_constraint_test").await;
        driver
            .query("CREATE TABLE frogs_oracle_constraint_test (vin VARCHAR2(64) UNIQUE)", &HashMap::new())
            .await
            .unwrap();

        let mut params = HashMap::new();
        params.insert("vin".to_string(), SqlValue::Text("1HGCM82633A004352".to_string()));
        driver
            .query("INSERT INTO frogs_oracle_constraint_test (vin) VALUES (:vin)", &params)
            .await
            .expect("the first insert should succeed");

        let err = driver
            .query("INSERT INTO frogs_oracle_constraint_test (vin) VALUES (:vin)", &params)
            .await
            .expect_err("a duplicate value against a UNIQUE column must fail");

        assert!(
            matches!(err, SqlError::QueryFailed(_)),
            "expected the documented QueryFailed fallback (see this test's own doc comment) — got {err:?}. \
             If this now fails because `err` is `ConstraintViolation`, `oracle-rs` may have started surfacing \
             the real ORA-00001 code for this case — flip this test's assertion back, per its own doc comment."
        );

        driver.query("DROP TABLE frogs_oracle_constraint_test", &HashMap::new()).await.unwrap();
    }

    /// Required by this session's plan-security-review (Finding 3): proves
    /// the actual per-*occurrence* binding mechanism this module's own doc
    /// comment describes is correct against a live `oracle-rs` connection,
    /// not just asserted by `translate_named_params`'s own unit test above.
    /// If oracle-rs's positional binding didn't actually line up the way the
    /// translator assumes, the second `:maker` occurrence would bind to
    /// nothing (or to whatever value happened to land in that slot), and
    /// this predicate would either error or spuriously fail to match the row
    /// it should match.
    #[tokio::test]
    #[ignore]
    async fn a_repeated_bind_name_resolves_to_the_same_value_at_every_occurrence() {
        let config = config_from_env();
        let driver = OracleDriver::connect(&config).await.expect("failed to connect");

        drop_table_if_exists(&driver, "frogs_oracle_repeated_bind_test").await;
        driver
            .query("CREATE TABLE frogs_oracle_repeated_bind_test (maker VARCHAR2(64))", &HashMap::new())
            .await
            .unwrap();
        driver
            .query("INSERT INTO frogs_oracle_repeated_bind_test (maker) VALUES ('Toyota')", &HashMap::new())
            .await
            .unwrap();

        let mut params = HashMap::new();
        params.insert("maker".to_string(), SqlValue::Text("Toyota".to_string()));
        let rows = driver
            .query(
                "SELECT maker FROM frogs_oracle_repeated_bind_test WHERE maker = :maker AND (:maker IS NOT NULL)",
                &params,
            )
            .await
            .expect("both occurrences of :maker should bind to the same supplied value");

        assert_eq!(rows.len(), 1);
        // "MAKER", not "maker" — see `queries_a_real_oracle_instance`'s own
        // doc comment on Oracle's uppercase unquoted-identifier folding.
        assert_eq!(rows[0].get("MAKER"), Some(&SqlValue::Text("Toyota".to_string())));

        driver.query("DROP TABLE frogs_oracle_repeated_bind_test", &HashMap::new()).await.unwrap();
    }
}
