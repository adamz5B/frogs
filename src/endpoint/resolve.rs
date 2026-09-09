use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::Path;
use std::pin::Pin;
use std::time::Duration;

use axum::http::HeaderMap;
use futures_util::StreamExt;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use super::error::SourceErrorCause;
use super::schema::{ArrayResponse, Cardinality, DetailedField, EndpointFile, Parameter, ParameterType, ResponseField, ResponseShape, SourceDef};
use crate::sql::{SqlDriver, SqlValue, json_value_to_sql_value, sql_value_to_json};

/// Default per-row call timeout for a nested-many source's fan-out
/// (`rowTimeoutMs` omitted) — see the design doc's "Many-Depends-on-Many
/// Array Fan-Out" plan, point 1.
pub(crate) const DEFAULT_NESTED_MANY_ROW_TIMEOUT_MS: u64 = 30_000;
/// Sanity cap on a declared `rowTimeoutMs` — enforced by `validate_nested_many`.
pub(crate) const MAX_NESTED_MANY_ROW_TIMEOUT_MS: u64 = 300_000;
/// Hard ceiling on a declared `maxConcurrency` — enforced by
/// `validate_nested_many`, independent of (and in addition to) the SQL
/// pool-derived ceiling that function also applies.
pub(crate) const MAX_NESTED_MANY_CONCURRENCY: usize = 50;
/// Hard ceiling on a declared `maxRows` — enforced by `validate_nested_many`.
pub(crate) const MAX_NESTED_MANY_ROWS: usize = 1000;

/// One resolved source's result, as plain JSON — a `Value::Object` whether
/// it came from a SQL row (converted once here) or an HTTP response body
/// (already JSON natively). `None` means the source failed and every
/// response field that reads from it should render as `null` — the design
/// doc's `optional` semantics. A non-optional failure never reaches this
/// map at all: it short-circuits the whole request via `Err(SourceFailure)`
/// below.
type ResolvedSources = HashMap<String, Option<Value>>;

/// A read-only view over already-resolved sources, handed to `resolve_from`/
/// `run_sql_source`/`run_http_source` instead of `&ResolvedSources` directly
/// — the abstraction that lets a nested-many fan-out's per-row future see
/// its own row substituted in for the bracket parent's *whole* array,
/// without cloning every other already-resolved source's payload once per
/// row (see `resolve_nested_many`). `Map` is the ordinary case every
/// call site outside nested-many resolution uses; `RowOverride` only ever
/// exists for the lifetime of one fan-out row's own future.
#[derive(Clone, Copy)]
enum ResolvedView<'a> {
    Map(&'a ResolvedSources),
    RowOverride {
        base: &'a ResolvedSources,
        parent_name: &'a str,
        row: &'a Value,
    },
}

impl<'a> ResolvedView<'a> {
    fn get_source(&self, name: &str) -> Option<&'a Value> {
        match self {
            ResolvedView::Map(m) => m.get(name).and_then(|v| v.as_ref()),
            ResolvedView::RowOverride { base, parent_name, row } => {
                if name == *parent_name {
                    Some(row)
                } else {
                    base.get(name).and_then(|v| v.as_ref())
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct SourceFailure {
    /// The source's own `onError` override, if it set one — `None` means
    /// "let the classified error code's registry `httpStatus` decide,"
    /// resolved later by whoever builds the actual HTTP response.
    pub on_error: Option<u16>,
    pub source_name: String,
    pub cause: SourceErrorCause,
}

/// What one source's *execution* should do instead of actually running —
/// the testing framework's mock-substitution mechanic (design doc,
/// "Testing"). `mocks` swaps source *execution*, not source *definition*:
/// a mocked source's `type`/`parameters`/everything in `endpoint.sources`
/// is untouched, only whether `resolve_sources` calls out to a real
/// SQL/HTTP call is affected. `Fail` classifies to
/// `SourceErrorCause::Mocked`, which flows through the exact same
/// `onError`/`optional`/registry-lookup path a real failure would — the
/// point is exercising the *real* error-handling logic against an
/// injected code, not reimplementing it here.
#[derive(Debug, Clone, PartialEq)]
pub enum MockOutcome {
    Success(Value),
    Fail(String),
}

/// A mock is `{"fail": "<code>"}` if — and only if — it's a JSON object
/// with exactly that one key and a string value; anything else (including
/// an object that happens to have other fields alongside a `fail` key) is
/// a literal success value. Avoids the ambiguity a generic
/// `#[serde(untagged)]` enum would have picking between the two shapes.
/// Lives here (not in `testing::schema`, where the rest of the test-file
/// parsing types live) because this *is* the type `resolve_sources` itself
/// consumes — one definition, not a parsed copy converted into an
/// execution-time one.
impl<'de> Deserialize<'de> for MockOutcome {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        if let Value::Object(map) = &value
            && map.len() == 1
            && let Some(Value::String(code)) = map.get("fail")
        {
            return Ok(MockOutcome::Fail(code.clone()));
        }
        Ok(MockOutcome::Success(value))
    }
}

/// The exact inverse of the `Deserialize` impl above — `frogs test record`
/// (Point 6) constructs `Success` values from a real run and needs them to
/// write back out in the same shape a hand-authored mock would use: a
/// success value serializes as itself (not wrapped), and `Fail` serializes
/// as the `{"fail": "<code>"}` object form.
impl Serialize for MockOutcome {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            MockOutcome::Success(value) => value.serialize(serializer),
            MockOutcome::Fail(code) => {
                let mut map = Map::new();
                map.insert("fail".to_string(), Value::String(code.clone()));
                Value::Object(map).serialize(serializer)
            }
        }
    }
}

/// Runs every source in `endpoint.sources` and collects each result. A
/// source whose own `parameters` reference another source's output
/// (`"from": "sources.<name>.<field>"`) has that dependency resolved first,
/// recursively — see `resolve_one`. Returns `Err` immediately if a
/// non-optional source fails, since there's no point building a response
/// the client can't use.
///
/// `mocks` is keyed by source name; a source with no entry runs for real.
/// The real (non-test) request path always passes an empty map — same
/// "empty means nothing special" convention `transaction_id: ""` uses.
#[allow(clippy::too_many_arguments)]
pub async fn resolve_sources(
    endpoint: &EndpointFile,
    services: &HashMap<String, String>,
    drivers: &HashMap<String, Box<dyn SqlDriver>>,
    sql_root: &Path,
    http_root: &Path,
    http_client: &reqwest::Client,
    path_params: &HashMap<String, String>,
    query_params: &HashMap<String, String>,
    body: &Value,
    transaction_id: &str,
    mocks: &HashMap<String, MockOutcome>,
    headers: &HeaderMap,
) -> Result<ResolvedSources, SourceFailure> {
    let mut resolved: ResolvedSources = HashMap::new();
    let mut in_progress: HashSet<String> = HashSet::new();

    for name in endpoint.sources.keys() {
        if !resolved.contains_key(name) {
            resolve_one(
                name,
                endpoint,
                services,
                drivers,
                sql_root,
                http_root,
                http_client,
                headers,
                path_params,
                query_params,
                body,
                transaction_id,
                mocks,
                &mut resolved,
                &mut in_progress,
            )
            .await?;
        }
    }

    Ok(resolved)
}

/// Resolves one source, first recursively resolving any dependency its own
/// `parameters` reference via `"sources.<name>..."` (skipped entirely for a
/// mocked source, which needs no parameters bound at all). A plain `async
/// fn` can't call itself directly — the compiler would need to know its own
/// future's size to define it — so this returns an explicitly boxed,
/// pinned future instead; the same problem `openapi::schema_walk`'s
/// (synchronous, so it doesn't hit this) recursive walk doesn't have to
/// work around. `in_progress` mirrors that module's own cycle-detection
/// idiom: a name still in it when re-entered means a real dependency cycle,
/// reported as a config error rather than hanging or silently picking an
/// order.
#[allow(clippy::too_many_arguments)]
fn resolve_one<'a>(
    name: &'a str,
    endpoint: &'a EndpointFile,
    services: &'a HashMap<String, String>,
    drivers: &'a HashMap<String, Box<dyn SqlDriver>>,
    sql_root: &'a Path,
    http_root: &'a Path,
    http_client: &'a reqwest::Client,
    headers: &'a HeaderMap,
    path_params: &'a HashMap<String, String>,
    query_params: &'a HashMap<String, String>,
    body: &'a Value,
    transaction_id: &'a str,
    mocks: &'a HashMap<String, MockOutcome>,
    resolved: &'a mut ResolvedSources,
    in_progress: &'a mut HashSet<String>,
) -> Pin<Box<dyn Future<Output = Result<(), SourceFailure>> + Send + 'a>> {
    Box::pin(async move {
        if resolved.contains_key(name) {
            return Ok(());
        }
        let Some(source) = endpoint.sources.get(name) else {
            return Ok(());
        };

        let (on_error, optional, parameters, allow_nested_many, max_concurrency, max_rows, row_timeout_ms) = match source {
            SourceDef::Sql {
                on_error,
                optional,
                parameters,
                allow_nested_many,
                max_concurrency,
                max_rows,
                row_timeout_ms,
                ..
            } => (*on_error, *optional, parameters, *allow_nested_many, *max_concurrency, *max_rows, *row_timeout_ms),
            SourceDef::Http {
                on_error,
                optional,
                parameters,
                allow_nested_many,
                max_concurrency,
                max_rows,
                row_timeout_ms,
                ..
            } => (*on_error, *optional, parameters, *allow_nested_many, *max_concurrency, *max_rows, *row_timeout_ms),
        };

        if allow_nested_many {
            return resolve_nested_many(
                name,
                on_error,
                optional,
                parameters,
                max_concurrency,
                max_rows,
                row_timeout_ms,
                source,
                endpoint,
                services,
                drivers,
                sql_root,
                http_root,
                http_client,
                headers,
                path_params,
                query_params,
                body,
                transaction_id,
                mocks,
                resolved,
                in_progress,
            )
            .await;
        }

        let mock = mocks.get(name);

        if mock.is_none() {
            if !in_progress.insert(name.to_string()) {
                return Err(SourceFailure {
                    on_error,
                    source_name: name.to_string(),
                    cause: SourceErrorCause::Config(format!("circular source dependency involving '{name}'")),
                });
            }
            for param in parameters {
                if let Some(dep_name) = source_dependency(&param.from)
                    && endpoint.sources.contains_key(dep_name)
                    && !resolved.contains_key(dep_name)
                {
                    resolve_one(
                        dep_name,
                        endpoint,
                        services,
                        drivers,
                        sql_root,
                        http_root,
                        http_client,
                        headers,
                        path_params,
                        query_params,
                        body,
                        transaction_id,
                        mocks,
                        resolved,
                        in_progress,
                    )
                    .await?;
                }
            }
            in_progress.remove(name);
        }

        let outcome = match mock {
            Some(MockOutcome::Success(value)) => Ok(value.clone()),
            Some(MockOutcome::Fail(code)) => Err(SourceErrorCause::Mocked(code.clone())),
            None => {
                run_source_row(
                    source,
                    parameters,
                    drivers,
                    sql_root,
                    http_root,
                    http_client,
                    services,
                    headers,
                    path_params,
                    query_params,
                    body,
                    transaction_id,
                    ResolvedView::Map(resolved),
                )
                .await
            }
        };

        match outcome {
            Ok(value) => {
                resolved.insert(name.to_string(), Some(value));
                Ok(())
            }
            Err(cause) => {
                if optional {
                    resolved.insert(name.to_string(), None);
                    Ok(())
                } else {
                    Err(SourceFailure {
                        on_error,
                        source_name: name.to_string(),
                        cause,
                    })
                }
            }
        }
    })
}

/// The dependency name out of a `"sources.<name>"`, `"sources.<name>.<field>"`,
/// or nested-many bracket-form `"sources.<name>[].<field>"` parameter `from`
/// value, or `None` for anything else (including bare `"sources"` with
/// nothing after it). The `"[]"` strip is what lets a nested-many source's
/// own bracket-parent parameter be recognized as a dependency to resolve
/// first, the same as any other `sources.*` parameter.
fn source_dependency(from: &str) -> Option<&str> {
    let name = from.strip_prefix("sources.")?.split('.').next().filter(|s| !s.is_empty())?;
    Some(name.strip_suffix("[]").unwrap_or(name))
}

/// Dispatches one source's real (non-mocked) execution to its own driver —
/// shared by `resolve_one`'s ordinary path (`ResolvedView::Map`) and
/// `resolve_nested_many`'s per-row fan-out (`ResolvedView::RowOverride`), so
/// the SQL-vs-HTTP dispatch logic isn't duplicated between the two.
#[allow(clippy::too_many_arguments)]
async fn run_source_row(
    source: &SourceDef,
    parameters: &[Parameter],
    drivers: &HashMap<String, Box<dyn SqlDriver>>,
    sql_root: &Path,
    http_root: &Path,
    http_client: &reqwest::Client,
    services: &HashMap<String, String>,
    headers: &HeaderMap,
    path_params: &HashMap<String, String>,
    query_params: &HashMap<String, String>,
    body: &Value,
    transaction_id: &str,
    resolved: ResolvedView<'_>,
) -> Result<Value, SourceErrorCause> {
    match source {
        SourceDef::Sql {
            connection, script, cardinality, ..
        } => {
            run_sql_source(
                drivers,
                sql_root,
                connection,
                script,
                *cardinality,
                parameters,
                headers,
                path_params,
                query_params,
                body,
                transaction_id,
                resolved,
            )
            .await
        }
        SourceDef::Http { request, cardinality, .. } => {
            run_http_source(
                services,
                http_root,
                http_client,
                request,
                *cardinality,
                parameters,
                headers,
                path_params,
                query_params,
                body,
                transaction_id,
                resolved,
            )
            .await
        }
    }
}

/// Fan-out resolution for a source declaring `allowNestedMany: true` — see
/// the design doc's "Many-Depends-on-Many Array Fan-Out" plan, points 4–5.
/// Diverges from `resolve_one`'s ordinary dependency handling in one
/// deliberate way: every dependency this source's own `parameters`
/// reference (the bracket-form parent included) is always resolved first,
/// even when this source itself is mocked — the row-count gate and merge
/// target both need the parent's real resolved array regardless of whether
/// the per-row calls themselves are mocked.
///
/// `max_concurrency`/`max_rows` being `None` here only happens via a caller
/// that skipped `validate_nested_many` (`resolve_for_test`'s test-runner
/// path, or `record_sources`) — classified as a config error, same
/// precedent as an unmatched security scheme.
#[allow(clippy::too_many_arguments)]
async fn resolve_nested_many<'a>(
    name: &'a str,
    on_error: Option<u16>,
    optional: bool,
    parameters: &'a [Parameter],
    max_concurrency: Option<NonZeroUsize>,
    max_rows: Option<NonZeroUsize>,
    row_timeout_ms: Option<NonZeroU64>,
    source: &'a SourceDef,
    endpoint: &'a EndpointFile,
    services: &'a HashMap<String, String>,
    drivers: &'a HashMap<String, Box<dyn SqlDriver>>,
    sql_root: &'a Path,
    http_root: &'a Path,
    http_client: &'a reqwest::Client,
    headers: &'a HeaderMap,
    path_params: &'a HashMap<String, String>,
    query_params: &'a HashMap<String, String>,
    body: &'a Value,
    transaction_id: &'a str,
    mocks: &'a HashMap<String, MockOutcome>,
    resolved: &'a mut ResolvedSources,
    in_progress: &'a mut HashSet<String>,
) -> Result<(), SourceFailure> {
    let (Some(max_concurrency), Some(max_rows)) = (max_concurrency, max_rows) else {
        return Err(SourceFailure {
            on_error,
            source_name: name.to_string(),
            cause: SourceErrorCause::Config(format!(
                "source '{name}' declares allowNestedMany but maxConcurrency/maxRows is missing — validate_nested_many should have caught this at startup"
            )),
        });
    };
    let row_timeout_ms = row_timeout_ms.map(NonZeroU64::get).unwrap_or(DEFAULT_NESTED_MANY_ROW_TIMEOUT_MS);
    let row_timeout = Duration::from_millis(row_timeout_ms);

    let parent_name = match nested_many_parent(parameters) {
        Ok(parent_name) => parent_name.to_string(),
        Err(message) => {
            return Err(SourceFailure {
                on_error,
                source_name: name.to_string(),
                cause: SourceErrorCause::Config(format!("source '{name}': {message}")),
            });
        }
    };

    // Every referenced dependency — the bracket parent included — is
    // resolved first, regardless of whether this source itself is mocked
    // (see this function's own doc comment).
    if !in_progress.insert(name.to_string()) {
        return Err(SourceFailure {
            on_error,
            source_name: name.to_string(),
            cause: SourceErrorCause::Config(format!("circular source dependency involving '{name}'")),
        });
    }
    for param in parameters {
        if let Some(dep_name) = source_dependency(&param.from)
            && endpoint.sources.contains_key(dep_name)
            && !resolved.contains_key(dep_name)
        {
            resolve_one(
                dep_name,
                endpoint,
                services,
                drivers,
                sql_root,
                http_root,
                http_client,
                headers,
                path_params,
                query_params,
                body,
                transaction_id,
                mocks,
                resolved,
                in_progress,
            )
            .await?;
        }
    }
    in_progress.remove(name);

    // The one necessary, bounded clone — of just the parent's own array,
    // taken once, not once per row. `None`/`Some(None)`/non-array parent
    // all fall into the same zero-rows arm, and `resolved[parent_name]` is
    // left completely untouched below in that case — never rewritten into a
    // fabricated empty array, which would misrepresent a failed-optional
    // parent as a successful empty list to anything else in the endpoint
    // reading `sources.<parent>` directly.
    let parent_rows: Vec<Value> = match resolved.get(parent_name.as_str()) {
        Some(Some(Value::Array(rows))) => rows.clone(),
        _ => Vec::new(),
    };

    if parent_rows.len() > max_rows.get() {
        let cause = SourceErrorCause::NestedManyRowLimitExceeded {
            resolved: parent_rows.len(),
            max: max_rows.get(),
        };
        return if optional {
            // Zero calls; every row's merged field simply stays absent —
            // no top-level `resolved[name]` entry, and the parent's own
            // array is untouched (no merge ever happened).
            Ok(())
        } else {
            Err(SourceFailure {
                on_error,
                source_name: name.to_string(),
                cause,
            })
        };
    }
    if parent_rows.is_empty() {
        return Ok(());
    }

    let mock = mocks.get(name);
    let mut row_values: HashMap<usize, Value> = match mock {
        Some(MockOutcome::Success(value)) => parent_rows.iter().enumerate().map(|(i, _)| (i, value.clone())).collect(),
        Some(MockOutcome::Fail(code)) => {
            if optional {
                HashMap::new()
            } else {
                return Err(SourceFailure {
                    on_error,
                    source_name: name.to_string(),
                    cause: SourceErrorCause::Mocked(code.clone()),
                });
            }
        }
        None => {
            // A shared, read-only reborrow of `resolved` — every concurrent
            // per-row future reads through this same borrow rather than
            // each cloning the whole map (see `ResolvedView`'s own doc
            // comment). Its last use is this `while let` loop below; NLL
            // lets `resolved` become mutably available again once this
            // whole match arm's block ends, well before the final
            // `resolved.insert(...)` further down.
            let base: &ResolvedSources = resolved;
            let parent_name_ref = parent_name.as_str();
            // A plain loop building an owned `Vec` of futures, not
            // `.iter().map(...)` — an iterator-adaptor closure here runs
            // into spurious higher-ranked-lifetime inference errors against
            // `base`'s already-fixed lifetime (each `async move` block
            // needs to be built with a concrete, not higher-ranked, `row`
            // lifetime).
            let mut futures = Vec::with_capacity(parent_rows.len());
            for (i, row) in parent_rows.iter().enumerate() {
                let view = ResolvedView::RowOverride {
                    base,
                    parent_name: parent_name_ref,
                    row,
                };
                futures.push(async move {
                    let outcome = tokio::time::timeout(
                        row_timeout,
                        run_source_row(
                            source,
                            parameters,
                            drivers,
                            sql_root,
                            http_root,
                            http_client,
                            services,
                            headers,
                            path_params,
                            query_params,
                            body,
                            transaction_id,
                            view,
                        ),
                    )
                    .await;
                    let outcome = outcome.unwrap_or(Err(SourceErrorCause::NestedManyRowTimedOut { after_ms: row_timeout_ms }));
                    (i, outcome)
                });
            }

            let mut stream = futures_util::stream::iter(futures).buffer_unordered(max_concurrency.get());
            let mut values = HashMap::new();
            let mut fatal = None;
            // First-detected non-optional per-row failure (including a
            // timeout) short-circuits immediately — dropping `stream` below
            // cancels every not-yet-completed row's future.
            while let Some((i, outcome)) = stream.next().await {
                match outcome {
                    Ok(value) => {
                        values.insert(i, value);
                    }
                    Err(cause) => {
                        if !optional {
                            fatal = Some(cause);
                            break;
                        }
                    }
                }
            }
            drop(stream);

            if let Some(cause) = fatal {
                return Err(SourceFailure {
                    on_error,
                    source_name: name.to_string(),
                    cause,
                });
            }
            values
        }
    };

    // Reordered by original row index (`buffer_unordered` completes rows in
    // whatever order they finish), each merged into a *clone of that one
    // row* under a new key equal to this source's own name — read by
    // unmodified `items`/`lookup_in_row`. A row with no entry (optional
    // per-row failure, or a mocked failure with `optional: true`) simply
    // doesn't get the key, rendering `null` wherever it's looked up.
    let merged: Vec<Value> = parent_rows
        .into_iter()
        .enumerate()
        .map(|(i, mut row)| {
            if let Some(value) = row_values.remove(&i)
                && let Value::Object(map) = &mut row
            {
                map.insert(name.to_string(), value);
            }
            row
        })
        .collect();

    resolved.insert(parent_name, Some(Value::Array(merged)));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_sql_source(
    drivers: &HashMap<String, Box<dyn SqlDriver>>,
    sql_root: &Path,
    connection: &str,
    script: &str,
    cardinality: Cardinality,
    parameters: &[Parameter],
    headers: &HeaderMap,
    path_params: &HashMap<String, String>,
    query_params: &HashMap<String, String>,
    body: &Value,
    transaction_id: &str,
    resolved: ResolvedView<'_>,
) -> Result<Value, SourceErrorCause> {
    let driver = drivers
        .get(connection)
        .ok_or_else(|| SourceErrorCause::Config(format!("no connection named '{connection}'")))?;

    let script_path = sql_root.join(connection).join(script);
    let script_contents = std::fs::read_to_string(&script_path).map_err(|e| SourceErrorCause::Config(format!("failed to read {}: {e}", script_path.display())))?;

    let mut bound = HashMap::new();
    for param in parameters {
        let value = resolve_from(&param.from, headers, path_params, query_params, body, transaction_id, resolved);
        bound.insert(param.name.clone(), clamp_numeric(value, param.default, param.min, param.max));
    }

    let rows = driver.query(&script_contents, &bound).await.map_err(SourceErrorCause::Sql)?;

    match cardinality {
        Cardinality::One => rows
            .into_iter()
            .next()
            .map(|row| Value::Object(row.iter().map(|(k, v)| (k.clone(), sql_value_to_json(v))).collect()))
            .ok_or(SourceErrorCause::NotFound),
        // Zero rows is a legitimate, non-error result for a list — an empty
        // array, not `SourceErrorCause::NotFound` (that's a "one" concept:
        // no such single row).
        Cardinality::Many => Ok(Value::Array(
            rows.into_iter()
                .map(|row| Value::Object(row.iter().map(|(k, v)| (k.clone(), sql_value_to_json(v))).collect()))
                .collect(),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_http_source(
    services: &HashMap<String, String>,
    http_root: &Path,
    client: &reqwest::Client,
    request: &str,
    cardinality: Cardinality,
    parameters: &[Parameter],
    headers: &HeaderMap,
    path_params: &HashMap<String, String>,
    query_params: &HashMap<String, String>,
    body: &Value,
    transaction_id: &str,
    resolved: ResolvedView<'_>,
) -> Result<Value, SourceErrorCause> {
    let request_path = http_root.join(request);
    let contents = std::fs::read_to_string(&request_path).map_err(|e| SourceErrorCause::Config(format!("failed to read {}: {e}", request_path.display())))?;
    let request_file: crate::http::HttpRequestFile =
        serde_json::from_str(&contents).map_err(|e| SourceErrorCause::Config(format!("invalid JSON in {}: {e}", request_path.display())))?;

    let mut bound = HashMap::new();
    // The service registry (design doc, `config/services.json`): a logical
    // name → base URL lookup, reachable from a `url`/`body` template as
    // `{{services.<name>}}` — no new template syntax needed, just more
    // entries in the same `{{name}}` substitution map every other parameter
    // already goes through. Seeded before `parameters` below so an endpoint
    // author can't accidentally shadow a registry entry with a same-named
    // declared parameter without it being obvious which one wins (`parameters`
    // wins, since it's inserted second).
    for (name, base_url) in services {
        bound.insert(format!("services.{name}"), SqlValue::Text(base_url.clone()));
    }
    let mut array_params = HashSet::new();
    for param in parameters {
        let value = resolve_from(&param.from, headers, path_params, query_params, body, transaction_id, resolved);
        bound.insert(param.name.clone(), clamp_numeric(value, param.default, param.min, param.max));
        if param.param_type == ParameterType::Array {
            array_params.insert(param.name.clone());
        }
    }

    let value = crate::http::execute(client, &request_file, &bound, &array_params, headers)
        .await
        .map_err(SourceErrorCause::Http)?;

    // `responsePath` (if declared) has already been unwrapped by `execute`
    // above — the array `cardinality: "many"` expects is exactly whatever
    // that unwrapping produced, the same way `responsePath` already lets
    // `cardinality: "one"` unwrap an envelope before the ordinary
    // field-mapping case sees it. No separate config knob needed.
    if cardinality == Cardinality::Many && !value.is_array() {
        return Err(SourceErrorCause::Http(crate::http::HttpError::NotAnArray(json_shape_name(&value).to_string())));
    }

    Ok(value)
}

fn json_shape_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

/// `path.`/`query.` look up the URL; `body.<field>` walks the parsed
/// request body's dot-path, and bare `body` binds the *whole* body as one
/// parameter (JSON-encoded as text if it isn't already a scalar — a
/// reasonable fallback until array-typed parameters get native handling,
/// see the design doc's write-operations section, point 1). `context.
/// transactionId` binds the same per-request correlation ID every log line
/// for this request is already tagged with (see `server::RequestId`) — a
/// shared identifier every source in a request can use for its own
/// coordination, per the design doc's multi-source write atomicity section;
/// the engine itself does no distributed-transaction/rollback logic.
/// `sources.<name>` / `sources.<name>.<field...>` reads another source's
/// already-resolved value — `resolve_one` guarantees it's resolved before
/// this ever runs, or the whole request already failed if it couldn't be.
/// `header.<name>` reads the caller's own request header, case-insensitively
/// (`HeaderMap::get` already is) — the exact same lookup
/// `security::bind_headers` uses for a verifier's parameters, just now also
/// available to an ordinary source. An unresolvable `from` becomes
/// `SqlValue::Null` rather than an error: a script author who references a
/// parameter that isn't available (or a body sent with a GET, or a header
/// the caller didn't send) gets a null bound value, not a crash.
fn resolve_from(
    from: &str,
    headers: &HeaderMap,
    path_params: &HashMap<String, String>,
    query_params: &HashMap<String, String>,
    body: &Value,
    transaction_id: &str,
    resolved: ResolvedView<'_>,
) -> SqlValue {
    if let Some(name) = from.strip_prefix("path.") {
        return path_params.get(name).map(|v| SqlValue::Text(v.clone())).unwrap_or(SqlValue::Null);
    }
    if let Some(name) = from.strip_prefix("query.") {
        return query_params.get(name).map(|v| SqlValue::Text(v.clone())).unwrap_or(SqlValue::Null);
    }
    if let Some(name) = from.strip_prefix("header.") {
        return headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|v| SqlValue::Text(v.to_string()))
            .unwrap_or(SqlValue::Null);
    }
    if from == "context.transactionId" {
        return SqlValue::Text(transaction_id.to_string());
    }
    if from == "body" {
        return json_value_to_sql_value(body);
    }
    if let Some(path) = from.strip_prefix("body.") {
        return match walk_dot_path(body, path) {
            Some(value) => json_value_to_sql_value(value),
            None => SqlValue::Null,
        };
    }
    if let Some(rest) = from.strip_prefix("sources.") {
        let mut segments = rest.splitn(2, '.');
        let Some(source_name) = segments.next().filter(|s| !s.is_empty()) else {
            return SqlValue::Null;
        };
        // The nested-many bracket form (`"sources.<parent>[].<field>"`) — a
        // trailing `"[]"` on the source name is a per-row substitution
        // marker, not part of the real source name, so it's stripped before
        // lookup. `get_source` then resolves it against whichever row this
        // particular future is bound to (`ResolvedView::RowOverride`), or
        // the parent's whole array otherwise.
        let source_name = source_name.strip_suffix("[]").unwrap_or(source_name);
        let Some(value) = resolved.get_source(source_name) else {
            return SqlValue::Null;
        };
        return match segments.next() {
            Some(path) => match walk_dot_path(value, path) {
                Some(v) => json_value_to_sql_value(v),
                None => SqlValue::Null,
            },
            None => json_value_to_sql_value(value),
        };
    }
    SqlValue::Null
}

/// Walks a dot-separated path (`"owner.name"`) into a JSON value, one
/// segment at a time — shared by `body.*`/`sources.*` parameter binding and
/// (via `lookup`) `response` field mapping, all three of which support
/// arbitrary-depth nesting.
fn walk_dot_path<'a>(mut current: &'a Value, path: &str) -> Option<&'a Value> {
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

/// General-purpose numeric clamping (design doc: "useful anywhere a
/// parameter is user-controlled, but the obvious safety net for `limit`
/// specifically") — a no-op, returning `value` completely untouched, unless
/// at least one of `default`/`min`/`max` is actually declared on this
/// parameter. Once any of them is set, the resolved value is reinterpreted
/// as a real integer (parsed from a path/query string, truncated from a
/// float, or `default`/`0` if it's missing/unparseable/`Null`) and clamped
/// into `[min, max]` — the clamped result always binds as `SqlValue::Int`,
/// a real number, not text, even though path/query params otherwise always
/// resolve as `SqlValue::Text` (see `resolve_from`).
fn clamp_numeric(value: SqlValue, default: Option<i64>, min: Option<i64>, max: Option<i64>) -> SqlValue {
    if default.is_none() && min.is_none() && max.is_none() {
        return value;
    }
    let mut n = match &value {
        SqlValue::Int(n) => *n,
        SqlValue::Float(f) => *f as i64,
        SqlValue::Text(s) => s.parse().unwrap_or(default.unwrap_or(0)),
        _ => default.unwrap_or(0),
    };
    if let Some(min) = min {
        n = n.max(min);
    }
    if let Some(max) = max {
        n = n.min(max);
    }
    SqlValue::Int(n)
}

/// Builds the JSON response body from resolved sources, per the endpoint's
/// `response` mapping — either the ordinary flat field map, or a top-level
/// array (see `ResponseShape`).
pub fn build_response(endpoint: &EndpointFile, resolved: &ResolvedSources) -> Value {
    match &endpoint.response {
        ResponseShape::Fields(fields) => build_fields(fields, resolved),
        ResponseShape::Array(array) => build_array(array, resolved),
        // A bare top-level `null` — an unmapped, no-response-schema stub.
        // In practice `_generated: true` already gates this at `501`
        // before response-building ever runs, but the empty object is the
        // honest answer if this were ever reached some other way.
        ResponseShape::Null => Value::Object(Map::new()),
    }
}

/// The ordinary case: each field is independently resolved against
/// `resolved` (every field's `from` is its own full `sources.<name>.<field>`
/// path) and formatted if it declares a `format`.
fn build_fields(fields: &HashMap<String, ResponseField>, resolved: &ResolvedSources) -> Value {
    let mut out = Map::new();
    for (field, mapping) in fields {
        out.insert(field.clone(), build_field(mapping, resolved));
    }
    Value::Object(out)
}

fn build_field(mapping: &ResponseField, resolved: &ResolvedSources) -> Value {
    match mapping {
        ResponseField::Array(array) => build_array(array, resolved),
        // An unmapped field (still `null`, as `frogs generate` leaves it in
        // a fresh stub) — nothing to look up, no `from` to have one.
        ResponseField::Null => Value::Null,
        ResponseField::Plain(_) | ResponseField::Detailed(_) => {
            let path = mapping.dot_path();
            // The original design doc's own bracket syntax
            // (`"sources.cars[].vin"`) — an ordinary field whose value is
            // an *array*, one entry per row of a `cardinality: "many"`
            // source, each entry being just that one field (not a whole
            // row object the way `array.source` + `items` builds). A
            // distinct capability from `array.source`, not just alternate
            // syntax for it — this is how you get a bare array of scalars
            // as one field among others without writing a full `items` map.
            if let Some((source_name, field_path)) = parse_bracket_array_path(path) {
                return build_bracket_array(source_name, field_path, mapping.detail(), resolved);
            }
            let value = lookup(path, resolved);
            match mapping.detail() {
                Some(detail) => super::format::apply(value, detail),
                None => value,
            }
        }
    }
}

/// Splits `"sources.<name>[].<field...>"` into `(name, field...)` — `None`
/// for anything else, including a bare `"sources.<name>"` (no brackets at
/// all, that's `lookup`'s ordinary job) or `"sources.<name>[]"` with
/// nothing after it (a bracket path always names a field to extract per
/// row; if you want the whole row, use `array.source` + `items` instead).
/// `pub(crate)`, not private — also the parsing `validate_nested_many`
/// (`endpoint::mod`) and `nested_many_parent` below use to find a nested-many
/// source's own bracket-form parameters, not just `response` field mapping.
pub(crate) fn parse_bracket_array_path(from: &str) -> Option<(&str, &str)> {
    let rest = from.strip_prefix("sources.")?;
    let (name, field_path) = rest.split_once("[].")?;
    (!name.is_empty() && !field_path.is_empty()).then_some((name, field_path))
}

/// The exactly-one bracket-form parent a nested-many source's own
/// `parameters` must reference (`"sources.<parent>[].<field>"`) — shared by
/// `validate_nested_many` (startup-time), `resolve_nested_many` (request-
/// time), and `commands::test::record`'s post-loop mock-capture pass, so
/// "find the one bracket-parent" isn't reimplemented three times. `Err`
/// describes zero or more-than-one distinct parent referenced.
pub(crate) fn nested_many_parent(parameters: &[Parameter]) -> Result<&str, String> {
    let mut parents: Vec<&str> = Vec::new();
    for param in parameters {
        if let Some((parent, _field)) = parse_bracket_array_path(&param.from)
            && !parents.contains(&parent)
        {
            parents.push(parent);
        }
    }
    match parents.as_slice() {
        [] => Err("no bracket-form parameter (\"sources.<parent>[].<field>\") found — allowNestedMany requires exactly one".to_string()),
        [only] => Ok(*only),
        many => Err(format!(
            "references {} distinct bracket-form parents ({}) — a nested-many source may depend on exactly one",
            many.len(),
            many.join(", ")
        )),
    }
}

/// Builds the array `parse_bracket_array_path` describes: `source_name`
/// must resolve to a real array (same "not actually an array -> empty
/// list, not an error" posture as `build_array`), and each row contributes
/// exactly one value — `field_path` walked into that row (arbitrary depth,
/// via `walk_dot_path`, same as any other nested field), formatted with
/// `detail` if given, applied per-element rather than to the array as a whole.
fn build_bracket_array(source_name: &str, field_path: &str, detail: Option<&DetailedField>, resolved: &ResolvedSources) -> Value {
    let Some(Some(Value::Array(rows))) = resolved.get(source_name) else {
        return Value::Array(Vec::new());
    };
    Value::Array(
        rows.iter()
            .map(|row| {
                let value = walk_dot_path(row, field_path).cloned().unwrap_or(Value::Null);
                match detail {
                    Some(detail) => super::format::apply(value, detail),
                    None => value,
                }
            })
            .collect(),
    )
}

/// `array.source` names a `cardinality: "many"` source's *whole* resolved
/// value (e.g. `"sources.books"` — not `sources.books.<field>`, since there
/// is no single object to pull one field from). Each row in that array gets
/// `array.items` applied against it independently, producing one output
/// object per row — a source that isn't actually an array (never resolved,
/// optional-and-failed, or a `cardinality: "one"` source used here by
/// mistake) yields an empty list rather than an error, matching this
/// project's general "a missing value renders as absent, not a crash"
/// posture for response assembly.
fn build_array(array: &ArrayResponse, resolved: &ResolvedSources) -> Value {
    let Value::Array(rows) = lookup_source(&array.source, resolved) else {
        return Value::Array(Vec::new());
    };
    Value::Array(rows.iter().map(|row| build_fields_against_row(&array.items, row)).collect())
}

/// `items`' own field paths are bare column names, not
/// `sources.<name>.<field>` — `array.source` already established which
/// row-shaped value they're read from, so each field is looked up directly
/// against that one row (dot-separated for a nested field, same traversal
/// `resolve_from`'s `body.*` handling already uses).
fn build_fields_against_row(fields: &HashMap<String, ResponseField>, row: &Value) -> Value {
    let mut out = Map::new();
    for (field, mapping) in fields {
        out.insert(field.clone(), build_field_against_row(mapping, row));
    }
    Value::Object(out)
}

fn build_field_against_row(mapping: &ResponseField, row: &Value) -> Value {
    match mapping {
        // Many-depends-on-many fan-out isn't supported yet — same scope
        // boundary as HTTP `cardinality: "many"` (see `run_http_source`).
        ResponseField::Array(_) => Value::Null,
        ResponseField::Null => Value::Null,
        ResponseField::Plain(path) => lookup_in_row(path, row),
        ResponseField::Detailed(detail) => super::format::apply(lookup_in_row(&detail.from, row), detail),
    }
}

fn lookup_in_row(path: &str, row: &Value) -> Value {
    let mut current = row;
    for segment in path.split('.') {
        match current.get(segment) {
            Some(next) => current = next,
            None => return Value::Null,
        }
    }
    current.clone()
}

/// `"sources.<name>.<field>"` reads one field, and — unlike the original 3-
/// segment-only implementation — `"sources.<name>.<field>.<nested>..."`
/// walks arbitrarily deep into that field's own value too, the same way
/// `resolve_from`'s `body.*`/`sources.*` parameter binding already does via
/// `walk_dot_path`. A path with nothing after the source name (`"sources.car"`
/// with no field at all) is null here — that's `lookup_source`'s job, not
/// this function's.
fn lookup(from: &str, resolved: &ResolvedSources) -> Value {
    let Some(rest) = from.strip_prefix("sources.") else {
        return Value::Null;
    };
    let mut parts = rest.splitn(2, '.');
    let Some(source_name) = parts.next().filter(|s| !s.is_empty()) else {
        return Value::Null;
    };
    let Some(field_path) = parts.next() else {
        return Value::Null;
    };

    match resolved.get(source_name) {
        Some(Some(value)) => walk_dot_path(value, field_path).cloned().unwrap_or(Value::Null),
        _ => Value::Null,
    }
}

/// Like `lookup`, but returns a source's *entire* resolved value —
/// `array.source` is `"sources.<name>"`, exactly two parts, unlike a scalar
/// field's `"sources.<name>.<field>"`.
fn lookup_source(from: &str, resolved: &ResolvedSources) -> Value {
    let mut parts = from.split('.');
    let (Some("sources"), Some(source_name), None) = (parts.next(), parts.next(), parts.next()) else {
        return Value::Null;
    };

    match resolved.get(source_name) {
        Some(Some(value)) => value.clone(),
        _ => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql::SqlError;
    use std::path::PathBuf;

    #[test]
    fn a_fail_object_parses_as_a_fail_mock() {
        let mock: MockOutcome = serde_json::from_str(r#"{ "fail": "datasource.sql.not_found" }"#).unwrap();
        assert_eq!(mock, MockOutcome::Fail("datasource.sql.not_found".to_string()));
    }

    #[test]
    fn a_success_object_with_other_fields_alongside_fail_is_not_reinterpreted() {
        let mock: MockOutcome = serde_json::from_str(r#"{ "fail": "not a code", "other": 1 }"#).unwrap();
        assert_eq!(mock, MockOutcome::Success(serde_json::json!({ "fail": "not a code", "other": 1 })));
    }

    /// A fake `SqlDriver` so these tests exercise the resolution logic
    /// (cardinality, optional-failure-to-null, response mapping) without a
    /// real Postgres instance — the same "swap what a source returns, not
    /// how it runs" principle the design doc's own testing section
    /// describes for the eventual `.test.json` mock runner.
    #[derive(Debug)]
    struct FakeDriver {
        rows: Vec<HashMap<String, SqlValue>>,
        fail: bool,
    }

    #[async_trait::async_trait]
    impl SqlDriver for FakeDriver {
        async fn query(&self, _script: &str, _params: &HashMap<String, SqlValue>) -> Result<Vec<HashMap<String, SqlValue>>, SqlError> {
            if self.fail {
                Err(SqlError::QueryFailed("simulated failure".to_string()))
            } else {
                Ok(self.rows.clone())
            }
        }
    }

    fn row(pairs: &[(&str, SqlValue)]) -> HashMap<String, SqlValue> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
    }

    /// `run_sql_source`/`run_http_source` read their config from disk before
    /// doing anything else — this scratch dir gives both a real place to
    /// read from: `db/q.sql` for the fake driver's tests (which ignore the
    /// script's *contents* but still need the file to exist), `http/` is
    /// created for parity even though most tests here don't use it.
    fn temp_project_root() -> PathBuf {
        // A nanosecond timestamp alone isn't a reliable uniqueness source on
        // every platform's clock resolution, and this module's test count
        // (several sharing the same relative "http/pricing.json" fixture
        // filename) makes a same-instant collision between two parallel
        // tokio test threads a real, if rare, flake risk — an atomic
        // counter guarantees uniqueness regardless of clock granularity.
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "frogs-resolve-test-{}-{}-{unique}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(root.join("db")).unwrap();
        std::fs::create_dir_all(root.join("http")).unwrap();
        std::fs::write(root.join("db/q.sql"), "SELECT 1;").unwrap();
        root
    }

    fn endpoint_with_one_sql_source(name: &str, optional: bool) -> EndpointFile {
        let json = format!(
            r#"{{
                "operationId": "test",
                "sources": {{
                    "{name}": {{
                        "type": "sql",
                        "connection": "db",
                        "script": "q.sql",
                        "cardinality": "one",
                        "onError": 500,
                        "optional": {optional},
                        "parameters": [{{ "name": "vin", "from": "path.vin" }}]
                    }}
                }},
                "response": {{ "vin": "sources.{name}.vin" }}
            }}"#
        );
        serde_json::from_str(&json).unwrap()
    }

    #[tokio::test]
    async fn resolves_a_row_and_maps_it_into_the_response() {
        let endpoint = endpoint_with_one_sql_source("car", false);
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert(
            "db".to_string(),
            Box::new(FakeDriver {
                rows: vec![row(&[("vin", SqlValue::Text("1HGCM82633A004352".to_string()))])],
                fail: false,
            }),
        );

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let path_params = HashMap::from([("vin".to_string(), "1HGCM82633A004352".to_string())]);
        let resolved = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &path_params,
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect("non-optional source with a row should resolve");

        let body = build_response(&endpoint, &resolved);
        assert_eq!(body["vin"], "1HGCM82633A004352");
    }

    /// A bare `null` response field (`ResponseField::Null`) renders as
    /// `null` in the built response — no `from` to look up, nothing to
    /// format. Distinct from the `_generated: true` 501 gate (`endpoint::
    /// tests`) — this is the ordinary response-building behavior for a
    /// field that's still unmapped regardless of why.
    #[tokio::test]
    async fn a_null_response_field_renders_as_null() {
        let json = r#"{
            "operationId": "test",
            "sources": {},
            "response": { "maker": "sources.car.maker", "year": null }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        let resolved = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect("an endpoint with no sources at all should resolve trivially");

        let body = build_response(&endpoint, &resolved);
        assert_eq!(body["maker"], Value::Null, "an unresolvable dot-path is null too, for a different reason");
        assert_eq!(body["year"], Value::Null, "a bare null field is null because there's nothing mapped at all");
    }

    /// The other half of the same class of stub: `ResponseShape::Null`
    /// (the whole `response` key is a bare JSON `null`, not an object of
    /// null fields) — `_generated: true` already gates this at `501`
    /// before response-building ever runs in practice, but this is the
    /// honest fallback if it were ever reached, and proves the new variant
    /// doesn't panic `build_response`'s match.
    #[tokio::test]
    async fn a_bare_null_top_level_response_renders_as_an_empty_object() {
        let json = r#"{ "operationId": "ping", "sources": {}, "response": null }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        let resolved = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect("an endpoint with no sources at all should resolve trivially");

        let body = build_response(&endpoint, &resolved);
        assert_eq!(body, serde_json::json!({}));
    }

    #[test]
    fn lookup_still_resolves_the_ordinary_3_segment_case() {
        let mut resolved: ResolvedSources = HashMap::new();
        resolved.insert("car".to_string(), Some(serde_json::json!({ "vin": "AAA" })));
        assert_eq!(lookup("sources.car.vin", &resolved), Value::String("AAA".to_string()));
    }

    #[test]
    fn lookup_now_walks_arbitrarily_deep_past_the_first_field() {
        let mut resolved: ResolvedSources = HashMap::new();
        resolved.insert("car".to_string(), Some(serde_json::json!({ "owner": { "name": "Alex" } })));
        assert_eq!(
            lookup("sources.car.owner.name", &resolved),
            Value::String("Alex".to_string()),
            "must resolve owner.name, not stop at the whole owner object"
        );
    }

    #[test]
    fn lookup_walks_even_deeper_than_two_levels() {
        let mut resolved: ResolvedSources = HashMap::new();
        resolved.insert("car".to_string(), Some(serde_json::json!({ "owner": { "address": { "city": "Springfield" } } })));
        assert_eq!(lookup("sources.car.owner.address.city", &resolved), Value::String("Springfield".to_string()));
    }

    #[test]
    fn lookup_a_missing_nested_field_is_null_not_a_crash() {
        let mut resolved: ResolvedSources = HashMap::new();
        resolved.insert("car".to_string(), Some(serde_json::json!({ "owner": { "name": "Alex" } })));
        assert_eq!(lookup("sources.car.owner.doesNotExist", &resolved), Value::Null);
    }

    /// The gap end to end: a real HTTP source's genuinely nested JSON
    /// response, mapped via a 4-segment `response` dot-path — not just the
    /// `lookup` unit tests above, through the full `resolve_sources` +
    /// `build_response` pipeline.
    #[tokio::test]
    async fn a_response_field_can_map_an_arbitrarily_nested_source_value() {
        use axum::routing::get;
        use axum::{Json, Router};

        let app = Router::new().route("/car", get(|| async { Json(serde_json::json!({ "owner": { "name": "Alex" } })) }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let root = temp_project_root();
        std::fs::write(root.join("http/car.json"), format!(r#"{{ "method": "GET", "url": "http://{addr}/car" }}"#)).unwrap();

        let json = r#"{
            "operationId": "test",
            "sources": { "car": { "type": "http", "request": "car.json" } },
            "response": { "ownerName": "sources.car.owner.name" }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        let client = reqwest::Client::new();
        let resolved = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect("the http source should resolve");

        let body = build_response(&endpoint, &resolved);
        assert_eq!(
            body["ownerName"], "Alex",
            "a 4-segment dot-path should reach owner.name, not stop at the whole owner object"
        );
    }

    #[tokio::test]
    async fn optional_source_failure_becomes_null_not_an_error() {
        let endpoint = endpoint_with_one_sql_source("pricing", true);
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(FakeDriver { rows: vec![], fail: true }));

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let resolved = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect("an optional source's failure must not fail the whole request");

        let body = build_response(&endpoint, &resolved);
        assert_eq!(body["vin"], Value::Null);
    }

    #[tokio::test]
    async fn non_optional_source_failure_returns_its_on_error_status() {
        let endpoint = endpoint_with_one_sql_source("car", false);
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(FakeDriver { rows: vec![], fail: true }));

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let failure = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect_err("a non-optional source's failure must fail the request");

        assert_eq!(failure.on_error, Some(500));
        assert_eq!(failure.source_name, "car");
        assert_eq!(failure.cause.code(), "datasource.sql.query_failed");
    }

    #[tokio::test]
    async fn omitted_on_error_carries_through_as_none() {
        let json = r#"{
            "operationId": "test",
            "sources": {
                "car": {
                    "type": "sql",
                    "connection": "db",
                    "script": "q.sql",
                    "parameters": [{ "name": "vin", "from": "path.vin" }]
                }
            },
            "response": { "vin": "sources.car.vin" }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();

        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(FakeDriver { rows: vec![], fail: true }));

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let failure = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect_err("a non-optional source's failure must fail the request");

        assert_eq!(failure.on_error, None);
    }

    #[tokio::test]
    async fn cardinality_one_with_no_rows_is_treated_as_a_failure() {
        let endpoint = endpoint_with_one_sql_source("car", false);
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(FakeDriver { rows: vec![], fail: false }));

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let failure = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect_err("zero rows for cardinality 'one' should be treated as not found");

        assert_eq!(failure.source_name, "car");
        assert_eq!(failure.cause.code(), "datasource.sql.not_found");
    }

    /// A real HTTP source, executed against a real local server, wired all
    /// the way through `resolve_sources` and the `sources.pricing.amount`
    /// dot-path lookup — not just `http::execute` in isolation.
    #[tokio::test]
    async fn resolves_a_real_http_source_and_maps_it_into_the_response() {
        use axum::routing::get;
        use axum::{Json, Router};

        let app = Router::new().route("/price", get(|| async { Json(serde_json::json!({ "amount": 24500, "currency": "USD" })) }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let root = temp_project_root();
        std::fs::write(root.join("http/pricing.json"), format!(r#"{{ "method": "GET", "url": "http://{addr}/price" }}"#)).unwrap();

        let json = r#"{
            "operationId": "test",
            "sources": {
                "pricing": {
                    "type": "http",
                    "request": "pricing.json",
                    "onError": 502,
                    "optional": false
                }
            },
            "response": { "price": "sources.pricing.amount" }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();

        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        let client = reqwest::Client::new();
        let resolved = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect("the real HTTP source should resolve");

        let body = build_response(&endpoint, &resolved);
        assert_eq!(body["price"], 24500);
    }

    /// The service registry (`config/services.json`): a `url` template can
    /// reference a logical name — `{{services.pricing}}` — instead of a
    /// hardcoded base URL, resolved through the exact same `{{name}}`
    /// substitution every other parameter already goes through (see
    /// `run_http_source`'s doc comment for why no new template syntax was
    /// needed for this).
    #[tokio::test]
    async fn a_url_can_reference_the_service_registry_by_name() {
        use axum::routing::get;
        use axum::{Json, Router};

        let app = Router::new().route("/price", get(|| async { Json(serde_json::json!({ "amount": 24500, "currency": "USD" })) }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let root = temp_project_root();
        std::fs::write(root.join("http/pricing.json"), r#"{ "method": "GET", "url": "{{services.pricing}}/price" }"#).unwrap();

        let json = r#"{
            "operationId": "test",
            "sources": {
                "pricing": {
                    "type": "http",
                    "request": "pricing.json",
                    "onError": 502,
                    "optional": false
                }
            },
            "response": { "price": "sources.pricing.amount" }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();

        let mut services = HashMap::new();
        services.insert("pricing".to_string(), format!("http://{addr}"));

        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        let client = reqwest::Client::new();
        let resolved = resolve_sources(
            &endpoint,
            &services,
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect("the registry-resolved URL should reach the real server");

        let body = build_response(&endpoint, &resolved);
        assert_eq!(body["price"], 24500);
    }

    /// An empty/absent service registry (the default, and what every project
    /// with `serviceRegistry` off always gets) leaves `{{services.<name>}}`
    /// unresolved — the same "unresolvable placeholder becomes an empty
    /// string" behavior every other `{{name}}` template already has, not a
    /// distinct failure mode.
    #[tokio::test]
    async fn a_services_reference_with_no_matching_registry_entry_resolves_to_an_empty_string() {
        use axum::routing::get;
        use axum::{Json, Router};

        // If `{{services.pricing}}` resolved to anything other than an empty
        // string, the request would land on some other path than exactly
        // `/price` and this handler would never be hit at all.
        let app = Router::new().route("/price", get(|| async { Json(serde_json::json!({ "seen": true })) }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let root = temp_project_root();
        // No `{{services.pricing}}` entry in the (empty) registry below, so
        // it resolves to "" — the request lands on this same server anyway,
        // just at `/price` instead of `http://elsewhere/price`, proving the
        // placeholder didn't panic or error, only came up empty.
        std::fs::write(
            root.join("http/pricing.json"),
            format!(r#"{{ "method": "GET", "url": "http://{addr}{{{{services.pricing}}}}/price" }}"#),
        )
        .unwrap();

        let json = r#"{
            "operationId": "test",
            "sources": {
                "pricing": {
                    "type": "http",
                    "request": "pricing.json",
                    "onError": 502,
                    "optional": false
                }
            },
            "response": { "seen": "sources.pricing.seen" }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();

        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        let client = reqwest::Client::new();
        let resolved = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect("an empty-but-present placeholder should still resolve, not fail");

        let body = build_response(&endpoint, &resolved);
        assert_eq!(body["seen"], true);
    }

    #[tokio::test]
    async fn sql_cardinality_many_resolves_to_an_array_of_rows() {
        let json = r#"{
            "operationId": "test",
            "sources": {
                "cars": { "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "many" }
            },
            "response": {}
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert(
            "db".to_string(),
            Box::new(FakeDriver {
                rows: vec![row(&[("vin", SqlValue::Text("AAA".to_string()))]), row(&[("vin", SqlValue::Text("BBB".to_string()))])],
                fail: false,
            }),
        );

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let resolved = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect("a many-cardinality source with rows should resolve");

        let Some(Value::Array(rows)) = resolved.get("cars").cloned().flatten() else {
            panic!("expected sources.cars to resolve to a JSON array");
        };
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["vin"], "AAA");
        assert_eq!(rows[1]["vin"], "BBB");
    }

    #[tokio::test]
    async fn sql_cardinality_many_with_zero_rows_is_an_empty_array_not_an_error() {
        let json = r#"{
            "operationId": "test",
            "sources": {
                "cars": { "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "many" }
            },
            "response": {}
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(FakeDriver { rows: vec![], fail: false }));

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let resolved = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect("zero rows is a valid result for a list, not a failure");

        assert_eq!(resolved.get("cars").cloned().flatten(), Some(Value::Array(Vec::new())));
    }

    #[tokio::test]
    async fn build_response_maps_a_many_source_into_a_top_level_array() {
        let json = r#"{
            "operationId": "test",
            "sources": {
                "cars": { "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "many" }
            },
            "response": {
                "type": "array",
                "source": "sources.cars",
                "items": { "vin": "vin", "year": { "from": "year", "format": "integer" } }
            }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert(
            "db".to_string(),
            Box::new(FakeDriver {
                rows: vec![row(&[("vin", SqlValue::Text("AAA".to_string())), ("year", SqlValue::Int(2020))])],
                fail: false,
            }),
        );

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let resolved = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .unwrap();

        let body = build_response(&endpoint, &resolved);
        assert_eq!(body, serde_json::json!([{ "vin": "AAA", "year": 2020 }]));
    }

    #[tokio::test]
    async fn build_response_maps_a_many_source_into_a_nested_array_field() {
        let json = r#"{
            "operationId": "test",
            "sources": {
                "cars": { "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "many" }
            },
            "response": {
                "items": {
                    "type": "array",
                    "source": "sources.cars",
                    "items": { "vin": "vin" }
                },
                "total": "sources.cars.doesNotExist"
            }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert(
            "db".to_string(),
            Box::new(FakeDriver {
                rows: vec![row(&[("vin", SqlValue::Text("AAA".to_string()))]), row(&[("vin", SqlValue::Text("BBB".to_string()))])],
                fail: false,
            }),
        );

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let resolved = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .unwrap();

        let body = build_response(&endpoint, &resolved);
        assert_eq!(body["items"], serde_json::json!([{ "vin": "AAA" }, { "vin": "BBB" }]));
        // `sources.cars` is an array, not an object with a `doesNotExist`
        // field — a mismatched lookup renders as null, same "absent, not a
        // crash" posture as every other unresolved response field.
        assert_eq!(body["total"], Value::Null);
    }

    #[tokio::test]
    async fn a_source_that_is_not_actually_an_array_yields_an_empty_list() {
        let endpoint = endpoint_with_one_sql_source("car", false);
        let mut endpoint = endpoint;
        endpoint.response = serde_json::from_str(r#"{ "type": "array", "source": "sources.car", "items": {} }"#).unwrap();

        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert(
            "db".to_string(),
            Box::new(FakeDriver {
                rows: vec![row(&[("vin", SqlValue::Text("AAA".to_string()))])],
                fail: false,
            }),
        );

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let path_params = HashMap::from([("vin".to_string(), "AAA".to_string())]);
        let resolved = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &path_params,
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .unwrap();

        let body = build_response(&endpoint, &resolved);
        assert_eq!(body, serde_json::json!([]));
    }

    #[test]
    fn parse_bracket_array_path_extracts_source_and_field() {
        assert_eq!(parse_bracket_array_path("sources.cars[].vin"), Some(("cars", "vin")));
        assert_eq!(
            parse_bracket_array_path("sources.cars[].owner.name"),
            Some(("cars", "owner.name")),
            "the field half can itself be nested"
        );
    }

    #[test]
    fn parse_bracket_array_path_rejects_non_bracket_forms() {
        assert_eq!(parse_bracket_array_path("sources.cars.vin"), None, "no brackets at all — lookup's ordinary job");
        assert_eq!(parse_bracket_array_path("sources.cars[]"), None, "brackets with nothing after them");
        assert_eq!(parse_bracket_array_path("not.even.sources"), None);
    }

    /// The design doc's own literal example syntax: a plain array-of-
    /// scalars field, distinct from `array.source` + `items` (which builds
    /// an array of *objects*, one per row) — this builds an array of just
    /// one field, as one field among others in an ordinary object response.
    #[tokio::test]
    async fn a_bracket_path_field_produces_an_array_of_one_field_per_row() {
        let json = r#"{
            "operationId": "test",
            "sources": {
                "cars": { "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "many" }
            },
            "response": { "vins": "sources.cars[].vin" }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert(
            "db".to_string(),
            Box::new(FakeDriver {
                rows: vec![row(&[("vin", SqlValue::Text("AAA".to_string()))]), row(&[("vin", SqlValue::Text("BBB".to_string()))])],
                fail: false,
            }),
        );

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let resolved = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .unwrap();

        let body = build_response(&endpoint, &resolved);
        assert_eq!(body["vins"], serde_json::json!(["AAA", "BBB"]));
    }

    #[tokio::test]
    async fn a_bracket_path_field_can_use_the_detailed_object_form_with_formatting() {
        let json = r#"{
            "operationId": "test",
            "sources": {
                "cars": { "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "many" }
            },
            "response": { "years": { "from": "sources.cars[].year", "format": "integer" } }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert(
            "db".to_string(),
            Box::new(FakeDriver {
                rows: vec![row(&[("year", SqlValue::Float(2003.0))]), row(&[("year", SqlValue::Float(2010.0))])],
                fail: false,
            }),
        );

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let resolved = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .unwrap();

        let body = build_response(&endpoint, &resolved);
        assert_eq!(
            body["years"],
            serde_json::json!([2003, 2010]),
            "format: integer should apply per-element, not to the array as a whole"
        );
    }

    #[tokio::test]
    async fn a_bracket_path_field_can_reach_a_nested_field_per_row() {
        use axum::routing::get;
        use axum::{Json, Router};

        let app = Router::new().route(
            "/cars",
            get(|| async { Json(serde_json::json!([{ "owner": { "name": "Alex" } }, { "owner": { "name": "Sam" } }])) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let root = temp_project_root();
        std::fs::write(root.join("http/cars.json"), format!(r#"{{ "method": "GET", "url": "http://{addr}/cars" }}"#)).unwrap();

        let json = r#"{
            "operationId": "test",
            "sources": {
                "cars": { "type": "http", "request": "cars.json", "cardinality": "many" }
            },
            "response": { "ownerNames": "sources.cars[].owner.name" }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        let client = reqwest::Client::new();
        let resolved = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .unwrap();

        let body = build_response(&endpoint, &resolved);
        assert_eq!(
            body["ownerNames"],
            serde_json::json!(["Alex", "Sam"]),
            "the field half of a bracket path should walk arbitrarily deep too"
        );
    }

    #[tokio::test]
    async fn a_bracket_path_referencing_a_non_array_source_yields_an_empty_list() {
        let endpoint = endpoint_with_one_sql_source("car", false);
        let mut endpoint = endpoint;
        endpoint.response = serde_json::from_str(r#"{ "vins": "sources.car[].vin" }"#).unwrap();

        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert(
            "db".to_string(),
            Box::new(FakeDriver {
                rows: vec![row(&[("vin", SqlValue::Text("AAA".to_string()))])],
                fail: false,
            }),
        );

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let path_params = HashMap::from([("vin".to_string(), "AAA".to_string())]);
        let resolved = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &path_params,
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .unwrap();

        let body = build_response(&endpoint, &resolved);
        assert_eq!(
            body["vins"],
            serde_json::json!([]),
            "sources.car is cardinality: one, not an array — must degrade to empty, not error or panic"
        );
    }

    #[tokio::test]
    async fn http_cardinality_many_resolves_a_real_json_array_response() {
        use axum::routing::get;
        use axum::{Json, Router};

        let app = Router::new().route("/cars", get(|| async { Json(serde_json::json!([{ "vin": "AAA" }, { "vin": "BBB" }])) }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let root = temp_project_root();
        std::fs::write(root.join("http/cars.json"), format!(r#"{{ "method": "GET", "url": "http://{addr}/cars" }}"#)).unwrap();

        let json = r#"{
            "operationId": "test",
            "sources": {
                "cars": { "type": "http", "request": "cars.json", "cardinality": "many" }
            },
            "response": { "type": "array", "source": "sources.cars", "items": { "vin": "vin" } }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();

        let client = reqwest::Client::new();
        let resolved = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect("a real JSON array response should resolve for cardinality: many");

        let body = build_response(&endpoint, &resolved);
        assert_eq!(body, serde_json::json!([{ "vin": "AAA" }, { "vin": "BBB" }]));
    }

    /// `responsePath` unwraps an enveloped array the same way it already
    /// unwraps a `cardinality: "one"` object — no separate config knob for
    /// "where does the array live in the response."
    #[tokio::test]
    async fn http_cardinality_many_unwraps_an_array_nested_via_response_path() {
        use axum::routing::get;
        use axum::{Json, Router};

        let app = Router::new().route(
            "/cars",
            get(|| async { Json(serde_json::json!({ "data": { "items": [{ "vin": "AAA" }] }, "total": 1 })) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let root = temp_project_root();
        std::fs::write(
            root.join("http/cars.json"),
            format!(r#"{{ "method": "GET", "url": "http://{addr}/cars", "responsePath": "data.items" }}"#),
        )
        .unwrap();

        let json = r#"{
            "operationId": "test",
            "sources": {
                "cars": { "type": "http", "request": "cars.json", "cardinality": "many" }
            },
            "response": { "type": "array", "source": "sources.cars", "items": { "vin": "vin" } }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();

        let client = reqwest::Client::new();
        let resolved = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect("responsePath should unwrap the envelope before the array check runs");

        let body = build_response(&endpoint, &resolved);
        assert_eq!(body, serde_json::json!([{ "vin": "AAA" }]));
    }

    #[tokio::test]
    async fn http_cardinality_many_with_a_non_array_response_is_a_clear_failure() {
        use axum::routing::get;
        use axum::{Json, Router};

        let app = Router::new().route("/cars", get(|| async { Json(serde_json::json!({ "not": "an array" })) }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let root = temp_project_root();
        std::fs::write(root.join("http/cars.json"), format!(r#"{{ "method": "GET", "url": "http://{addr}/cars" }}"#)).unwrap();

        let json = r#"{
            "operationId": "test",
            "sources": {
                "cars": { "type": "http", "request": "cars.json", "cardinality": "many", "onError": 502 }
            },
            "response": {}
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();

        let client = reqwest::Client::new();
        let failure = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect_err("a non-array response for cardinality: many must fail clearly, not silently coerce or empty out");

        assert_eq!(failure.cause.code(), "datasource.http.upstream_error");
        assert_eq!(failure.on_error, Some(502));
    }

    #[tokio::test]
    async fn referencing_an_unknown_connection_name_is_a_config_failure() {
        let endpoint = endpoint_with_one_sql_source("car", false);
        // No "db" connection registered at all — a typo'd or removed entry
        // in connections.json, distinct from the driver itself failing.
        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let failure = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect_err("a source referencing a connection that isn't configured must fail clearly");

        assert_eq!(failure.source_name, "car");
        assert_eq!(failure.cause.code(), "unexpected.error");
    }

    #[tokio::test]
    async fn a_missing_sql_script_file_is_a_config_failure() {
        let json = r#"{
            "operationId": "test",
            "sources": {
                "car": { "type": "sql", "connection": "db", "script": "does_not_exist.sql" }
            },
            "response": {}
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(FakeDriver { rows: vec![], fail: false }));

        let root = temp_project_root(); // only creates db/q.sql, not does_not_exist.sql
        let client = reqwest::Client::new();
        let failure = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect_err("a script file that isn't on disk must fail before ever reaching the driver");

        assert_eq!(failure.cause.code(), "unexpected.error");
    }

    #[tokio::test]
    async fn a_failing_non_optional_http_source_fails_the_whole_request() {
        use axum::routing::get;
        use axum::{Json, Router};

        let app = Router::new().route(
            "/price",
            get(|| async { (axum::http::StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({}))) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let root = temp_project_root();
        std::fs::write(root.join("http/pricing.json"), format!(r#"{{ "method": "GET", "url": "http://{addr}/price" }}"#)).unwrap();

        let json = r#"{
            "operationId": "test",
            "sources": {
                "pricing": { "type": "http", "request": "pricing.json", "onError": 502, "optional": false }
            },
            "response": { "price": "sources.pricing.amount" }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();

        let root_http = root.join("http");
        let client = reqwest::Client::new();
        let failure = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root_http,
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect_err("a non-optional http source returning a server error must fail the request");

        assert_eq!(failure.on_error, Some(502));
        assert_eq!(failure.cause.code(), "datasource.http.upstream_error");
    }

    /// Mirrors `cars-demo`'s real shape: a `sql` source and an `http` source
    /// resolving side by side (not chained — parameter chaining isn't wired
    /// up yet, see the module doc comment) and both landing in one response.
    #[tokio::test]
    async fn a_sql_source_and_an_http_source_together_both_populate_the_response() {
        use axum::routing::get;
        use axum::{Json, Router};

        let app = Router::new().route("/price", get(|| async { Json(serde_json::json!({ "amount": 24500, "currency": "USD" })) }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let root = temp_project_root();
        std::fs::write(root.join("http/pricing.json"), format!(r#"{{ "method": "GET", "url": "http://{addr}/price" }}"#)).unwrap();

        let json = r#"{
            "operationId": "getCarByVin",
            "sources": {
                "car": {
                    "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "one",
                    "parameters": [{ "name": "vin", "from": "path.vin" }]
                },
                "pricing": {
                    "type": "http", "request": "pricing.json", "optional": true
                }
            },
            "response": {
                "vin": "sources.car.vin",
                "maker": "sources.car.maker",
                "price": "sources.pricing.amount",
                "currency": "sources.pricing.currency"
            }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();

        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert(
            "db".to_string(),
            Box::new(FakeDriver {
                rows: vec![row(&[
                    ("vin", SqlValue::Text("1HGCM82633A004352".to_string())),
                    ("maker", SqlValue::Text("Honda".to_string())),
                ])],
                fail: false,
            }),
        );

        let path_params = HashMap::from([("vin".to_string(), "1HGCM82633A004352".to_string())]);
        let client = reqwest::Client::new();
        let resolved = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &path_params,
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect("both sources should resolve independently");

        let body = build_response(&endpoint, &resolved);
        assert_eq!(body["vin"], "1HGCM82633A004352");
        assert_eq!(body["maker"], "Honda");
        assert_eq!(body["price"], 24500);
        assert_eq!(body["currency"], "USD");
    }

    #[test]
    fn resolve_from_reads_a_top_level_body_field() {
        let body = serde_json::json!({ "maker": "Honda" });
        assert_eq!(
            resolve_from(
                "body.maker",
                &HeaderMap::new(),
                &HashMap::new(),
                &HashMap::new(),
                &body,
                "",
                ResolvedView::Map(&HashMap::new())
            ),
            SqlValue::Text("Honda".to_string())
        );
    }

    #[test]
    fn resolve_from_reads_a_nested_body_field() {
        let body = serde_json::json!({ "car": { "maker": "Honda" } });
        assert_eq!(
            resolve_from(
                "body.car.maker",
                &HeaderMap::new(),
                &HashMap::new(),
                &HashMap::new(),
                &body,
                "",
                ResolvedView::Map(&HashMap::new())
            ),
            SqlValue::Text("Honda".to_string())
        );
    }

    #[test]
    fn resolve_from_a_missing_body_field_is_null_not_an_error() {
        let body = serde_json::json!({ "maker": "Honda" });
        assert_eq!(
            resolve_from(
                "body.model",
                &HeaderMap::new(),
                &HashMap::new(),
                &HashMap::new(),
                &body,
                "",
                ResolvedView::Map(&HashMap::new())
            ),
            SqlValue::Null
        );
    }

    #[test]
    fn resolve_from_bare_body_binds_the_whole_value_json_encoded() {
        let body = serde_json::json!({ "maker": "Honda" });
        assert_eq!(
            resolve_from(
                "body",
                &HeaderMap::new(),
                &HashMap::new(),
                &HashMap::new(),
                &body,
                "",
                ResolvedView::Map(&HashMap::new())
            ),
            SqlValue::Text(r#"{"maker":"Honda"}"#.to_string())
        );
    }

    #[test]
    fn resolve_from_bare_body_as_a_scalar_binds_the_scalar_directly() {
        let body = serde_json::json!(42);
        assert_eq!(
            resolve_from(
                "body",
                &HeaderMap::new(),
                &HashMap::new(),
                &HashMap::new(),
                &body,
                "",
                ResolvedView::Map(&HashMap::new())
            ),
            SqlValue::Int(42)
        );
    }

    #[test]
    fn resolve_from_with_no_body_sent_is_null() {
        assert_eq!(
            resolve_from(
                "body.maker",
                &HeaderMap::new(),
                &HashMap::new(),
                &HashMap::new(),
                &Value::Null,
                "",
                ResolvedView::Map(&HashMap::new())
            ),
            SqlValue::Null
        );
    }

    #[test]
    fn resolve_from_binds_the_transaction_id() {
        assert_eq!(
            resolve_from(
                "context.transactionId",
                &HeaderMap::new(),
                &HashMap::new(),
                &HashMap::new(),
                &Value::Null,
                "txn-123",
                ResolvedView::Map(&HashMap::new())
            ),
            SqlValue::Text("txn-123".to_string())
        );
    }

    #[test]
    fn resolve_from_reads_a_header() {
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", "secret-123".parse().unwrap());
        assert_eq!(
            resolve_from(
                "header.X-Api-Key",
                &headers,
                &HashMap::new(),
                &HashMap::new(),
                &Value::Null,
                "",
                ResolvedView::Map(&HashMap::new())
            ),
            SqlValue::Text("secret-123".to_string())
        );
    }

    #[test]
    fn resolve_from_a_missing_header_is_null_not_a_crash() {
        assert_eq!(
            resolve_from(
                "header.X-Api-Key",
                &HeaderMap::new(),
                &HashMap::new(),
                &HashMap::new(),
                &Value::Null,
                "",
                ResolvedView::Map(&HashMap::new())
            ),
            SqlValue::Null
        );
    }

    #[test]
    fn resolve_from_reads_another_sources_whole_resolved_value_json_encoded() {
        let mut resolved: ResolvedSources = HashMap::new();
        resolved.insert("car".to_string(), Some(serde_json::json!({ "vin": "AAA" })));
        assert_eq!(
            resolve_from(
                "sources.car",
                &HeaderMap::new(),
                &HashMap::new(),
                &HashMap::new(),
                &Value::Null,
                "",
                ResolvedView::Map(&resolved)
            ),
            SqlValue::Text(r#"{"vin":"AAA"}"#.to_string())
        );
    }

    #[test]
    fn resolve_from_reads_a_field_out_of_another_sources_resolved_value() {
        let mut resolved: ResolvedSources = HashMap::new();
        resolved.insert("car".to_string(), Some(serde_json::json!({ "vin": "AAA" })));
        assert_eq!(
            resolve_from(
                "sources.car.vin",
                &HeaderMap::new(),
                &HashMap::new(),
                &HashMap::new(),
                &Value::Null,
                "",
                ResolvedView::Map(&resolved)
            ),
            SqlValue::Text("AAA".to_string())
        );
    }

    #[test]
    fn resolve_from_reads_an_arbitrarily_nested_field_out_of_another_source() {
        let mut resolved: ResolvedSources = HashMap::new();
        resolved.insert("car".to_string(), Some(serde_json::json!({ "owner": { "name": "Alex" } })));
        assert_eq!(
            resolve_from(
                "sources.car.owner.name",
                &HeaderMap::new(),
                &HashMap::new(),
                &HashMap::new(),
                &Value::Null,
                "",
                ResolvedView::Map(&resolved)
            ),
            SqlValue::Text("Alex".to_string())
        );
    }

    #[test]
    fn resolve_from_a_source_that_failed_optionally_is_null_not_a_crash() {
        let mut resolved: ResolvedSources = HashMap::new();
        resolved.insert("pricing".to_string(), None);
        assert_eq!(
            resolve_from(
                "sources.pricing.amount",
                &HeaderMap::new(),
                &HashMap::new(),
                &HashMap::new(),
                &Value::Null,
                "",
                ResolvedView::Map(&resolved)
            ),
            SqlValue::Null
        );
    }

    #[test]
    fn resolve_from_an_unknown_source_name_is_null_not_a_crash() {
        assert_eq!(
            resolve_from(
                "sources.doesNotExist.field",
                &HeaderMap::new(),
                &HashMap::new(),
                &HashMap::new(),
                &Value::Null,
                "",
                ResolvedView::Map(&HashMap::new())
            ),
            SqlValue::Null
        );
    }

    /// A shared coordination ID, not a per-source secret — every source in
    /// the same request must see the exact same value, so two sources
    /// resolved side by side (mirroring `resolve_sources`' own real usage,
    /// not just a direct `resolve_from` call) both end up with it.
    #[tokio::test]
    async fn every_source_in_a_request_receives_the_same_transaction_id() {
        #[derive(Debug)]
        struct RecordingDriver {
            received: std::sync::Arc<std::sync::Mutex<Vec<HashMap<String, SqlValue>>>>,
        }

        #[async_trait::async_trait]
        impl SqlDriver for RecordingDriver {
            async fn query(&self, _script: &str, params: &HashMap<String, SqlValue>) -> Result<Vec<HashMap<String, SqlValue>>, SqlError> {
                self.received.lock().unwrap().push(params.clone());
                Ok(vec![row(&[("id", SqlValue::Int(1))])])
            }
        }

        let json = r#"{
            "operationId": "createCar",
            "sources": {
                "a": {
                    "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "one",
                    "parameters": [{ "name": "txId", "from": "context.transactionId" }]
                },
                "b": {
                    "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "one",
                    "parameters": [{ "name": "txId", "from": "context.transactionId" }]
                }
            },
            "response": {}
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();

        let received = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(RecordingDriver { received: received.clone() }));

        let root = temp_project_root();
        let client = reqwest::Client::new();
        resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "shared-txn-id",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect("both sources should resolve");

        let calls = received.lock().unwrap();
        assert_eq!(calls.len(), 2);
        for call in calls.iter() {
            assert_eq!(call.get("txId"), Some(&SqlValue::Text("shared-txn-id".to_string())));
        }
    }

    /// The parity gap flagged in review: the test above only proves
    /// `context.transactionId` for two *SQL* sources — `run_http_source`
    /// calls the exact same `resolve_from` function, but that path had no
    /// test of its own. Proven here via a real local HTTP server that
    /// records the raw query string it actually received, the same
    /// "capture what a fake server got" technique used in
    /// `security::verify`'s injection test.
    #[tokio::test]
    async fn an_http_source_also_receives_the_shared_transaction_id() {
        use axum::extract::{RawQuery, State};
        use axum::routing::get;
        use axum::{Json, Router};
        use std::sync::{Arc, Mutex};

        async fn record(State(received): State<Arc<Mutex<Option<String>>>>, RawQuery(query): RawQuery) -> Json<Value> {
            *received.lock().unwrap() = query;
            Json(serde_json::json!({ "ok": true }))
        }

        let received_query: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let app = Router::new().route("/ping", get(record)).with_state(received_query.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let root = temp_project_root();
        std::fs::write(
            root.join("http/ping.json"),
            format!(r#"{{ "method": "GET", "url": "http://{addr}/ping?txId={{{{txId}}}}" }}"#),
        )
        .unwrap();

        let json = r#"{
            "operationId": "test",
            "sources": {
                "ping": {
                    "type": "http",
                    "request": "ping.json",
                    "parameters": [{ "name": "txId", "from": "context.transactionId" }]
                }
            },
            "response": {}
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();

        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        let client = reqwest::Client::new();
        resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "shared-txn-id",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect("the http source should resolve");

        assert_eq!(
            received_query.lock().unwrap().as_deref(),
            Some("txId=shared-txn-id"),
            "an HTTP source's context.transactionId parameter must receive the same transaction id a SQL source would"
        );
    }

    /// The point-2 exit criterion, proven through the real `resolve_sources`
    /// path (not just the `resolve_from` unit tests above): a SQL source's
    /// `"from": "body.maker"` parameter actually receives the request
    /// body's `maker` field, recorded here by a driver that captures
    /// exactly what it was bound — the same "swap what a source returns"
    /// principle as `FakeDriver`, but recording inbound params instead of
    /// controlling outbound rows.
    #[tokio::test]
    async fn a_sql_source_reads_a_parameter_from_the_request_body() {
        #[derive(Debug)]
        struct RecordingDriver {
            received: std::sync::Arc<std::sync::Mutex<Option<HashMap<String, SqlValue>>>>,
        }

        #[async_trait::async_trait]
        impl SqlDriver for RecordingDriver {
            async fn query(&self, _script: &str, params: &HashMap<String, SqlValue>) -> Result<Vec<HashMap<String, SqlValue>>, SqlError> {
                *self.received.lock().unwrap() = Some(params.clone());
                Ok(vec![row(&[("id", SqlValue::Int(1))])])
            }
        }

        let json = r#"{
            "operationId": "createCar",
            "sources": {
                "car": {
                    "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "one",
                    "parameters": [{ "name": "maker", "from": "body.maker" }]
                }
            },
            "response": { "id": "sources.car.id" }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();

        let received = std::sync::Arc::new(std::sync::Mutex::new(None));
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(RecordingDriver { received: received.clone() }));

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let body = serde_json::json!({ "maker": "Honda" });
        let resolved = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &body,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect("the sql source should resolve using the body-derived parameter");

        let response = build_response(&endpoint, &resolved);
        assert_eq!(response["id"], 1);

        let received_params = received.lock().unwrap().clone().unwrap();
        assert_eq!(received_params.get("maker"), Some(&SqlValue::Text("Honda".to_string())));
    }

    /// An array of *objects* still can't be a native SQL array element (no
    /// driver models a JSON-object array element) — each element falls back
    /// to JSON-encoded text individually, wrapped in a real `SqlValue::Array`
    /// rather than the whole thing collapsing to one JSON-encoded string
    /// the way it did before per-driver native array binding existed. See
    /// `sql::postgres::bind_array` for what Postgres actually does with a
    /// homogeneous-scalar array at bind time — this level just proves the
    /// `SqlValue` shape `resolve_sources` hands the driver is correct.
    #[tokio::test]
    async fn a_sql_source_receives_an_array_typed_body_field_as_a_native_sql_value_array() {
        #[derive(Debug)]
        struct RecordingDriver {
            received: std::sync::Arc<std::sync::Mutex<Option<HashMap<String, SqlValue>>>>,
        }

        #[async_trait::async_trait]
        impl SqlDriver for RecordingDriver {
            async fn query(&self, _script: &str, params: &HashMap<String, SqlValue>) -> Result<Vec<HashMap<String, SqlValue>>, SqlError> {
                *self.received.lock().unwrap() = Some(params.clone());
                Ok(vec![row(&[("count", SqlValue::Int(2))])])
            }
        }

        let json = r#"{
            "operationId": "createCarBatch",
            "sources": {
                "batch": {
                    "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "one",
                    "parameters": [{ "name": "items", "from": "body.items", "type": "array" }]
                }
            },
            "response": { "count": "sources.batch.count" }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();

        let received = std::sync::Arc::new(std::sync::Mutex::new(None));
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(RecordingDriver { received: received.clone() }));

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let body = serde_json::json!({ "items": [{ "maker": "Honda" }, { "maker": "Ford" }] });
        resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &body,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect("the sql source should resolve using the array-typed body parameter");

        let received_params = received.lock().unwrap().clone().unwrap();
        assert_eq!(
            received_params.get("items"),
            Some(&SqlValue::Array(vec![
                SqlValue::Text(r#"{"maker":"Honda"}"#.to_string()),
                SqlValue::Text(r#"{"maker":"Ford"}"#.to_string()),
            ]))
        );
    }

    /// The common case in practice: a scalar array (not an array of
    /// objects) round-trips as a `SqlValue::Array` of the matching scalar
    /// variant, ready for a driver like Postgres to bind natively.
    #[tokio::test]
    async fn a_sql_source_receives_a_scalar_array_body_field_as_a_typed_array() {
        #[derive(Debug)]
        struct RecordingDriver {
            received: std::sync::Arc<std::sync::Mutex<Option<HashMap<String, SqlValue>>>>,
        }

        #[async_trait::async_trait]
        impl SqlDriver for RecordingDriver {
            async fn query(&self, _script: &str, params: &HashMap<String, SqlValue>) -> Result<Vec<HashMap<String, SqlValue>>, SqlError> {
                *self.received.lock().unwrap() = Some(params.clone());
                Ok(vec![row(&[("count", SqlValue::Int(1))])])
            }
        }

        let json = r#"{
            "operationId": "test",
            "sources": {
                "batch": {
                    "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "one",
                    "parameters": [{ "name": "ids", "from": "body.ids", "type": "array" }]
                }
            },
            "response": { "count": "sources.batch.count" }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();

        let received = std::sync::Arc::new(std::sync::Mutex::new(None));
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(RecordingDriver { received: received.clone() }));

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let body = serde_json::json!({ "ids": [1, 2, 3] });
        resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &body,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect("the sql source should resolve using the scalar array body parameter");

        let received_params = received.lock().unwrap().clone().unwrap();
        assert_eq!(
            received_params.get("ids"),
            Some(&SqlValue::Array(vec![SqlValue::Int(1), SqlValue::Int(2), SqlValue::Int(3)]))
        );
    }

    #[test]
    fn clamp_numeric_is_a_no_op_when_nothing_is_declared() {
        assert_eq!(
            clamp_numeric(SqlValue::Text("hello".to_string()), None, None, None),
            SqlValue::Text("hello".to_string())
        );
        assert_eq!(clamp_numeric(SqlValue::Null, None, None, None), SqlValue::Null);
    }

    #[test]
    fn clamp_numeric_clamps_an_over_max_value_down() {
        assert_eq!(clamp_numeric(SqlValue::Text("999999999".to_string()), Some(20), None, Some(100)), SqlValue::Int(100));
    }

    #[test]
    fn clamp_numeric_clamps_a_below_min_value_up() {
        assert_eq!(clamp_numeric(SqlValue::Text("-5".to_string()), Some(0), Some(0), None), SqlValue::Int(0));
    }

    #[test]
    fn clamp_numeric_uses_default_for_a_missing_value() {
        assert_eq!(clamp_numeric(SqlValue::Null, Some(20), None, Some(100)), SqlValue::Int(20));
    }

    #[test]
    fn clamp_numeric_uses_default_for_an_unparseable_value() {
        assert_eq!(
            clamp_numeric(SqlValue::Text("not-a-number".to_string()), Some(20), None, Some(100)),
            SqlValue::Int(20)
        );
    }

    #[test]
    fn clamp_numeric_a_value_within_bounds_passes_through_unclamped() {
        assert_eq!(clamp_numeric(SqlValue::Text("50".to_string()), Some(20), Some(0), Some(100)), SqlValue::Int(50));
    }

    #[test]
    fn clamp_numeric_truncates_a_float() {
        assert_eq!(clamp_numeric(SqlValue::Float(42.9), Some(0), None, None), SqlValue::Int(42));
    }

    #[test]
    fn clamp_numeric_with_only_default_declared_still_activates_clamping() {
        // Even with no min/max at all, declaring `default` alone still
        // means "this is a numeric parameter" — a text value must convert.
        assert_eq!(clamp_numeric(SqlValue::Text("7".to_string()), Some(0), None, None), SqlValue::Int(7));
    }

    /// The design doc's own worked example, proven end to end: an
    /// unbounded caller-supplied `limit` gets clamped before it ever
    /// reaches the driver, and an omitted one falls back to `default` —
    /// both as a real `SqlValue::Int`, not the usual all-text query-param
    /// binding.
    #[tokio::test]
    async fn a_query_parameter_with_default_min_max_is_clamped_end_to_end() {
        #[derive(Debug)]
        struct RecordingDriver {
            received: std::sync::Arc<std::sync::Mutex<Option<HashMap<String, SqlValue>>>>,
        }
        #[async_trait::async_trait]
        impl SqlDriver for RecordingDriver {
            async fn query(&self, _script: &str, params: &HashMap<String, SqlValue>) -> Result<Vec<HashMap<String, SqlValue>>, SqlError> {
                *self.received.lock().unwrap() = Some(params.clone());
                Ok(vec![row(&[("id", SqlValue::Int(1))])])
            }
        }

        let json = r#"{
            "operationId": "test",
            "sources": {
                "cars": {
                    "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "one",
                    "parameters": [
                        { "name": "limit", "from": "query.limit", "default": 20, "min": 0, "max": 100 },
                        { "name": "offset", "from": "query.offset", "default": 0, "min": 0 }
                    ]
                }
            },
            "response": {}
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();

        let received = std::sync::Arc::new(std::sync::Mutex::new(None));
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(RecordingDriver { received: received.clone() }));

        let root = temp_project_root();
        let client = reqwest::Client::new();
        // Caller sends an absurdly high limit and no offset at all.
        let query_params = HashMap::from([("limit".to_string(), "999999999".to_string())]);
        resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &query_params,
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect("the sql source should resolve using the clamped parameters");

        let received_params = received.lock().unwrap().clone().unwrap();
        assert_eq!(
            received_params.get("limit"),
            Some(&SqlValue::Int(100)),
            "limit=999999999 must be clamped down to max: 100"
        );
        assert_eq!(
            received_params.get("offset"),
            Some(&SqlValue::Int(0)),
            "an omitted offset must fall back to default: 0, as a real integer"
        );
    }

    /// A driver that panics if it's ever actually queried — the strongest
    /// possible proof a mocked source bypasses real execution entirely,
    /// not just "the mocked value happened to win."
    #[derive(Debug)]
    struct PanicsIfCalledDriver;

    #[async_trait::async_trait]
    impl SqlDriver for PanicsIfCalledDriver {
        async fn query(&self, _script: &str, _params: &HashMap<String, SqlValue>) -> Result<Vec<HashMap<String, SqlValue>>, SqlError> {
            panic!("a mocked source must never reach the real driver");
        }
    }

    #[tokio::test]
    async fn a_mocked_source_success_bypasses_real_execution_entirely() {
        let endpoint = endpoint_with_one_sql_source("car", false);
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(PanicsIfCalledDriver));

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let mut mocks = HashMap::new();
        mocks.insert("car".to_string(), MockOutcome::Success(serde_json::json!({ "vin": "MOCKED-VIN" })));

        let resolved = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &mocks,
            &HeaderMap::new(),
        )
        .await
        .expect("a mocked source should resolve without touching the real driver");

        let body = build_response(&endpoint, &resolved);
        assert_eq!(body["vin"], "MOCKED-VIN");
    }

    #[tokio::test]
    async fn a_mocked_source_failure_is_classified_by_its_injected_code_and_respects_on_error() {
        let endpoint = endpoint_with_one_sql_source("car", false);
        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new(); // no "db" connection at all — proves the mock never needs one

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let mut mocks = HashMap::new();
        mocks.insert("car".to_string(), MockOutcome::Fail("datasource.sql.connection_failed".to_string()));

        let failure = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &mocks,
            &HeaderMap::new(),
        )
        .await
        .expect_err("a mocked failure on a non-optional source must fail the request");

        // `endpoint_with_one_sql_source` sets `"onError": 500` on the source itself.
        assert_eq!(failure.on_error, Some(500));
        assert_eq!(failure.cause.code(), "datasource.sql.connection_failed");
    }

    #[tokio::test]
    async fn a_mocked_failure_on_an_optional_source_degrades_to_null_like_a_real_one_would() {
        let endpoint = endpoint_with_one_sql_source("pricing", true);
        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let mut mocks = HashMap::new();
        mocks.insert("pricing".to_string(), MockOutcome::Fail("datasource.http.timeout".to_string()));

        let resolved = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &mocks,
            &HeaderMap::new(),
        )
        .await
        .expect("an optional source's mocked failure must not fail the whole request");

        let body = build_response(&endpoint, &resolved);
        assert_eq!(body["vin"], Value::Null);
    }

    /// The design doc's "hybrid" case: `mocks` can cover some sources and
    /// not others in the same file format — one mocked, one real, both
    /// landing in the same response.
    #[tokio::test]
    async fn a_partially_mocked_request_runs_the_unmocked_source_for_real() {
        let json = r#"{
            "operationId": "getCarByVin",
            "sources": {
                "car": {
                    "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "one",
                    "parameters": [{ "name": "vin", "from": "path.vin" }]
                },
                "pricing": { "type": "http", "request": "pricing.json" }
            },
            "response": {
                "vin": "sources.car.vin",
                "price": "sources.pricing.amount"
            }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();

        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert(
            "db".to_string(),
            Box::new(FakeDriver {
                rows: vec![row(&[("vin", SqlValue::Text("1HGCM82633A004352".to_string()))])],
                fail: false,
            }),
        );

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let path_params = HashMap::from([("vin".to_string(), "1HGCM82633A004352".to_string())]);
        let mut mocks = HashMap::new();
        mocks.insert("pricing".to_string(), MockOutcome::Success(serde_json::json!({ "amount": 24500 })));

        let resolved = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"), // never actually read — the http source is mocked
            &client,
            &path_params,
            &HashMap::new(),
            &Value::Null,
            "",
            &mocks,
            &HeaderMap::new(),
        )
        .await
        .expect("the real sql source and the mocked http source should both resolve");

        let body = build_response(&endpoint, &resolved);
        assert_eq!(body["vin"], "1HGCM82633A004352", "the unmocked source ran for real");
        assert_eq!(body["price"], 24500, "the mocked source used its substituted value");
    }

    #[tokio::test]
    async fn an_http_source_can_be_mocked_bypassing_the_real_request_entirely() {
        let json = r#"{
            "operationId": "test",
            "sources": {
                "pricing": { "type": "http", "request": "does_not_exist.json" }
            },
            "response": { "price": "sources.pricing.amount" }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();

        // No http/does_not_exist.json on disk at all — if the mock didn't
        // bypass real execution, this would fail trying to read the file.
        let root = temp_project_root();
        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        let client = reqwest::Client::new();
        let mut mocks = HashMap::new();
        mocks.insert("pricing".to_string(), MockOutcome::Success(serde_json::json!({ "amount": 100 })));

        let resolved = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &mocks,
            &HeaderMap::new(),
        )
        .await
        .expect("a mocked http source must resolve without ever reading its request file");

        let body = build_response(&endpoint, &resolved);
        assert_eq!(body["price"], 100);
    }

    /// The `cars-demo` example's real, previously-broken shape: `pricing`'s
    /// own `vin` parameter reads `sources.car.vin` — proving the chain is
    /// resolved in dependency order (car before pricing) even though it's
    /// declared second in the JSON map, not just that both happen to
    /// resolve independently.
    #[tokio::test]
    async fn a_source_can_chain_a_parameter_off_another_sources_resolved_output() {
        use axum::extract::{RawQuery, State};
        use axum::routing::get;
        use axum::{Json, Router};
        use std::sync::{Arc, Mutex};

        async fn record(State(received): State<Arc<Mutex<Option<String>>>>, RawQuery(query): RawQuery) -> Json<Value> {
            *received.lock().unwrap() = query;
            Json(serde_json::json!({ "amount": 24500 }))
        }

        let received_query: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let app = Router::new().route("/price", get(record)).with_state(received_query.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let root = temp_project_root();
        std::fs::write(
            root.join("http/pricing.json"),
            format!(r#"{{ "method": "GET", "url": "http://{addr}/price?vin={{{{vin}}}}" }}"#),
        )
        .unwrap();

        let json = r#"{
            "operationId": "getCarInfo",
            "sources": {
                "pricing": {
                    "type": "http", "request": "pricing.json", "optional": true,
                    "parameters": [{ "name": "vin", "from": "sources.car.vin" }]
                },
                "car": {
                    "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "one",
                    "parameters": [{ "name": "maker", "from": "query.maker" }]
                }
            },
            "response": { "vin": "sources.car.vin", "price": "sources.pricing.amount" }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();

        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert(
            "db".to_string(),
            Box::new(FakeDriver {
                rows: vec![row(&[("vin", SqlValue::Text("1HGCM82633A004352".to_string()))])],
                fail: false,
            }),
        );

        let root_http = root.join("http");
        let client = reqwest::Client::new();
        let resolved = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root_http,
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect("pricing's dependency on car should resolve car first, then chain into pricing");

        let body = build_response(&endpoint, &resolved);
        assert_eq!(body["vin"], "1HGCM82633A004352");
        assert_eq!(body["price"], 24500);
        assert_eq!(
            received_query.lock().unwrap().as_deref(),
            Some("vin=1HGCM82633A004352"),
            "pricing's own outbound request must carry car's real resolved vin, not an empty/null placeholder"
        );
    }

    /// SQL rows are flat, but an HTTP source's resolved body is genuine
    /// nested JSON — proving a dependent source's parameter can chain a
    /// field more than one level deep (`sources.pricing.seller.name`), not
    /// just a single top-level field like the other chaining tests here.
    #[tokio::test]
    async fn a_dependent_source_can_chain_an_arbitrarily_nested_field() {
        use axum::extract::{Query, State};
        use axum::routing::get;
        use axum::{Json, Router};
        use std::collections::HashMap as StdHashMap;
        use std::sync::{Arc, Mutex};

        async fn price() -> Json<Value> {
            Json(serde_json::json!({ "seller": { "name": "Bob" } }))
        }
        async fn notify(State(received): State<Arc<Mutex<Option<String>>>>, Query(params): Query<StdHashMap<String, String>>) -> Json<Value> {
            *received.lock().unwrap() = params.get("sellerName").cloned();
            Json(serde_json::json!({ "ok": true }))
        }

        let received_seller_name: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let app = Router::new()
            .route("/price", get(price))
            .route("/notify", get(notify))
            .with_state(received_seller_name.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let root = temp_project_root();
        std::fs::write(root.join("http/pricing.json"), format!(r#"{{ "method": "GET", "url": "http://{addr}/price" }}"#)).unwrap();
        std::fs::write(
            root.join("http/notify.json"),
            format!(r#"{{ "method": "GET", "url": "http://{addr}/notify?sellerName={{{{sellerName}}}}" }}"#),
        )
        .unwrap();

        let json = r#"{
            "operationId": "test",
            "sources": {
                "notify": {
                    "type": "http", "request": "notify.json",
                    "parameters": [{ "name": "sellerName", "from": "sources.pricing.seller.name" }]
                },
                "pricing": { "type": "http", "request": "pricing.json" }
            },
            "response": {}
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();

        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        let client = reqwest::Client::new();
        resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect("notify's nested chained parameter should resolve against pricing's real nested response");

        assert_eq!(
            received_seller_name.lock().unwrap().as_deref(),
            Some("Bob"),
            "notify must receive pricing.seller.name two levels deep, not just pricing's top-level fields"
        );
    }

    #[tokio::test]
    async fn a_cycle_between_two_sources_is_a_clear_config_failure_not_a_hang() {
        let json = r#"{
            "operationId": "test",
            "sources": {
                "a": {
                    "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "one",
                    "parameters": [{ "name": "x", "from": "sources.b.x" }]
                },
                "b": {
                    "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "one",
                    "parameters": [{ "name": "x", "from": "sources.a.x" }]
                }
            },
            "response": {}
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(FakeDriver { rows: vec![], fail: false }));

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let failure = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect_err("two sources depending on each other must fail clearly, not hang or loop forever");

        assert_eq!(failure.cause.code(), "unexpected.error");
    }

    /// A mocked dependency still counts as resolved for a source chaining
    /// off it — the point of mocks + chaining together: swap what `car`
    /// returns, and prove `pricing`'s own chained parameter picks up the
    /// substituted value, not a real (unmocked) one.
    #[tokio::test]
    async fn a_source_can_chain_off_a_mocked_dependency() {
        let json = r#"{
            "operationId": "test",
            "sources": {
                "car": { "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "one" },
                "pricing": {
                    "type": "http", "request": "pricing.json",
                    "parameters": [{ "name": "vin", "from": "sources.car.vin" }]
                }
            },
            "response": { "vin": "sources.pricing.echoedVin" }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();

        let root = temp_project_root();
        // `pricing` is also mocked here — if the chain didn't resolve `car`
        // first, this would still pass by accident. It's only a meaningful
        // proof together with the unmocked-chain test above.
        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        let client = reqwest::Client::new();
        let mut mocks = HashMap::new();
        mocks.insert("car".to_string(), MockOutcome::Success(serde_json::json!({ "vin": "MOCKED-VIN" })));
        mocks.insert("pricing".to_string(), MockOutcome::Success(serde_json::json!({ "echoedVin": "MOCKED-VIN" })));

        let resolved = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &mocks,
            &HeaderMap::new(),
        )
        .await
        .expect("both mocked sources should resolve without touching real drivers");

        let body = build_response(&endpoint, &resolved);
        assert_eq!(body["vin"], "MOCKED-VIN");
    }

    #[tokio::test]
    async fn a_non_optional_sources_failure_propagates_through_a_dependent_source() {
        let json = r#"{
            "operationId": "test",
            "sources": {
                "car": { "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "one", "onError": 500 },
                "pricing": {
                    "type": "http", "request": "pricing.json",
                    "parameters": [{ "name": "vin", "from": "sources.car.vin" }]
                }
            },
            "response": {}
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(FakeDriver { rows: vec![], fail: true }));

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let failure = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect_err("car's non-optional failure must fail the request before pricing ever runs");

        assert_eq!(failure.source_name, "car");
    }

    #[tokio::test]
    async fn an_optional_sources_failure_lets_a_dependent_source_chain_a_null() {
        use axum::extract::{Query, State};
        use axum::routing::get;
        use axum::{Json, Router};
        use std::collections::HashMap as StdHashMap;
        use std::sync::{Arc, Mutex};

        async fn notify(State(received): State<Arc<Mutex<Option<String>>>>, Query(params): Query<StdHashMap<String, String>>) -> Json<Value> {
            // A null `sources.car.vin` templates as an empty string, per
            // the usual "unresolvable {{name}} -> empty string" rule — the
            // key is still present (`?vin=`), just with an empty value.
            *received.lock().unwrap() = Some(params.get("vin").cloned().unwrap_or_default());
            Json(serde_json::json!({ "echoedVin": "resolved-despite-null-vin" }))
        }

        let received_vin: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let app = Router::new().route("/price", get(notify)).with_state(received_vin.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let json = r#"{
            "operationId": "test",
            "sources": {
                "car": { "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "one", "optional": true },
                "pricing": {
                    "type": "http", "request": "pricing.json",
                    "parameters": [{ "name": "vin", "from": "sources.car.vin" }]
                }
            },
            "response": { "vin": "sources.pricing.echoedVin" }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(FakeDriver { rows: vec![], fail: true }));

        let root = temp_project_root();
        std::fs::write(
            root.join("http/pricing.json"),
            format!(r#"{{ "method": "GET", "url": "http://{addr}/price?vin={{{{vin}}}}" }}"#),
        )
        .unwrap();

        let client = reqwest::Client::new();
        let resolved = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect("car's optional failure must not stop pricing from resolving, chained parameter or not");

        assert_eq!(
            received_vin.lock().unwrap().as_deref(),
            Some(""),
            "car's optional failure means sources.car.vin resolves to null, which templates as an empty string, same as any other unresolvable {{name}}"
        );
        let body = build_response(&endpoint, &resolved);
        assert_eq!(body["vin"], "resolved-despite-null-vin");
    }

    /// `header.*` end to end through `resolve_sources`, not just the
    /// `resolve_from` unit tests above — a SQL source's own parameter reads
    /// the caller's `X-Api-Key` header, the same way a security verifier's
    /// parameters already could.
    #[tokio::test]
    async fn a_sql_source_reads_a_parameter_from_a_caller_header() {
        #[derive(Debug)]
        struct RecordingDriver {
            received: std::sync::Arc<std::sync::Mutex<Option<HashMap<String, SqlValue>>>>,
        }
        #[async_trait::async_trait]
        impl SqlDriver for RecordingDriver {
            async fn query(&self, _script: &str, params: &HashMap<String, SqlValue>) -> Result<Vec<HashMap<String, SqlValue>>, SqlError> {
                *self.received.lock().unwrap() = Some(params.clone());
                Ok(vec![row(&[("ok", SqlValue::Bool(true))])])
            }
        }

        let json = r#"{
            "operationId": "test",
            "sources": {
                "car": {
                    "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "one",
                    "parameters": [{ "name": "apiKey", "from": "header.X-Api-Key" }]
                }
            },
            "response": {}
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();

        let received = std::sync::Arc::new(std::sync::Mutex::new(None));
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(RecordingDriver { received: received.clone() }));

        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", "secret-123".parse().unwrap());

        let root = temp_project_root();
        let client = reqwest::Client::new();
        resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &headers,
        )
        .await
        .expect("the sql source should resolve using the header-derived parameter");

        let received_params = received.lock().unwrap().clone().unwrap();
        assert_eq!(received_params.get("apiKey"), Some(&SqlValue::Text("secret-123".to_string())));
    }

    /// Same proof for an HTTP source's own parameter, and for a header the
    /// caller *didn't* send — templates as an empty string, same as any
    /// other unresolvable `{{name}}`, not a request failure.
    #[tokio::test]
    async fn an_http_source_reads_a_parameter_from_a_caller_header_and_a_missing_one_is_empty() {
        use axum::extract::{Query, State};
        use axum::routing::get;
        use axum::{Json, Router};
        use std::collections::HashMap as StdHashMap;
        use std::sync::{Arc, Mutex};

        async fn record(State(received): State<Arc<Mutex<Option<String>>>>, Query(params): Query<StdHashMap<String, String>>) -> Json<Value> {
            *received.lock().unwrap() = Some(params.get("forwarded").cloned().unwrap_or_default());
            Json(serde_json::json!({ "ok": true }))
        }

        let received_forwarded: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let app = Router::new().route("/ping", get(record)).with_state(received_forwarded.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let root = temp_project_root();
        std::fs::write(
            root.join("http/ping.json"),
            format!(r#"{{ "method": "GET", "url": "http://{addr}/ping?forwarded={{{{token}}}}" }}"#),
        )
        .unwrap();

        let json = r#"{
            "operationId": "test",
            "sources": {
                "ping": {
                    "type": "http", "request": "ping.json",
                    "parameters": [{ "name": "token", "from": "header.X-Forwarded-Token" }]
                }
            },
            "response": {}
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        let client = reqwest::Client::new();

        // First: the caller genuinely sends the header.
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-token", "abc-123".parse().unwrap());
        resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &headers,
        )
        .await
        .expect("the http source should resolve using the header-derived parameter");
        assert_eq!(received_forwarded.lock().unwrap().as_deref(), Some("abc-123"));

        // Second: the caller doesn't send it at all — null, templated empty,
        // not a failure.
        resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect("a missing header must not fail the request, just bind null");
        assert_eq!(received_forwarded.lock().unwrap().as_deref(), Some(""));
    }

    // ---- Many-Depends-on-Many Array Fan-Out (`resolve_nested_many`) ----

    /// Shared by every nested-many test below: a `cardinality: "many"`
    /// parent's own rows, executed against `FakeDriver` so no real
    /// connection is needed — the fan-out's own child source is what each
    /// test actually cares about exercising for real.
    fn cars_endpoint_json(nested_many_source_json: &str) -> String {
        format!(
            r#"{{
                "operationId": "test",
                "sources": {{
                    "cars": {{ "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "many" }},
                    "pricing": {nested_many_source_json}
                }},
                "response": {{}}
            }}"#
        )
    }

    fn cars_driver(vins: &[&str]) -> Box<dyn SqlDriver> {
        Box::new(FakeDriver {
            rows: vins.iter().map(|vin| row(&[("vin", SqlValue::Text(vin.to_string()))])).collect(),
            fail: false,
        })
    }

    #[tokio::test]
    async fn row_count_exceeding_max_rows_with_optional_false_fails_the_whole_request_and_issues_zero_real_calls() {
        use axum::routing::get;
        use axum::{Json, Router};

        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter_for_route = call_count.clone();
        let app = Router::new().route(
            "/price",
            get(move || {
                let counter = counter_for_route.clone();
                async move {
                    counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Json(serde_json::json!({ "amount": 100 }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let root = temp_project_root();
        std::fs::write(root.join("http/pricing.json"), format!(r#"{{ "method": "GET", "url": "http://{addr}/price" }}"#)).unwrap();

        let json = cars_endpoint_json(
            r#"{
                "type": "http", "request": "pricing.json",
                "allowNestedMany": true, "maxConcurrency": 2, "maxRows": 2, "optional": false,
                "parameters": [{ "name": "vin", "from": "sources.cars[].vin" }]
            }"#,
        );
        let endpoint: EndpointFile = serde_json::from_str(&json).unwrap();
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), cars_driver(&["AAA", "BBB", "CCC"]));

        let client = reqwest::Client::new();
        let failure = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect_err("3 rows exceeds maxRows: 2 with optional: false, the whole request must fail");

        assert_eq!(failure.cause.code(), "datasource.nested_many.row_limit_exceeded");
        let message = failure.cause.message();
        assert!(message.contains('3') && message.contains('2'), "message should name resolved/max: {message}");
        assert_eq!(
            call_count.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the row-count gate must fire before any per-row future is ever built"
        );
    }

    /// The same maxRows-exceeded gate, but driven by a `.test.json`-style
    /// parent-only mock (`MockOutcome::Success` on `cars`, exactly what a
    /// test case's own `mocks` block deserializes into — see `MockOutcome`'s
    /// own doc comment) rather than a real driver's row count. The
    /// nested-many source itself has no mock at all, proving the row-count
    /// gate is checked against the *mocked* parent's array length before any
    /// real per-row call, not skipped just because the parent came from a mock.
    #[tokio::test]
    async fn a_mocked_parent_row_count_exceeding_max_rows_fails_before_any_real_per_row_call() {
        use axum::routing::get;
        use axum::{Json, Router};

        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter_for_route = call_count.clone();
        let app = Router::new().route(
            "/price",
            get(move || {
                let counter = counter_for_route.clone();
                async move {
                    counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Json(serde_json::json!({ "amount": 100 }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let root = temp_project_root();
        std::fs::write(root.join("http/pricing.json"), format!(r#"{{ "method": "GET", "url": "http://{addr}/price" }}"#)).unwrap();

        let json = cars_endpoint_json(
            r#"{
                "type": "http", "request": "pricing.json",
                "allowNestedMany": true, "maxConcurrency": 2, "maxRows": 2, "optional": false,
                "parameters": [{ "name": "vin", "from": "sources.cars[].vin" }]
            }"#,
        );
        let endpoint: EndpointFile = serde_json::from_str(&json).unwrap();
        // Never queried at all — `cars` is fully mocked below, this exists
        // purely so `drivers` has an entry for `connection: "db"`.
        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();

        let mut mocks = HashMap::new();
        mocks.insert(
            "cars".to_string(),
            MockOutcome::Success(serde_json::json!([{ "vin": "AAA" }, { "vin": "BBB" }, { "vin": "CCC" }])),
        );

        let client = reqwest::Client::new();
        let failure = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &mocks,
            &HeaderMap::new(),
        )
        .await
        .expect_err("a mocked parent with 3 rows still exceeds maxRows: 2");

        assert_eq!(failure.cause.code(), "datasource.nested_many.row_limit_exceeded");
        assert_eq!(
            call_count.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the row-count gate must fire against the mocked parent's array before any real per-row call"
        );
    }

    #[tokio::test]
    async fn row_count_exceeding_max_rows_with_optional_true_nulls_every_merged_field_and_issues_zero_calls() {
        use axum::routing::get;
        use axum::{Json, Router};

        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter_for_route = call_count.clone();
        let app = Router::new().route(
            "/price",
            get(move || {
                let counter = counter_for_route.clone();
                async move {
                    counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Json(serde_json::json!({ "amount": 100 }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let root = temp_project_root();
        std::fs::write(root.join("http/pricing.json"), format!(r#"{{ "method": "GET", "url": "http://{addr}/price" }}"#)).unwrap();

        let json = cars_endpoint_json(
            r#"{
                "type": "http", "request": "pricing.json",
                "allowNestedMany": true, "maxConcurrency": 2, "maxRows": 2, "optional": true,
                "parameters": [{ "name": "vin", "from": "sources.cars[].vin" }]
            }"#,
        );
        let endpoint: EndpointFile = serde_json::from_str(&json).unwrap();
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), cars_driver(&["AAA", "BBB", "CCC"]));

        let client = reqwest::Client::new();
        let resolved = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect("optional: true must degrade gracefully rather than fail the whole request");

        assert!(!resolved.contains_key("pricing"), "a nested-many source never gets its own top-level resolved entry");
        let Some(Some(Value::Array(rows))) = resolved.get("cars") else {
            panic!("expected sources.cars to still resolve to an array");
        };
        assert_eq!(rows.len(), 3);
        for row in rows {
            assert!(
                row.get("pricing").is_none(),
                "no merge should have happened once the row-count gate rejected the fan-out"
            );
        }
        assert_eq!(
            call_count.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the row-count gate must fire before any per-row future is ever built, even when optional"
        );
    }

    #[tokio::test]
    async fn nested_many_happy_path_merges_each_rows_own_field_under_the_sources_own_name() {
        use axum::extract::Query;
        use axum::routing::get;
        use axum::{Json, Router};

        let app = Router::new().route(
            "/price",
            get(|Query(params): Query<HashMap<String, String>>| async move {
                let amount = if params.get("vin").map(String::as_str) == Some("AAA") { 100 } else { 200 };
                Json(serde_json::json!({ "amount": amount }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let root = temp_project_root();
        std::fs::write(
            root.join("http/pricing.json"),
            format!(r#"{{ "method": "GET", "url": "http://{addr}/price?vin={{{{vin}}}}" }}"#),
        )
        .unwrap();

        let json = cars_endpoint_json(
            r#"{
                "type": "http", "request": "pricing.json",
                "allowNestedMany": true, "maxConcurrency": 2, "maxRows": 10, "optional": false,
                "parameters": [{ "name": "vin", "from": "sources.cars[].vin" }]
            }"#,
        );
        let endpoint: EndpointFile = serde_json::from_str(&json).unwrap();
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), cars_driver(&["AAA", "BBB"]));

        let client = reqwest::Client::new();
        let resolved = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect("the happy path should resolve cleanly");

        assert!(!resolved.contains_key("pricing"), "a nested-many source never gets its own top-level resolved entry");
        let Some(Some(Value::Array(rows))) = resolved.get("cars") else {
            panic!("expected sources.cars to resolve to an array");
        };
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["vin"], "AAA");
        assert_eq!(rows[0]["pricing"]["amount"], 100, "each row should get its own merged field");
        assert_eq!(rows[1]["vin"], "BBB");
        assert_eq!(rows[1]["pricing"]["amount"], 200);
    }

    /// Proves the coder's own noted deviation (a plain `for` loop building
    /// the per-row futures instead of `.iter().enumerate().map()`) still
    /// produces real concurrent execution through `buffer_unordered`, not an
    /// accidentally-serialized fan-out — a peak in-flight count of 1 would
    /// mean every row waited for the previous one to finish.
    #[tokio::test]
    async fn max_concurrency_actually_bounds_and_achieves_real_in_flight_concurrency() {
        use axum::routing::get;
        use axum::{Json, Router};

        let current = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let peak = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let current_for_route = current.clone();
        let peak_for_route = peak.clone();
        let app = Router::new().route(
            "/price",
            get(move || {
                let current = current_for_route.clone();
                let peak = peak_for_route.clone();
                async move {
                    let now = current.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                    peak.fetch_max(now, std::sync::atomic::Ordering::SeqCst);
                    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                    current.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                    Json(serde_json::json!({ "amount": 1 }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let root = temp_project_root();
        std::fs::write(root.join("http/pricing.json"), format!(r#"{{ "method": "GET", "url": "http://{addr}/price" }}"#)).unwrap();

        let json = cars_endpoint_json(
            r#"{
                "type": "http", "request": "pricing.json",
                "allowNestedMany": true, "maxConcurrency": 2, "maxRows": 10, "optional": false,
                "parameters": [{ "name": "vin", "from": "sources.cars[].vin" }]
            }"#,
        );
        let endpoint: EndpointFile = serde_json::from_str(&json).unwrap();
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), cars_driver(&["A", "B", "C", "D", "E", "F"]));

        let client = reqwest::Client::new();
        resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect("6 rows within maxRows should resolve cleanly");

        let observed_peak = peak.load(std::sync::atomic::Ordering::SeqCst);
        assert!(observed_peak <= 2, "maxConcurrency: 2 must never be exceeded, observed peak {observed_peak}");
        assert!(
            observed_peak >= 2,
            "buffer_unordered must actually run rows concurrently, not serialize them one at a time (observed peak {observed_peak})"
        );
    }

    #[tokio::test]
    async fn a_per_row_call_exceeding_row_timeout_ms_is_classified_as_a_row_timeout() {
        use axum::routing::get;
        use axum::{Json, Router};

        let app = Router::new().route(
            "/price",
            get(|| async move {
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                Json(serde_json::json!({ "amount": 1 }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let root = temp_project_root();
        std::fs::write(root.join("http/pricing.json"), format!(r#"{{ "method": "GET", "url": "http://{addr}/price" }}"#)).unwrap();

        let json = cars_endpoint_json(
            r#"{
                "type": "http", "request": "pricing.json",
                "allowNestedMany": true, "maxConcurrency": 2, "maxRows": 10, "optional": false, "rowTimeoutMs": 50,
                "parameters": [{ "name": "vin", "from": "sources.cars[].vin" }]
            }"#,
        );
        let endpoint: EndpointFile = serde_json::from_str(&json).unwrap();
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), cars_driver(&["AAA"]));

        let client = reqwest::Client::new();
        let failure = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect_err("a per-row call slower than rowTimeoutMs must fail a non-optional nested-many source");

        assert_eq!(failure.cause.code(), "datasource.nested_many.row_timed_out");
        assert!(
            failure.cause.message().contains("50"),
            "message should mention the configured timeout: {}",
            failure.cause.message()
        );
    }

    #[tokio::test]
    async fn zero_parent_rows_means_the_nested_many_source_never_runs() {
        use axum::routing::get;
        use axum::{Json, Router};

        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter_for_route = call_count.clone();
        let app = Router::new().route(
            "/price",
            get(move || {
                let counter = counter_for_route.clone();
                async move {
                    counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Json(serde_json::json!({ "amount": 1 }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let root = temp_project_root();
        std::fs::write(root.join("http/pricing.json"), format!(r#"{{ "method": "GET", "url": "http://{addr}/price" }}"#)).unwrap();

        let json = cars_endpoint_json(
            r#"{
                "type": "http", "request": "pricing.json",
                "allowNestedMany": true, "maxConcurrency": 2, "maxRows": 10, "optional": false,
                "parameters": [{ "name": "vin", "from": "sources.cars[].vin" }]
            }"#,
        );
        let endpoint: EndpointFile = serde_json::from_str(&json).unwrap();
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), cars_driver(&[]));

        let client = reqwest::Client::new();
        let resolved = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect("zero parent rows must resolve cleanly, not error");

        assert_eq!(resolved.get("cars").cloned().flatten(), Some(Value::Array(Vec::new())));
        assert!(!resolved.contains_key("pricing"));
        assert_eq!(call_count.load(std::sync::atomic::Ordering::SeqCst), 0, "zero rows means zero per-row calls");
    }

    #[tokio::test]
    async fn a_failed_optional_parent_is_treated_as_zero_rows_but_its_own_resolved_entry_stays_exactly_some_none() {
        use axum::routing::get;
        use axum::{Json, Router};

        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter_for_route = call_count.clone();
        let app = Router::new().route(
            "/price",
            get(move || {
                let counter = counter_for_route.clone();
                async move {
                    counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Json(serde_json::json!({ "amount": 1 }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let root = temp_project_root();
        std::fs::write(root.join("http/pricing.json"), format!(r#"{{ "method": "GET", "url": "http://{addr}/price" }}"#)).unwrap();

        let json = r#"{
            "operationId": "test",
            "sources": {
                "cars": { "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "many", "optional": true },
                "pricing": {
                    "type": "http", "request": "pricing.json",
                    "allowNestedMany": true, "maxConcurrency": 2, "maxRows": 10, "optional": false,
                    "parameters": [{ "name": "vin", "from": "sources.cars[].vin" }]
                }
            },
            "response": {}
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        // The parent's own query fails outright — since `cars` is optional,
        // that failure becomes `resolved["cars"] = None`, not a request
        // failure.
        drivers.insert("db".to_string(), Box::new(FakeDriver { rows: vec![], fail: true }));

        let client = reqwest::Client::new();
        let resolved = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect("a failed-optional parent must not fail the whole request, even with a non-optional nested-many child");

        assert_eq!(
            resolved.get("cars"),
            Some(&None),
            "the parent's own failed-optional entry must stay exactly Some(None), never rewritten into a fabricated empty array"
        );
        assert!(!resolved.contains_key("pricing"));
        assert_eq!(
            call_count.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a failed-optional parent means zero rows, so zero per-row calls, regardless of the child's own optional flag"
        );
    }

    #[tokio::test]
    async fn two_independent_nested_many_sources_sharing_one_parent_both_merge_without_clobbering_each_other() {
        use axum::extract::Query;
        use axum::routing::get;
        use axum::{Json, Router};

        let app = Router::new()
            .route(
                "/pricing",
                get(|Query(params): Query<HashMap<String, String>>| async move {
                    Json(serde_json::json!({ "amount": if params.get("vin").map(String::as_str) == Some("AAA") { 100 } else { 200 } }))
                }),
            )
            .route(
                "/specs",
                get(|Query(params): Query<HashMap<String, String>>| async move {
                    Json(serde_json::json!({ "engine": if params.get("vin").map(String::as_str) == Some("AAA") { "V6" } else { "V8" } }))
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let root = temp_project_root();
        std::fs::write(
            root.join("http/pricing.json"),
            format!(r#"{{ "method": "GET", "url": "http://{addr}/pricing?vin={{{{vin}}}}" }}"#),
        )
        .unwrap();
        std::fs::write(
            root.join("http/specs.json"),
            format!(r#"{{ "method": "GET", "url": "http://{addr}/specs?vin={{{{vin}}}}" }}"#),
        )
        .unwrap();

        let json = r#"{
            "operationId": "test",
            "sources": {
                "cars": { "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "many" },
                "pricing": {
                    "type": "http", "request": "pricing.json",
                    "allowNestedMany": true, "maxConcurrency": 2, "maxRows": 10, "optional": false,
                    "parameters": [{ "name": "vin", "from": "sources.cars[].vin" }]
                },
                "specs": {
                    "type": "http", "request": "specs.json",
                    "allowNestedMany": true, "maxConcurrency": 2, "maxRows": 10, "optional": false,
                    "parameters": [{ "name": "vin", "from": "sources.cars[].vin" }]
                }
            },
            "response": {}
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), cars_driver(&["AAA", "BBB"]));

        let client = reqwest::Client::new();
        let resolved = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect("both nested-many sources should resolve cleanly");

        let Some(Some(Value::Array(rows))) = resolved.get("cars") else {
            panic!("expected sources.cars to resolve to an array");
        };
        assert_eq!(rows.len(), 2);
        let by_vin: HashMap<&str, &Value> = rows.iter().map(|r| (r["vin"].as_str().unwrap(), r)).collect();
        assert_eq!(by_vin["AAA"]["pricing"]["amount"], 100, "pricing's own merge must survive specs' later merge");
        assert_eq!(by_vin["AAA"]["specs"]["engine"], "V6", "specs' merge must not clobber pricing's");
        assert_eq!(by_vin["BBB"]["pricing"]["amount"], 200);
        assert_eq!(by_vin["BBB"]["specs"]["engine"], "V8");
    }

    #[tokio::test]
    async fn per_row_optional_true_nulls_only_the_failing_rows_field_and_lets_others_proceed() {
        use axum::extract::Query;
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        use axum::routing::get;
        use axum::{Json, Router};

        let app = Router::new().route(
            "/price",
            get(|Query(params): Query<HashMap<String, String>>| async move {
                if params.get("vin").map(String::as_str) == Some("BBB") {
                    (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({}))).into_response()
                } else {
                    Json(serde_json::json!({ "amount": 100 })).into_response()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let root = temp_project_root();
        std::fs::write(
            root.join("http/pricing.json"),
            format!(r#"{{ "method": "GET", "url": "http://{addr}/price?vin={{{{vin}}}}" }}"#),
        )
        .unwrap();

        let json = cars_endpoint_json(
            r#"{
                "type": "http", "request": "pricing.json",
                "allowNestedMany": true, "maxConcurrency": 2, "maxRows": 10, "optional": true,
                "parameters": [{ "name": "vin", "from": "sources.cars[].vin" }]
            }"#,
        );
        let endpoint: EndpointFile = serde_json::from_str(&json).unwrap();
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), cars_driver(&["AAA", "BBB"]));

        let client = reqwest::Client::new();
        let resolved = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect("a per-row optional: true failure must not fail the whole request");

        let Some(Some(Value::Array(rows))) = resolved.get("cars") else {
            panic!("expected sources.cars to resolve to an array");
        };
        let by_vin: HashMap<&str, &Value> = rows.iter().map(|r| (r["vin"].as_str().unwrap(), r)).collect();
        assert_eq!(by_vin["AAA"]["pricing"]["amount"], 100, "the succeeding row must still get its merged field");
        assert!(by_vin["BBB"].get("pricing").is_none(), "the failing row's field must be absent, not present-but-null");
    }

    #[tokio::test]
    async fn per_row_optional_false_fails_the_whole_request_on_the_first_detected_row_failure() {
        use axum::extract::Query;
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        use axum::routing::get;
        use axum::{Json, Router};

        let app = Router::new().route(
            "/price",
            get(|Query(params): Query<HashMap<String, String>>| async move {
                if params.get("vin").map(String::as_str) == Some("BBB") {
                    (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({}))).into_response()
                } else {
                    Json(serde_json::json!({ "amount": 100 })).into_response()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let root = temp_project_root();
        std::fs::write(
            root.join("http/pricing.json"),
            format!(r#"{{ "method": "GET", "url": "http://{addr}/price?vin={{{{vin}}}}" }}"#),
        )
        .unwrap();

        let json = cars_endpoint_json(
            r#"{
                "type": "http", "request": "pricing.json",
                "allowNestedMany": true, "maxConcurrency": 2, "maxRows": 10, "optional": false,
                "parameters": [{ "name": "vin", "from": "sources.cars[].vin" }]
            }"#,
        );
        let endpoint: EndpointFile = serde_json::from_str(&json).unwrap();
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), cars_driver(&["AAA", "BBB"]));

        let client = reqwest::Client::new();
        let failure = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            &HeaderMap::new(),
        )
        .await
        .expect_err("a per-row optional: false failure must fail the whole request");

        assert_eq!(failure.source_name, "pricing");
        assert_eq!(failure.cause.code(), "datasource.http.upstream_error");
    }

    #[tokio::test]
    async fn a_nested_many_sources_own_mock_applies_uniformly_to_every_row_without_a_real_call() {
        use axum::routing::get;
        use axum::{Json, Router};

        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter_for_route = call_count.clone();
        let app = Router::new().route(
            "/price",
            get(move || {
                let counter = counter_for_route.clone();
                async move {
                    counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Json(serde_json::json!({ "amount": 999 }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let root = temp_project_root();
        std::fs::write(root.join("http/pricing.json"), format!(r#"{{ "method": "GET", "url": "http://{addr}/price" }}"#)).unwrap();

        let json = cars_endpoint_json(
            r#"{
                "type": "http", "request": "pricing.json",
                "allowNestedMany": true, "maxConcurrency": 2, "maxRows": 10, "optional": false,
                "parameters": [{ "name": "vin", "from": "sources.cars[].vin" }]
            }"#,
        );
        let endpoint: EndpointFile = serde_json::from_str(&json).unwrap();
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), cars_driver(&["AAA", "BBB", "CCC"]));

        let mut mocks = HashMap::new();
        mocks.insert("pricing".to_string(), MockOutcome::Success(serde_json::json!({ "amount": 42 })));

        let client = reqwest::Client::new();
        let resolved = resolve_sources(
            &endpoint,
            &HashMap::new(),
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &mocks,
            &HeaderMap::new(),
        )
        .await
        .expect("a mocked nested-many source should resolve cleanly");

        let Some(Some(Value::Array(rows))) = resolved.get("cars") else {
            panic!("expected sources.cars to resolve to an array");
        };
        assert_eq!(rows.len(), 3);
        for row in rows {
            assert_eq!(row["pricing"]["amount"], 42, "every row must get the exact same mocked value");
        }
        assert_eq!(
            call_count.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a mocked nested-many source must never make a real call"
        );
    }
}
