mod docs_summary;
mod error;
mod format;
pub(crate) mod mock;
mod request_validation;
mod resolve;
mod schema;

use std::collections::{BTreeMap, HashMap};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::extract::{Extension, Path as AxumPath, Query, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, any, delete, get, patch, post, put};
use axum::{Json, Router};

use crate::config::ConnectionConfig;
use crate::errors::{DiscoveredErrors, ErrorRegistry};
use crate::openapi::method_token;
use crate::openapi::{Operation, ResponseMode};
use crate::security::{ClientCertIdentity, SecurityConfig, VerifierCache};
use crate::server::RequestId;
use crate::sql::SqlDriver;
use serde_json::{Map, Value};

/// Re-exported for `testing`, the only other module that needs to reach
/// into `endpoint`'s internals — `EndpointFile` to load the file a test
/// case runs against, `MockOutcome` because it's the exact type
/// `resolve_sources` consumes (test-file `mocks` deserialize directly into
/// it, see `endpoint::resolve::MockOutcome`, rather than a separate parsed
/// copy `testing` would otherwise have to convert), `nested_many_parent` and
/// `SourceDef` because `commands::test::record`'s own nested-many mock-
/// capture pass needs to find each `allowNestedMany` source's bracket
/// parent the same way `resolve_nested_many`/`validate_nested_many` do.
pub(crate) use docs_summary::endpoint_summaries;
use mock::{InboundRequest, MockProvider, MockSelection, RouteKey, Served};
pub(crate) use resolve::{MockOutcome, nested_many_parent};
use schema::{Cardinality, ErrorOverride};
pub(crate) use schema::{EndpointFile, SourceDef};

/// Everything one route's handler needs, baked in at startup so the handler
/// function itself can stay generic and shared across every route.
struct RouteState {
    endpoint: EndpointFile,
    /// This route in OpenAPI-style `{name}` form — what a `MockProvider`
    /// keys its `.test.json` files by, and what the report names.
    route: RouteKey,
    sql_root: PathBuf,
    http_root: PathBuf,
    drivers: Arc<HashMap<String, Box<dyn SqlDriver>>>,
    http_client: reqwest::Client,
    errors: Arc<ErrorRegistry>,
    security: Arc<SecurityConfig>,
    /// The service registry (`config/services.json`), name → base URL —
    /// only ever non-empty when `features.serviceRegistry` is on (see
    /// `config::Config::load`); reachable from an HTTP source's `url`/`body`
    /// templates as `{{services.<name>}}`.
    services: Arc<HashMap<String, String>>,
    /// Shared across every route (not one cache per route), so two
    /// endpoints protected by the same scheme reuse one cached result for
    /// the same credential instead of each paying their own round-trip.
    verifier_cache: Arc<VerifierCache>,
    /// The observe half of observe–react (design doc): shared, mutable,
    /// updated in place by `error_envelope` whenever a classified code
    /// isn't in `errors` and `debugMode` is on — see
    /// `record_discovered_error`.
    discovered_errors: Arc<Mutex<DiscoveredErrors>>,
    discovered_errors_path: PathBuf,
    debug_mode: bool,
    /// This route's matching `openapi.yaml` operation, for request
    /// validation — `None` when `features.requestValidation` is off, or
    /// (a warn-and-skip, not a startup failure) no operation matching this
    /// route's path+method was found.
    operation: Option<Operation>,
    /// Shared across every route (the same `openapi.yaml` document, not a
    /// fresh copy per route) — only ever consulted when `operation` above
    /// is `Some`, for resolving a request body schema's `$ref`s.
    component_schemas: Arc<Map<String, Value>>,
    /// The project-wide fallback bound on one ordinary source's real call,
    /// already clamped at router-assembly time via
    /// `ServerConfig::effective_source_call_timeout_ms` — a source's own
    /// `callTimeoutMs` overrides it per source (see
    /// `resolve::resolve_sources`).
    source_call_timeout_ms: NonZeroU64,
    /// `Some` only under `frogs test` — every request on this route then
    /// resolves from the provider's mocks instead of real infrastructure
    /// (see `mock::MockProvider`). `frogs run` always passes `None`, so its
    /// request path is byte-for-byte the pre-mock-server one.
    mock_provider: Option<Arc<dyn MockProvider>>,
    /// Copied from the matched `openapi.yaml` operation (`Single` when there
    /// is none). Only ever a seam today: every mode is served as one JSON
    /// response.
    response_mode: ResponseMode,
}

/// Whether an endpoint file declares the top-level `"stream"` key, which is
/// reserved for streaming support this version doesn't have. Presence is
/// enough (a `null` value counts); nested `stream` keys don't.
pub(crate) fn has_reserved_stream_key(contents: &str) -> bool {
    serde_json::from_str::<Value>(contents).is_ok_and(|v| v.as_object().is_some_and(|obj| obj.contains_key("stream")))
}

pub(crate) fn reserved_stream_key_files(endpoints_root: &Path) -> Vec<PathBuf> {
    discover_endpoint_files(endpoints_root)
        .into_iter()
        .filter(|(_, _, file_path)| std::fs::read_to_string(file_path).is_ok_and(|contents| has_reserved_stream_key(&contents)))
        .map(|(_, _, file_path)| file_path)
        .collect()
}

/// Scans `datasources/endpoints/` for `endpoint.<method>.json` files (one
/// of `method_token::ROUTABLE_FIXED`) and registers one axum route per
/// distinct path (QUERY lives in a per-path dispatch table, see
/// `dispatch_extension`).
/// `drivers` is already `Arc`-wrapped by the caller (`commands::run`), not
/// built fresh here, so the same connection pool can be shared with
/// `server::router`'s `/readyz` check rather than each holding its own copy.
/// `discovered_errors` likewise arrives pre-loaded (from the same `Config`
/// that loaded `errors`), wrapped in a `Mutex` here since — unlike
/// `errors`, loaded once and read-only for the process's whole lifetime —
/// it's written to at request time.
#[allow(clippy::too_many_arguments)]
pub fn build_router(
    project_root: &Path,
    drivers: Arc<HashMap<String, Box<dyn SqlDriver>>>,
    connections: &HashMap<String, ConnectionConfig>,
    errors: Arc<ErrorRegistry>,
    security: Arc<SecurityConfig>,
    services: Arc<HashMap<String, String>>,
    discovered_errors: Arc<Mutex<DiscoveredErrors>>,
    debug_mode: bool,
    // `None` when `features.requestValidation` is off, or `openapi.yaml`
    // couldn't be loaded at all (`commands::run` already warns about that
    // case — this function just degrades to "no route gets validation"
    // rather than failing every route registration over it).
    openapi_document: Option<&crate::openapi::OpenApiDocument>,
    mock_provider: Option<Arc<dyn MockProvider>>,
    // Already-resolved and already-clamped — the caller
    // (`commands::run::assemble_api_router`) passes
    // `config.server.effective_source_call_timeout_ms()`, which is where the
    // `MAX_SOURCE_CALL_TIMEOUT_MS` ceiling and its one-time warning live.
    source_call_timeout_ms: NonZeroU64,
    // Whether this process can ever hand a handler a client-certificate
    // identity (a `clientAuth`-enabled TLS listener, or `frogs test`'s mock
    // provider). A route whose verifier needs one is refused otherwise —
    // it could never succeed, and "no certificate required" must never be
    // what an unreachable cert-dependent route silently degrades to.
    client_identity_available: bool,
) -> Router {
    let sql_root = project_root.join("datasources/sql");
    let http_root = project_root.join("datasources/http");
    let endpoints_root = project_root.join("datasources/endpoints");
    let discovered_errors_path = project_root.join("config/errors.discovered.json");
    // One shared client for every route — reuses connection pooling across
    // requests instead of paying a fresh-connection cost per call.
    let http_client = reqwest::Client::new();
    let verifier_cache = Arc::new(VerifierCache::new());
    let component_schemas = Arc::new(openapi_document.map(|doc| doc.component_schemas.clone()).unwrap_or_default());

    for (file_path, canonical) in non_canonical_method_files(&endpoints_root) {
        tracing::warn!(
            "{} is not served; rename it to endpoint.{canonical}.json",
            crate::openapi::untrusted(&file_path.display().to_string())
        );
    }

    let mut by_path: BTreeMap<String, PathRoutes> = BTreeMap::new();
    for (url_path, method, file_path) in discover_endpoint_files(&endpoints_root) {
        let Some(token) = method_token::parse_file_token(&method) else {
            tracing::warn!("skipping {}: not a method frogs routes", file_path.display());
            continue;
        };
        let wire = token.wire();
        let contents = match std::fs::read_to_string(&file_path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("skipping {}: {e}", file_path.display());
                continue;
            }
        };
        let endpoint: EndpointFile = match serde_json::from_str(&contents) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("skipping {}: invalid JSON: {e}", file_path.display());
                continue;
            }
        };

        // A declared scheme that `security/schemes.json` doesn't actually
        // define is a config mistake — fail closed by refusing to serve
        // the route at all rather than accidentally leaving it open, the
        // same "skip with a loud warning" posture used for a malformed
        // endpoint file above.
        if let Some(scheme) = &endpoint.security
            && !security.verifiers.contains_key(scheme)
        {
            tracing::warn!(
                "skipping {}: security scheme '{scheme}' has no matching entry in security/schemes.json",
                file_path.display()
            );
            continue;
        }

        if let Some(scheme) = &endpoint.security
            && let Some(verifier) = security.verifiers.get(scheme)
            && verifier.requires_client_cert()
            && !client_identity_available
        {
            tracing::warn!(
                "skipping {}: security scheme '{scheme}' needs a client certificate, but this server's TLS listener doesn't request one \
                 (set tls.mode to \"manual\" and enable tls.clientAuth in config/server.json)",
                file_path.display()
            );
            continue;
        }

        let mut source_problems = validate_nested_many(&endpoint, connections);
        source_problems.extend(validate_source_call_timeout(&endpoint));
        if !source_problems.is_empty() {
            for problem in &source_problems {
                tracing::warn!("skipping {}: {problem}", file_path.display());
            }
            continue;
        }

        tracing::info!("{wire} {url_path} -> {} (operationId: {})", file_path.display(), endpoint.operation_id);

        if has_reserved_stream_key(&contents) {
            tracing::warn!(
                "{}: \"stream\" is reserved for streaming responses, which this frogs version does not implement — serving a single JSON response",
                file_path.display()
            );
        }

        let operation = openapi_document.and_then(|doc| find_operation(doc, &url_path, &method));
        if openapi_document.is_some() && operation.is_none() {
            tracing::warn!(
                "{}: no matching operation found in openapi.yaml — request validation skipped for this route",
                file_path.display()
            );
        }
        if let Some(op) = operation {
            if let ResponseMode::Stream(spec) = &op.response_mode {
                tracing::warn!(
                    "{wire} {url_path}: declares a streaming response ({}); frogs does not serve streaming responses — serving a single JSON response",
                    crate::openapi::untrusted(&spec.media_type)
                );
            }
            if let Some(reason) = &op.request_body_unresolved {
                tracing::warn!("{wire} {url_path}: request body schema unresolved ({reason}) — body validation skipped for this route");
            }
        }
        let response_mode = operation.map(|op| op.response_mode.clone()).unwrap_or_default();

        // Each route gets its own `RouteState` baked in via `with_state` —
        // this is what lets one shared `handle_request` function serve
        // every endpoint file: axum's `State` extractor pulls out whichever
        // `Arc<RouteState>` this particular route was registered with.
        let state = Arc::new(RouteState {
            endpoint,
            route: RouteKey {
                method: method.clone(),
                path: mock::openapi_style_path(&url_path),
            },
            sql_root: sql_root.clone(),
            http_root: http_root.clone(),
            drivers: drivers.clone(),
            http_client: http_client.clone(),
            errors: errors.clone(),
            security: security.clone(),
            services: services.clone(),
            verifier_cache: verifier_cache.clone(),
            discovered_errors: discovered_errors.clone(),
            discovered_errors_path: discovered_errors_path.clone(),
            debug_mode,
            operation: operation.cloned(),
            component_schemas: component_schemas.clone(),
            source_call_timeout_ms,
            mock_provider: mock_provider.clone(),
            response_mode,
        });
        // Read back out before `state` moves into `.with_state` below —
        // this endpoint's own `rateLimit`, if it declared one, gets its own
        // dedicated bucket layered onto just this route (in addition to,
        // not instead of, the global bucket `apply_rate_limit` applies to
        // the whole router in `commands::run`).
        let rate_limit_override = state.endpoint.rate_limit.clone();

        let routes = by_path.entry(url_path.clone()).or_default();
        let mut method_router: MethodRouter<()> = match token.standard_method() {
            Some(Method::GET) => get(handle_request).with_state(state),
            Some(Method::POST) => post(handle_request).with_state(state),
            Some(Method::PUT) => put(handle_request).with_state(state),
            Some(Method::PATCH) => patch(handle_request).with_state(state),
            Some(Method::DELETE) => delete(handle_request).with_state(state),
            _ => any(handle_request).with_state(state),
        };
        if let Some(rate_limit) = rate_limit_override {
            let limiter = Arc::new(crate::server::RateLimiter::new(rate_limit.requests_per_second, rate_limit.burst));
            method_router = crate::server::apply_rate_limit_to_route(method_router, limiter);
        }
        if token.standard_method().is_some() {
            if routes.standard_names.iter().any(|n| n == wire.as_ref()) {
                tracing::warn!("skipping {}: {wire} {url_path} is already registered by another endpoint file", file_path.display());
                continue;
            }
            routes.standard_names.push(wire.to_string());
            routes.standard = Some(match routes.standard.take() {
                Some(existing) => existing.merge(method_router),
                None => method_router,
            });
        } else {
            let Ok(wire_method) = Method::from_bytes(wire.as_bytes()) else {
                tracing::warn!("skipping {}: {wire} is not a valid HTTP method", file_path.display());
                continue;
            };
            if routes.table.contains_key(&wire_method) {
                tracing::warn!("skipping {}: {wire} {url_path} is already registered by another endpoint file", file_path.display());
                continue;
            }
            routes.table.insert(wire_method, method_router);
        }
    }

    // axum merges per-path method routers but rejects a second fallback, so the
    // extension-method dispatcher can only be attached once everything for the
    // path is merged — hence one `router.route` per path, not per file.
    let mut router = Router::new();
    for (url_path, routes) in by_path {
        let PathRoutes { standard, standard_names, table } = routes;
        let mut combined = standard.unwrap_or_default();
        if !table.is_empty() {
            let allow = allow_header_value(&standard_names, &table);
            let table = Arc::new(table);
            combined = combined.fallback(move |req: axum::extract::Request| dispatch_extension(table.clone(), allow.clone(), req));
        }
        router = router.route(&url_path, combined);
    }
    router
}

#[derive(Default)]
struct PathRoutes {
    standard: Option<MethodRouter<()>>,
    standard_names: Vec<String>,
    table: HashMap<Method, MethodRouter<()>>,
}

/// Same comma-separated, no-space format axum builds for its own `Allow`.
/// Never OPTIONS: frogs doesn't route it.
fn allow_header_value(standard_names: &[String], table: &HashMap<Method, MethodRouter<()>>) -> HeaderValue {
    let has = |name: &str| standard_names.iter().any(|n| n == name);
    let mut parts: Vec<String> = Vec::new();
    for name in ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"] {
        let present = if name == "HEAD" { has("GET") } else { has(name) };
        if present {
            parts.push(name.to_string());
        }
    }
    let mut extension: Vec<&str> = table.keys().map(Method::as_str).collect();
    extension.sort_unstable();
    parts.extend(extension.into_iter().map(str::to_string));
    HeaderValue::from_str(&parts.join(",")).unwrap_or_else(|_| HeaderValue::from_static(""))
}

/// Serves the methods axum's `MethodFilter` can't express (QUERY today). The
/// lookup is an exact, case-sensitive match on the method as it reached the
/// router; the request is handed on untouched and its body is never read here.
async fn dispatch_extension(table: Arc<HashMap<Method, MethodRouter<()>>>, allow: HeaderValue, req: axum::extract::Request) -> Response {
    use tower_service::Service;

    let Some(entry) = table.get(req.method()) else {
        let mut response = Response::new(axum::body::Body::empty());
        *response.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
        response.headers_mut().insert(header::ALLOW, allow);
        return response;
    };
    let mut service = entry.clone();
    let ready = std::future::poll_fn(|cx| Service::<axum::extract::Request>::poll_ready(&mut service, cx)).await;
    let mut response = match ready {
        Ok(()) => match service.call(req).await {
            Ok(response) => response,
            Err(infallible) => match infallible {},
        },
        Err(infallible) => match infallible {},
    };
    // axum's per-path fallback fills in a partial (or empty) Allow on every
    // response that lacks one, 200s included — set the full list ourselves.
    if !response.headers().contains_key(header::ALLOW) {
        response.headers_mut().insert(header::ALLOW, allow);
    }
    response
}

/// Parses every discovered endpoint file and reports problems without
/// building any routes — `frogs validate`'s read-only counterpart to
/// `build_router`'s own per-file loop. Deliberately not sharing code with
/// `build_router` itself: that function also constructs a route/
/// `RouteState` per file, which a dry run has no use for, and the actual
/// check logic (parse JSON, confirm a declared security scheme resolves)
/// is small enough that duplicating it here stays cheaper than
/// restructuring `build_router` to serve both callers.
pub(crate) fn validate_endpoint_files(
    endpoints_root: &Path,
    security: &SecurityConfig,
    connections: &HashMap<String, ConnectionConfig>,
    client_identity_available: bool,
) -> (usize, Vec<String>) {
    let discovered = discover_endpoint_files(endpoints_root);
    let count = discovered.len();
    let mut problems = Vec::new();

    for (_, _, file_path) in discovered {
        let contents = match std::fs::read_to_string(&file_path) {
            Ok(c) => c,
            Err(e) => {
                problems.push(format!("{}: {e}", file_path.display()));
                continue;
            }
        };
        let endpoint: EndpointFile = match serde_json::from_str(&contents) {
            Ok(e) => e,
            Err(e) => {
                problems.push(format!("{}: invalid JSON: {e}", file_path.display()));
                continue;
            }
        };
        if let Some(scheme) = &endpoint.security
            && !security.verifiers.contains_key(scheme)
        {
            problems.push(format!(
                "{}: security scheme '{scheme}' has no matching entry in security/schemes.json",
                file_path.display()
            ));
        }
        if let Some(scheme) = &endpoint.security
            && let Some(verifier) = security.verifiers.get(scheme)
            && verifier.requires_client_cert()
            && !client_identity_available
        {
            problems.push(format!(
                "{}: security scheme '{scheme}' needs a client certificate, but tls.clientAuth is off or absent — this route would be refused at startup",
                file_path.display()
            ));
        }
        for problem in validate_nested_many(&endpoint, connections) {
            problems.push(format!("{}: {problem}", file_path.display()));
        }
        for problem in validate_source_call_timeout(&endpoint) {
            problems.push(format!("{}: {problem}", file_path.display()));
        }
    }

    (count, problems)
}

/// The fraction of a SQL connection's real pool capacity
/// (`sql::pool_capacity`) a single nested-many source's own `maxConcurrency`
/// may claim — so this feature's own concurrency surface can't alone
/// exhaust a shared pool other requests/sources also depend on. Evaluates to
/// 3 at today's real `DEFAULT_POOL_MAX_CONNECTIONS` (5) default.
/// Validation-time-only, so it lives here rather than alongside
/// `resolve.rs`'s other nested-many constants.
const NESTED_MANY_POOL_CONCURRENCY_FRACTION: f64 = 0.6;

/// Rejects a per-endpoint nested-many misconfiguration before it can ever
/// run — see the design doc's "Many-Depends-on-Many Array Fan-Out" plan,
/// point 7. Called from both `build_router` (fail-closed: skip the route,
/// same posture as an unmatched security scheme) and
/// `validate_endpoint_files` (`frogs validate`'s read-only report). Skips
/// the pool-derived `maxConcurrency` ceiling check entirely when `connections`
/// doesn't name the source's own SQL connection at all — a pre-existing,
/// more general "unknown connection" gap, not newly invented here; it
/// already fails every request for that source at runtime regardless.
fn validate_nested_many(endpoint: &EndpointFile, connections: &HashMap<String, ConnectionConfig>) -> Vec<String> {
    let mut problems = Vec::new();

    for (name, source) in &endpoint.sources {
        let (allow_nested_many, max_concurrency, max_rows, row_timeout_ms, parameters, sql_connection) = match source {
            SourceDef::Sql {
                allow_nested_many,
                max_concurrency,
                max_rows,
                row_timeout_ms,
                parameters,
                connection,
                ..
            } => (
                *allow_nested_many,
                *max_concurrency,
                *max_rows,
                *row_timeout_ms,
                parameters,
                Some(connection.as_str()),
            ),
            SourceDef::Http {
                allow_nested_many,
                max_concurrency,
                max_rows,
                row_timeout_ms,
                parameters,
                ..
            } => (*allow_nested_many, *max_concurrency, *max_rows, *row_timeout_ms, parameters, None),
        };

        if !allow_nested_many {
            // A bracket-form parameter on a source that isn't itself
            // `allowNestedMany` is a config mistake regardless of whether
            // this source has any of the other nested-many fields set.
            for param in parameters {
                if resolve::parse_bracket_array_path(&param.from).is_some() {
                    problems.push(format!(
                        "source '{name}': parameter '{}' uses bracket fan-out syntax (\"sources.<parent>[].<field>\") \
                         but this source doesn't declare \"allowNestedMany\": true",
                        param.from
                    ));
                }
            }
            continue;
        }

        let Some(max_concurrency) = max_concurrency else {
            problems.push(format!("source '{name}': \"allowNestedMany\": true requires \"maxConcurrency\" to be set"));
            continue;
        };
        let Some(max_rows) = max_rows else {
            problems.push(format!("source '{name}': \"allowNestedMany\": true requires \"maxRows\" to be set"));
            continue;
        };

        if max_concurrency.get() > resolve::MAX_NESTED_MANY_CONCURRENCY {
            problems.push(format!(
                "source '{name}': maxConcurrency {} exceeds the hard ceiling of {}",
                max_concurrency.get(),
                resolve::MAX_NESTED_MANY_CONCURRENCY
            ));
        }
        if max_rows.get() > resolve::MAX_NESTED_MANY_ROWS {
            problems.push(format!(
                "source '{name}': maxRows {} exceeds the hard ceiling of {}",
                max_rows.get(),
                resolve::MAX_NESTED_MANY_ROWS
            ));
        }
        if let Some(row_timeout_ms) = row_timeout_ms
            && row_timeout_ms.get() > resolve::MAX_NESTED_MANY_ROW_TIMEOUT_MS
        {
            problems.push(format!(
                "source '{name}': rowTimeoutMs {} exceeds the hard ceiling of {}",
                row_timeout_ms.get(),
                resolve::MAX_NESTED_MANY_ROW_TIMEOUT_MS
            ));
        }

        if let Some(connection_name) = sql_connection
            && let Some(conn) = connections.get(connection_name)
            && let Some(capacity) = crate::sql::pool_capacity(conn)
        {
            let pool_ceiling = ((capacity as f64 * NESTED_MANY_POOL_CONCURRENCY_FRACTION).floor() as usize).max(1);
            let ceiling = resolve::MAX_NESTED_MANY_CONCURRENCY.min(pool_ceiling);
            if max_concurrency.get() > ceiling {
                problems.push(format!(
                    "source '{name}': maxConcurrency {} exceeds the pool-derived ceiling of {ceiling} for connection \
                     '{connection_name}' (pool capacity {capacity}) — a single nested-many source may claim at most \
                     {}% of a connection's pool",
                    max_concurrency.get(),
                    (NESTED_MANY_POOL_CONCURRENCY_FRACTION * 100.0) as u32
                ));
            }
        }

        match resolve::nested_many_parent(parameters) {
            Ok(parent_name) => match endpoint.sources.get(parent_name) {
                Some(SourceDef::Sql {
                    cardinality,
                    allow_nested_many: parent_nested,
                    ..
                })
                | Some(SourceDef::Http {
                    cardinality,
                    allow_nested_many: parent_nested,
                    ..
                }) => {
                    if *cardinality != Cardinality::Many {
                        problems.push(format!("source '{name}': bracket-parent '{parent_name}' must declare \"cardinality\": \"many\""));
                    }
                    if *parent_nested {
                        problems.push(format!(
                            "source '{name}': bracket-parent '{parent_name}' is itself allowNestedMany — multi-level fan-out isn't supported"
                        ));
                    }
                }
                None => problems.push(format!("source '{name}': bracket-parent '{parent_name}' isn't declared in this endpoint's sources")),
            },
            Err(message) => problems.push(format!("source '{name}': {message}")),
        }
    }

    problems
}

/// Rejects a per-source `callTimeoutMs` misconfiguration before it can ever
/// run — same two callers and same fail-closed "skip the route" posture as
/// `validate_nested_many`. No pool-capacity-relative ceiling here, unlike
/// nested-many's `maxConcurrency`: bounding a *single* call's duration
/// doesn't create the same concurrency-vs-pool-size pressure.
/// `server.json`'s own `sourceCallTimeoutMs` isn't checked here at all —
/// `ServerConfig::effective_source_call_timeout_ms` clamps it (and
/// `commands::validate` reports it), rather than a startup refusal.
fn validate_source_call_timeout(endpoint: &EndpointFile) -> Vec<String> {
    let mut problems = Vec::new();

    for (name, source) in &endpoint.sources {
        let (allow_nested_many, call_timeout_ms) = match source {
            SourceDef::Sql {
                allow_nested_many,
                call_timeout_ms,
                ..
            }
            | SourceDef::Http {
                allow_nested_many,
                call_timeout_ms,
                ..
            } => (*allow_nested_many, *call_timeout_ms),
        };

        let Some(call_timeout_ms) = call_timeout_ms else { continue };

        if call_timeout_ms.get() > crate::config::MAX_SOURCE_CALL_TIMEOUT_MS {
            problems.push(format!(
                "source '{name}': callTimeoutMs {} exceeds the hard ceiling of {}",
                call_timeout_ms.get(),
                crate::config::MAX_SOURCE_CALL_TIMEOUT_MS
            ));
        }
        if allow_nested_many {
            problems.push(format!(
                "source '{name}' declares both allowNestedMany and callTimeoutMs — callTimeoutMs only bounds an ordinary single call; \
                 use rowTimeoutMs to bound this source's per-row fan-out calls instead"
            ));
        }
    }

    problems
}

async fn handle_request(
    State(state): State<Arc<RouteState>>,
    AxumPath(path_params): AxumPath<HashMap<String, String>>,
    Query(query_params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    // `Option` rather than a bare `Extension<RequestId>`: the extractor
    // fails the request outright if the extension isn't present, which
    // would make every route depend on `server::apply_middleware` having
    // run first. It always has in the real `commands::run` path, but
    // falling back gracefully here (see below) keeps that an operational
    // guarantee this handler benefits from, not one it silently requires.
    transaction_id: Option<Extension<RequestId>>,
    // Set only by `server::tls::ClientCertAcceptor` (which strips any
    // pre-existing copy first) — never derived from a header.
    client_cert: Option<Extension<Arc<ClientCertIdentity>>>,
    // A body-consuming extractor must come last — axum can only hand the
    // request body to one extractor. `Bytes` (not `Json<Value>`) since a
    // GET/DELETE typically sends none at all, and `Json` would hard-fail
    // on an empty body instead of treating "no body" as `Value::Null`.
    raw_body: axum::body::Bytes,
) -> Response {
    // A missing or malformed body becomes `Value::Null` — request
    // validation (below, when `state.operation` is `Some`) is what catches
    // a genuinely malformed/missing body against the OpenAPI schema; this
    // is just "don't crash parsing it."
    let body: Value = if raw_body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&raw_body).unwrap_or(Value::Null)
    };
    let transaction_id = transaction_id.map(|Extension(RequestId(id))| id).unwrap_or_default();
    let client_cert = client_cert.map(|Extension(identity)| identity);

    match &state.response_mode {
        ResponseMode::Single => respond_single(&state, &headers, client_cert.as_deref(), &path_params, &query_params, &body, &transaction_id).await,
        // The seam for a future stream executor; today a declared stream is still one JSON response.
        ResponseMode::Stream(_) => respond_single(&state, &headers, client_cert.as_deref(), &path_params, &query_params, &body, &transaction_id).await,
    }
}

async fn respond_single(
    state: &RouteState,
    headers: &HeaderMap,
    client_cert: Option<&ClientCertIdentity>,
    path_params: &HashMap<String, String>,
    query_params: &HashMap<String, String>,
    body: &Value,
    transaction_id: &str,
) -> Response {
    let (http_status, response_body) = match &state.mock_provider {
        None => {
            resolve_request(
                &state.endpoint,
                &state.security,
                &state.services,
                &state.drivers,
                &state.sql_root,
                &state.http_root,
                &state.http_client,
                &state.errors,
                &state.discovered_errors,
                &state.discovered_errors_path,
                state.debug_mode,
                &state.verifier_cache,
                headers,
                client_cert,
                path_params,
                query_params,
                body,
                transaction_id,
                &HashMap::new(),
                state.operation.as_ref(),
                &state.component_schemas,
                state.source_call_timeout_ms,
            )
            .await
        }
        Some(provider) => handle_mocked(state, provider.as_ref(), headers, client_cert, path_params, query_params, body, transaction_id).await,
    };

    let status = StatusCode::from_u16(http_status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, Json(response_body)).into_response()
}

/// The `frogs test` request path: ask the provider which case (and mocks)
/// this request gets, fill in every unmocked source so nothing real is
/// ever contacted, resolve through the exact same `resolve_request` a real
/// request uses, then hand the outcome back to the provider for its
/// report. A `Reject`/`NoMatch` never reaches resolution at all — it's
/// classified through `error_envelope` like any other failure, honoring
/// the endpoint's own `debugMode`/`errorOverrides` the same way
/// `resolve_request` itself does.
#[allow(clippy::too_many_arguments)]
async fn handle_mocked(
    state: &RouteState,
    provider: &dyn MockProvider,
    headers: &HeaderMap,
    // The identity of a real TLS connection to the mock server, when it
    // runs with `clientAuth` — a case's own `clientCert` wins over it, and
    // neither is ever read from a header.
    connection_cert: Option<&ClientCertIdentity>,
    path_params: &HashMap<String, String>,
    query_params: &HashMap<String, String>,
    body: &Value,
    transaction_id: &str,
) -> (u16, Value) {
    let started = std::time::Instant::now();
    let inbound = InboundRequest {
        path_params,
        query_params,
        headers,
        body,
    };
    let selection = provider.select(&state.route, &inbound);
    let debug_mode = state.endpoint.debug_mode.unwrap_or(state.debug_mode);

    let mut unmocked = Vec::new();
    let (status, response_body) = match &selection {
        MockSelection::Reject { code, detail, .. } => error_envelope(
            &state.errors,
            &state.discovered_errors,
            &state.discovered_errors_path,
            debug_mode,
            code,
            detail,
            None,
            &state.endpoint.error_overrides,
        ),
        MockSelection::NoMatch { detail, .. } => error_envelope(
            &state.errors,
            &state.discovered_errors,
            &state.discovered_errors_path,
            debug_mode,
            mock::NO_MATCHING_CASE,
            detail,
            None,
            &state.endpoint.error_overrides,
        ),
        MockSelection::Case { case, mocks, client_cert, .. } => {
            let mut mocks = mocks.clone();
            let verifier_is_datasource_free = state
                .endpoint
                .security
                .as_ref()
                .and_then(|scheme| state.security.verifiers.get(scheme))
                .is_some_and(|verifier| verifier.mtls.is_some());
            unmocked = mock::enforce_no_real_infrastructure(&state.endpoint, verifier_is_datasource_free, &mut mocks);
            let (status, mut response_body) = resolve_request(
                &state.endpoint,
                &state.security,
                &state.services,
                &state.drivers,
                &state.sql_root,
                &state.http_root,
                &state.http_client,
                &state.errors,
                &state.discovered_errors,
                &state.discovered_errors_path,
                state.debug_mode,
                &state.verifier_cache,
                headers,
                client_cert.as_deref().or(connection_cert),
                path_params,
                query_params,
                body,
                transaction_id,
                &mocks,
                state.operation.as_ref(),
                &state.component_schemas,
                state.source_call_timeout_ms,
            )
            .await;
            // The generic "mocked failure: <code>" detail `resolve_request`
            // produces is replaced with one naming what wasn't mocked and
            // which case was matched — only when a detail is being exposed
            // at all, so `exposeDetail`/`debugMode`/`errorOverrides` still
            // have the last word on whether a caller sees any detail.
            if response_body.get("name").and_then(Value::as_str) == Some(mock::SOURCE_NOT_MOCKED) && response_body.get("detail").is_some() {
                response_body["detail"] = Value::String(not_mocked_detail(&unmocked, case.as_ref()));
            }
            (status, response_body)
        }
    };

    let served = Served {
        status,
        body: &response_body,
        unmocked: &unmocked,
        request_id: transaction_id,
        elapsed: started.elapsed(),
    };
    provider.observe(&state.route, &selection, &served);

    (status, response_body)
}

fn not_mocked_detail(unmocked: &[mock::Unmocked], case: Option<&mock::CaseRef>) -> String {
    let required: Vec<&str> = unmocked.iter().filter(|u| !u.optional).map(|u| u.name.as_str()).collect();
    let matched = match case {
        Some(case) => format!("matched case \"{}\" in {}", case.name, case.file.display()),
        None => "no .test.json file exists for this route".to_string(),
    };
    format!(
        "source(s) not mocked: {} — {matched}; frogs test never contacts real infrastructure, add a mock for each",
        required.join(", ")
    )
}

/// Runs one endpoint's whole request — the security check (real, or mocked
/// via the reserved `"verifier"` key), then source resolution (real or
/// mocked per `mocks`) — and builds the exact `(status, body)` a caller
/// would receive. `handle_request` calls this for every real HTTP request
/// (with an empty `mocks` map); the `testing` module's case runner calls it
/// too, with whatever a `.test.json` case declares — this is what makes a
/// test case exercise the *real* security/response-building/error-envelope
/// logic end to end, never a reimplementation of it. `mocks` may contain
/// ordinary source names, the reserved `"verifier"` name, or both —
/// `resolve::resolve_sources` only ever looks up real source names, so a
/// `"verifier"` entry already present is simply never matched there.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn resolve_request(
    endpoint: &EndpointFile,
    security: &SecurityConfig,
    services: &HashMap<String, String>,
    drivers: &HashMap<String, Box<dyn SqlDriver>>,
    sql_root: &Path,
    http_root: &Path,
    http_client: &reqwest::Client,
    errors: &ErrorRegistry,
    discovered_errors: &Mutex<DiscoveredErrors>,
    discovered_errors_path: &Path,
    debug_mode: bool,
    verifier_cache: &VerifierCache,
    headers: &HeaderMap,
    // The connection's validated client certificate, if it presented one —
    // see `server::tls`. Only a certificate-dependent verifier ever reads it.
    client_cert: Option<&ClientCertIdentity>,
    path_params: &HashMap<String, String>,
    query_params: &HashMap<String, String>,
    body: &Value,
    transaction_id: &str,
    mocks: &HashMap<String, MockOutcome>,
    // `None` either means `features.requestValidation` is off, or this
    // endpoint's operation couldn't be matched in `openapi.yaml` at
    // startup — both cases skip validation entirely rather than block the
    // request, the same graceful-degradation posture an unmatched security
    // scheme does *not* get (that one fails closed, since it's a security
    // concern; this one isn't).
    operation: Option<&Operation>,
    component_schemas: &Map<String, Value>,
    // The project-wide source-call bound, already resolved and clamped by
    // the caller — threaded into both ordinary source resolution and the
    // security verifier (which has no per-verifier override of its own).
    source_call_timeout_ms: NonZeroU64,
) -> (u16, Value) {
    // A still-`_generated: true` stub is refused *before* anything else
    // runs — including the security check below. It isn't really "this
    // endpoint's own request handling" yet, so there's nothing to
    // authorize a caller against; gating here first also means a stub
    // that's still mid-edit (security scheme not wired up correctly yet,
    // say) doesn't produce a confusing auth error while someone's actively
    // filling it in. Always shows the todo message regardless of
    // `exposeDetail`/`debugMode` — the whole point is telling whoever's
    // looking exactly what to do next, not something to hide from a caller.
    if endpoint.generated {
        let body = serde_json::json!({
            "code": 501,
            "name": "endpoint.not_configured",
            "detail": endpoint.todo.as_deref().unwrap_or("this endpoint is a generated stub and hasn't been filled in yet"),
        });
        return (501, body);
    }

    // This endpoint's own `debugMode`, if it set one, overrides the
    // server-wide default for everything below — every use of `debug_mode`
    // for the rest of this function (including inside `error_envelope`)
    // sees this effective value, not the raw parameter.
    let debug_mode = endpoint.debug_mode.unwrap_or(debug_mode);

    if let Some(scheme) = &endpoint.security {
        let Some(verifier) = security.verifiers.get(scheme) else {
            // In the real `build_router` path this can't happen — a route
            // whose scheme has no matching verifier is never registered at
            // all (see below). The test runner discovers endpoint files
            // directly, without that same pre-check, so this stays a
            // reachable (if unusual) outcome there, classified the same
            // way any other configuration mistake is.
            return error_envelope(
                errors,
                discovered_errors,
                discovered_errors_path,
                debug_mode,
                "unexpected.error",
                &format!("security scheme '{scheme}' has no matching entry in security/schemes.json"),
                None,
                &endpoint.error_overrides,
            );
        };

        // Before the verifier is consulted at all (real or mocked): a
        // certificate-dependent scheme with no certificate, or one that has
        // outlived its validity on a long-lived connection, is refused
        // without touching any datasource.
        let cert_failure = if verifier.requires_client_cert() {
            match client_cert {
                None => Some(("auth.client_cert_missing", "no client certificate was presented")),
                Some(identity) if !identity.is_valid_at(chrono::Utc::now()) => {
                    Some(("auth.client_cert_expired", "the client certificate is outside its validity period"))
                }
                Some(_) => None,
            }
        } else {
            None
        };

        let verify_result = if let Some((code, message)) = cert_failure {
            Err((code.to_string(), message.to_string()))
        } else {
            match mocks.get("verifier") {
                Some(MockOutcome::Success(mock_value)) => {
                    let holds = match &verifier.mtls {
                        Some(condition) => ClientCertIdentity::from_identity_json(mock_value).is_some_and(|identity| condition.matches(&identity)),
                        None => verifier.valid_if.evaluate(mock_value),
                    };
                    if holds {
                        Ok(())
                    } else {
                        Err(("auth.invalid_credentials".to_string(), "mocked verifier: validIf did not hold".to_string()))
                    }
                }
                Some(MockOutcome::Fail(code)) => Err((code.clone(), format!("mocked failure: {code}"))),
                None => crate::security::verify(
                    scheme,
                    verifier,
                    drivers,
                    sql_root,
                    http_root,
                    http_client,
                    headers,
                    client_cert,
                    verifier_cache,
                    source_call_timeout_ms,
                )
                .await
                .map_err(|cause| (cause.code().to_string(), cause.message())),
            }
        };

        if let Err((code, message)) = verify_result {
            return error_envelope(
                errors,
                discovered_errors,
                discovered_errors_path,
                debug_mode,
                &code,
                &message,
                None,
                &endpoint.error_overrides,
            );
        }
    }

    // Runs *after* the security check above, deliberately — a caller who
    // fails authorization gets that failure regardless of whether their
    // request body also happens to be malformed; a request never gets
    // structurally validated before it's known the caller is even allowed
    // to make it.
    if let Some(operation) = operation
        && let Err(problem) = request_validation::validate_request(operation, component_schemas, path_params, query_params, headers, body)
    {
        return error_envelope(
            errors,
            discovered_errors,
            discovered_errors_path,
            debug_mode,
            problem.code,
            &problem.message,
            None,
            &endpoint.error_overrides,
        );
    }

    match resolve::resolve_sources(
        endpoint,
        services,
        drivers,
        sql_root,
        http_root,
        http_client,
        path_params,
        query_params,
        body,
        transaction_id,
        mocks,
        headers,
        source_call_timeout_ms,
    )
    .await
    {
        Ok(resolved) => {
            // `None` (the common GET case) or a status this endpoint file
            // never actually declared a valid one for — `generate`-time
            // validation is what catches the latter (see
            // `openapi::Operation::validate_success_status`), so falling
            // back to 200 here rather than 500 keeps a request-time bug
            // from also becoming a request-time crash.
            let status = endpoint.success_status.unwrap_or(200);
            (status, resolve::build_response(endpoint, &resolved))
        }
        Err(failure) => {
            // The source's own `onError`, if it set one, is a per-source
            // override of the classified code's registry status — omitted,
            // the registry's `httpStatus` for this code decides (e.g. a
            // `not_found` failure naturally returns 404 rather than a
            // generic 500), matching "override per source if you want
            // different behavior for a specific endpoint."
            error_envelope(
                errors,
                discovered_errors,
                discovered_errors_path,
                debug_mode,
                failure.cause.code(),
                &failure.cause.message(),
                failure.on_error,
                &endpoint.error_overrides,
            )
        }
    }
}

/// Runs every source in `endpoint.sources` for real — no mocks at all,
/// regardless of what a sibling `.test.json` file declares — and returns
/// each source's own resolved value alongside the would-be `(status,
/// body)` a real request would get. This is `frogs test record`'s engine:
/// unlike `resolve_request`, it never touches the security check at all
/// (recording captures *data-source* output; a verifier mock only ever
/// needs one field, `active`, cheap enough to author by hand — the design
/// doc's own example does exactly that) and it hands back the per-source
/// breakdown `resolve_request` normally collapses away, since that
/// breakdown *is* the `mocks` block record mode exists to produce.
///
/// `Err` is only returned for a *non-optional* source failure — nothing
/// can be recorded past that point, so the caller gets the failing
/// source's name, classified code, and message to report directly, without
/// `testing`/`commands` needing to know anything about `SourceErrorCause`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn record_sources(
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
    source_call_timeout_ms: NonZeroU64,
) -> Result<(u16, Value, HashMap<String, Option<Value>>), (String, String, String)> {
    match resolve::resolve_sources(
        endpoint,
        services,
        drivers,
        sql_root,
        http_root,
        http_client,
        path_params,
        query_params,
        body,
        transaction_id,
        &HashMap::new(),
        // Record mode has no caller headers to work with at all (see
        // `docs/TODO.md`'s record-mode gap) — an ordinary source's
        // `header.*` parameter resolves to null during recording, same as
        // any other value that isn't available yet.
        &HeaderMap::new(),
        source_call_timeout_ms,
    )
    .await
    {
        Ok(resolved) => {
            let status = endpoint.success_status.unwrap_or(200);
            let response_body = resolve::build_response(endpoint, &resolved);
            Ok((status, response_body, resolved))
        }
        Err(failure) => Err((failure.source_name, failure.cause.code().to_string(), failure.cause.message())),
    }
}

/// Builds the standard `{code, name, detail}` error envelope's status and
/// body — shared by source-resolution failures and security-verifier
/// failures, both real and mocked. Resolves `httpStatus`/`exposeDetail`
/// through the design doc's full 3-tier lookup: the canonical `errors`
/// registry wins if `code` is classified there; otherwise a matching entry
/// in `discovered_errors` (so hand-editing `errors.discovered.json` takes
/// effect on the very next request, without waiting for `errors freeze` to
/// promote it into `config/errors/`); otherwise `unexpected.error`.
/// `resolve_request` is this function's only caller; `handle_request` gets
/// the same envelope indirectly through it, converting the plain `(u16,
/// Value)` into an axum `Response` itself. Also where the design doc's
/// observe–react discovery happens: `code` reaching here with no entry in
/// the *canonical* registry is the "unclassified" case, recorded via
/// `record_discovered_error` whenever `debugMode` is on — regardless of
/// whether a discovered entry for it already exists (`record` itself is
/// the idempotent, occurrence-counting half of that).
#[allow(clippy::too_many_arguments)]
fn error_envelope(
    errors: &ErrorRegistry,
    discovered_errors: &Mutex<DiscoveredErrors>,
    discovered_errors_path: &Path,
    debug_mode: bool,
    code: &str,
    message: &str,
    on_error: Option<u16>,
    // This endpoint's own `errorOverrides` (`EndpointFile::error_overrides`)
    // — the final, most-specific layer on top of the 3-tier lookup below.
    // `on_error` (a *source's* own override, more specific still) wins over
    // this for `httpStatus` when both apply to the same failure;
    // `exposeDetail` has no source-level equivalent, so an override here is
    // always the last word on it.
    error_overrides: &HashMap<String, ErrorOverride>,
) -> (u16, Value) {
    // Tier 3 fallback (`unexpected.error`) — also what seeds a *new*
    // discovered entry's initial `httpStatus`/`exposeDetail` below, same as
    // before this function grew tier 2.
    let fallback_definition = errors.lookup(code);
    let (tiered_http_status, tiered_expose_detail) = match errors.get(code) {
        Some(definition) => (definition.http_status, definition.expose_detail),
        // This guard MUST stay a statement-scoped temporary: `std::sync::Mutex`
        // is non-reentrant, and `record_discovered_error` below locks this same
        // mutex — hoisting this to a `let guard = ...` deadlocks the request
        // thread forever.
        None => match discovered_errors
            .lock()
            .unwrap_or_else(|poisoned| {
                tracing::error!(
                    mutex = "endpoint::error_envelope discovered_errors",
                    "recovered a poisoned mutex — a previous request panicked while holding it; error classification continues with the recovered state"
                );
                poisoned.into_inner()
            })
            .lookup(code)
        {
            Some(entry) => (entry.http_status, entry.expose_detail),
            None => (fallback_definition.http_status, fallback_definition.expose_detail),
        },
    };

    let override_for_code = error_overrides.get(code);
    let http_status = on_error.or_else(|| override_for_code.and_then(|o| o.http_status)).unwrap_or(tiered_http_status);
    let expose_detail = override_for_code.and_then(|o| o.expose_detail).unwrap_or(tiered_expose_detail);
    let status = StatusCode::from_u16(http_status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    if debug_mode && errors.get(code).is_none() {
        record_discovered_error(discovered_errors, discovered_errors_path, code, fallback_definition, message);
    }

    let mut body = serde_json::json!({
        "code": status.as_u16(),
        "name": code,
    });
    if expose_detail || debug_mode {
        body["detail"] = serde_json::json!(message);
    }

    (status.as_u16(), body)
}

/// Records one occurrence of `code` — a classification the merged
/// `config/errors/` registry doesn't define — into the shared discovery
/// scratch file, per the design doc's observe–react behavior (only ever
/// called when `debugMode` is on; see `error_envelope`). The recorded
/// `httpStatus`/`exposeDetail` are whatever `errors.lookup(code)` already
/// fell back to (i.e. `unexpected.error`'s), giving the entry a real,
/// working starting point rather than a placeholder — matching the design
/// doc's own worked example. Saves to disk synchronously, right here,
/// which only ever runs against a development-time trickle of unclassified
/// errors, never production request volume.
fn record_discovered_error(discovered_errors: &Mutex<DiscoveredErrors>, path: &Path, code: &str, definition: &crate::errors::ErrorDefinition, message: &str) {
    let mut discovered = discovered_errors.lock().unwrap_or_else(|poisoned| {
        tracing::error!(
            mutex = "endpoint::record_discovered_error discovered_errors",
            "recovered a poisoned mutex — a previous request panicked while holding it; error discovery continues with the recovered state"
        );
        poisoned.into_inner()
    });
    discovered.record(code, definition.http_status, definition.expose_detail, message);
    if let Err(e) = discovered.save(path) {
        tracing::warn!("failed to save {}: {e}", path.display());
    }
}

pub(crate) fn discover_endpoint_files(root: &Path) -> Vec<(String, String, PathBuf)> {
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, String, PathBuf)>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // `_backups/` holds history, not live config — never routable.
            if path.file_name().and_then(|n| n.to_str()) == Some("_backups") {
                continue;
            }
            walk(root, &path, out);
        } else if let Some(method) = routable_method(&path)
            && let Some(url_path) = url_path_for(root, &path)
        {
            out.push((url_path, method, path.clone()));
        }
    }
}

/// The file token of an `endpoint.<method>.json` file, if it's one of
/// `method_token::ROUTABLE_FIXED` byte-for-byte — `None` for a
/// `.reference.json`/`.test.json` sibling (whose "method" segment would
/// contain a `.`), an underscore-prefixed orphaned file, a case variant like
/// `endpoint.GET.json`, or a currently-unrouted method like `options`/`head`/`trace`.
fn routable_method(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    let token = method_token::parse_file_token(method_token::stub_file_token(name)?)?;
    method_token::is_routable(&token).then(|| name["endpoint.".len()..name.len() - ".json".len()].to_string())
}

/// `endpoint.<token>.json` files whose token is a non-canonical spelling of a
/// fixed method (`endpoint.GET.json`, `endpoint.Query.json`): never routed and
/// never renamed, only reported. Uses `DirEntry::file_type`, so links are not followed.
pub(crate) fn non_canonical_method_files(endpoints_root: &Path) -> Vec<(PathBuf, &'static str)> {
    let mut out = Vec::new();
    walk_non_canonical(endpoints_root, &mut out);
    out.sort();
    out
}

fn walk_non_canonical(dir: &Path, out: &mut Vec<(PathBuf, &'static str)>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else { continue };
        let path = entry.path();
        if file_type.is_dir() {
            if path.file_name().and_then(|n| n.to_str()) != Some("_backups") {
                walk_non_canonical(&path, out);
            }
        } else if file_type.is_file()
            && let Some(name) = path.file_name().and_then(|n| n.to_str())
            && let Some(token) = method_token::stub_file_token(name)
            && let Some(canonical) = method_token::fixed_case_variant(token)
        {
            out.push((path.clone(), canonical));
        }
    }
}

/// Finds the `openapi.yaml` operation matching an already-registered
/// route's axum-style path (`/cars/:vin`) and method — converts each
/// candidate operation's own OpenAPI-style path (`/cars/{vin}`) the same
/// way `url_path_for` converts a folder path, so the two naming
/// conventions actually meet in the middle. `None` if nothing matches
/// (a spec/filesystem drift this project otherwise tolerates — see
/// `commands::generate`'s own orphaned-endpoint handling). `Operation.path`
/// is the loader's normalised form (no trailing slash), and paths the loader
/// set aside as case-ambiguous are still searched, by exact bytes, so an
/// existing project that serves both `/Cars` and `/cars` keeps validating both.
fn find_operation<'a>(doc: &'a crate::openapi::OpenApiDocument, url_path: &str, method: &str) -> Option<&'a Operation> {
    doc.operations
        .iter()
        .chain(doc.ambiguous_operations.iter())
        .find(|op| op.method == method && axum_style_path(&op.path) == url_path)
}

/// An endpoint file whose `security` doesn't agree with what `openapi.yaml`
/// requires for the matching operation(s). `acceptable` is the intersection of
/// every requiring operation's acceptable schemes.
pub(crate) struct SecurityMismatch {
    pub method: String,
    pub url_path: String,
    pub file: PathBuf,
    pub stub: Option<String>,
    pub matched: Vec<(String, String)>,
    pub acceptable: Vec<String>,
}

fn quoted_names(names: &[String]) -> String {
    names.iter().map(|n| format!("'{}'", crate::openapi::untrusted(n))).collect::<Vec<_>>().join(", ")
}

impl SecurityMismatch {
    pub(crate) fn message(&self) -> String {
        use crate::openapi::untrusted;
        let head = format!(
            "{} {} ({})",
            method_token::display_token(&self.method),
            untrusted(&self.url_path),
            untrusted(&self.file.display().to_string())
        );
        let acceptable = quoted_names(&self.acceptable);
        let mut message = match &self.stub {
            None => {
                format!("{head}: openapi.yaml requires security ({acceptable}) but the endpoint file declares no \"security\" — the route would be served unprotected")
            }
            Some(stub) => format!(
                "{head}: endpoint file declares security '{}', which is not one openapi.yaml allows for this operation (acceptable: {acceptable})",
                untrusted(stub)
            ),
        };
        if self.matched.len() > 1 {
            let ops: Vec<String> = self.matched.iter().map(|(m, p)| format!("{m} {}", untrusted(p))).collect();
            message.push_str(&format!(
                " (matched by parameter-name/case-insensitive comparison against: {}; it must satisfy all of them)",
                ops.join(", ")
            ));
        }
        message
    }
}

/// An endpoint file that declares security the spec doesn't ask for.
pub(crate) struct SecurityStricter {
    pub method: String,
    pub url_path: String,
    pub file: PathBuf,
    pub stub: String,
}

impl SecurityStricter {
    pub(crate) fn message(&self) -> String {
        use crate::openapi::untrusted;
        format!(
            "{} {} ({}): declares security '{}' but openapi.yaml declares none for this operation",
            method_token::display_token(&self.method),
            untrusted(&self.url_path),
            untrusted(&self.file.display().to_string()),
            untrusted(&self.stub)
        )
    }
}

#[derive(Default)]
pub(crate) struct SecurityCheck {
    pub mismatches: Vec<SecurityMismatch>,
    pub stricter: Vec<SecurityStricter>,
    pub unmatched: Vec<PathBuf>,
}

pub(crate) fn unmatched_security_message(file: &Path) -> String {
    format!(
        "{}: no matching operation in openapi.yaml — endpoint security was not checked for this route",
        crate::openapi::untrusted(&file.display().to_string())
    )
}

/// Parameter names and letter case don't matter for the fallback match: a
/// `:`-prefixed segment becomes `{}` and the whole path is case-folded.
fn match_key(axum_path: &str) -> String {
    let normalised = axum_path
        .split('/')
        .map(|segment| if segment.starts_with(':') { "{}" } else { segment })
        .collect::<Vec<_>>()
        .join("/");
    crate::openapi::dir_index::fold(&normalised)
}

/// The schemes an operation accepts from an endpoint file: the sole key of a
/// single-key requirement, the first key of a multi-key one (frogs enforces
/// only that), in spec order, deduped. `None` when the operation requires no
/// security at all.
fn acceptable_schemes(op: &Operation) -> Option<Vec<String>> {
    if !op.security_alternatives.iter().any(|alt| !alt.is_empty()) {
        return None;
    }
    let mut out: Vec<String> = Vec::new();
    for first in op.security_alternatives.iter().filter_map(|alt| alt.first()) {
        if !out.contains(first) {
            out.push(first.clone());
        }
    }
    Some(out)
}

/// Compares every readable endpoint file's `security` against what
/// `openapi.yaml` requires for the operation it maps to. Read-only; opens no
/// connections.
pub(crate) fn security_check(endpoints_root: &Path, doc: &crate::openapi::OpenApiDocument) -> SecurityCheck {
    let mut check = SecurityCheck::default();
    for (url_path, method, file) in discover_endpoint_files(endpoints_root) {
        let Ok(contents) = std::fs::read_to_string(&file) else { continue };
        let Ok(endpoint) = serde_json::from_str::<EndpointFile>(&contents) else { continue };
        let stub = endpoint.security;

        let mut matched: Vec<&Operation> = find_operation(doc, &url_path, &method).into_iter().collect();
        if matched.is_empty() {
            let key = match_key(&url_path);
            matched = doc
                .operations
                .iter()
                .chain(doc.ambiguous_operations.iter())
                .filter(|op| op.method == method && match_key(&axum_style_path(&op.path)) == key)
                .collect();
        }
        if matched.is_empty() {
            check.unmatched.push(file);
            continue;
        }

        let requiring: Vec<Vec<String>> = matched.iter().filter_map(|op| acceptable_schemes(op)).collect();
        if requiring.is_empty() {
            if let Some(stub) = stub {
                check.stricter.push(SecurityStricter { method, url_path, file, stub });
            }
            continue;
        }
        let mut acceptable = requiring[0].clone();
        acceptable.retain(|name| requiring.iter().all(|other| other.contains(name)));
        let ok = stub.as_ref().is_some_and(|s| requiring.iter().all(|other| other.contains(s)));
        if !ok {
            check.mismatches.push(SecurityMismatch {
                method,
                url_path,
                file,
                stub,
                matched: matched.iter().map(|op| (op.http_method.clone(), op.path.clone())).collect(),
                acceptable,
            });
        }
    }
    check
}

/// `{name}` -> `:name`, segment by segment — the same conversion
/// `url_path_for` does for a filesystem path, applied directly to an
/// OpenAPI path string instead.
fn axum_style_path(openapi_path: &str) -> String {
    openapi_path
        .split('/')
        .map(|segment| match segment.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            Some(name) => format!(":{name}"),
            None => segment.to_string(),
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Converts a folder path under `datasources/endpoints/` into an axum route,
/// e.g. `.../cars/{vin}/endpoint.get.json` -> `/cars/:vin`. This project
/// pins `axum = "0.7"` (matchit 0.7), which uses `:name` for path
/// parameters — OpenAPI's `{name}` folder-naming convention (design doc,
/// "File and folder naming") isn't axum's own route syntax, so it has to be
/// translated at registration time.
fn url_path_for(root: &Path, file_path: &Path) -> Option<String> {
    let dir = file_path.parent()?;
    let relative = dir.strip_prefix(root).ok()?;

    let mut segments = Vec::new();
    for component in relative.components() {
        let segment = component.as_os_str().to_str()?;
        match segment.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            Some(name) => segments.push(format!(":{name}")),
            None => segments.push(segment.to_string()),
        }
    }

    if segments.is_empty() {
        Some("/".to_string())
    } else {
        Some(format!("/{}", segments.join("/")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A generous bound for every test that isn't itself about the source-
    /// call timeout — what `ServerConfig::effective_source_call_timeout_ms`
    /// would hand `build_router`/`resolve_request` in production.
    fn test_call_timeout() -> NonZeroU64 {
        NonZeroU64::new(5_000).unwrap()
    }

    #[test]
    fn converts_openapi_style_path_params_to_axum_syntax() {
        let root = Path::new("/proj/datasources/endpoints");
        let file = root.join("cars").join("{vin}").join("endpoint.get.json");
        assert_eq!(url_path_for(root, &file).unwrap(), "/cars/:vin");
    }

    #[test]
    fn flat_path_has_no_parameters() {
        let root = Path::new("/proj/datasources/endpoints");
        let file = root.join("cars").join("endpoint.get.json");
        assert_eq!(url_path_for(root, &file).unwrap(), "/cars");
    }

    #[test]
    fn discovers_endpoint_files_and_skips_reference_test_and_backup_siblings() {
        let root = std::env::temp_dir().join(format!(
            "frogs-endpoint-discover-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(root.join("cars/{vin}/_backups")).unwrap();
        std::fs::write(root.join("cars/endpoint.get.json"), "{}").unwrap();
        std::fs::write(root.join("cars/endpoint.get.reference.json"), "{}").unwrap();
        std::fs::write(root.join("cars/endpoint.post.json"), "{}").unwrap();
        std::fs::write(root.join("cars/{vin}/endpoint.get.json"), "{}").unwrap();
        std::fs::write(root.join("cars/{vin}/endpoint.get.test.json"), "{}").unwrap();
        std::fs::write(root.join("cars/{vin}/_backups/endpoint.get.2026-07-30T15-45-40Z.json"), "{}").unwrap();

        let mut found: Vec<(String, String)> = discover_endpoint_files(&root).into_iter().map(|(path, method, _)| (path, method)).collect();
        found.sort();
        let _ = std::fs::remove_dir_all(&root);

        assert_eq!(
            found,
            vec![
                ("/cars".to_string(), "get".to_string()),
                ("/cars".to_string(), "post".to_string()),
                ("/cars/:vin".to_string(), "get".to_string()),
            ]
        );
    }

    #[test]
    fn routable_method_recognizes_every_supported_verb() {
        let root = Path::new("/proj/datasources/endpoints/cars");
        for method in method_token::ROUTABLE_FIXED {
            assert_eq!(routable_method(&root.join(format!("endpoint.{method}.json"))), Some(method.to_string()));
        }
    }

    #[test]
    fn routable_method_ignores_reference_and_test_siblings() {
        let root = Path::new("/proj/datasources/endpoints/cars");
        assert_eq!(routable_method(&root.join("endpoint.get.reference.json")), None);
        assert_eq!(routable_method(&root.join("endpoint.get.test.json")), None);
    }

    #[test]
    fn routable_method_ignores_an_unsupported_http_method() {
        let root = Path::new("/proj/datasources/endpoints/cars");
        assert_eq!(routable_method(&root.join("endpoint.options.json")), None);
    }

    #[test]
    fn routable_method_ignores_an_orphaned_underscore_prefixed_file() {
        // The underscore is part of the file *name*, not stripped by
        // `strip_prefix("endpoint.")`, so this already falls through
        // naturally rather than needing a dedicated check.
        let root = Path::new("/proj/datasources/endpoints/cars");
        assert_eq!(routable_method(&root.join("_endpoint.get.json")), None);
    }

    /// The roadmap's own Phase 3 exit criterion, proven against a real
    /// running server (not just the `security::verify` unit tests): a
    /// route with a declared security scheme rejects a request with no
    /// credential, rejects one with the wrong credential, and accepts one
    /// with the right credential — a real DB-backed API key check, same
    /// "spin up a real server, hit it with reqwest" convention used
    /// elsewhere in this project.
    #[tokio::test]
    async fn a_protected_endpoint_rejects_bad_credentials_and_accepts_good_ones() {
        use crate::errors::ErrorRegistry;
        use crate::security::{LoadedVerifier, SecurityConfig, ValidIf, VerifierDef};
        use crate::sql::{SqlError, SqlValue};

        #[derive(Debug)]
        struct FakeDriver;

        #[async_trait::async_trait]
        impl SqlDriver for FakeDriver {
            async fn query(&self, _script: &str, params: &HashMap<String, SqlValue>) -> Result<Vec<HashMap<String, SqlValue>>, SqlError> {
                match params.get("key") {
                    Some(SqlValue::Text(k)) if k == "good-key" => {
                        let mut row = HashMap::new();
                        row.insert("active".to_string(), SqlValue::Bool(true));
                        Ok(vec![row])
                    }
                    _ => Ok(vec![]),
                }
            }
        }

        let root = std::env::temp_dir().join(format!(
            "frogs-endpoint-security-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(root.join("sql/db")).unwrap();
        std::fs::write(root.join("sql/db/verify_key.sql"), "SELECT active FROM api_keys WHERE key = :key;").unwrap();
        std::fs::create_dir_all(root.join("errors")).unwrap();
        std::fs::write(
            root.join("errors/core.json"),
            r#"{
                "auth.invalid_credentials": { "httpStatus": 401, "exposeDetail": true },
                "auth.verifier_unavailable": { "httpStatus": 500, "exposeDetail": false }
            }"#,
        )
        .unwrap();

        let def: VerifierDef = serde_json::from_str(
            r#"{
                "type": "sql",
                "connection": "db",
                "script": "verify_key.sql",
                "parameters": [{ "name": "key", "from": "header.X-Api-Key" }],
                "validIf": "row.active = true"
            }"#,
        )
        .unwrap();
        let verifier = LoadedVerifier {
            valid_if: ValidIf::parse(def.valid_if()).unwrap(),
            def,
            mtls: None,
        };
        let mut verifiers = HashMap::new();
        verifiers.insert("apiKeyAuth".to_string(), verifier);
        let security = Arc::new(SecurityConfig {
            schemes: HashMap::new(),
            verifiers,
        });

        let endpoint: EndpointFile = serde_json::from_str(r#"{ "operationId": "getSecret", "security": "apiKeyAuth", "sources": {}, "response": {} }"#).unwrap();

        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(FakeDriver));

        let state = Arc::new(RouteState {
            endpoint,
            route: RouteKey {
                method: "get".to_string(),
                path: "/secret".to_string(),
            },
            sql_root: root.join("sql"),
            http_root: root.join("http"),
            drivers: Arc::new(drivers),
            http_client: reqwest::Client::new(),
            errors: Arc::new(ErrorRegistry::load(&root.join("errors")).unwrap()),
            security,
            services: Arc::new(HashMap::new()),
            verifier_cache: Arc::new(crate::security::VerifierCache::new()),
            discovered_errors: Arc::new(Mutex::new(DiscoveredErrors::default())),
            discovered_errors_path: root.join("errors.discovered.json"),
            debug_mode: true,
            operation: None,
            component_schemas: Arc::new(Map::new()),
            source_call_timeout_ms: test_call_timeout(),
            mock_provider: None,
            response_mode: ResponseMode::Single,
        });

        let router = Router::new().route("/secret", get(handle_request)).with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let client = reqwest::Client::new();

        let resp = client.get(format!("http://{addr}/secret")).send().await.unwrap();
        assert_eq!(resp.status(), 401, "no credential at all must be rejected");

        let resp = client.get(format!("http://{addr}/secret")).header("X-Api-Key", "wrong-key").send().await.unwrap();
        assert_eq!(resp.status(), 401, "an unrecognized key must be rejected");

        let resp = client.get(format!("http://{addr}/secret")).header("X-Api-Key", "good-key").send().await.unwrap();
        assert_eq!(resp.status(), 200, "a valid, active key must be accepted");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Point 1's whole point, proven end to end via the real `build_router`
    /// (not a hand-built router, unlike the security test above): a POST
    /// endpoint file is discovered and routed just like a GET one, and its
    /// `successStatus` is what the response actually comes back as — 200
    /// only when nothing else was declared.
    #[tokio::test]
    async fn write_methods_are_routed_and_success_status_is_applied() {
        let root = std::env::temp_dir().join(format!(
            "frogs-endpoint-write-routing-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let dir = root.join("datasources/endpoints/things");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("endpoint.get.json"), r#"{ "operationId": "getThing", "sources": {}, "response": {} }"#).unwrap();
        std::fs::write(
            dir.join("endpoint.post.json"),
            r#"{ "operationId": "createThing", "successStatus": 201, "sources": {}, "response": {} }"#,
        )
        .unwrap();

        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        let errors = Arc::new(ErrorRegistry::load(&root.join("does-not-exist")).unwrap());
        let security = Arc::new(SecurityConfig::default());
        let router = build_router(
            &root,
            Arc::new(drivers),
            &HashMap::new(),
            errors,
            security,
            Arc::new(HashMap::new()),
            Arc::new(Mutex::new(DiscoveredErrors::default())),
            false,
            None,
            None,
            test_call_timeout(),
            false,
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let client = reqwest::Client::new();

        let get_resp = client.get(format!("http://{addr}/things")).send().await.unwrap();
        assert_eq!(get_resp.status(), 200, "GET declares no successStatus, so it defaults to 200");

        let post_resp = client.post(format!("http://{addr}/things")).send().await.unwrap();
        assert_eq!(post_resp.status(), 201, "POST's own successStatus must be applied to the real response");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// An endpoint's own `rateLimit` applies to just that route, proven
    /// through the real `build_router` with `features.rateLimiting` off
    /// entirely (no global bucket in play at all) — the override alone is
    /// what throttles `/limited`, and a sibling route with no override of
    /// its own is completely unaffected by it.
    #[tokio::test]
    async fn a_per_endpoint_rate_limit_throttles_only_that_route() {
        let root = std::env::temp_dir().join(format!(
            "frogs-endpoint-rate-limit-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let limited_dir = root.join("datasources/endpoints/limited");
        let unlimited_dir = root.join("datasources/endpoints/unlimited");
        std::fs::create_dir_all(&limited_dir).unwrap();
        std::fs::create_dir_all(&unlimited_dir).unwrap();
        std::fs::write(
            limited_dir.join("endpoint.get.json"),
            r#"{ "operationId": "limited", "sources": {}, "response": {}, "rateLimit": { "requestsPerSecond": 1, "burst": 1 } }"#,
        )
        .unwrap();
        std::fs::write(
            unlimited_dir.join("endpoint.get.json"),
            r#"{ "operationId": "unlimited", "sources": {}, "response": {} }"#,
        )
        .unwrap();

        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        let errors = Arc::new(ErrorRegistry::load(&root.join("does-not-exist")).unwrap());
        let security = Arc::new(SecurityConfig::default());
        // No `apply_rate_limit` call at all here — this test's whole point
        // is that the per-route override works independently of the global
        // `features.rateLimiting` layer, which isn't part of `build_router`.
        let router = build_router(
            &root,
            Arc::new(drivers),
            &HashMap::new(),
            errors,
            security,
            Arc::new(HashMap::new()),
            Arc::new(Mutex::new(DiscoveredErrors::default())),
            false,
            None,
            None,
            test_call_timeout(),
            false,
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let client = reqwest::Client::new();

        let first = client.get(format!("http://{addr}/limited")).send().await.unwrap();
        assert_eq!(first.status(), 200, "the first request should still consume the lone token and succeed");
        let second = client.get(format!("http://{addr}/limited")).send().await.unwrap();
        assert_eq!(second.status(), 429, "burst: 1 leaves no token for a second immediate request");

        for _ in 0..5 {
            let resp = client.get(format!("http://{addr}/unlimited")).send().await.unwrap();
            assert_eq!(resp.status(), 200, "a route with no rateLimit override must be unaffected by /limited's own bucket");
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Point 4's exit criterion, proven at the real HTTP layer: the same
    /// per-request correlation ID `server::apply_middleware` generates (and
    /// echoes back in `X-Request-Id`) is exactly what a source's
    /// `"from": "context.transactionId"` parameter receives — not a
    /// separately generated ID, and not empty. Uses `build_router` +
    /// `apply_middleware` together, the same composition `commands::run`
    /// itself uses, rather than constructing `RouteState` by hand.
    #[tokio::test]
    async fn context_transaction_id_matches_the_requests_correlation_id() {
        #[derive(Debug)]
        struct RecordingDriver {
            received: std::sync::Arc<std::sync::Mutex<Option<HashMap<String, crate::sql::SqlValue>>>>,
        }

        #[async_trait::async_trait]
        impl SqlDriver for RecordingDriver {
            async fn query(
                &self,
                _script: &str,
                params: &HashMap<String, crate::sql::SqlValue>,
            ) -> Result<Vec<HashMap<String, crate::sql::SqlValue>>, crate::sql::SqlError> {
                *self.received.lock().unwrap() = Some(params.clone());
                Ok(vec![HashMap::from([("id".to_string(), crate::sql::SqlValue::Int(1))])])
            }
        }

        let root = std::env::temp_dir().join(format!(
            "frogs-endpoint-transaction-id-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let dir = root.join("datasources/endpoints/things");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("endpoint.post.json"),
            r#"{
                "operationId": "createThing",
                "successStatus": 201,
                "sources": {
                    "thing": {
                        "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "one",
                        "parameters": [{ "name": "txId", "from": "context.transactionId" }]
                    }
                },
                "response": {}
            }"#,
        )
        .unwrap();
        std::fs::create_dir_all(root.join("datasources/sql/db")).unwrap();
        std::fs::write(root.join("datasources/sql/db/q.sql"), "SELECT 1;").unwrap();

        let received = std::sync::Arc::new(std::sync::Mutex::new(None));
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(RecordingDriver { received: received.clone() }));
        let errors = Arc::new(ErrorRegistry::load(&root.join("does-not-exist")).unwrap());
        let security = Arc::new(SecurityConfig::default());
        let router = build_router(
            &root,
            Arc::new(drivers),
            &HashMap::new(),
            errors,
            security,
            Arc::new(HashMap::new()),
            Arc::new(Mutex::new(DiscoveredErrors::default())),
            false,
            None,
            None,
            test_call_timeout(),
            false,
        );
        let router = crate::server::apply_middleware(router);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/things"))
            .header("x-request-id", "caller-supplied-id")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201);
        assert_eq!(
            resp.headers().get("x-request-id").unwrap(),
            "caller-supplied-id",
            "sanity check: the middleware really did reuse the caller's own id"
        );

        let received_params = received.lock().unwrap().clone().unwrap();
        assert_eq!(received_params.get("txId"), Some(&crate::sql::SqlValue::Text("caller-supplied-id".to_string())));

        let _ = std::fs::remove_dir_all(&root);
    }

    fn temp_discovered_errors_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "frogs-discovered-errors-test-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ))
    }

    #[test]
    fn error_envelope_records_an_unclassified_code_when_debug_mode_is_on() {
        let errors = ErrorRegistry::load(Path::new("/does/not/exist")).unwrap();
        let discovered = Mutex::new(DiscoveredErrors::default());
        let path = temp_discovered_errors_path();

        error_envelope(&errors, &discovered, &path, true, "datasource.sql.not_found", "no rows", None, &HashMap::new());

        assert_eq!(discovered.lock().unwrap().len(), 1);
        assert!(
            discovered.lock().unwrap().lookup("datasource.sql.not_found").is_some(),
            "an unclassified code must be recorded under its own classification, not a placeholder"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn error_envelope_does_not_record_when_debug_mode_is_off() {
        let errors = ErrorRegistry::load(Path::new("/does/not/exist")).unwrap();
        let discovered = Mutex::new(DiscoveredErrors::default());
        let path = temp_discovered_errors_path();

        error_envelope(&errors, &discovered, &path, false, "datasource.sql.not_found", "no rows", None, &HashMap::new());

        assert!(discovered.lock().unwrap().is_empty(), "discovery is a debugMode-only aid, per the design doc");
        assert!(!path.is_file(), "nothing should have been written at all");
    }

    #[test]
    fn error_envelope_does_not_record_a_code_that_is_already_classified() {
        let errors = ErrorRegistry::load(Path::new("/does/not/exist")).unwrap();
        let discovered = Mutex::new(DiscoveredErrors::default());
        let path = temp_discovered_errors_path();

        // "unexpected.error" is always present (`ErrorRegistry::load` force-
        // inserts it) — a genuinely classified code, not a gap to discover.
        error_envelope(&errors, &discovered, &path, true, "unexpected.error", "boom", None, &HashMap::new());

        assert!(discovered.lock().unwrap().is_empty());
    }

    #[test]
    fn error_envelope_persists_the_recorded_entry_to_disk() {
        let errors = ErrorRegistry::load(Path::new("/does/not/exist")).unwrap();
        let discovered = Mutex::new(DiscoveredErrors::default());
        let path = temp_discovered_errors_path();

        error_envelope(&errors, &discovered, &path, true, "datasource.sql.not_found", "no rows", None, &HashMap::new());

        let reloaded = DiscoveredErrors::load(&path).expect("the recorded entry must be saved to disk, not just in-memory");
        assert_eq!(reloaded.len(), 1);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn error_envelope_repeated_occurrences_update_the_same_entry_in_place() {
        let errors = ErrorRegistry::load(Path::new("/does/not/exist")).unwrap();
        let discovered = Mutex::new(DiscoveredErrors::default());
        let path = temp_discovered_errors_path();

        error_envelope(&errors, &discovered, &path, true, "datasource.sql.not_found", "first", None, &HashMap::new());
        error_envelope(&errors, &discovered, &path, true, "datasource.sql.not_found", "second", None, &HashMap::new());

        let locked = discovered.lock().unwrap();
        assert_eq!(locked.len(), 1, "the same code occurring twice must update one entry, not create two");
        assert_eq!(locked.lookup("datasource.sql.not_found").unwrap().occurrences, 2);

        drop(locked);
        let _ = std::fs::remove_file(&path);
    }

    /// The single most important regression this fix touches: `error_envelope`
    /// locks `discovered_errors` once, and `record_discovered_error` (called
    /// from inside it, only when `debugMode` is on and `code` is
    /// unclassified) locks the very same `Mutex` again a few lines later.
    /// `std::sync::Mutex` is non-reentrant, so if the first lock's guard were
    /// ever hoisted into a `let` spanning both lock sites instead of staying
    /// a statement-scoped temporary, this would deadlock the calling thread
    /// forever. Run on its own thread with a hard deadline so a regression
    /// here fails this test loudly instead of hanging the whole `cargo test`
    /// run silently.
    #[test]
    fn error_envelope_does_not_self_deadlock_when_recording_a_discovered_error() {
        let discovered = Arc::new(Mutex::new(DiscoveredErrors::default()));
        let path = temp_discovered_errors_path();

        let (tx, rx) = std::sync::mpsc::channel();
        let discovered_for_thread = discovered.clone();
        let path_for_thread = path.clone();
        std::thread::spawn(move || {
            let errors = ErrorRegistry::load(Path::new("/does/not/exist")).unwrap();
            let result = error_envelope(
                &errors,
                &discovered_for_thread,
                &path_for_thread,
                true,
                "datasource.sql.not_found",
                "no rows",
                None,
                &HashMap::new(),
            );
            let _ = tx.send(result);
        });

        let (status, body) = rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("error_envelope hung — the discovered_errors mutex guard was likely hoisted across both lock sites, self-deadlocking the thread");

        assert_eq!(status, 500, "unexpected.error's fallback status, since this code has no canonical registry entry");
        assert_eq!(body["name"], "datasource.sql.not_found");
        assert_eq!(
            discovered.lock().unwrap().len(),
            1,
            "record_discovered_error must actually have run, not just returned promptly"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// Same canary, but with `discovered_errors` already poisoned before
    /// this call — a previous (simulated) request panicked while holding
    /// the lock. Confirms the request path recovers via
    /// `poisoned.into_inner()` at *both* lock sites rather than deadlocking
    /// or panicking again. The panic hook is swapped to a no-op only for the
    /// duration of the deliberate poisoning so the expected panic doesn't
    /// spam this test run's own stderr, then restored unconditionally.
    #[test]
    fn error_envelope_recovers_a_poisoned_discovered_errors_mutex_without_hanging() {
        let discovered = Arc::new(Mutex::new(DiscoveredErrors::default()));
        let path = temp_discovered_errors_path();

        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let poison_target = discovered.clone();
        let handle = std::thread::spawn(move || {
            let _guard = poison_target.lock().unwrap();
            panic!("deliberately poisoning the mutex for this test");
        });
        let _ = handle.join();
        std::panic::set_hook(previous_hook);
        assert!(discovered.lock().is_err(), "sanity check: the mutex really is poisoned at this point");

        let (tx, rx) = std::sync::mpsc::channel();
        let discovered_for_thread = discovered.clone();
        let path_for_thread = path.clone();
        std::thread::spawn(move || {
            let errors = ErrorRegistry::load(Path::new("/does/not/exist")).unwrap();
            let result = error_envelope(
                &errors,
                &discovered_for_thread,
                &path_for_thread,
                true,
                "datasource.sql.not_found",
                "no rows",
                None,
                &HashMap::new(),
            );
            let _ = tx.send(result);
        });

        let (status, body) = rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("error_envelope hung against an already-poisoned mutex — recovery via into_inner() at one of the two lock sites likely regressed");

        assert_eq!(status, 500, "the same prompt, correct envelope must come back even after recovering from poisoning");
        assert_eq!(body["name"], "datasource.sql.not_found");
        assert_eq!(
            discovered.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).len(),
            1,
            "the discovery write must still have gone through despite the recovered poisoned state"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// The tier-2 gap this section closes: a discovered entry's own
    /// `httpStatus`/`exposeDetail` — as if hand-edited in
    /// `errors.discovered.json` before `errors freeze` ever ran — actually
    /// changes what a live response looks like, instead of every
    /// unclassified code always falling straight through to
    /// `unexpected.error`'s status.
    #[test]
    fn error_envelope_uses_a_discovered_entrys_own_status_and_expose_detail() {
        let errors = ErrorRegistry::load(Path::new("/does/not/exist")).unwrap();
        let discovered = Mutex::new(DiscoveredErrors::default());
        let path = temp_discovered_errors_path();

        // Seeded directly, the same as a hand-edit to errors.discovered.json
        // followed by a reload would look like — distinct from
        // `unexpected.error`'s own defaults (500, exposeDetail: false) so a
        // pass-through bug would be obvious.
        discovered.lock().unwrap().record("plugin.hmac.unknown:BadSignature", 422, true, "signature mismatch");

        let (status, body) = error_envelope(
            &errors,
            &discovered,
            &path,
            false,
            "plugin.hmac.unknown:BadSignature",
            "signature mismatch",
            None,
            &HashMap::new(),
        );

        assert_eq!(status, 422, "the discovered entry's own httpStatus should win over unexpected.error's 500");
        assert_eq!(body["code"], 422);
        assert_eq!(body["name"], "plugin.hmac.unknown:BadSignature");
        assert_eq!(
            body["detail"], "signature mismatch",
            "the discovered entry's own exposeDetail: true should show detail even with debugMode off"
        );
    }

    /// Tier 1 still wins over tier 2 — a code genuinely classified in the
    /// canonical registry is never shadowed by a stale/differing discovered
    /// entry for the same code (e.g. one recorded before the code was
    /// formally added to `config/errors/`).
    #[test]
    fn error_envelope_prefers_the_canonical_registry_over_a_discovered_entry() {
        let dir = std::env::temp_dir().join(format!(
            "frogs-error-envelope-tiers-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("core.json"),
            r#"{ "auth.invalid_credentials": { "httpStatus": 401, "exposeDetail": true } }"#,
        )
        .unwrap();
        let errors = ErrorRegistry::load(&dir).unwrap();

        let discovered = Mutex::new(DiscoveredErrors::default());
        // A stale discovered entry for the same code, with a different
        // status — must never win once the code is canonically classified.
        discovered.lock().unwrap().record("auth.invalid_credentials", 418, false, "stale");
        let path = temp_discovered_errors_path();

        let (status, body) = error_envelope(&errors, &discovered, &path, false, "auth.invalid_credentials", "wrong key", None, &HashMap::new());

        assert_eq!(status, 401, "the canonical registry's own status must win over a discovered entry for the same code");
        assert_eq!(body["detail"], "wrong key");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An endpoint's own `errorOverrides` wins over the canonical registry's
    /// `httpStatus`/`exposeDetail` for a matching code — the final, most
    /// specific layer, scoped to just this one endpoint.
    #[test]
    fn error_envelope_applies_a_per_endpoint_error_override() {
        let dir = std::env::temp_dir().join(format!(
            "frogs-error-envelope-overrides-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("core.json"),
            r#"{ "datasource.sql.connection_failed": { "httpStatus": 500, "exposeDetail": false } }"#,
        )
        .unwrap();
        let errors = ErrorRegistry::load(&dir).unwrap();
        let discovered = Mutex::new(DiscoveredErrors::default());
        let path = temp_discovered_errors_path();

        let mut overrides = HashMap::new();
        overrides.insert(
            "datasource.sql.connection_failed".to_string(),
            ErrorOverride {
                http_status: Some(503),
                expose_detail: Some(true),
            },
        );

        let (status, body) = error_envelope(
            &errors,
            &discovered,
            &path,
            false,
            "datasource.sql.connection_failed",
            "pool exhausted",
            None,
            &overrides,
        );

        assert_eq!(status, 503, "the endpoint's own override should win over the registry's 500");
        assert_eq!(
            body["detail"], "pool exhausted",
            "exposeDetail: true in the override should show detail even though the registry says false"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Setting only one field in an override leaves the other at whatever
    /// the registry (or a lower tier) already says — not reset to a default.
    #[test]
    fn error_envelope_override_can_set_just_one_field() {
        let dir = std::env::temp_dir().join(format!(
            "frogs-error-envelope-overrides-partial-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("core.json"),
            r#"{ "datasource.sql.connection_failed": { "httpStatus": 500, "exposeDetail": true } }"#,
        )
        .unwrap();
        let errors = ErrorRegistry::load(&dir).unwrap();
        let discovered = Mutex::new(DiscoveredErrors::default());
        let path = temp_discovered_errors_path();

        let mut overrides = HashMap::new();
        overrides.insert(
            "datasource.sql.connection_failed".to_string(),
            ErrorOverride {
                http_status: Some(503),
                expose_detail: None,
            },
        );

        let (status, body) = error_envelope(
            &errors,
            &discovered,
            &path,
            false,
            "datasource.sql.connection_failed",
            "pool exhausted",
            None,
            &overrides,
        );

        assert_eq!(status, 503);
        assert_eq!(
            body["detail"], "pool exhausted",
            "exposeDetail wasn't overridden, so the registry's own true should still apply"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A source's own `onError` is still more specific than an endpoint-wide
    /// `errorOverrides` entry for `httpStatus` — the override exists for
    /// codes without a source-level lever (or ones shared across sources),
    /// not to override `onError` itself.
    #[test]
    fn error_envelope_source_level_on_error_wins_over_an_endpoint_level_override() {
        let errors = ErrorRegistry::load(Path::new("/does/not/exist")).unwrap();
        let discovered = Mutex::new(DiscoveredErrors::default());
        let path = temp_discovered_errors_path();

        let mut overrides = HashMap::new();
        overrides.insert(
            "datasource.sql.connection_failed".to_string(),
            ErrorOverride {
                http_status: Some(503),
                expose_detail: None,
            },
        );

        let (status, _) = error_envelope(
            &errors,
            &discovered,
            &path,
            false,
            "datasource.sql.connection_failed",
            "pool exhausted",
            Some(502), // this source's own onError
            &overrides,
        );

        assert_eq!(status, 502, "onError is more specific than an endpoint-wide errorOverrides entry and must win");
    }

    /// A code with no matching override entry falls straight through to the
    /// existing 3-tier lookup, unaffected — `errorOverrides` on an endpoint
    /// with unrelated codes doesn't change anything for codes it doesn't name.
    #[test]
    fn error_envelope_a_code_with_no_matching_override_is_unaffected() {
        let errors = ErrorRegistry::load(Path::new("/does/not/exist")).unwrap();
        let discovered = Mutex::new(DiscoveredErrors::default());
        let path = temp_discovered_errors_path();

        let mut overrides = HashMap::new();
        overrides.insert(
            "some.other.code".to_string(),
            ErrorOverride {
                http_status: Some(503),
                expose_detail: Some(true),
            },
        );

        let (status, _) = error_envelope(&errors, &discovered, &path, false, "datasource.sql.not_found", "no rows", None, &overrides);

        // Empty registry (`/does/not/exist`) — "datasource.sql.not_found"
        // isn't classified anywhere, so it falls through to
        // `unexpected.error`'s own default (500), same as if `overrides`
        // were empty entirely. The override for an unrelated code must not
        // leak into this one.
        assert_eq!(status, 500);
    }

    /// End-to-end proof through a real running server (not just the direct
    /// `error_envelope` calls above): a SQL source that returns zero rows,
    /// against an `ErrorRegistry` with no `core.json` scaffolded at all, so
    /// `datasource.sql.not_found` is genuinely unclassified — the same
    /// "verify it live" discipline used elsewhere in this project.
    #[tokio::test]
    async fn a_real_unclassified_failure_is_recorded_end_to_end_in_debug_mode() {
        #[derive(Debug)]
        struct EmptyResultDriver;

        #[async_trait::async_trait]
        impl SqlDriver for EmptyResultDriver {
            async fn query(&self, _script: &str, _params: &HashMap<String, crate::sql::SqlValue>) -> Result<Vec<crate::sql::SqlRow>, crate::sql::SqlError> {
                Ok(vec![])
            }
        }

        let root = std::env::temp_dir().join(format!(
            "frogs-discovery-e2e-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let dir = root.join("datasources/endpoints/things");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("endpoint.get.json"),
            r#"{
                "operationId": "getThing",
                "sources": {
                    "thing": { "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "one" }
                },
                "response": {}
            }"#,
        )
        .unwrap();
        std::fs::create_dir_all(root.join("datasources/sql/db")).unwrap();
        std::fs::write(root.join("datasources/sql/db/q.sql"), "SELECT 1;").unwrap();
        // In a real project `config/` always exists by the time `frogs run`
        // executes — `generate` scaffolds it — so `record_discovered_error`
        // doesn't defensively create it; this test has to, standing in for
        // that guarantee.
        std::fs::create_dir_all(root.join("config")).unwrap();

        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(EmptyResultDriver));
        // No `config/errors/` directory at all — only the always-forced
        // `unexpected.error` exists, so `datasource.sql.not_found` (what a
        // zero-row "one"-cardinality source classifies to) is unclassified.
        let errors = Arc::new(ErrorRegistry::load(&root.join("config/errors")).unwrap());
        let security = Arc::new(SecurityConfig::default());
        let router = build_router(
            &root,
            Arc::new(drivers),
            &HashMap::new(),
            errors,
            security,
            Arc::new(HashMap::new()),
            Arc::new(Mutex::new(DiscoveredErrors::default())),
            true,
            None,
            None,
            test_call_timeout(),
            false,
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let response = reqwest::get(format!("http://{addr}/things")).await.unwrap();
        // Not 404 — with no `config/errors/` scaffolded at all, this
        // registry has no entry for "datasource.sql.not_found" either, so
        // it falls back to the force-inserted `unexpected.error`'s own
        // status (500), same as any other unclassified code. That gap is
        // exactly what's being recorded below.
        assert_eq!(response.status(), 500);

        let discovered_path = root.join("config/errors.discovered.json");
        let discovered = DiscoveredErrors::load(&discovered_path).expect("a real unclassified failure in debugMode must be saved to config/errors.discovered.json");
        assert_eq!(discovered.len(), 1);
        let entry = discovered.lookup("datasource.sql.not_found").expect("recorded under its real classification code");
        assert_eq!(entry.occurrences, 1);
        assert_eq!(entry.sample_message, "query returned no rows");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// `errorOverrides` end to end through `resolve_request` — parsed from
    /// real endpoint-file JSON (not constructed via `ErrorOverride`
    /// literals), through a genuine source failure, not just the direct
    /// `error_envelope` unit tests above.
    #[tokio::test]
    async fn an_endpoint_files_error_overrides_change_a_real_response() {
        #[derive(Debug)]
        struct AlwaysFailsDriver;
        #[async_trait::async_trait]
        impl SqlDriver for AlwaysFailsDriver {
            async fn query(&self, _script: &str, _params: &HashMap<String, crate::sql::SqlValue>) -> Result<Vec<crate::sql::SqlRow>, crate::sql::SqlError> {
                Err(crate::sql::SqlError::ConnectionFailed("pool exhausted".to_string()))
            }
        }

        let json = r#"{
            "operationId": "test",
            "sources": {
                "car": { "type": "sql", "connection": "db", "script": "q.sql" }
            },
            "response": {},
            "errorOverrides": {
                "datasource.sql.connection_failed": { "httpStatus": 503, "exposeDetail": true }
            }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        assert!(
            endpoint.error_overrides.contains_key("datasource.sql.connection_failed"),
            "errorOverrides should parse from real endpoint JSON"
        );

        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(AlwaysFailsDriver));

        let root = std::env::temp_dir().join(format!(
            "frogs-error-overrides-e2e-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(root.join("db")).unwrap();
        std::fs::write(root.join("db/q.sql"), "SELECT 1;").unwrap();
        // Registry says 500/no-detail — the endpoint's own override should
        // win over both.
        let errors_dir = root.join("config-errors");
        std::fs::create_dir_all(&errors_dir).unwrap();
        std::fs::write(
            errors_dir.join("core.json"),
            r#"{ "datasource.sql.connection_failed": { "httpStatus": 500, "exposeDetail": false } }"#,
        )
        .unwrap();
        let errors = ErrorRegistry::load(&errors_dir).unwrap();

        let security = SecurityConfig {
            schemes: HashMap::new(),
            verifiers: HashMap::new(),
        };
        let discovered_errors = Mutex::new(DiscoveredErrors::default());

        let (status, body) = resolve_request(
            &endpoint,
            &security,
            &HashMap::new(),
            &drivers,
            &root,
            &root,
            &reqwest::Client::new(),
            &errors,
            &discovered_errors,
            &root.join("errors.discovered.json"),
            false,
            &crate::security::VerifierCache::new(),
            &HeaderMap::new(),
            None,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            None,
            &Map::new(),
            test_call_timeout(),
        )
        .await;

        assert_eq!(status, 503, "the endpoint's own errorOverrides should win over the registry's 500");
        assert_eq!(
            body["detail"], "connection failed: pool exhausted",
            "exposeDetail: true in the override should show detail despite the registry saying false"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A `_generated: true` stub is refused with `501` and the real `_todo`
    /// message, without ever touching sources, security, or validation —
    /// proven by a `PanicsIfCalledDriver`-equivalent (a driver that would
    /// panic if `resolve_sources` ever reached it) and a security scheme
    /// with no matching verifier at all (which would otherwise itself be a
    /// hard failure) still resolving to the *generated-stub* response, not
    /// a security error.
    #[tokio::test]
    async fn a_generated_stub_is_refused_with_501_before_security_or_sources_run() {
        #[derive(Debug)]
        struct PanicsIfCalledDriver;
        #[async_trait::async_trait]
        impl SqlDriver for PanicsIfCalledDriver {
            async fn query(&self, _script: &str, _params: &HashMap<String, crate::sql::SqlValue>) -> Result<Vec<crate::sql::SqlRow>, crate::sql::SqlError> {
                panic!("a _generated: true stub must never reach a real source");
            }
        }

        let json = r#"{
            "operationId": "getCarInfo",
            "_generated": true,
            "_todo": "See getCarInfo.reference.json for available request/response fields.",
            "security": "apiKeyAuth",
            "sources": { "car": { "type": "sql", "connection": "db", "script": "q.sql" } },
            "response": { "maker": null }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        assert!(endpoint.generated);

        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(PanicsIfCalledDriver));

        // No "apiKeyAuth" scheme registered at all — if the security check
        // ran before the generated-stub gate, this alone would already be a
        // hard failure (see `a_missing_verifier_is_a_clear_config_failure`-
        // style tests elsewhere), proving the gate really does run first.
        let security = SecurityConfig::default();
        let errors = ErrorRegistry::load(Path::new("/does/not/exist")).unwrap();
        let discovered_errors = Mutex::new(DiscoveredErrors::default());
        let root = std::env::temp_dir();

        let (status, body) = resolve_request(
            &endpoint,
            &security,
            &HashMap::new(),
            &drivers,
            &root,
            &root,
            &reqwest::Client::new(),
            &errors,
            &discovered_errors,
            &root.join("errors.discovered.json"),
            false,
            &crate::security::VerifierCache::new(),
            &HeaderMap::new(),
            None,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            None,
            &Map::new(),
            test_call_timeout(),
        )
        .await;

        assert_eq!(status, 501);
        assert_eq!(body["name"], "endpoint.not_configured");
        assert_eq!(body["detail"], "See getCarInfo.reference.json for available request/response fields.");
    }

    #[tokio::test]
    async fn a_generated_stub_with_no_todo_message_gets_a_sensible_default_detail() {
        let json = r#"{ "operationId": "test", "_generated": true, "sources": {}, "response": {} }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();

        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        let security = SecurityConfig::default();
        let errors = ErrorRegistry::load(Path::new("/does/not/exist")).unwrap();
        let discovered_errors = Mutex::new(DiscoveredErrors::default());
        let root = std::env::temp_dir();

        let (status, body) = resolve_request(
            &endpoint,
            &security,
            &HashMap::new(),
            &drivers,
            &root,
            &root,
            &reqwest::Client::new(),
            &errors,
            &discovered_errors,
            &root.join("errors.discovered.json"),
            false,
            &crate::security::VerifierCache::new(),
            &HeaderMap::new(),
            None,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            None,
            &Map::new(),
            test_call_timeout(),
        )
        .await;

        assert_eq!(status, 501);
        assert!(body["detail"].as_str().is_some_and(|d| !d.is_empty()));
    }

    /// A hand-edited, no-longer-generated endpoint (the common case —
    /// `frogs generate` never overwrites a file once it exists, so this is
    /// what a filled-in stub actually looks like) behaves exactly as before
    /// this gate existed.
    #[tokio::test]
    async fn an_endpoint_with_generated_false_is_unaffected() {
        let json = r#"{ "operationId": "test", "_generated": false, "sources": {}, "response": {} }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();

        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        let security = SecurityConfig::default();
        let errors = ErrorRegistry::load(Path::new("/does/not/exist")).unwrap();
        let discovered_errors = Mutex::new(DiscoveredErrors::default());
        let root = std::env::temp_dir();

        let (status, _) = resolve_request(
            &endpoint,
            &security,
            &HashMap::new(),
            &drivers,
            &root,
            &root,
            &reqwest::Client::new(),
            &errors,
            &discovered_errors,
            &root.join("errors.discovered.json"),
            false,
            &crate::security::VerifierCache::new(),
            &HeaderMap::new(),
            None,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            None,
            &Map::new(),
            test_call_timeout(),
        )
        .await;

        assert_eq!(status, 200, "an ordinary (non-generated) endpoint must resolve normally");
    }

    /// End to end through a real running server via `build_router` — not
    /// just the direct `resolve_request` calls above.
    #[tokio::test]
    async fn a_generated_stub_returns_501_through_a_real_running_server() {
        let root = std::env::temp_dir().join(format!(
            "frogs-generated-stub-501-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let dir = root.join("datasources/endpoints/things");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("endpoint.get.json"),
            r#"{ "operationId": "getThing", "_generated": true, "_todo": "fill me in", "sources": {}, "response": { "id": null } }"#,
        )
        .unwrap();

        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        let errors = Arc::new(ErrorRegistry::load(&root.join("does-not-exist")).unwrap());
        let security = Arc::new(SecurityConfig::default());
        let router = build_router(
            &root,
            Arc::new(drivers),
            &HashMap::new(),
            errors,
            security,
            Arc::new(HashMap::new()),
            Arc::new(Mutex::new(DiscoveredErrors::default())),
            false,
            None,
            None,
            test_call_timeout(),
            false,
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let response = reqwest::get(format!("http://{addr}/things")).await.unwrap();
        assert_eq!(response.status(), 501);
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["detail"], "fill me in");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A helper shared by the per-endpoint `debugMode` tests below: one
    /// non-optional SQL source that always fails, resolved through
    /// `resolve_request` with a fresh, isolated `errors`/`discovered`/`root`
    /// set each call, returning just the built response body.
    async fn run_with_debug_mode(endpoint_json: &str, global_debug_mode: bool) -> Value {
        #[derive(Debug)]
        struct AlwaysFailsDriver;
        #[async_trait::async_trait]
        impl SqlDriver for AlwaysFailsDriver {
            async fn query(&self, _script: &str, _params: &HashMap<String, crate::sql::SqlValue>) -> Result<Vec<crate::sql::SqlRow>, crate::sql::SqlError> {
                Err(crate::sql::SqlError::ConnectionFailed("pool exhausted".to_string()))
            }
        }

        let endpoint: EndpointFile = serde_json::from_str(endpoint_json).unwrap();
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(AlwaysFailsDriver));

        let root = std::env::temp_dir().join(format!(
            "frogs-per-endpoint-debug-mode-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(root.join("db")).unwrap();
        std::fs::write(root.join("db/q.sql"), "SELECT 1;").unwrap();
        // exposeDetail: false — so any `detail` that shows up must be
        // because of debugMode, not the registry's own exposure setting.
        let errors_dir = root.join("config-errors");
        std::fs::create_dir_all(&errors_dir).unwrap();
        std::fs::write(
            errors_dir.join("core.json"),
            r#"{ "datasource.sql.connection_failed": { "httpStatus": 500, "exposeDetail": false } }"#,
        )
        .unwrap();
        let errors = ErrorRegistry::load(&errors_dir).unwrap();

        let security = SecurityConfig {
            schemes: HashMap::new(),
            verifiers: HashMap::new(),
        };
        let discovered_errors = Mutex::new(DiscoveredErrors::default());

        let (_, body) = resolve_request(
            &endpoint,
            &security,
            &HashMap::new(),
            &drivers,
            &root,
            &root,
            &reqwest::Client::new(),
            &errors,
            &discovered_errors,
            &root.join("errors.discovered.json"),
            global_debug_mode,
            &crate::security::VerifierCache::new(),
            &HeaderMap::new(),
            None,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            None,
            &Map::new(),
            test_call_timeout(),
        )
        .await;

        let _ = std::fs::remove_dir_all(&root);
        body
    }

    #[tokio::test]
    async fn an_endpoints_own_debug_mode_true_overrides_a_false_global_default() {
        let json = r#"{
            "operationId": "test",
            "sources": { "car": { "type": "sql", "connection": "db", "script": "q.sql" } },
            "response": {},
            "debugMode": true
        }"#;
        let body = run_with_debug_mode(json, false).await;

        assert!(
            body.get("detail").is_some(),
            "the endpoint's own debugMode: true should show detail even though the global default is off and exposeDetail is false: {body:?}"
        );
    }

    #[tokio::test]
    async fn an_endpoints_own_debug_mode_false_overrides_a_true_global_default() {
        let json = r#"{
            "operationId": "test",
            "sources": { "car": { "type": "sql", "connection": "db", "script": "q.sql" } },
            "response": {},
            "debugMode": false
        }"#;
        let body = run_with_debug_mode(json, true).await;

        assert!(
            body.get("detail").is_none(),
            "the endpoint's own debugMode: false should suppress detail even though the global default is on: {body:?}"
        );
    }

    #[tokio::test]
    async fn an_endpoint_with_no_debug_mode_of_its_own_uses_the_global_default() {
        let json = r#"{
            "operationId": "test",
            "sources": { "car": { "type": "sql", "connection": "db", "script": "q.sql" } },
            "response": {}
        }"#;
        assert!(
            run_with_debug_mode(json, true).await.get("detail").is_some(),
            "global debugMode: true should still apply with no per-endpoint override"
        );
        assert!(
            run_with_debug_mode(json, false).await.get("detail").is_none(),
            "global debugMode: false should still apply with no per-endpoint override"
        );
    }

    /// The discovery-recording side effect (not just detail exposure) also
    /// follows the effective, per-endpoint `debugMode` — an unclassified
    /// code gets recorded when *this endpoint's* debugMode is on, even
    /// though the server-wide default is off.
    #[tokio::test]
    async fn per_endpoint_debug_mode_also_governs_discovered_error_recording() {
        #[derive(Debug)]
        struct EmptyResultDriver;
        #[async_trait::async_trait]
        impl SqlDriver for EmptyResultDriver {
            async fn query(&self, _script: &str, _params: &HashMap<String, crate::sql::SqlValue>) -> Result<Vec<crate::sql::SqlRow>, crate::sql::SqlError> {
                Ok(vec![])
            }
        }

        let json = r#"{
            "operationId": "test",
            "sources": { "car": { "type": "sql", "connection": "db", "script": "q.sql" } },
            "response": {},
            "debugMode": true
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(EmptyResultDriver));

        let root = std::env::temp_dir().join(format!(
            "frogs-per-endpoint-debug-mode-discovery-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(root.join("db")).unwrap();
        std::fs::write(root.join("db/q.sql"), "SELECT 1;").unwrap();
        // Empty registry — "datasource.sql.not_found" is genuinely unclassified.
        let errors = ErrorRegistry::load(&root.join("does-not-exist")).unwrap();
        let security = SecurityConfig {
            schemes: HashMap::new(),
            verifiers: HashMap::new(),
        };
        let discovered_errors = Mutex::new(DiscoveredErrors::default());

        resolve_request(
            &endpoint,
            &security,
            &HashMap::new(),
            &drivers,
            &root,
            &root,
            &reqwest::Client::new(),
            &errors,
            &discovered_errors,
            &root.join("errors.discovered.json"),
            false, // global default is off
            &crate::security::VerifierCache::new(),
            &HeaderMap::new(),
            None,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
            None,
            &Map::new(),
            test_call_timeout(),
        )
        .await;

        assert_eq!(
            discovered_errors.lock().unwrap().len(),
            1,
            "the endpoint's own debugMode: true should still trigger discovery recording despite the global default being off"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// `resolve_request`'s own request-validation step, exercised directly
    /// rather than through a real HTTP server — it's `pub(crate)` and
    /// already the exact integration point both `handle_request` and
    /// `frogs test`'s case runner call through.
    mod request_validation_tests {
        use super::*;
        use crate::openapi::{Operation, ParameterInfo};
        use crate::sql::{SqlError, SqlValue};

        fn error_registry_with_validation_codes() -> ErrorRegistry {
            let root = std::env::temp_dir().join(format!(
                "frogs-endpoint-validation-errors-{}-{}",
                std::process::id(),
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
            ));
            std::fs::create_dir_all(&root).unwrap();
            std::fs::write(
                root.join("core.json"),
                r#"{
                    "validation.missing_parameter": { "httpStatus": 400, "exposeDetail": true },
                    "validation.invalid_type": { "httpStatus": 400, "exposeDetail": true },
                    "auth.invalid_credentials": { "httpStatus": 401, "exposeDetail": true }
                }"#,
            )
            .unwrap();
            let registry = ErrorRegistry::load(&root).unwrap();
            let _ = std::fs::remove_dir_all(&root);
            registry
        }

        fn no_op_endpoint() -> EndpointFile {
            serde_json::from_str(r#"{ "operationId": "test", "sources": {}, "response": {} }"#).unwrap()
        }

        fn temp_project_root() -> PathBuf {
            let root = std::env::temp_dir().join(format!(
                "frogs-endpoint-validation-test-{}-{}",
                std::process::id(),
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
            ));
            std::fs::create_dir_all(&root).unwrap();
            root
        }

        #[allow(clippy::too_many_arguments)]
        async fn run(
            endpoint: &EndpointFile,
            security: &SecurityConfig,
            drivers: &HashMap<String, Box<dyn SqlDriver>>,
            errors: &ErrorRegistry,
            path_params: &HashMap<String, String>,
            query_params: &HashMap<String, String>,
            headers: &HeaderMap,
            body: &Value,
            operation: Option<&Operation>,
        ) -> (u16, Value) {
            let root = temp_project_root();
            // A verifier's own sql script needs a real file on disk to read
            // (its *contents* are never actually inspected — `SqlDriver` is
            // faked — but `run_sql`/`security::verify` still `fs::read_to_string`
            // it before ever reaching the fake driver).
            std::fs::create_dir_all(root.join("db")).unwrap();
            std::fs::write(root.join("db/verify_key.sql"), "SELECT active FROM api_keys WHERE key = :key;").unwrap();
            let discovered_errors = Mutex::new(DiscoveredErrors::default());
            let component_schemas = Map::new();
            let result = resolve_request(
                endpoint,
                security,
                &HashMap::new(),
                drivers,
                &root,
                &root,
                &reqwest::Client::new(),
                errors,
                &discovered_errors,
                &root.join("errors.discovered.json"),
                false,
                &crate::security::VerifierCache::new(),
                headers,
                None,
                path_params,
                query_params,
                body,
                "",
                &HashMap::new(),
                operation,
                &component_schemas,
                test_call_timeout(),
            )
            .await;
            let _ = std::fs::remove_dir_all(&root);
            result
        }

        fn operation_requiring_query_param(name: &str, schema_type: &str) -> Operation {
            Operation {
                path: "/test".to_string(),
                method: "get".to_string(),
                http_method: "GET".to_string(),
                operation_id: "test".to_string(),
                response_schema: None,
                parameters: vec![ParameterInfo {
                    name: name.to_string(),
                    location: "query".to_string(),
                    required: true,
                    schema_type: Some(schema_type.to_string()),
                }],
                request_body: None,
                response_status_codes: vec![200],
                security: None,
                ..Default::default()
            }
        }

        #[tokio::test]
        async fn a_missing_required_query_parameter_is_rejected_with_400() {
            let endpoint = no_op_endpoint();
            let security = SecurityConfig {
                schemes: HashMap::new(),
                verifiers: HashMap::new(),
            };
            let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
            let errors = error_registry_with_validation_codes();
            let operation = operation_requiring_query_param("maker", "string");

            let (status, body) = run(
                &endpoint,
                &security,
                &drivers,
                &errors,
                &HashMap::new(),
                &HashMap::new(),
                &HeaderMap::new(),
                &Value::Null,
                Some(&operation),
            )
            .await;

            assert_eq!(status, 400);
            assert_eq!(body["name"], "validation.missing_parameter");
        }

        #[tokio::test]
        async fn a_wrong_typed_query_parameter_is_rejected_with_400() {
            let endpoint = no_op_endpoint();
            let security = SecurityConfig {
                schemes: HashMap::new(),
                verifiers: HashMap::new(),
            };
            let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
            let errors = error_registry_with_validation_codes();
            let operation = operation_requiring_query_param("limit", "integer");
            let query_params = HashMap::from([("limit".to_string(), "not-a-number".to_string())]);

            let (status, body) = run(
                &endpoint,
                &security,
                &drivers,
                &errors,
                &HashMap::new(),
                &query_params,
                &HeaderMap::new(),
                &Value::Null,
                Some(&operation),
            )
            .await;

            assert_eq!(status, 400);
            assert_eq!(body["name"], "validation.invalid_type");
        }

        #[tokio::test]
        async fn a_present_correctly_typed_parameter_passes_and_the_request_proceeds() {
            let endpoint = no_op_endpoint();
            let security = SecurityConfig {
                schemes: HashMap::new(),
                verifiers: HashMap::new(),
            };
            let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
            let errors = error_registry_with_validation_codes();
            let operation = operation_requiring_query_param("limit", "integer");
            let query_params = HashMap::from([("limit".to_string(), "10".to_string())]);

            let (status, body) = run(
                &endpoint,
                &security,
                &drivers,
                &errors,
                &HashMap::new(),
                &query_params,
                &HeaderMap::new(),
                &Value::Null,
                Some(&operation),
            )
            .await;

            // The no-op endpoint has no sources at all, so a request that
            // clears validation resolves to a plain empty 200 — proof
            // resolution actually ran, not just that validation didn't
            // reject it.
            assert_eq!(status, 200);
            assert_eq!(body, serde_json::json!({}));
        }

        #[tokio::test]
        async fn operation_none_skips_validation_entirely_even_for_an_otherwise_invalid_request() {
            let endpoint = no_op_endpoint();
            let security = SecurityConfig {
                schemes: HashMap::new(),
                verifiers: HashMap::new(),
            };
            let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
            let errors = error_registry_with_validation_codes();

            // No `operation` passed at all (the `features.requestValidation:
            // false` equivalent) — a request that would fail the same
            // operation's own validation if it were `Some` sails through.
            let (status, body) = run(
                &endpoint,
                &security,
                &drivers,
                &errors,
                &HashMap::new(),
                &HashMap::new(),
                &HeaderMap::new(),
                &Value::Null,
                None,
            )
            .await;

            assert_eq!(status, 200);
            assert_eq!(body, serde_json::json!({}));
        }

        /// The explicit ordering decision: a request that fails *both* the
        /// security check and request validation gets the security
        /// failure, never validation's — a caller who isn't even allowed to
        /// call this endpoint shouldn't learn anything about its request
        /// shape.
        #[tokio::test]
        async fn a_security_failure_wins_over_a_request_validation_failure() {
            use crate::security::{LoadedVerifier, ValidIf, VerifierDef};

            #[derive(Debug)]
            struct AlwaysDeniesDriver;
            #[async_trait::async_trait]
            impl SqlDriver for AlwaysDeniesDriver {
                async fn query(&self, _script: &str, _params: &HashMap<String, SqlValue>) -> Result<Vec<HashMap<String, SqlValue>>, SqlError> {
                    Ok(vec![])
                }
            }

            let def: VerifierDef = serde_json::from_str(
                r#"{
                    "type": "sql",
                    "connection": "db",
                    "script": "verify_key.sql",
                    "parameters": [{ "name": "key", "from": "header.X-Api-Key" }],
                    "validIf": "row.active = true"
                }"#,
            )
            .unwrap();
            let verifier = LoadedVerifier {
                valid_if: ValidIf::parse(def.valid_if()).unwrap(),
                def,
                mtls: None,
            };
            let mut verifiers = HashMap::new();
            verifiers.insert("apiKeyAuth".to_string(), verifier);
            let security = SecurityConfig {
                schemes: HashMap::new(),
                verifiers,
            };

            let endpoint: EndpointFile = serde_json::from_str(r#"{ "operationId": "test", "security": "apiKeyAuth", "sources": {}, "response": {} }"#).unwrap();
            let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
            drivers.insert("db".to_string(), Box::new(AlwaysDeniesDriver));
            let errors = error_registry_with_validation_codes();
            // Would also fail request validation (missing required query
            // param) if the security check didn't already stop the request.
            let operation = operation_requiring_query_param("maker", "string");

            // No `X-Api-Key` header sent at all, and no `maker` query
            // parameter either — both checks would fail independently.
            let (status, body) = run(
                &endpoint,
                &security,
                &drivers,
                &errors,
                &HashMap::new(),
                &HashMap::new(),
                &HeaderMap::new(),
                &Value::Null,
                Some(&operation),
            )
            .await;

            assert_eq!(status, 401);
            assert_eq!(body["name"], "auth.invalid_credentials");
        }
    }

    // ---- `validate_nested_many` ----

    mod validate_nested_many_tests {
        use super::*;

        fn endpoint_with(source_json: &str) -> EndpointFile {
            let json = format!(
                r#"{{
                    "operationId": "test",
                    "sources": {{
                        "cars": {{ "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "many" }},
                        "pricing": {source_json}
                    }},
                    "response": {{}}
                }}"#
            );
            serde_json::from_str(&json).unwrap()
        }

        fn sqlite_connection(in_memory: bool) -> ConnectionConfig {
            let mut settings = HashMap::new();
            if in_memory {
                settings.insert("database".to_string(), Value::String(":memory:".to_string()));
            }
            ConnectionConfig {
                driver: "sqlite".to_string(),
                settings,
            }
        }

        #[test]
        fn rejects_allow_nested_many_with_max_concurrency_omitted() {
            let endpoint = endpoint_with(
                r#"{
                    "type": "sql", "connection": "db", "script": "q.sql",
                    "allowNestedMany": true, "maxRows": 10,
                    "parameters": [{ "name": "vin", "from": "sources.cars[].vin" }]
                }"#,
            );
            let problems = validate_nested_many(&endpoint, &HashMap::new());
            assert!(
                problems.iter().any(|p| p.contains("maxConcurrency")),
                "expected a maxConcurrency problem, got: {problems:?}"
            );
        }

        #[test]
        fn rejects_allow_nested_many_with_max_rows_omitted() {
            let endpoint = endpoint_with(
                r#"{
                    "type": "sql", "connection": "db", "script": "q.sql",
                    "allowNestedMany": true, "maxConcurrency": 2,
                    "parameters": [{ "name": "vin", "from": "sources.cars[].vin" }]
                }"#,
            );
            let problems = validate_nested_many(&endpoint, &HashMap::new());
            assert!(problems.iter().any(|p| p.contains("maxRows")), "expected a maxRows problem, got: {problems:?}");
        }

        #[test]
        fn rejects_max_concurrency_exceeding_the_hard_ceiling() {
            let endpoint = endpoint_with(
                r#"{
                    "type": "http", "request": "pricing.json",
                    "allowNestedMany": true, "maxConcurrency": 51, "maxRows": 10,
                    "parameters": [{ "name": "vin", "from": "sources.cars[].vin" }]
                }"#,
            );
            let problems = validate_nested_many(&endpoint, &HashMap::new());
            assert!(
                problems.iter().any(|p| p.contains("maxConcurrency") && p.contains("hard ceiling")),
                "expected a hard-ceiling maxConcurrency problem, got: {problems:?}"
            );
        }

        #[test]
        fn rejects_max_rows_exceeding_the_hard_ceiling() {
            let endpoint = endpoint_with(
                r#"{
                    "type": "http", "request": "pricing.json",
                    "allowNestedMany": true, "maxConcurrency": 2, "maxRows": 1001,
                    "parameters": [{ "name": "vin", "from": "sources.cars[].vin" }]
                }"#,
            );
            let problems = validate_nested_many(&endpoint, &HashMap::new());
            assert!(
                problems.iter().any(|p| p.contains("maxRows") && p.contains("hard ceiling")),
                "expected a hard-ceiling maxRows problem, got: {problems:?}"
            );
        }

        #[test]
        fn rejects_row_timeout_ms_exceeding_the_hard_ceiling() {
            let endpoint = endpoint_with(
                r#"{
                    "type": "http", "request": "pricing.json",
                    "allowNestedMany": true, "maxConcurrency": 2, "maxRows": 10, "rowTimeoutMs": 300001,
                    "parameters": [{ "name": "vin", "from": "sources.cars[].vin" }]
                }"#,
            );
            let problems = validate_nested_many(&endpoint, &HashMap::new());
            assert!(
                problems.iter().any(|p| p.contains("rowTimeoutMs") && p.contains("hard ceiling")),
                "expected a hard-ceiling rowTimeoutMs problem, got: {problems:?}"
            );
        }

        /// A normal (non-in-memory) SQL connection has the default pool
        /// capacity of 5 (`sql::DEFAULT_POOL_MAX_CONNECTIONS`) — 0.6 of that,
        /// floored, is 3, so `maxConcurrency: 4` must be rejected and
        /// `maxConcurrency: 3` must not be.
        #[test]
        fn rejects_sql_backed_max_concurrency_exceeding_the_pool_derived_ceiling_for_a_normal_connection() {
            let mut connections = HashMap::new();
            connections.insert("db".to_string(), sqlite_connection(false));

            let over = endpoint_with(
                r#"{
                    "type": "sql", "connection": "db", "script": "q.sql",
                    "allowNestedMany": true, "maxConcurrency": 4, "maxRows": 10,
                    "parameters": [{ "name": "vin", "from": "sources.cars[].vin" }]
                }"#,
            );
            let problems = validate_nested_many(&over, &connections);
            assert!(
                problems.iter().any(|p| p.contains("pool-derived ceiling")),
                "maxConcurrency: 4 should exceed the pool-derived ceiling of 3, got: {problems:?}"
            );

            let at_ceiling = endpoint_with(
                r#"{
                    "type": "sql", "connection": "db", "script": "q.sql",
                    "allowNestedMany": true, "maxConcurrency": 3, "maxRows": 10,
                    "parameters": [{ "name": "vin", "from": "sources.cars[].vin" }]
                }"#,
            );
            let problems = validate_nested_many(&at_ceiling, &connections);
            assert!(
                !problems.iter().any(|p| p.contains("pool-derived ceiling")),
                "maxConcurrency: 3 should be exactly at the pool-derived ceiling, got: {problems:?}"
            );
        }

        /// An in-memory sqlite connection is pinned to exactly 1 real
        /// connection (`sql::pool_capacity`) — 0.6 of that, floored and
        /// clamped to a minimum of 1, is still 1, so `maxConcurrency: 2` must
        /// be rejected and `maxConcurrency: 1` must not be.
        #[test]
        fn rejects_sql_backed_max_concurrency_exceeding_the_pool_derived_ceiling_for_an_in_memory_sqlite_connection() {
            let mut connections = HashMap::new();
            connections.insert("db".to_string(), sqlite_connection(true));

            let over = endpoint_with(
                r#"{
                    "type": "sql", "connection": "db", "script": "q.sql",
                    "allowNestedMany": true, "maxConcurrency": 2, "maxRows": 10,
                    "parameters": [{ "name": "vin", "from": "sources.cars[].vin" }]
                }"#,
            );
            let problems = validate_nested_many(&over, &connections);
            assert!(
                problems.iter().any(|p| p.contains("pool-derived ceiling")),
                "maxConcurrency: 2 should exceed the in-memory-sqlite pool-derived ceiling of 1, got: {problems:?}"
            );

            let at_ceiling = endpoint_with(
                r#"{
                    "type": "sql", "connection": "db", "script": "q.sql",
                    "allowNestedMany": true, "maxConcurrency": 1, "maxRows": 10,
                    "parameters": [{ "name": "vin", "from": "sources.cars[].vin" }]
                }"#,
            );
            let problems = validate_nested_many(&at_ceiling, &connections);
            assert!(
                !problems.iter().any(|p| p.contains("pool-derived ceiling")),
                "maxConcurrency: 1 should be exactly at the in-memory-sqlite pool-derived ceiling, got: {problems:?}"
            );
        }

        #[test]
        fn rejects_a_bracket_parent_that_isnt_cardinality_many() {
            let json = r#"{
                "operationId": "test",
                "sources": {
                    "car": { "type": "sql", "connection": "db", "script": "q.sql" },
                    "pricing": {
                        "type": "http", "request": "pricing.json",
                        "allowNestedMany": true, "maxConcurrency": 2, "maxRows": 10,
                        "parameters": [{ "name": "vin", "from": "sources.car[].vin" }]
                    }
                },
                "response": {}
            }"#;
            let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
            let problems = validate_nested_many(&endpoint, &HashMap::new());
            assert!(
                problems.iter().any(|p| p.contains("cardinality")),
                "a bracket-parent that isn't cardinality: many must be rejected, got: {problems:?}"
            );
        }

        #[test]
        fn rejects_a_bracket_parent_that_is_itself_allow_nested_many() {
            let json = r#"{
                "operationId": "test",
                "sources": {
                    "trucks": { "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "many" },
                    "specs": {
                        "type": "http", "request": "specs.json",
                        "allowNestedMany": true, "maxConcurrency": 2, "maxRows": 10,
                        "parameters": [{ "name": "plate", "from": "sources.trucks[].plate" }]
                    },
                    "pricing": {
                        "type": "http", "request": "pricing.json",
                        "allowNestedMany": true, "maxConcurrency": 2, "maxRows": 10,
                        "parameters": [{ "name": "plate", "from": "sources.specs[].plate" }]
                    }
                },
                "response": {}
            }"#;
            let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
            let problems = validate_nested_many(&endpoint, &HashMap::new());
            assert!(
                problems.iter().any(|p| p.contains("pricing") && p.contains("itself allowNestedMany")),
                "'pricing' depending on the already-nested-many 'specs' must be rejected (multi-level fan-out isn't supported), got: {problems:?}"
            );
        }

        #[test]
        fn rejects_zero_bracket_form_parents() {
            let endpoint = endpoint_with(
                r#"{
                    "type": "http", "request": "pricing.json",
                    "allowNestedMany": true, "maxConcurrency": 2, "maxRows": 10,
                    "parameters": [{ "name": "vin", "from": "path.vin" }]
                }"#,
            );
            let problems = validate_nested_many(&endpoint, &HashMap::new());
            assert!(
                problems.iter().any(|p| p.contains("no bracket-form parameter")),
                "a nested-many source with no bracket-form parameter at all must be rejected, got: {problems:?}"
            );
        }

        #[test]
        fn rejects_multiple_distinct_bracket_form_parents() {
            let json = r#"{
                "operationId": "test",
                "sources": {
                    "cars": { "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "many" },
                    "trucks": { "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "many" },
                    "pricing": {
                        "type": "http", "request": "pricing.json",
                        "allowNestedMany": true, "maxConcurrency": 2, "maxRows": 10,
                        "parameters": [
                            { "name": "vin", "from": "sources.cars[].vin" },
                            { "name": "plate", "from": "sources.trucks[].plate" }
                        ]
                    }
                },
                "response": {}
            }"#;
            let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
            let problems = validate_nested_many(&endpoint, &HashMap::new());
            assert!(
                problems.iter().any(|p| p.contains("distinct bracket-form parents")),
                "a nested-many source referencing two different bracket parents must be rejected, got: {problems:?}"
            );
        }

        #[test]
        fn rejects_bracket_form_syntax_on_a_source_that_isnt_itself_allow_nested_many() {
            let json = r#"{
                "operationId": "test",
                "sources": {
                    "cars": { "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "many" },
                    "pricing": {
                        "type": "http", "request": "pricing.json",
                        "parameters": [{ "name": "vin", "from": "sources.cars[].vin" }]
                    }
                },
                "response": {}
            }"#;
            let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
            let problems = validate_nested_many(&endpoint, &HashMap::new());
            assert!(
                problems.iter().any(|p| p.contains("doesn't declare") && p.contains("allowNestedMany")),
                "bracket syntax on a non-allowNestedMany source must be rejected, got: {problems:?}"
            );
        }

        /// The nested-many source's own result cardinality (`"one"`, the
        /// default — one merged object per row) is a completely separate
        /// concept from its *bracket-parent's* cardinality (which must be
        /// `"many"`) — a correctly configured `cardinality: "one"`
        /// nested-many source must not be rejected.
        #[test]
        fn does_not_reject_a_correctly_configured_cardinality_one_nested_many_source() {
            let endpoint = endpoint_with(
                r#"{
                    "type": "http", "request": "pricing.json", "cardinality": "one",
                    "allowNestedMany": true, "maxConcurrency": 2, "maxRows": 10,
                    "parameters": [{ "name": "vin", "from": "sources.cars[].vin" }]
                }"#,
            );
            let problems = validate_nested_many(&endpoint, &HashMap::new());
            assert!(
                problems.is_empty(),
                "a correctly configured cardinality: one nested-many source must not be rejected, got: {problems:?}"
            );
        }
    }

    // ---- `validate_source_call_timeout` ----

    mod validate_source_call_timeout_tests {
        use super::*;

        fn endpoint_with_source(source_json: &str) -> EndpointFile {
            let json = format!(
                r#"{{
                    "operationId": "test",
                    "sources": {{ "car": {source_json} }},
                    "response": {{}}
                }}"#
            );
            serde_json::from_str(&json).unwrap()
        }

        #[test]
        fn accepts_an_ordinary_source_with_no_call_timeout_ms_at_all() {
            let endpoint = endpoint_with_source(r#"{ "type": "sql", "connection": "db", "script": "q.sql" }"#);
            let problems = validate_source_call_timeout(&endpoint);
            assert!(
                problems.is_empty(),
                "an ordinary source with no callTimeoutMs must not be rejected, got: {problems:?}"
            );
        }

        #[test]
        fn accepts_a_call_timeout_ms_at_the_hard_ceiling() {
            let endpoint = endpoint_with_source(r#"{ "type": "sql", "connection": "db", "script": "q.sql", "callTimeoutMs": 300000 }"#);
            let problems = validate_source_call_timeout(&endpoint);
            assert!(
                problems.is_empty(),
                "callTimeoutMs exactly at the hard ceiling must not be rejected, got: {problems:?}"
            );
        }

        #[test]
        fn rejects_a_sql_sources_call_timeout_ms_exceeding_the_hard_ceiling() {
            let endpoint = endpoint_with_source(r#"{ "type": "sql", "connection": "db", "script": "q.sql", "callTimeoutMs": 300001 }"#);
            let problems = validate_source_call_timeout(&endpoint);
            assert!(
                problems.iter().any(|p| p.contains("callTimeoutMs") && p.contains("hard ceiling")),
                "expected a hard-ceiling callTimeoutMs problem, got: {problems:?}"
            );
        }

        #[test]
        fn rejects_a_http_sources_call_timeout_ms_exceeding_the_hard_ceiling() {
            let endpoint = endpoint_with_source(r#"{ "type": "http", "request": "car.json", "callTimeoutMs": 300001 }"#);
            let problems = validate_source_call_timeout(&endpoint);
            assert!(
                problems.iter().any(|p| p.contains("callTimeoutMs") && p.contains("hard ceiling")),
                "expected a hard-ceiling callTimeoutMs problem for an HTTP source too, got: {problems:?}"
            );
        }

        #[test]
        fn rejects_a_source_declaring_both_allow_nested_many_and_call_timeout_ms() {
            let endpoint = endpoint_with_source(
                r#"{
                    "type": "http", "request": "car.json",
                    "allowNestedMany": true, "maxConcurrency": 2, "maxRows": 10, "callTimeoutMs": 1000,
                    "parameters": [{ "name": "vin", "from": "sources.car[].vin" }]
                }"#,
            );
            let problems = validate_source_call_timeout(&endpoint);
            assert!(
                problems.iter().any(|p| p.contains("allowNestedMany") && p.contains("callTimeoutMs")),
                "expected a problem naming the allowNestedMany/callTimeoutMs conflict, got: {problems:?}"
            );
        }

        #[test]
        fn does_not_reject_allow_nested_many_alone_without_call_timeout_ms() {
            let endpoint = endpoint_with_source(
                r#"{
                    "type": "http", "request": "car.json",
                    "allowNestedMany": true, "maxConcurrency": 2, "maxRows": 10,
                    "parameters": [{ "name": "vin", "from": "sources.car[].vin" }]
                }"#,
            );
            let problems = validate_source_call_timeout(&endpoint);
            assert!(
                problems.is_empty(),
                "allowNestedMany without callTimeoutMs is not this validator's concern, got: {problems:?}"
            );
        }
    }

    /// Mirrors the existing unmatched-security-scheme precedent: an endpoint
    /// file with an invalid nested-many configuration is skipped at
    /// `build_router` time (the route is simply never registered, a plain
    /// 404 rather than a startup crash) and `validate_endpoint_files`
    /// reports the exact same problem as a string, for `frogs validate`.
    #[tokio::test]
    async fn an_endpoint_with_an_invalid_nested_many_config_is_skipped_by_build_router_and_reported_by_validate_endpoint_files() {
        let root = std::env::temp_dir().join(format!(
            "frogs-endpoint-nested-many-invalid-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let dir = root.join("datasources/endpoints/pricing");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("endpoint.get.json"),
            r#"{
                "operationId": "getPricing",
                "sources": {
                    "cars": { "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "many" },
                    "pricing": {
                        "type": "http", "request": "pricing.json",
                        "allowNestedMany": true, "maxRows": 10,
                        "parameters": [{ "name": "vin", "from": "sources.cars[].vin" }]
                    }
                },
                "response": {}
            }"#,
        )
        .unwrap();

        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        let errors = Arc::new(ErrorRegistry::load(&root.join("does-not-exist")).unwrap());
        let security = Arc::new(SecurityConfig::default());
        let router = build_router(
            &root,
            Arc::new(drivers),
            &HashMap::new(),
            errors,
            security,
            Arc::new(HashMap::new()),
            Arc::new(Mutex::new(DiscoveredErrors::default())),
            false,
            None,
            None,
            test_call_timeout(),
            false,
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let client = reqwest::Client::new();
        let resp = client.get(format!("http://{addr}/pricing")).send().await.unwrap();
        assert_eq!(resp.status(), 404, "an invalid nested-many config must mean the route was never registered at all");

        let (count, problems) = validate_endpoint_files(&root.join("datasources/endpoints"), &SecurityConfig::default(), &HashMap::new(), false);
        assert_eq!(count, 1, "the file was still discovered — just invalid");
        assert!(
            problems.iter().any(|p| p.contains("maxConcurrency")),
            "validate_endpoint_files should report the same missing-maxConcurrency problem as a string: {problems:?}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A scripted `MockProvider` for pinning the `handle_mocked` seam
    /// itself, independently of `testing::session`: it returns whatever
    /// selection it was built with and records every `observe` call.
    struct Observed {
        route: RouteKey,
        status: u16,
        body: Value,
        unmocked: Vec<mock::Unmocked>,
    }

    struct ScriptedProvider {
        selection: MockSelection,
        observed: Mutex<Vec<Observed>>,
    }

    impl MockProvider for ScriptedProvider {
        fn select(&self, _route: &RouteKey, _request: &InboundRequest<'_>) -> MockSelection {
            self.selection.clone()
        }

        fn observe(&self, route: &RouteKey, _selection: &MockSelection, served: &Served<'_>) {
            self.observed.lock().unwrap().push(Observed {
                route: route.clone(),
                status: served.status,
                body: served.body.clone(),
                unmocked: served.unmocked.to_vec(),
            });
        }
    }

    fn baseline_choice() -> mock::ScenarioChoice {
        mock::ScenarioChoice {
            name: None,
            source: mock::ScenarioSource::Baseline,
        }
    }

    /// Builds a one-route router (`GET /cars`) from `endpoint_json` with
    /// `provider` installed and serves it on an ephemeral port.
    async fn serve_with_provider(endpoint_json: &str, provider: Arc<ScriptedProvider>) -> (String, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "frogs-endpoint-mock-seam-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let dir = root.join("datasources/endpoints/cars");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("endpoint.get.json"), endpoint_json).unwrap();

        let mut errors = ErrorRegistry::load(&root.join("does-not-exist")).unwrap();
        errors.insert_if_absent(
            mock::NO_MATCHING_CASE,
            crate::errors::ErrorDefinition {
                http_status: 404,
                expose_detail: true,
            },
        );
        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        let router = build_router(
            &root,
            Arc::new(drivers),
            &HashMap::new(),
            Arc::new(errors),
            Arc::new(SecurityConfig::default()),
            Arc::new(HashMap::new()),
            Arc::new(Mutex::new(DiscoveredErrors::default())),
            false,
            None,
            Some(provider),
            test_call_timeout(),
            false,
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (format!("http://{addr}"), root)
    }

    /// The route is keyed in OpenAPI `{name}` form for the provider, and
    /// the served status/body/unmocked list reach `observe` exactly as the
    /// client saw them — including an optional source the enforcer had to
    /// degrade.
    #[tokio::test]
    async fn handle_mocked_keys_the_route_in_openapi_form_and_hands_the_served_outcome_to_observe() {
        let provider = Arc::new(ScriptedProvider {
            selection: MockSelection::Case {
                case: None,
                mocks: HashMap::from([("car".to_string(), MockOutcome::Success(serde_json::json!({ "maker": "Honda" })))]),
                scenario: baseline_choice(),
                client_cert: None,
            },
            observed: Mutex::new(Vec::new()),
        });
        let (base, root) = serve_with_provider(
            r#"{
                "operationId": "getCar",
                "sources": {
                    "car": { "type": "http", "request": "never-read.json" },
                    "pricing": { "type": "http", "request": "never-read.json", "optional": true }
                },
                "response": { "maker": "sources.car.maker", "price": "sources.pricing.amount" }
            }"#,
            provider.clone(),
        )
        .await;

        let response = reqwest::get(format!("{base}/cars")).await.unwrap();
        assert_eq!(response.status(), 200);
        let body: Value = response.json().await.unwrap();
        assert_eq!(body, serde_json::json!({ "maker": "Honda", "price": null }));

        let observed = provider.observed.lock().unwrap();
        assert_eq!(observed.len(), 1);
        let Observed {
            route,
            status,
            body: served_body,
            unmocked,
        } = &observed[0];
        assert_eq!(
            route,
            &RouteKey {
                method: "get".to_string(),
                path: "/cars".to_string()
            }
        );
        assert_eq!(*status, 200);
        assert_eq!(served_body, &body);
        assert_eq!(
            unmocked,
            &vec![mock::Unmocked {
                name: "pricing".to_string(),
                optional: true
            }]
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A `NoMatch` never reaches resolution, but it is still classified
    /// through `error_envelope` — so the endpoint's own `errorOverrides`
    /// apply to it exactly as they would to any other failure.
    #[tokio::test]
    async fn handle_mocked_classifies_a_no_match_through_the_endpoints_own_error_overrides() {
        let provider = Arc::new(ScriptedProvider {
            selection: MockSelection::NoMatch {
                scenario: baseline_choice(),
                detail: "nothing matched".to_string(),
            },
            observed: Mutex::new(Vec::new()),
        });
        let (base, root) = serve_with_provider(
            r#"{
                "operationId": "getCar",
                "sources": {},
                "response": {},
                "errorOverrides": { "test.no_matching_case": { "httpStatus": 418, "exposeDetail": false } }
            }"#,
            provider.clone(),
        )
        .await;

        let response = reqwest::get(format!("{base}/cars")).await.unwrap();
        assert_eq!(response.status(), 418, "the endpoint's own override of the harness code must win");
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["name"], mock::NO_MATCHING_CASE);
        assert!(
            body.get("detail").is_none(),
            "exposeDetail: false must hide the detail even for a harness code: {body}"
        );

        let observed = provider.observed.lock().unwrap();
        assert_eq!(observed.len(), 1);
        assert_eq!(observed[0].status, 418, "observe sees the status the client actually got");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A provider-side `Reject` is served with the provider's own code —
    /// and, like `NoMatch`, never reaches source resolution.
    #[tokio::test]
    async fn handle_mocked_serves_a_reject_with_the_providers_code_without_resolving_any_source() {
        let provider = Arc::new(ScriptedProvider {
            selection: MockSelection::Reject {
                code: mock::UNKNOWN_SCENARIO,
                detail: "unknown scenario 'x'".to_string(),
                scenario: baseline_choice(),
            },
            observed: Mutex::new(Vec::new()),
        });
        let (base, root) = serve_with_provider(
            r#"{
                "operationId": "getCar",
                "sources": { "car": { "type": "http", "request": "never-read.json" } },
                "response": { "maker": "sources.car.maker" },
                "errorOverrides": { "test.unknown_scenario": { "httpStatus": 400, "exposeDetail": true } }
            }"#,
            provider.clone(),
        )
        .await;

        let response = reqwest::get(format!("{base}/cars")).await.unwrap();
        assert_eq!(response.status(), 400);
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["name"], mock::UNKNOWN_SCENARIO);
        assert_eq!(body["detail"], "unknown scenario 'x'");
        assert_eq!(provider.observed.lock().unwrap().len(), 1);

        let _ = std::fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod mtls_tests;

#[cfg(test)]
mod m2_tests {
    use super::*;

    fn temp_root() -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "frogs-endpoint-m2-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn write_endpoint(root: &Path, dir: &str, method: &str, json: &str) {
        let d = root.join("datasources/endpoints").join(dir);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(format!("endpoint.{method}.json")), json).unwrap();
    }

    async fn serve(root: &Path, doc: Option<&crate::openapi::OpenApiDocument>) -> String {
        let errors = Arc::new(ErrorRegistry::load(&root.join("does-not-exist")).unwrap());
        let router = build_router(
            root,
            Arc::new(HashMap::new()),
            &HashMap::new(),
            errors,
            Arc::new(SecurityConfig::default()),
            Arc::new(HashMap::new()),
            Arc::new(Mutex::new(DiscoveredErrors::default())),
            false,
            doc,
            None,
            NonZeroU64::new(5_000).unwrap(),
            false,
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        format!("http://{addr}")
    }

    #[test]
    fn has_reserved_stream_key_matches_only_a_top_level_stream_member() {
        let cases: &[(&str, bool)] = &[
            (r#"{"stream":{}}"#, true),
            (r#"{"stream":null}"#, true),
            (r#"{"stream":"x"}"#, true),
            (r#"{"operationId":"a","response":{"stream":"sources.a.b"}}"#, false),
            (r#"{"sources":{"stream":{}}}"#, false),
            (r#"{"Stream":{}}"#, false),
            ("{ not json", false),
            ("[]", false),
            ("", false),
        ];
        for (json, expected) in cases {
            assert_eq!(has_reserved_stream_key(json), *expected, "{json}");
        }
    }

    #[test]
    fn reserved_stream_key_files_lists_exactly_the_files_with_a_top_level_stream_key() {
        let root = temp_root();
        write_endpoint(&root, "a", "get", r#"{ "operationId": "a", "stream": {}, "sources": {}, "response": {} }"#);
        write_endpoint(&root, "b", "get", r#"{ "operationId": "b", "sources": {}, "response": { "stream": "sources.x.y" } }"#);
        write_endpoint(&root, "c", "post", r#"{ "operationId": "c", "stream": null, "sources": {}, "response": {} }"#);
        let mut files = reserved_stream_key_files(&root.join("datasources/endpoints"));
        files.sort();
        assert_eq!(files.len(), 2, "{files:?}");
        assert!(files[0].ends_with("a/endpoint.get.json") || files[0].to_string_lossy().contains('a'));
        assert!(
            files
                .iter()
                .all(|f| !f.to_string_lossy().contains(&format!("{}b{}", std::path::MAIN_SEPARATOR, std::path::MAIN_SEPARATOR)))
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_endpoint_file_with_a_top_level_stream_key_still_deserializes() {
        let parsed: Result<EndpointFile, _> = serde_json::from_str(r#"{ "operationId": "a", "stream": { "anything": 1 }, "sources": {}, "response": {} }"#);
        assert!(parsed.is_ok(), "{:?}", parsed.err());
    }

    #[tokio::test]
    async fn a_stream_keyed_endpoint_is_still_registered_and_served_as_one_json_response() {
        let root = temp_root();
        write_endpoint(
            &root,
            "things",
            "get",
            r#"{ "operationId": "getThings", "stream": {}, "sources": {}, "response": {} }"#,
        );
        let base = serve(&root, None).await;
        let resp = reqwest::get(format!("{base}/things")).await.unwrap();
        assert_eq!(resp.status(), 200);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_route_for_a_streaming_operation_serves_the_same_json_as_a_non_streaming_one() {
        let root = temp_root();
        std::fs::write(
            root.join("openapi.yaml"),
            "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths:\n  /events:\n    get:\n      operationId: events\n      responses:\n        '200':\n          description: ok\n          content:\n            text/event-stream: { itemSchema: { type: string } }\n  /plain:\n    get:\n      operationId: plain\n      responses:\n        '200':\n          description: ok\n          content:\n            application/json: { schema: { type: object } }\n",
        )
        .unwrap();
        let doc = crate::openapi::load(&root.join("openapi.yaml"), crate::openapi::LoadOptions::default()).unwrap();
        assert!(matches!(
            doc.operations.iter().find(|o| o.path == "/events").unwrap().response_mode,
            ResponseMode::Stream(_)
        ));

        let literal = r#"{ "operationId": "x", "sources": {}, "response": {} }"#;
        write_endpoint(&root, "events", "get", literal);
        write_endpoint(&root, "plain", "get", literal);
        let base = serve(&root, Some(&doc)).await;

        let streaming = reqwest::get(format!("{base}/events")).await.unwrap();
        let plain = reqwest::get(format!("{base}/plain")).await.unwrap();
        assert_eq!(streaming.status(), 200);
        assert_eq!(plain.status(), 200);
        assert_eq!(streaming.headers().get("content-type"), plain.headers().get("content-type"));
        assert!(streaming.headers().get("content-type").unwrap().to_str().unwrap().starts_with("application/json"));
        assert_eq!(streaming.text().await.unwrap(), plain.text().await.unwrap());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_route_whose_security_names_an_unresolvable_scheme_is_never_registered() {
        let root = temp_root();
        write_endpoint(
            &root,
            "ref",
            "get",
            r##"{ "operationId": "a", "security": "#/components/securitySchemes/Nope", "sources": {}, "response": {} }"##,
        );
        write_endpoint(
            &root,
            "uri",
            "get",
            r#"{ "operationId": "b", "security": "https://x/y", "sources": {}, "response": {} }"#,
        );
        write_endpoint(&root, "open", "get", r#"{ "operationId": "c", "sources": {}, "response": {} }"#);
        let base = serve(&root, None).await;
        assert_eq!(reqwest::get(format!("{base}/ref")).await.unwrap().status(), 404);
        assert_eq!(reqwest::get(format!("{base}/uri")).await.unwrap().status(), 404);
        assert_eq!(reqwest::get(format!("{base}/open")).await.unwrap().status(), 200);
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod m2_7_security_check_tests {
    use super::*;

    fn temp_root() -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "frogs-endpoint-m27-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    const SCHEMES: &str = "components:\n  securitySchemes:\n    a: { type: apiKey, in: header, name: k }\n    b: { type: apiKey, in: header, name: k2 }\n    c: { type: apiKey, in: header, name: k3 }\n";

    /// `ops` is `(spec path, method, security yaml line or "")`.
    fn spec(top: &str, ops: &[(&str, &str, &str)]) -> String {
        let mut yaml = format!("openapi: 3.2.0\ninfo: {{ title: t, version: 1 }}\n{top}{SCHEMES}paths:\n");
        for (i, (path, method, security)) in ops.iter().enumerate() {
            yaml.push_str(&format!("  '{path}':\n    {method}:\n      operationId: op{i}\n"));
            if !security.is_empty() {
                yaml.push_str(&format!("      security: {security}\n"));
            }
            yaml.push_str("      responses:\n        '200': { description: ok }\n");
        }
        yaml
    }

    fn endpoint(security: Option<&str>) -> String {
        match security {
            Some(s) => format!(
                r#"{{ "operationId": "x", "security": {}, "sources": {{}}, "response": {{}} }}"#,
                serde_json::to_string(s).unwrap()
            ),
            None => r#"{ "operationId": "x", "sources": {}, "response": {} }"#.to_string(),
        }
    }

    /// Builds a project and runs the check. `files` is `(folder under endpoints, method, file contents)`.
    fn run(spec_yaml: &str, files: &[(&str, &str, String)]) -> SecurityCheck {
        let root = temp_root();
        std::fs::write(root.join("openapi.yaml"), spec_yaml).unwrap();
        let endpoints = root.join("datasources/endpoints");
        for (dir, method, contents) in files {
            let d = endpoints.join(dir);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join(format!("endpoint.{method}.json")), contents).unwrap();
        }
        let doc = crate::openapi::load(&root.join("openapi.yaml"), crate::openapi::LoadOptions::default()).unwrap();
        let check = security_check(&endpoints, &doc);
        let _ = std::fs::remove_dir_all(&root);
        check
    }

    fn one(security_yaml: &str, stub: Option<&str>) -> SecurityCheck {
        run(&spec("", &[("/p", "get", security_yaml)]), &[("p", "get", endpoint(stub))])
    }

    #[test]
    fn a_required_scheme_with_no_security_in_the_file_is_an_unprotected_mismatch() {
        let check = one("[ { a: [] } ]", None);
        assert_eq!(check.mismatches.len(), 1);
        let m = &check.mismatches[0];
        assert_eq!(m.stub, None);
        assert_eq!(m.acceptable, vec!["a".to_string()]);
        let msg = m.message();
        assert!(msg.starts_with("GET /p ("), "{msg}");
        assert!(
            msg.contains("openapi.yaml requires security ('a') but the endpoint file declares no \"security\" — the route would be served unprotected"),
            "{msg}"
        );
    }

    #[test]
    fn a_different_scheme_in_the_file_is_a_mismatch_listing_the_acceptable_one() {
        let check = one("[ { a: [] } ]", Some("b"));
        assert_eq!(check.mismatches.len(), 1);
        let msg = check.mismatches[0].message();
        assert!(
            msg.contains("endpoint file declares security 'b', which is not one openapi.yaml allows for this operation (acceptable: 'a')"),
            "{msg}"
        );
    }

    #[test]
    fn the_matching_scheme_is_ok() {
        let check = one("[ { a: [] } ]", Some("a"));
        assert!(check.mismatches.is_empty() && check.stricter.is_empty() && check.unmatched.is_empty());
    }

    #[test]
    fn with_alternatives_any_single_key_one_is_accepted_and_an_outsider_lists_all() {
        assert!(one("[ { a: [] }, { b: [] } ]", Some("b")).mismatches.is_empty());
        assert!(one("[ { a: [] }, { b: [] } ]", Some("a")).mismatches.is_empty());
        let check = one("[ { a: [] }, { b: [] } ]", Some("c"));
        assert_eq!(check.mismatches.len(), 1);
        assert!(check.mismatches[0].message().contains("(acceptable: 'a', 'b')"));
    }

    #[test]
    fn for_an_and_requirement_only_the_first_key_is_acceptable() {
        assert!(one("[ { a: [], b: [] } ]", Some("a")).mismatches.is_empty());
        let check = one("[ { a: [], b: [] } ]", Some("b"));
        assert_eq!(check.mismatches.len(), 1);
        assert_eq!(check.mismatches[0].acceptable, vec!["a".to_string()]);
    }

    #[test]
    fn a_mix_of_and_and_single_alternatives_accepts_the_first_of_each() {
        assert!(one("[ { a: [], b: [] }, { c: [] } ]", Some("c")).mismatches.is_empty());
        assert!(one("[ { a: [], b: [] }, { c: [] } ]", Some("a")).mismatches.is_empty());
        assert_eq!(one("[ { a: [], b: [] }, { c: [] } ]", Some("b")).mismatches.len(), 1);
    }

    #[test]
    fn an_empty_alternative_never_makes_no_security_acceptable_while_a_real_one_exists() {
        let check = one("[ {}, { a: [] } ]", None);
        assert_eq!(check.mismatches.len(), 1);
        assert!(one("[ {}, { a: [] } ]", Some("a")).mismatches.is_empty());
    }

    #[test]
    fn a_spec_with_only_an_empty_requirement_object_requires_nothing() {
        let check = one("[ {} ]", None);
        assert!(check.mismatches.is_empty() && check.stricter.is_empty());
    }

    #[test]
    fn a_file_with_security_where_the_spec_has_none_is_stricter_not_a_mismatch() {
        for security_yaml in ["[]", ""] {
            let check = one(security_yaml, Some("b"));
            assert!(check.mismatches.is_empty(), "{security_yaml}");
            assert_eq!(check.stricter.len(), 1, "{security_yaml}");
            assert!(
                check.stricter[0]
                    .message()
                    .ends_with("): declares security 'b' but openapi.yaml declares none for this operation")
            );
        }
        assert!(one("", None).mismatches.is_empty());
    }

    #[test]
    fn an_operation_inheriting_the_document_default_is_checked_against_it() {
        let yaml = spec("security: [ { a: [] } ]\n", &[("/p", "get", "")]);
        let check = run(&yaml, &[("p", "get", endpoint(None))]);
        assert_eq!(check.mismatches.len(), 1);
        let ok = run(&yaml, &[("p", "get", endpoint(Some("a")))]);
        assert!(ok.mismatches.is_empty());
    }

    #[test]
    fn the_uri_form_of_a_scheme_in_the_spec_equals_the_plain_name_in_the_file() {
        assert!(one("[ { '#/components/securitySchemes/a': [] } ]", Some("a")).mismatches.is_empty());
        assert_eq!(one("[ { '#/components/securitySchemes/a': [] } ]", None).mismatches.len(), 1);
    }

    #[test]
    fn invalid_json_and_non_matching_methods_are_ignored_or_unmatched() {
        let yaml = spec("", &[("/p", "get", "[ { a: [] } ]")]);
        let check = run(&yaml, &[("p", "get", "{ not json".to_string())]);
        assert!(check.mismatches.is_empty() && check.unmatched.is_empty());
        let check = run(&yaml, &[("p", "post", endpoint(None))]);
        assert!(check.mismatches.is_empty());
        assert_eq!(check.unmatched.len(), 1, "a POST file has no POST operation in the spec");
    }

    #[test]
    fn a_file_with_no_matching_operation_is_unmatched_with_the_documented_message() {
        let yaml = spec("", &[("/p", "get", "[ { a: [] } ]")]);
        let check = run(&yaml, &[("other", "get", endpoint(None))]);
        assert!(check.mismatches.is_empty());
        assert_eq!(check.unmatched.len(), 1);
        let msg = unmatched_security_message(&check.unmatched[0]);
        assert!(
            msg.ends_with(": no matching operation in openapi.yaml — endpoint security was not checked for this route"),
            "{msg}"
        );
    }

    #[test]
    fn a_renamed_path_parameter_still_matches_by_position() {
        let yaml = spec("", &[("/cars/{vin}", "get", "[ { a: [] } ]")]);
        let bad = run(&yaml, &[("cars/{id}", "get", endpoint(None))]);
        assert_eq!(bad.mismatches.len(), 1, "{}", bad.unmatched.len());
        let good = run(&yaml, &[("cars/{id}", "get", endpoint(Some("a")))]);
        assert!(good.mismatches.is_empty() && good.unmatched.is_empty());
    }

    #[test]
    fn a_case_drifted_folder_still_matches_the_spec_path() {
        let yaml = spec("", &[("/cars", "get", "[ { a: [] } ]")]);
        let check = run(&yaml, &[("Cars", "get", endpoint(None))]);
        assert_eq!(check.mismatches.len(), 1);
        assert!(check.unmatched.is_empty());
    }

    #[test]
    fn a_trailing_slash_spec_path_matches_its_folder() {
        let yaml = spec("", &[("/cars/", "get", "[ { a: [] } ]")]);
        let check = run(&yaml, &[("cars", "get", endpoint(None))]);
        assert_eq!(check.mismatches.len(), 1);
        assert!(check.unmatched.is_empty());
    }

    #[test]
    fn several_fallback_matches_must_all_be_satisfied_and_the_message_lists_them() {
        let yaml = spec("", &[("/a/{x}", "get", "[ { a: [] } ]"), ("/a/{y}", "get", "[ { b: [] } ]")]);
        let check = run(&yaml, &[("a/{z}", "get", endpoint(Some("a")))]);
        assert_eq!(check.mismatches.len(), 1);
        let msg = check.mismatches[0].message();
        assert!(msg.contains("it must satisfy all of them"), "{msg}");
        assert!(msg.contains("GET /a/{x}") && msg.contains("GET /a/{y}"), "{msg}");

        let both = spec("", &[("/a/{x}", "get", "[ { a: [] }, { b: [] } ]"), ("/a/{y}", "get", "[ { b: [] } ]")]);
        assert!(run(&both, &[("a/{z}", "get", endpoint(Some("b")))]).mismatches.is_empty());
        let none_file = run(&yaml, &[("a/{z}", "get", endpoint(None))]);
        assert_eq!(none_file.mismatches.len(), 1, "no security is a mismatch if any matched op requires");
    }

    #[test]
    fn a_requiring_and_a_non_requiring_fallback_match_still_fail_closed_for_no_security() {
        let yaml = spec("", &[("/a/{x}", "get", "[ { a: [] } ]"), ("/a/{y}", "get", "[]")]);
        let check = run(&yaml, &[("a/{z}", "get", endpoint(None))]);
        assert_eq!(check.mismatches.len(), 1);
    }

    #[test]
    fn case_colliding_spec_paths_are_still_checked_by_exact_bytes() {
        let yaml = spec("", &[("/Cars", "get", "[ { a: [] } ]"), ("/cars", "get", "[ { a: [] } ]")]);
        let check = run(&yaml, &[("cars", "get", endpoint(None)), ("Cars", "get", endpoint(Some("a")))]);
        // On a case-insensitive filesystem both files share one folder; either way the unprotected one is caught.
        assert!(check.mismatches.len() <= 1);
        let solo = run(&yaml, &[("cars", "get", endpoint(None))]);
        assert_eq!(solo.mismatches.len(), 1);
    }

    #[test]
    fn hostile_scheme_names_and_file_names_are_escaped_in_every_message() {
        let yaml = spec("", &[("/p", "get", "[ { a: [] } ]")]);
        let check = run(&yaml, &[("p", "get", endpoint(Some("evil\u{1b}[31m\nname")))]);
        assert_eq!(check.mismatches.len(), 1);
        let msg = check.mismatches[0].message();
        assert!(!msg.contains('\u{1b}') && !msg.contains('\n'), "{msg:?}");

        let hostile_spec = spec("", &[("/p", "get", "[ { \"x\\u001b[0m\": [] } ]")]);
        let check = run(&hostile_spec, &[("p", "get", endpoint(None))]);
        assert_eq!(check.mismatches.len(), 1);
        let msg = check.mismatches[0].message();
        assert!(!msg.contains('\u{1b}'), "{msg:?}");

        let mismatch = SecurityMismatch {
            method: "get".into(),
            url_path: "/p".into(),
            file: PathBuf::from("dir/evil\u{1b}[2Jfile.json"),
            stub: None,
            matched: vec![("get".into(), "/p".into())],
            acceptable: vec!["a".into()],
        };
        assert!(!mismatch.message().contains('\u{1b}'));
        assert!(!unmatched_security_message(Path::new("x/\u{1b}[2Jy.json")).contains('\u{1b}'));
    }

    #[test]
    fn match_key_ignores_parameter_names_and_case_but_not_literal_segments_or_arity() {
        assert_eq!(match_key("/cars/:vin"), match_key("/CARS/:id"));
        assert_ne!(match_key("/cars/:vin"), match_key("/cars/:vin/owners"));
        assert_ne!(match_key("/cars/:vin"), match_key("/cars/vin"));
    }
}

#[cfg(test)]
mod m3_router_tests {
    use super::*;
    use crate::server::{raw_request, spawn_served};
    use crate::sql::{SqlError, SqlValue};

    fn temp_root() -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "frogs-endpoint-m3-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn write_endpoint(root: &Path, dir: &str, token: &str, json: &str) {
        let d = root.join("datasources/endpoints").join(dir);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(format!("endpoint.{token}.json")), json).unwrap();
    }

    const LITERAL: &str = r#"{ "operationId": "x", "sources": {}, "response": { "ok": "literal" } }"#;

    /// Answers the verifier (any call that carries a `key` parameter) with `active = (key == "good")`
    /// and every other call with a row echoing the bound `maker` parameter.
    #[derive(Debug)]
    struct TestDriver;

    #[async_trait::async_trait]
    impl SqlDriver for TestDriver {
        async fn query(&self, _script: &str, params: &HashMap<String, SqlValue>) -> Result<Vec<HashMap<String, SqlValue>>, SqlError> {
            if let Some(key) = params.get("key") {
                return Ok(vec![HashMap::from([("active".to_string(), SqlValue::Bool(*key == SqlValue::Text("good".to_string())))])]);
            }
            let maker = params.get("maker").cloned().unwrap_or(SqlValue::Null);
            Ok(vec![HashMap::from([("maker".to_string(), maker)])])
        }
    }

    fn router_for(root: &Path) -> Router {
        std::fs::create_dir_all(root.join("datasources/sql/db")).unwrap();
        std::fs::write(root.join("datasources/sql/db/q.sql"), "SELECT 1").unwrap();
        std::fs::write(root.join("datasources/sql/db/verify.sql"), "SELECT 1").unwrap();
        let sec = root.join("sec");
        std::fs::create_dir_all(sec.join("verifiers")).unwrap();
        std::fs::write(sec.join("schemes.json"), r#"{ "keyAuth": { "verifier": "key.json" } }"#).unwrap();
        std::fs::write(
            sec.join("verifiers/key.json"),
            r#"{ "type": "sql", "connection": "db", "script": "verify.sql", "parameters": [{ "name": "key", "from": "header.X-Api-Key" }], "validIf": "row.active = true" }"#,
        )
        .unwrap();
        let errs = root.join("errs");
        std::fs::create_dir_all(&errs).unwrap();
        std::fs::write(
            errs.join("core.json"),
            r#"{ "auth.invalid_credentials": { "httpStatus": 401, "exposeDetail": true }, "auth.verifier_unavailable": { "httpStatus": 500, "exposeDetail": false } }"#,
        )
        .unwrap();
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(TestDriver));
        build_router(
            root,
            Arc::new(drivers),
            &HashMap::new(),
            Arc::new(ErrorRegistry::load(&errs).unwrap()),
            Arc::new(SecurityConfig::load(&sec).unwrap()),
            Arc::new(HashMap::new()),
            Arc::new(Mutex::new(DiscoveredErrors::default())),
            false,
            None,
            None,
            NonZeroU64::new(5_000).unwrap(),
            false,
        )
    }

    async fn serve_root(root: &Path) -> String {
        format!("http://{}", spawn_served(router_for(root), false).await)
    }

    fn query_method() -> reqwest::Method {
        reqwest::Method::from_bytes(b"QUERY").unwrap()
    }

    fn allow_of(resp: &reqwest::Response) -> String {
        resp.headers().get("allow").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default()
    }

    #[tokio::test]
    async fn a_query_request_with_a_json_body_reaches_a_source_parameter_and_the_response() {
        let root = temp_root();
        write_endpoint(
            &root,
            "cars",
            "query",
            r#"{ "operationId": "searchCars", "sources": { "car": { "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "one",
               "parameters": [{ "name": "maker", "from": "body.maker" }] } }, "response": { "maker": "sources.car.maker" } }"#,
        );
        let base = serve_root(&root).await;
        let resp = reqwest::Client::new().request(query_method(), format!("{base}/cars")).json(&serde_json::json!({ "maker": "Honda" })).send().await.unwrap();
        assert_eq!(resp.status(), 200);
        let body: Value = resp.json().await.unwrap();
        assert_eq!(body["maker"], "Honda");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_query_request_with_no_body_at_all_is_served_like_a_bodyless_post() {
        let root = temp_root();
        write_endpoint(&root, "things", "query", LITERAL);
        let base = serve_root(&root).await;
        let resp = reqwest::Client::new().request(query_method(), format!("{base}/things")).send().await.unwrap();
        assert_eq!(resp.status(), 200);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn get_and_query_on_one_path_both_work_and_have_independent_rate_limit_buckets() {
        let root = temp_root();
        let limited = r#"{ "operationId": "x", "sources": {}, "response": {}, "rateLimit": { "requestsPerSecond": 1, "burst": 1 } }"#;
        write_endpoint(&root, "things", "get", limited);
        write_endpoint(&root, "things", "query", limited);
        let base = serve_root(&root).await;
        let client = reqwest::Client::new();
        let get = |c: &reqwest::Client| c.get(format!("{base}/things")).send();
        let query = |c: &reqwest::Client| c.request(query_method(), format!("{base}/things")).send();
        assert_eq!(get(&client).await.unwrap().status(), 200);
        assert_eq!(get(&client).await.unwrap().status(), 429, "GET bucket exhausted");
        assert_eq!(query(&client).await.unwrap().status(), 200, "QUERY has its own bucket, untouched by GET");
        assert_eq!(query(&client).await.unwrap().status(), 429);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_body_over_the_two_mib_default_is_413_for_post_and_query_alike() {
        let root = temp_root();
        write_endpoint(&root, "things", "post", LITERAL);
        write_endpoint(&root, "things", "query", LITERAL);
        let base = serve_root(&root).await;
        let big = vec![b'a'; 2 * 1024 * 1024 + 1024];
        let client = reqwest::Client::new();
        let post = client.post(format!("{base}/things")).body(big.clone()).send().await.unwrap();
        let query = client.request(query_method(), format!("{base}/things")).body(big).send().await.unwrap();
        assert_eq!(post.status(), 413);
        assert_eq!(query.status(), 413);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_protected_query_route_rejects_missing_and_wrong_credentials_exactly_like_get() {
        let root = temp_root();
        let protected = r#"{ "operationId": "x", "security": "keyAuth", "sources": {}, "response": {} }"#;
        write_endpoint(&root, "secret", "get", protected);
        write_endpoint(&root, "secret", "query", protected);
        let base = serve_root(&root).await;
        let client = reqwest::Client::new();
        for method in [reqwest::Method::GET, query_method()] {
            let req = |key: Option<&str>| {
                let mut r = client.request(method.clone(), format!("{base}/secret"));
                if let Some(k) = key {
                    r = r.header("X-Api-Key", k);
                }
                r.send()
            };
            assert_eq!(req(None).await.unwrap().status(), 401, "{method}: no credential");
            assert_eq!(req(Some("bad")).await.unwrap().status(), 401, "{method}: wrong credential");
            assert_eq!(req(Some("good")).await.unwrap().status(), 200, "{method}: right credential");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_standard_only_path_keeps_axums_own_405_and_allow_header() {
        let root = temp_root();
        write_endpoint(&root, "things", "get", LITERAL);
        let base = serve_root(&root).await;
        let client = reqwest::Client::new();
        let put = client.put(format!("{base}/things")).send().await.unwrap();
        assert_eq!(put.status(), 405);
        assert_eq!(allow_of(&put), "GET,HEAD");
        let query = client.request(query_method(), format!("{base}/things")).send().await.unwrap();
        assert_eq!(query.status(), 405, "no QUERY file, no QUERY route");
        assert_eq!(allow_of(&query), "GET,HEAD");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn put_on_a_get_plus_query_path_is_405_listing_query_in_allow() {
        let root = temp_root();
        write_endpoint(&root, "things", "get", LITERAL);
        write_endpoint(&root, "things", "query", LITERAL);
        let base = serve_root(&root).await;
        let resp = reqwest::Client::new().put(format!("{base}/things")).send().await.unwrap();
        assert_eq!(resp.status(), 405);
        assert_eq!(allow_of(&resp), "GET,HEAD,QUERY");
        assert!(resp.bytes().await.unwrap().is_empty(), "the dispatcher's 405 body is empty");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_successful_query_response_carries_a_complete_allow_header_never_an_empty_one() {
        let root = temp_root();
        write_endpoint(&root, "both", "get", LITERAL);
        write_endpoint(&root, "both", "post", LITERAL);
        write_endpoint(&root, "both", "query", LITERAL);
        write_endpoint(&root, "only", "query", LITERAL);
        let base = serve_root(&root).await;
        let client = reqwest::Client::new();

        let both = client.request(query_method(), format!("{base}/both")).send().await.unwrap();
        assert_eq!(both.status(), 200);
        assert_eq!(allow_of(&both), "GET,HEAD,POST,QUERY");

        let only = client.request(query_method(), format!("{base}/only")).send().await.unwrap();
        assert_eq!(only.status(), 200);
        assert_eq!(allow_of(&only), "QUERY");

        let wrong = client.get(format!("{base}/only")).send().await.unwrap();
        assert_eq!(wrong.status(), 405);
        assert_eq!(allow_of(&wrong), "QUERY");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn an_unknown_extension_method_on_a_query_path_is_a_bare_405_with_the_full_allow() {
        let root = temp_root();
        write_endpoint(&root, "things", "query", LITERAL);
        let base = serve_root(&root).await;
        let resp = reqwest::Client::new().request(reqwest::Method::from_bytes(b"PURGE").unwrap(), format!("{base}/things")).send().await.unwrap();
        assert_eq!(resp.status(), 405);
        assert_eq!(allow_of(&resp), "QUERY");
        // Lowercase is a different method to the exact-match dispatcher when nothing normalizes it.
        let strict_addr = spawn_served(router_for(&root), true).await;
        let lower = reqwest::Client::new().request(reqwest::Method::from_bytes(b"query").unwrap(), format!("http://{strict_addr}/things")).send().await.unwrap();
        assert_eq!(lower.status(), 405);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn query_is_served_when_the_router_is_nested_under_an_api_root() {
        let root = temp_root();
        write_endpoint(&root, "things", "query", LITERAL);
        write_endpoint(&root, "things", "get", LITERAL);
        let nested = Router::new().nest("/api", router_for(&root));
        let addr = spawn_served(nested, false).await;
        let resp = reqwest::Client::new().request(query_method(), format!("http://{addr}/api/things")).send().await.unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(allow_of(&resp), "GET,HEAD,QUERY");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn router_level_layers_wrap_a_query_response_with_cors_and_a_correlation_id() {
        let root = temp_root();
        write_endpoint(&root, "things", "query", LITERAL);
        let router = crate::server::apply_cors(crate::server::apply_middleware(router_for(&root)), &["https://app.example".to_string()]);
        let addr = spawn_served(router, false).await;
        let resp = reqwest::Client::new()
            .request(query_method(), format!("http://{addr}/things"))
            .header("origin", "https://app.example")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert!(resp.headers().get("access-control-allow-origin").is_some());
        assert!(resp.headers().get("x-request-id").is_some());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn lowercase_query_is_served_when_case_insensitive_and_405_when_case_sensitive() {
        let root = temp_root();
        write_endpoint(&root, "things", "query", LITERAL);
        write_endpoint(&root, "things", "get", LITERAL);
        let request = b"query /things HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";

        let insensitive = spawn_served(router_for(&root), false).await;
        let (line, headers, _, _) = raw_request(insensitive, request).await;
        assert!(line.contains(" 200 "), "{line}");
        assert!(headers.iter().any(|(k, v)| k == "allow" && v == "GET,HEAD,QUERY"), "{headers:?}");

        let sensitive = spawn_served(router_for(&root), true).await;
        let (line, headers, _, _) = raw_request(sensitive, request).await;
        assert!(line.contains(" 405 "), "{line}");
        assert!(headers.iter().any(|(k, v)| k == "allow" && v == "GET,HEAD,QUERY"), "{headers:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_non_canonical_stub_name_is_never_routed_and_is_listed_by_non_canonical_method_files() {
        let root = temp_root();
        write_endpoint(&root, "upper", "GET", LITERAL);
        write_endpoint(&root, "mixed", "Query", LITERAL);
        write_endpoint(&root, "fine", "get", LITERAL);
        write_endpoint(&root, "other", "purge", LITERAL);
        let base = serve_root(&root).await;
        let client = reqwest::Client::new();
        for path in ["/upper", "/mixed", "/other"] {
            assert_eq!(client.get(format!("{base}{path}")).send().await.unwrap().status(), 404, "{path}");
            assert_eq!(client.request(query_method(), format!("{base}{path}")).send().await.unwrap().status(), 404, "{path}");
        }
        assert_eq!(client.get(format!("{base}/fine")).send().await.unwrap().status(), 200);

        let found = non_canonical_method_files(&root.join("datasources/endpoints"));
        let mut names: Vec<_> = found
            .iter()
            .map(|(p, c)| (p.file_name().unwrap().to_str().unwrap().to_string(), *c))
            .collect();
        names.sort();
        assert_eq!(names, vec![("endpoint.GET.json".to_string(), "get"), ("endpoint.Query.json".to_string(), "query")]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn non_canonical_method_files_ignores_siblings_backups_and_canonical_files() {
        let root = temp_root();
        let ep = root.join("datasources/endpoints");
        write_endpoint(&root, "a", "get", LITERAL);
        std::fs::write(ep.join("a/endpoint.GET.reference.json"), "{}").unwrap();
        std::fs::write(ep.join("a/endpoint.GET.test.json"), "{}").unwrap();
        std::fs::write(ep.join("a/_endpoint.GET.json"), "{}").unwrap();
        std::fs::create_dir_all(ep.join("a/_backups")).unwrap();
        std::fs::write(ep.join("a/_backups/endpoint.GET.json"), "{}").unwrap();
        assert!(non_canonical_method_files(&ep).is_empty());
        assert!(non_canonical_method_files(&root.join("nope")).is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn options_head_and_trace_stub_files_stay_unrouted() {
        let root = temp_root();
        write_endpoint(&root, "o", "options", LITERAL);
        write_endpoint(&root, "h", "head", LITERAL);
        write_endpoint(&root, "t", "trace", LITERAL);
        let base = serve_root(&root).await;
        for path in ["/o", "/h", "/t"] {
            assert_eq!(reqwest::get(format!("{base}{path}")).await.unwrap().status(), 404, "{path}");
        }
        assert!(non_canonical_method_files(&root.join("datasources/endpoints")).is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn many_paths_register_deterministically_and_each_gets_its_own_allow_list() {
        let root = temp_root();
        for dir in ["z", "a", "m"] {
            write_endpoint(&root, dir, "get", LITERAL);
            write_endpoint(&root, dir, "query", LITERAL);
        }
        write_endpoint(&root, "a", "delete", LITERAL);
        let first = serve_root(&root).await;
        let second = serve_root(&root).await;
        let client = reqwest::Client::new();
        for base in [&first, &second] {
            for (path, expected) in [("/a", "GET,HEAD,DELETE,QUERY"), ("/m", "GET,HEAD,QUERY"), ("/z", "GET,HEAD,QUERY")] {
                let resp = client.put(format!("{base}{path}")).send().await.unwrap();
                assert_eq!(allow_of(&resp), expected, "{path}");
            }
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn path_parameters_work_for_query_routes() {
        let root = temp_root();
        write_endpoint(&root, "cars/{vin}", "query", LITERAL);
        let base = serve_root(&root).await;
        let resp = reqwest::Client::new().request(query_method(), format!("{base}/cars/ABC")).send().await.unwrap();
        assert_eq!(resp.status(), 200);
        let _ = std::fs::remove_dir_all(&root);
    }
}
