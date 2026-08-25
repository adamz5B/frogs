mod error;
mod format;
mod resolve;
mod schema;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::extract::{Extension, Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post, put};
use axum::{Json, Router};

use crate::errors::{DiscoveredErrors, ErrorRegistry};
use crate::security::{SecurityConfig, VerifierCache};
use crate::server::RequestId;
use crate::sql::SqlDriver;
use serde_json::Value;

/// Re-exported for `testing`, the only other module that needs to reach
/// into `endpoint`'s internals — `EndpointFile` to load the file a test
/// case runs against, `MockOutcome` because it's the exact type
/// `resolve_sources` consumes (test-file `mocks` deserialize directly into
/// it, see `endpoint::resolve::MockOutcome`, rather than a separate parsed
/// copy `testing` would otherwise have to convert).
pub(crate) use resolve::MockOutcome;
pub(crate) use schema::EndpointFile;

/// The HTTP methods frogs actually routes — an `endpoint.<method>.json`
/// file for anything else (or one of OpenAPI's non-request-body-shaped
/// verbs like `options`/`head`/`trace`) is never discovered as a route.
const ROUTABLE_METHODS: &[&str] = &["get", "post", "put", "patch", "delete"];

/// Everything one route's handler needs, baked in at startup so the handler
/// function itself can stay generic and shared across every route.
struct RouteState {
    endpoint: EndpointFile,
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
}

/// Scans `datasources/endpoints/` for `endpoint.<method>.json` files (one
/// of `ROUTABLE_METHODS`) and registers one axum route per file found.
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
    errors: Arc<ErrorRegistry>,
    security: Arc<SecurityConfig>,
    services: Arc<HashMap<String, String>>,
    discovered_errors: Arc<Mutex<DiscoveredErrors>>,
    debug_mode: bool,
) -> Router {
    let sql_root = project_root.join("datasources/sql");
    let http_root = project_root.join("datasources/http");
    let endpoints_root = project_root.join("datasources/endpoints");
    let discovered_errors_path = project_root.join("config/errors.discovered.json");
    // One shared client for every route — reuses connection pooling across
    // requests instead of paying a fresh-connection cost per call.
    let http_client = reqwest::Client::new();
    let verifier_cache = Arc::new(VerifierCache::new());

    let mut router = Router::new();
    for (url_path, method, file_path) in discover_endpoint_files(&endpoints_root) {
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
        if let Some(scheme) = &endpoint.security {
            if !security.verifiers.contains_key(scheme) {
                tracing::warn!(
                    "skipping {}: security scheme '{scheme}' has no matching entry in security/schemes.json",
                    file_path.display()
                );
                continue;
            }
        }

        tracing::info!("{} {url_path} -> {}", method.to_uppercase(), file_path.display());
        // Each route gets its own `RouteState` baked in via `with_state` —
        // this is what lets one shared `handle_request` function serve
        // every endpoint file: axum's `State` extractor pulls out whichever
        // `Arc<RouteState>` this particular route was registered with.
        let state = Arc::new(RouteState {
            endpoint,
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
        });
        // `Router::route` merges method routers registered for the same
        // path across separate calls (a GET and a PUT on the same path
        // each get their own call here), so looping one method at a time
        // is enough — it doesn't overwrite a sibling method already
        // registered for this same `url_path`.
        let method_router = match method.as_str() {
            "get" => get(handle_request).with_state(state),
            "post" => post(handle_request).with_state(state),
            "put" => put(handle_request).with_state(state),
            "patch" => patch(handle_request).with_state(state),
            "delete" => delete(handle_request).with_state(state),
            other => unreachable!("discover_endpoint_files only yields ROUTABLE_METHODS, got '{other}'"),
        };
        router = router.route(&url_path, method_router);
    }
    router
}

/// Parses every discovered endpoint file and reports problems without
/// building any routes — `frogs validate`'s read-only counterpart to
/// `build_router`'s own per-file loop. Deliberately not sharing code with
/// `build_router` itself: that function also constructs a route/
/// `RouteState` per file, which a dry run has no use for, and the actual
/// check logic (parse JSON, confirm a declared security scheme resolves)
/// is small enough that duplicating it here stays cheaper than
/// restructuring `build_router` to serve both callers.
pub(crate) fn validate_endpoint_files(endpoints_root: &Path, security: &SecurityConfig) -> (usize, Vec<String>) {
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
        if let Some(scheme) = &endpoint.security {
            if !security.verifiers.contains_key(scheme) {
                problems.push(format!(
                    "{}: security scheme '{scheme}' has no matching entry in security/schemes.json",
                    file_path.display()
                ));
            }
        }
    }

    (count, problems)
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
    // A body-consuming extractor must come last — axum can only hand the
    // request body to one extractor. `Bytes` (not `Json<Value>`) since a
    // GET/DELETE typically sends none at all, and `Json` would hard-fail
    // on an empty body instead of treating "no body" as `Value::Null`.
    raw_body: axum::body::Bytes,
) -> Response {
    // A missing or malformed body becomes `Value::Null`, the same
    // "unresolvable input, not a crash" posture as an unresolvable
    // `{{param}}` or missing header elsewhere — request validation (still
    // not built, see the design doc) is where a genuinely malformed body
    // would eventually be caught, not source resolution.
    let body: Value = if raw_body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&raw_body).unwrap_or(Value::Null)
    };
    let transaction_id = transaction_id.map(|Extension(RequestId(id))| id).unwrap_or_default();

    let (http_status, response_body) = resolve_for_test(
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
        &headers,
        &path_params,
        &query_params,
        &body,
        &transaction_id,
        &HashMap::new(),
    )
    .await;

    let status = StatusCode::from_u16(http_status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, Json(response_body)).into_response()
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
pub(crate) async fn resolve_for_test(
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
    path_params: &HashMap<String, String>,
    query_params: &HashMap<String, String>,
    body: &Value,
    transaction_id: &str,
    mocks: &HashMap<String, MockOutcome>,
) -> (u16, Value) {
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
            );
        };

        let verify_result = match mocks.get("verifier") {
            Some(MockOutcome::Success(mock_value)) => {
                if verifier.valid_if.evaluate(mock_value) {
                    Ok(())
                } else {
                    Err(("auth.invalid_credentials".to_string(), "mocked verifier: validIf did not hold".to_string()))
                }
            }
            Some(MockOutcome::Fail(code)) => Err((code.clone(), format!("mocked failure: {code}"))),
            None => crate::security::verify(scheme, verifier, drivers, sql_root, http_root, http_client, headers, verifier_cache)
                .await
                .map_err(|cause| (cause.code().to_string(), cause.message())),
        };

        if let Err((code, message)) = verify_result {
            return error_envelope(errors, discovered_errors, discovered_errors_path, debug_mode, &code, &message, None);
        }
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
            )
        }
    }
}

/// Runs every source in `endpoint.sources` for real — no mocks at all,
/// regardless of what a sibling `.test.json` file declares — and returns
/// each source's own resolved value alongside the would-be `(status,
/// body)` a real request would get. This is `frogs test record`'s engine:
/// unlike `resolve_for_test`, it never touches the security check at all
/// (recording captures *data-source* output; a verifier mock only ever
/// needs one field, `active`, cheap enough to author by hand — the design
/// doc's own example does exactly that) and it hands back the per-source
/// breakdown `resolve_for_test` normally collapses away, since that
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
/// failures, both real and mocked, since they all classify into the same
/// registry-driven `httpStatus`/`exposeDetail` lookup. `resolve_for_test`
/// is this function's only caller; `handle_request` gets the same envelope
/// indirectly through it, converting the plain `(u16, Value)` into an axum
/// `Response` itself. Also where the design doc's observe–react discovery
/// happens: `code` reaching here with no entry in `errors` is exactly the
/// "unclassified" case, recorded via `record_discovered_error` whenever
/// `debugMode` is on.
#[allow(clippy::too_many_arguments)]
fn error_envelope(
    errors: &ErrorRegistry,
    discovered_errors: &Mutex<DiscoveredErrors>,
    discovered_errors_path: &Path,
    debug_mode: bool,
    code: &str,
    message: &str,
    on_error: Option<u16>,
) -> (u16, Value) {
    let definition = errors.lookup(code);
    let http_status = on_error.unwrap_or(definition.http_status);
    let status = StatusCode::from_u16(http_status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    if debug_mode && errors.get(code).is_none() {
        record_discovered_error(discovered_errors, discovered_errors_path, code, definition, message);
    }

    let mut body = serde_json::json!({
        "code": status.as_u16(),
        "name": code,
    });
    if definition.expose_detail || debug_mode {
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
fn record_discovered_error(
    discovered_errors: &Mutex<DiscoveredErrors>,
    path: &Path,
    code: &str,
    definition: &crate::errors::ErrorDefinition,
    message: &str,
) {
    let mut discovered = discovered_errors.lock().unwrap();
    discovered.record(code, definition.http_status, definition.expose_detail, message);
    if let Err(e) = discovered.save(path) {
        tracing::warn!("failed to save {}: {e}", path.display());
    }
}

fn discover_endpoint_files(root: &Path) -> Vec<(String, String, PathBuf)> {
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
        } else if let Some(method) = routable_method(&path) {
            if let Some(url_path) = url_path_for(root, &path) {
                out.push((url_path, method.to_string(), path.clone()));
            }
        }
    }
}

/// The HTTP method an `endpoint.<method>.json` file represents, if it's one
/// of `ROUTABLE_METHODS` — `None` for a `.reference.json`/`.test.json`
/// sibling (whose "method" segment would contain a `.` after stripping),
/// an underscore-prefixed orphaned file, or a currently-unsupported method
/// like `options`/`head`/`trace`.
fn routable_method(path: &Path) -> Option<&'static str> {
    let name = path.file_name()?.to_str()?;
    let method = name.strip_prefix("endpoint.")?.strip_suffix(".json")?;
    ROUTABLE_METHODS.iter().find(|&&m| m == method).copied()
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

        let mut found: Vec<(String, String)> =
            discover_endpoint_files(&root).into_iter().map(|(path, method, _)| (path, method)).collect();
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
        for method in ROUTABLE_METHODS {
            assert_eq!(routable_method(&root.join(format!("endpoint.{method}.json"))), Some(*method));
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
            async fn query(
                &self,
                _script: &str,
                params: &HashMap<String, SqlValue>,
            ) -> Result<Vec<HashMap<String, SqlValue>>, SqlError> {
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
        let verifier = LoadedVerifier { valid_if: ValidIf::parse(def.valid_if()).unwrap(), def };
        let mut verifiers = HashMap::new();
        verifiers.insert("apiKeyAuth".to_string(), verifier);
        let security = Arc::new(SecurityConfig { schemes: HashMap::new(), verifiers });

        let endpoint: EndpointFile = serde_json::from_str(
            r#"{ "operationId": "getSecret", "security": "apiKeyAuth", "sources": {}, "response": {} }"#,
        )
        .unwrap();

        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(FakeDriver));

        let state = Arc::new(RouteState {
            endpoint,
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

        let resp = client
            .get(format!("http://{addr}/secret"))
            .header("X-Api-Key", "wrong-key")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401, "an unrecognized key must be rejected");

        let resp = client
            .get(format!("http://{addr}/secret"))
            .header("X-Api-Key", "good-key")
            .send()
            .await
            .unwrap();
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
        std::fs::write(
            dir.join("endpoint.get.json"),
            r#"{ "operationId": "getThing", "sources": {}, "response": {} }"#,
        )
        .unwrap();
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
            errors,
            security,
            Arc::new(HashMap::new()),
            Arc::new(Mutex::new(DiscoveredErrors::default())),
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
            errors,
            security,
            Arc::new(HashMap::new()),
            Arc::new(Mutex::new(DiscoveredErrors::default())),
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

        error_envelope(&errors, &discovered, &path, true, "datasource.sql.not_found", "no rows", None);

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

        error_envelope(&errors, &discovered, &path, false, "datasource.sql.not_found", "no rows", None);

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
        error_envelope(&errors, &discovered, &path, true, "unexpected.error", "boom", None);

        assert!(discovered.lock().unwrap().is_empty());
    }

    #[test]
    fn error_envelope_persists_the_recorded_entry_to_disk() {
        let errors = ErrorRegistry::load(Path::new("/does/not/exist")).unwrap();
        let discovered = Mutex::new(DiscoveredErrors::default());
        let path = temp_discovered_errors_path();

        error_envelope(&errors, &discovered, &path, true, "datasource.sql.not_found", "no rows", None);

        let reloaded = DiscoveredErrors::load(&path).expect("the recorded entry must be saved to disk, not just in-memory");
        assert_eq!(reloaded.len(), 1);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn error_envelope_repeated_occurrences_update_the_same_entry_in_place() {
        let errors = ErrorRegistry::load(Path::new("/does/not/exist")).unwrap();
        let discovered = Mutex::new(DiscoveredErrors::default());
        let path = temp_discovered_errors_path();

        error_envelope(&errors, &discovered, &path, true, "datasource.sql.not_found", "first", None);
        error_envelope(&errors, &discovered, &path, true, "datasource.sql.not_found", "second", None);

        let locked = discovered.lock().unwrap();
        assert_eq!(locked.len(), 1, "the same code occurring twice must update one entry, not create two");
        assert_eq!(locked.lookup("datasource.sql.not_found").unwrap().occurrences, 2);

        drop(locked);
        let _ = std::fs::remove_file(&path);
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
            async fn query(
                &self,
                _script: &str,
                _params: &HashMap<String, crate::sql::SqlValue>,
            ) -> Result<Vec<crate::sql::SqlRow>, crate::sql::SqlError> {
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
        let router =
            build_router(
                &root,
                Arc::new(drivers),
                errors,
                security,
                Arc::new(HashMap::new()),
                Arc::new(Mutex::new(DiscoveredErrors::default())),
                true,
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
        let discovered = DiscoveredErrors::load(&discovered_path)
            .expect("a real unclassified failure in debugMode must be saved to config/errors.discovered.json");
        assert_eq!(discovered.len(), 1);
        let entry = discovered.lookup("datasource.sql.not_found").expect("recorded under its real classification code");
        assert_eq!(entry.occurrences, 1);
        assert_eq!(entry.sample_message, "query returned no rows");

        let _ = std::fs::remove_dir_all(&root);
    }
}
