pub mod logging;
pub mod pidfile;
pub mod service;
#[cfg(windows)]
pub mod service_host;
#[cfg(test)]
pub(crate) mod test_pki;
pub mod tls;

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::extract::connect_info::IntoMakeServiceWithConnectInfo;
use axum::extract::{Request, State};
use axum::http::{HeaderName, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::{Router, routing::MethodRouter, routing::get};
use tracing::Instrument;
use uuid::Uuid;

use crate::sql::SqlDriver;

const CORRELATION_HEADER: &str = "x-request-id";

/// The one request identifier every source in a request can reuse for its
/// own coordination (`context.transactionId` in the design doc) — read out
/// of request extensions by whatever eventually needs it.
#[derive(Clone)]
pub struct RequestId(pub String);

/// The method as it arrived on the wire, kept only when `NormalizeMethod`
/// rewrote it. Diagnostic only — nothing branches on it.
#[derive(Clone)]
pub(crate) struct OriginalMethod(pub String);

/// Longest method name `NormalizeMethod` will rewrite; anything longer is
/// passed through untouched (and never logged).
const MAX_NORMALIZED_METHOD_LEN: usize = 64;

/// Matches request method names case-insensitively (unless `case_sensitive`)
/// by rewriting the method to its uppercase form before the Router sees it.
///
/// Method normalization must wrap the fully assembled Router as a tower Service, never `Router::layer`. axum 0.7 applies Router layers per method slot, inside method dispatch (`method_routing.rs:974-986`). The 'outermost' comments on `apply_cors`/`apply_metrics`/`apply_rate_limit` describe their order relative to each other, not relative to method dispatch.
///
/// Generic over the body type because `axum::serve` hands the service a
/// `Request<Body>` while axum-server hands it a `Request<Incoming>`.
#[derive(Clone)]
pub(crate) struct NormalizeMethod<S> {
    inner: S,
    case_sensitive: bool,
}

impl<S, B> tower_service::Service<Request<B>> for NormalizeMethod<S>
where
    S: tower_service::Service<Request<B>, Response = Response, Error = Infallible>,
{
    type Response = Response;
    type Error = Infallible;
    type Future = futures_util::future::Either<std::future::Ready<Result<Response, Infallible>>, S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        use futures_util::future::Either;

        let name = req.method().as_str();
        if name == "CONNECT" {
            // Never reaches the Router, so this response skips CORS, request
            // correlation and metrics. A 501 is never a 2xx, so hyper can never
            // open a tunnel, and `Connection: close` drops the connection.
            let mut response = Response::new(axum::body::Body::empty());
            *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
            response.headers_mut().insert(header::CONNECTION, HeaderValue::from_static("close"));
            return Either::Left(std::future::ready(Ok(response)));
        }
        if self.case_sensitive || !name.bytes().any(|b| b.is_ascii_lowercase()) {
            return Either::Right(self.inner.call(req));
        }
        if name.eq_ignore_ascii_case("head") || name.eq_ignore_ascii_case("connect") {
            // Deliberately NOT normalized. hyper decides whether a response has a body (HEAD responses have none) from the method it parsed off the wire. If a lowercase `head` were rewritten to HEAD here, axum would run its HEAD handling while hyper still sends a body, so the response would be malformed. Lowercase `connect` is not a tunnel for hyper either. Passing them through untouched makes the router answer 405 with a correct `Allow` header. See docs/frogs-openapi-3.2-support.md, "Why lowercase head is rejected".
            return Either::Right(self.inner.call(req));
        }
        if name.len() > MAX_NORMALIZED_METHOD_LEN {
            return Either::Right(self.inner.call(req));
        }
        let original = name.to_string();
        let upper = name.to_ascii_uppercase();
        if let Ok(method) = Method::from_bytes(upper.as_bytes()) {
            tracing::debug!(original_method = %original, method = %upper, "request method normalized");
            *req.method_mut() = method;
            req.extensions_mut().insert(OriginalMethod(original));
        }
        Either::Right(self.inner.call(req))
    }
}

/// The one way every listener wraps a Router. See `NormalizeMethod` for why
/// this cannot be a `Router::layer`. Outermost to innermost the request
/// passes `IdentityService` (TLS only), `ConnectInfo`, `NormalizeMethod`, the
/// Router.
pub(crate) fn served_service(router: Router, case_sensitive: bool) -> IntoMakeServiceWithConnectInfo<NormalizeMethod<Router>, SocketAddr> {
    // Request type named only to pick the trait impl; NormalizeMethod is generic
    // over the body, so the result still serves Request<Body> and Request<Incoming>.
    <NormalizeMethod<Router> as axum::ServiceExt<axum::extract::Request>>::into_make_service_with_connect_info::<SocketAddr>(NormalizeMethod {
        inner: router,
        case_sensitive,
    })
}

/// The base router: just `/healthz` for now. Real endpoint routing (from
/// `openapi.yaml`) is added separately by `endpoint::build_router` and
/// merged in by the caller — the correlation-ID middleware is deliberately
/// *not* applied here; see `apply_middleware`.
pub fn router() -> Router {
    Router::new().route("/healthz", get(healthz))
}

/// Mounts `router` (already carrying `/healthz` plus every endpoint route —
/// call this *after* `router()` and `endpoint::build_router` are merged
/// together, so `/healthz` moves under the prefix along with everything
/// else, per `config/server.json`'s `apiRoot` field) under `api_root` via
/// `Router::nest`, or leaves it unprefixed when `api_root` is empty —
/// today's default behavior, and every single-role API project's behavior
/// unless it's hand-edited. Call this *before* `apply_middleware`, same
/// "wrap once, after everything's registered" ordering that function's own
/// doc comment requires — `nest` is just another kind of wrapping.
pub fn mount_under(router: Router, api_root: &str) -> Router {
    match normalize_api_root(api_root) {
        Some(prefix) => Router::new().nest(&prefix, router),
        None => router,
    }
}

/// `/readyz` — real readiness, not just "the process is up" like `/healthz`:
/// pings every configured SQL connection and reports unready if any can't
/// be reached. A separate, independently-stated router merged in by the
/// caller (`commands::run`) only when `features.readyzCheck` is on, rather
/// than baked into `router()` unconditionally — so turning the feature off
/// means the route isn't registered at all, not just hidden.
pub fn readyz_router(drivers: Arc<HashMap<String, Box<dyn SqlDriver>>>) -> Router {
    Router::new().route("/readyz", get(readyz)).with_state(drivers)
}

async fn readyz(State(drivers): State<Arc<HashMap<String, Box<dyn SqlDriver>>>>) -> Response {
    for (name, driver) in drivers.iter() {
        if let Err(e) = driver.query("SELECT 1", &HashMap::new()).await {
            return (StatusCode::SERVICE_UNAVAILABLE, format!("connection '{name}' is not reachable: {e}")).into_response();
        }
    }
    (StatusCode::OK, "ready").into_response()
}

/// `/metrics` — Prometheus text exposition format, hand-rolled rather than
/// pulling in a metrics crate (matching this project's dependency
/// consciousness elsewhere). Same "separate router, merged in only when the
/// feature is on" shape as `readyz_router`. The `Metrics` instance here must
/// be the *same* `Arc` passed to `apply_metrics`, so what this endpoint
/// reports is actually what the middleware recorded, not an empty copy.
pub fn metrics_router(metrics: Arc<Metrics>) -> Router {
    Router::new().route("/metrics", get(metrics_handler)).with_state(metrics)
}

async fn metrics_handler(State(metrics): State<Arc<Metrics>>) -> Response {
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], metrics.render()).into_response()
}

/// Shared read-only state for every docs-UI route — an `Arc`-cheap clone of
/// the same `OpenApiDocument`/`SecurityConfig` `commands::run` already
/// built for `endpoint::build_router`, not a second copy of either, plus
/// the sanitized per-endpoint summaries `endpoint::endpoint_summaries`
/// computed once at startup (see `docs_ui_endpoints_handler`).
#[derive(Clone)]
struct DocsUiState {
    openapi_document: Option<Arc<crate::openapi::OpenApiDocument>>,
    security: Arc<crate::security::SecurityConfig>,
    endpoint_summaries: Arc<Vec<serde_json::Value>>,
}

/// Normalizes `docsUi.path` the same lenient way `normalize_api_root`
/// normalizes `apiRoot`: `"docs"`, `"/docs"`, and `"/docs/"` all mean the
/// same thing, and a blank/all-slashes value falls back to `"docs"` rather
/// than mounting the console at the API root itself. Unlike
/// `normalize_api_root`, the result never starts with `/` — callers here
/// build `format!("/{path}")` themselves, since every one of them needs the
/// bare segment for a nested sub-path too (`/docs/operations.json`).
pub(crate) fn normalize_docs_ui_path(raw: &str) -> String {
    let trimmed = raw.trim().trim_matches('/');
    if trimmed.is_empty() { "docs".to_string() } else { trimmed.to_string() }
}

/// The console page (a single embedded HTML/CSS/vanilla-JS file, no
/// framework, no CDN, see `docs_ui.html`), `/<path>/operations.json`
/// (Point 2: `openapi.yaml`'s own structural data), and
/// `/<path>/endpoints.json` (Point 4: each endpoint file's own sanitized
/// `sources`/response config) — all three mounted under `path`
/// (`config/server.json`'s `docsUi.path`, `"docs"` by default, normalized
/// via `normalize_docs_ui_path`). Same "separate router, merged in only
/// when the feature is on" shape as `readyz_router`/`metrics_router`; the
/// caller checks `mode != DocsUiMode::Off` before merging this in at all,
/// so `Off` never reaches this function. `Localhost` wraps every route in
/// `docs_ui_localhost_gate`; `Public` serves them ungated; `Off` is the
/// caller's problem, not this function's.
pub fn docs_ui_router(
    mode: crate::config::DocsUiMode,
    path: &str,
    openapi_document: Option<Arc<crate::openapi::OpenApiDocument>>,
    security: Arc<crate::security::SecurityConfig>,
    endpoint_summaries: Vec<serde_json::Value>,
) -> Router {
    let path = normalize_docs_ui_path(path);
    let state = DocsUiState {
        openapi_document,
        security,
        endpoint_summaries: Arc::new(endpoint_summaries),
    };
    let router = Router::new()
        .route(&format!("/{path}"), get(docs_ui_page))
        .route(&format!("/{path}/operations.json"), get(docs_ui_operations_handler))
        .route(&format!("/{path}/endpoints.json"), get(docs_ui_endpoints_handler))
        .with_state(state);
    match mode {
        crate::config::DocsUiMode::Localhost => router.layer(middleware::from_fn(docs_ui_localhost_gate)),
        crate::config::DocsUiMode::Public | crate::config::DocsUiMode::Off => router,
    }
}

/// `include_str!`, not a file read at request time — the whole point of
/// embedding is that the console works with nothing on disk beyond the
/// compiled binary itself. `docs_ui.html` derives both the API's own
/// `apiRoot` prefix *and* its own mount path from `window.location.pathname`
/// client-side (strip the page's own last path segment for the former, use
/// the page's own full path for the latter) rather than needing this
/// handler to template anything in — so this stays a byte-for-byte
/// constant no matter what `docsUi.path`/`apiRoot` are configured to.
const DOCS_UI_HTML: &str = include_str!("docs_ui.html");

async fn docs_ui_page() -> Response {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], DOCS_UI_HTML).into_response()
}

/// Every discovered endpoint file's own sanitized `sources`/response
/// mapping — see `endpoint::endpoint_summaries`'s doc comment for the full
/// allowlist and why it's safe to expose. Feeds the console's per-operation
/// configuration panel; an empty list (rather than a route failure) is the
/// honest answer for a project with no endpoint files at all yet.
async fn docs_ui_endpoints_handler(State(state): State<DocsUiState>) -> Response {
    axum::Json(serde_json::json!({ "endpoints": state.endpoint_summaries.as_ref() })).into_response()
}

/// A structural summary of `openapi.yaml`'s own operations (paths, methods,
/// parameters, request body schema, declared success codes) plus which
/// security scheme guards each one and, when derivable, which *header
/// name* a caller needs to set — see `docs_ui_operation_json`'s doc comment
/// for why this is safe to expose (never a header/credential *value*).
/// Feeds the console's operation browser and "Try it out"; `operations`/
/// `componentSchemas` are both empty when `openapi.yaml` failed to load
/// (same graceful-degradation posture `commands::run`'s own load-failure
/// warning already established) rather than this route failing outright.
async fn docs_ui_operations_handler(State(state): State<DocsUiState>) -> Response {
    let operations: Vec<serde_json::Value> = state
        .openapi_document
        .as_ref()
        .map(|doc| {
            doc.operations
                .iter()
                .map(|op| docs_ui_operation_json(op, &state.security, &doc.deprecated_security_schemes))
                .collect()
        })
        .unwrap_or_default();
    let component_schemas = state
        .openapi_document
        .as_ref()
        .map(|doc| serde_json::Value::Object(doc.component_schemas.clone()))
        .unwrap_or_default();

    axum::Json(serde_json::json!({
        "operations": operations,
        "componentSchemas": component_schemas,
    }))
    .into_response()
}

/// One operation's entry in `/docs/operations.json`. `security.header`, when
/// present, names the header a caller must set to authenticate — read from
/// the guarding verifier's own `parameters` (whichever one reads
/// `header.<name>`, the only prefix a header-based verifier ever uses — see
/// `security::verifier::Parameter`). This is always just a header *name*
/// (`"X-Api-Key"`), never a value: `HttpAuth`/`VerifierDef` never store a
/// real secret anywhere in project config, only env-var *names* the process
/// looks up at request time, so there is nothing sensitive here to redact.
/// `None` when the scheme isn't found (a startup misconfiguration
/// elsewhere would already have failed loudly) or its verifier reads its
/// check from somewhere other than a header (e.g. a body field, or
/// `context.transactionId`) — the console then just shows "protected
/// (scheme name)" with no specific input to render. `clientCert` is true
/// when the verifier needs the connection's client certificate (an `mtls`
/// verifier, or any `cert.*` parameter) — presented by the browser/OS during
/// the TLS handshake, so the console has no field for it.
fn docs_ui_operation_json(
    op: &crate::openapi::Operation,
    security: &crate::security::SecurityConfig,
    deprecated: &std::collections::HashSet<String>,
) -> serde_json::Value {
    let parameters: Vec<serde_json::Value> = op
        .parameters
        .iter()
        .map(|p| serde_json::json!({ "name": p.name, "in": p.location, "required": p.required, "type": p.schema_type }))
        .collect();

    let request_body = op.request_body.as_ref().map(|b| serde_json::json!({ "required": b.required, "schema": b.schema }));

    let security_info = op.security.as_ref().map(|scheme_name| {
        let header = security
            .verifiers
            .get(scheme_name)
            .and_then(|v| v.def.parameters().iter().find(|p| p.from.starts_with("header.")))
            .map(|p| p.from.trim_start_matches("header.").to_string());
        let client_cert = security.verifiers.get(scheme_name).is_some_and(|v| v.requires_client_cert());
        let mut info = serde_json::json!({ "scheme": scheme_name, "header": header, "clientCert": client_cert });
        if deprecated.contains(scheme_name) {
            info["deprecated"] = serde_json::Value::Bool(true);
        }
        info
    });

    let mut out = serde_json::json!({
        "method": op.http_method,
        "path": op.path,
        "operationId": op.operation_id,
        "parameters": parameters,
        "requestBody": request_body,
        "successStatusCodes": op.response_status_codes,
        "security": security_info,
    });
    if matches!(op.response_mode, crate::openapi::ResponseMode::Stream(_)) {
        out["streaming"] = serde_json::Value::Bool(true);
    }
    out
}

/// Restricts `/docs` to the real TCP peer being loopback, for
/// `DocsUiMode::Localhost`. Needs `ConnectInfo<SocketAddr>` in request
/// extensions, which only exists when the listener was bound via
/// `into_make_service_with_connect_info` (see `commands::run`'s
/// `serve_http`/`serve_https`) — when it's missing entirely (a test router
/// spawned the plain way, or in principle some future listener setup that
/// forgets it), this fails **closed**: no `ConnectInfo` is treated the same
/// as "not loopback," not "trust it." Same limitation `RateLimitConfig`'s
/// own doc comment already accepts for per-client throttling: this looks at
/// the raw connecting socket, not `X-Forwarded-For` — behind a reverse
/// proxy, every request's peer is the proxy itself, so `localhost` mode
/// would only actually admit the proxy, not the real remote client. There's
/// no proxy-aware version of this today.
async fn docs_ui_localhost_gate(req: Request, next: Next) -> Response {
    let is_loopback = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .is_some_and(|axum::extract::ConnectInfo(addr)| addr.ip().is_loopback());

    if is_loopback {
        next.run(req).await
    } else {
        (StatusCode::FORBIDDEN, "the docs UI is restricted to localhost (config/server.json's docsUi.mode)").into_response()
    }
}

/// Fixed histogram bucket upper bounds, in seconds — Prometheus' own
/// default set, since there's no principled reason to pick different ones
/// for a general-purpose server like this.
const LATENCY_BUCKETS_SECONDS: &[f64] = &[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0];

/// Process-lifetime request counters — one shared instance (`Arc`), written
/// by `apply_metrics`'s middleware on every request, read by
/// `metrics_router`'s handler. Deliberately just two metrics (a status-code
/// counter, a latency histogram): enough to answer "is this server healthy
/// and fast," not an attempt at a general-purpose metrics library.
#[derive(Debug, Default)]
pub struct Metrics {
    status_counts: Mutex<HashMap<u16, u64>>,
    // Non-cumulative per-bucket counts — turned cumulative only at render
    // time (`render`'s running `cumulative` sum), the same "store raw,
    // compute derived values on read" split used elsewhere in this project.
    bucket_counts: Vec<AtomicU64>,
    over_max_count: AtomicU64,
    sum_millis: AtomicU64,
    total: AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Metrics {
            status_counts: Mutex::new(HashMap::new()),
            bucket_counts: LATENCY_BUCKETS_SECONDS.iter().map(|_| AtomicU64::new(0)).collect(),
            over_max_count: AtomicU64::new(0),
            sum_millis: AtomicU64::new(0),
            total: AtomicU64::new(0),
        }
    }

    fn record(&self, status: u16, elapsed: Duration) {
        self.total.fetch_add(1, Ordering::Relaxed);
        self.sum_millis.fetch_add(elapsed.as_millis() as u64, Ordering::Relaxed);
        *self
            .status_counts
            .lock()
            .unwrap_or_else(|poisoned| {
                tracing::error!(
                    mutex = "server::Metrics status_counts (record)",
                    "recovered a poisoned mutex — a previous request panicked while holding it; metrics continue accumulating onto the recovered counts"
                );
                poisoned.into_inner()
            })
            .entry(status)
            .or_insert(0) += 1;

        let elapsed_secs = elapsed.as_secs_f64();
        match LATENCY_BUCKETS_SECONDS.iter().position(|&bound| elapsed_secs <= bound) {
            Some(index) => {
                self.bucket_counts[index].fetch_add(1, Ordering::Relaxed);
            }
            None => {
                self.over_max_count.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Renders in Prometheus text exposition format
    /// (<https://prometheus.io/docs/instrumenting/exposition_formats/>).
    fn render(&self) -> String {
        let mut out = String::new();

        out.push_str("# HELP http_requests_total Total HTTP requests handled, by status code.\n");
        out.push_str("# TYPE http_requests_total counter\n");
        let mut statuses: Vec<(u16, u64)> = self
            .status_counts
            .lock()
            .unwrap_or_else(|poisoned| {
                tracing::error!(
                    mutex = "server::Metrics status_counts (render)",
                    "recovered a poisoned mutex — a previous request panicked while holding it; the scrape reports the recovered counts"
                );
                poisoned.into_inner()
            })
            .iter()
            .map(|(&s, &c)| (s, c))
            .collect();
        statuses.sort_unstable_by_key(|(status, _)| *status);
        for (status, count) in statuses {
            out.push_str(&format!("http_requests_total{{status=\"{status}\"}} {count}\n"));
        }

        out.push_str("# HELP http_request_duration_seconds Request latency in seconds.\n");
        out.push_str("# TYPE http_request_duration_seconds histogram\n");
        let mut cumulative = 0u64;
        for (bound, counter) in LATENCY_BUCKETS_SECONDS.iter().zip(&self.bucket_counts) {
            cumulative += counter.load(Ordering::Relaxed);
            out.push_str(&format!("http_request_duration_seconds_bucket{{le=\"{bound}\"}} {cumulative}\n"));
        }
        cumulative += self.over_max_count.load(Ordering::Relaxed);
        out.push_str(&format!("http_request_duration_seconds_bucket{{le=\"+Inf\"}} {cumulative}\n"));
        out.push_str(&format!(
            "http_request_duration_seconds_sum {}\n",
            self.sum_millis.load(Ordering::Relaxed) as f64 / 1000.0
        ));
        out.push_str(&format!("http_request_duration_seconds_count {}\n", self.total.load(Ordering::Relaxed)));

        out
    }
}

/// Applies the metrics-recording middleware — same "call this last, after
/// every route is registered" requirement as `apply_middleware`, and for
/// the same reason (`Router::layer` only wraps routes already present at
/// the time it's called). Independent of `apply_middleware`; the two can be
/// applied in either order since neither depends on the other.
pub fn apply_metrics(router: Router, metrics: Arc<Metrics>) -> Router {
    router.layer(middleware::from_fn_with_state(metrics, metrics_middleware))
}

async fn metrics_middleware(State(metrics): State<Arc<Metrics>>, req: Request, next: Next) -> Response {
    let start = Instant::now();
    let response = next.run(req).await;
    metrics.record(response.status().as_u16(), start.elapsed());
    response
}

/// Applies CORS headers per `features.cors`'s `allowedOrigins` allowlist —
/// `tower_http::cors::CorsLayer`, not hand-rolled (see docs/frogs-quick-wins.md
/// for why: a well-audited dependency for header-interaction subtlety that's
/// easy to get wrong by hand, at a binary-size cost too small to matter).
/// A literal `"*"` entry means "any origin" (`AllowOrigin::any()`); anything
/// else builds an exact-match allowlist (`AllowOrigin::list`) — invalid
/// entries (not parseable as a header value) are dropped with a warning
/// rather than failing the whole list. Methods/headers are mirrored from
/// each request rather than fixed, since frogs doesn't know an operator's
/// endpoint shapes in advance; safe to combine with any origin policy here
/// because `allow_credentials` is never set (frogs' auth types are headers,
/// not cookies — there's nothing that needs credentialed CORS).
///
/// Call this **last**, after every route is registered — same
/// `Router::layer`-only-wraps-what-exists-already requirement
/// `apply_middleware`/`apply_metrics`/`apply_rate_limit` all have — and
/// applied *after* (so outermost of) those three specifically, so a
/// 429/401/500 response generated by one of those inner layers still
/// carries `Access-Control-Allow-Origin`: without it, a browser hides that
/// response's real status from calling JS behind a generic network error.
///
/// "Outermost" here is relative to the other layers only; see `NormalizeMethod` for where method dispatch sits.
pub fn apply_cors(router: Router, allowed_origins: &[String]) -> Router {
    use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer};

    let allow_origin = if allowed_origins.iter().any(|o| o == "*") {
        AllowOrigin::any()
    } else {
        let origins: Vec<HeaderValue> = allowed_origins
            .iter()
            .filter_map(|o| match HeaderValue::from_str(o) {
                Ok(v) => Some(v),
                Err(e) => {
                    tracing::warn!("cors.allowedOrigins entry {o:?} is not a valid header value ({e}) — ignoring it");
                    None
                }
            })
            .collect();
        AllowOrigin::list(origins)
    };

    let layer = CorsLayer::new()
        .allow_origin(allow_origin)
        .allow_methods(AllowMethods::mirror_request())
        .allow_headers(AllowHeaders::mirror_request());
    router.layer(layer)
}

/// A global (not per-client — see `config::RateLimitConfig`'s doc comment)
/// token bucket: `capacity` tokens to start, refilling continuously at
/// `refill_per_second`, capped back at `capacity`. One request costs exactly
/// one token; a request that would take the bucket below zero is rejected
/// instead. `state` is a single short-lived `Mutex` (never held across an
/// `.await`) around both fields together — refilling and spending must be
/// one atomic step, or two concurrent requests could each read the same
/// pre-refill token count and both spend it.
#[derive(Debug)]
pub struct RateLimiter {
    capacity: f64,
    refill_per_second: f64,
    state: Mutex<RateLimiterState>,
}

#[derive(Debug)]
struct RateLimiterState {
    tokens: f64,
    last_refill: Instant,
}

/// What a rejected request should do — a whole-second `retry_after` (HTTP's
/// `Retry-After` only has whole-second granularity) rounded up from however
/// long until the bucket would actually have a full token again, never 0
/// (a caller retrying in the same instant would just be rejected again).
struct RateLimitExceeded {
    retry_after_secs: u64,
}

impl RateLimiter {
    pub fn new(requests_per_second: u32, burst: u32) -> Self {
        RateLimiter {
            capacity: burst.max(1) as f64,
            refill_per_second: requests_per_second.max(1) as f64,
            state: Mutex::new(RateLimiterState {
                tokens: burst.max(1) as f64,
                last_refill: Instant::now(),
            }),
        }
    }

    fn try_acquire(&self) -> Result<(), RateLimitExceeded> {
        // `into_inner` deliberately keeps whatever `tokens`/`last_refill` were
        // in the bucket at poison time — resetting to full capacity here would
        // hand every caller a fresh burst allowance, i.e. a fail-open rate
        // limiter.
        let mut state = self.state.lock().unwrap_or_else(|poisoned| {
            tracing::error!(
                mutex = "server::RateLimiter state",
                "recovered a poisoned mutex — a previous request panicked while holding it; the existing token state is preserved, not refilled"
            );
            poisoned.into_inner()
        });

        let now = Instant::now();
        let elapsed = now.duration_since(state.last_refill).as_secs_f64();
        state.tokens = (state.tokens + elapsed * self.refill_per_second).min(self.capacity);
        state.last_refill = now;

        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            Ok(())
        } else {
            let seconds_needed = (1.0 - state.tokens) / self.refill_per_second;
            Err(RateLimitExceeded {
                retry_after_secs: seconds_needed.ceil().max(1.0) as u64,
            })
        }
    }
}

/// Applies the rate-limiting middleware — same "call this last, after every
/// route is registered" requirement `apply_middleware`/`apply_metrics` both
/// have, for the same reason (`Router::layer` only wraps routes already
/// present on that specific `Router` value).
pub fn apply_rate_limit(router: Router, limiter: Arc<RateLimiter>) -> Router {
    router.layer(middleware::from_fn_with_state(limiter, rate_limit_middleware))
}

/// The same middleware, scoped to a single route's own `MethodRouter`
/// instead of the whole `Router` — what an endpoint's own `rateLimit`
/// override (`EndpointFile::rate_limit`) attaches to just that route in
/// `endpoint::build_router`, *in addition to* whatever `apply_rate_limit`
/// above applies globally (a request through an overridden route must
/// clear both buckets, since this doesn't replace the global one).
pub fn apply_rate_limit_to_route<S>(method_router: MethodRouter<S>, limiter: Arc<RateLimiter>) -> MethodRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    method_router.layer(middleware::from_fn_with_state(limiter, rate_limit_middleware))
}

async fn rate_limit_middleware(State(limiter): State<Arc<RateLimiter>>, req: Request, next: Next) -> Response {
    match limiter.try_acquire() {
        Ok(()) => next.run(req).await,
        Err(exceeded) => {
            let body = serde_json::json!({
                "code": 429,
                "name": "rate_limit_exceeded",
                "detail": "rate limit exceeded, try again later"
            });
            let mut response = (StatusCode::TOO_MANY_REQUESTS, axum::Json(body)).into_response();
            if let Ok(value) = HeaderValue::from_str(&exceeded.retry_after_secs.to_string()) {
                response.headers_mut().insert(HeaderName::from_static("retry-after"), value);
            }
            response
        }
    }
}

/// A single leading slash, no trailing one — the exact form `Router::nest`
/// expects — or `None` for a blank/all-slashes value, meaning "mount
/// unprefixed." Accepts `api`, `/api`, and `/api/` alike, since a
/// hand-edited `config/server.json` shouldn't have to get this exactly
/// right to work.
pub(crate) fn normalize_api_root(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_matches('/');
    if trimmed.is_empty() { None } else { Some(format!("/{trimmed}")) }
}

/// Applies the correlation-ID/tracing middleware. Call this **last**, after
/// every route — including ones merged in from elsewhere, like
/// `endpoint::build_router`'s — has already been registered.
///
/// `Router::layer` only wraps whatever routes already exist on that
/// specific `Router` value at the moment it's called; `Router::merge`
/// combines two routers as siblings without sharing layers between them.
/// So layering here *before* merging in the endpoint routes would leave
/// every endpoint route unwrapped — exactly the bug this function exists
/// to avoid: build the whole router first, then wrap it once, whole.
pub fn apply_middleware(router: Router) -> Router {
    router.layer(middleware::from_fn(correlation_id_middleware))
}

async fn healthz() -> &'static str {
    "ok"
}

/// Reuses an inbound `X-Request-Id` if the caller sent one, otherwise
/// generates a fresh UUID — either way, every log line for this request is
/// tagged with it via a tracing span, and it's echoed back in the response
/// so a caller can correlate their request with server-side logs.
async fn correlation_id_middleware(mut req: Request, next: Next) -> Response {
    let id = req
        .headers()
        .get(CORRELATION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    req.extensions_mut().insert(RequestId(id.clone()));

    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let original_method = req.extensions().get::<OriginalMethod>().cloned();
    let span = tracing::info_span!("request", request_id = %id, %method, %path);

    let mut response = async move {
        if let Some(original) = original_method {
            tracing::debug!(original_method = %original.0, "request method was normalized");
        }
        let response = next.run(req).await;
        // `debug`, not `info` — see `docs/frogs-persistent-logging.md`'s
        // severity-contract note: this fires once per HTTP request, so an
        // `info`-level per-request line would make unbounded, request-volume
        // -driven disk growth the *default* behavior of turning this feature
        // on at all, now that the file layer shares this same `EnvFilter`.
        tracing::debug!(status = %response.status(), "request completed");
        response
    }
    .instrument(span)
    .await;

    if let Ok(value) = HeaderValue::from_str(&id) {
        response.headers_mut().insert(HeaderName::from_static(CORRELATION_HEADER), value);
    }
    response
}

/// Binds an ephemeral port and serves `router` through the real
/// `served_service` wrapper, never a bare `axum::serve(listener, router)`.
#[cfg(test)]
pub(crate) async fn spawn_served(router: Router, case_sensitive: bool) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, served_service(router, case_sensitive)).await.unwrap();
    });
    addr
}

/// Sends `bytes` verbatim over a fresh TCP connection and returns the status
/// line, the headers (names lowercased), the raw body bytes after the header
/// block, and whether the server closed the connection.
#[cfg(test)]
pub(crate) async fn raw_request(addr: SocketAddr, bytes: &[u8]) -> (String, Vec<(String, String)>, Vec<u8>, bool) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(bytes).await.unwrap();
    let mut received = Vec::new();
    let mut closed = false;
    loop {
        let mut chunk = [0u8; 4096];
        match tokio::time::timeout(Duration::from_millis(500), stream.read(&mut chunk)).await {
            Ok(Ok(0)) => {
                closed = true;
                break;
            }
            Ok(Ok(n)) => received.extend_from_slice(&chunk[..n]),
            Ok(Err(_)) => {
                closed = true;
                break;
            }
            Err(_) => break,
        }
    }
    let split = received.windows(4).position(|w| w == b"\r\n\r\n");
    let (head, body) = match split {
        Some(i) => (&received[..i], received[i + 4..].to_vec()),
        None => (&received[..], Vec::new()),
    };
    let head = String::from_utf8_lossy(head).into_owned();
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default().to_string();
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    (status_line, headers, body, closed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This project's established pattern for testing real HTTP behavior:
    /// bind an ephemeral port, serve the router for real, hit it with a
    /// real `reqwest` client — see `http::mod`/`endpoint::resolve` tests.
    async fn spawn(router: Router) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        addr
    }

    /// Same as `spawn`, but wired the way `commands::run::serve_http` really
    /// wires it — with `ConnectInfo<SocketAddr>` available to extractors —
    /// since a plain `spawn`'d router never populates it at all, which would
    /// make `docs_ui_localhost_gate` fail closed for every request
    /// regardless of the real (loopback) peer.
    async fn spawn_with_connect_info(router: Router) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .await
                .unwrap();
        });
        addr
    }

    #[tokio::test]
    async fn healthz_returns_ok() {
        let addr = spawn(apply_middleware(router())).await;
        let response = reqwest::get(format!("http://{addr}/healthz")).await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.text().await.unwrap(), "ok");
    }

    #[derive(Debug)]
    struct FakeDriver {
        fail: bool,
    }

    #[async_trait::async_trait]
    impl SqlDriver for FakeDriver {
        async fn query(&self, _script: &str, _params: &HashMap<String, crate::sql::SqlValue>) -> Result<Vec<crate::sql::SqlRow>, crate::sql::SqlError> {
            if self.fail {
                Err(crate::sql::SqlError::ConnectionFailed("simulated failure".to_string()))
            } else {
                Ok(vec![])
            }
        }
    }

    #[tokio::test]
    async fn readyz_is_ready_with_no_configured_connections_at_all() {
        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        let addr = spawn(readyz_router(Arc::new(drivers))).await;
        let response = reqwest::get(format!("http://{addr}/readyz")).await.unwrap();
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn readyz_is_ready_when_every_connection_succeeds() {
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(FakeDriver { fail: false }));
        let addr = spawn(readyz_router(Arc::new(drivers))).await;
        let response = reqwest::get(format!("http://{addr}/readyz")).await.unwrap();
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn readyz_is_not_ready_when_a_connection_fails() {
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("good".to_string(), Box::new(FakeDriver { fail: false }));
        drivers.insert("bad".to_string(), Box::new(FakeDriver { fail: true }));
        let addr = spawn(readyz_router(Arc::new(drivers))).await;
        let response = reqwest::get(format!("http://{addr}/readyz")).await.unwrap();
        assert_eq!(response.status(), 503);
        assert!(response.text().await.unwrap().contains("bad"), "the response should name the failing connection");
    }

    #[test]
    fn metrics_render_is_empty_before_anything_is_recorded() {
        let metrics = Metrics::new();
        let rendered = metrics.render();
        assert!(rendered.contains("http_request_duration_seconds_count 0"));
        assert!(!rendered.contains("http_requests_total{"), "no status has been recorded yet");
    }

    #[test]
    fn metrics_render_reports_status_counts_and_histogram_totals() {
        let metrics = Metrics::new();
        metrics.record(200, Duration::from_millis(10));
        metrics.record(200, Duration::from_millis(20));
        metrics.record(404, Duration::from_millis(5));

        let rendered = metrics.render();
        assert!(rendered.contains("http_requests_total{status=\"200\"} 2"));
        assert!(rendered.contains("http_requests_total{status=\"404\"} 1"));
        assert!(rendered.contains("http_request_duration_seconds_count 3"));
        assert!(rendered.contains("http_request_duration_seconds_sum 0.035"));
    }

    #[test]
    fn metrics_render_buckets_are_cumulative_and_include_a_plus_inf_bucket() {
        let metrics = Metrics::new();
        // Well past the largest named bound (10s) — must land in +Inf, not
        // silently vanish.
        metrics.record(200, Duration::from_secs(30));

        let rendered = metrics.render();
        assert!(rendered.contains("http_request_duration_seconds_bucket{le=\"+Inf\"} 1"));
        // Every named bound is below the 30s observation, so each of their
        // cumulative counts must still be 0 — nothing should have leaked
        // into a bucket smaller than the actual observation.
        assert!(rendered.contains("http_request_duration_seconds_bucket{le=\"10\"} 0"));
    }

    /// Poisons `status_counts` (a previous request panicked mid-`record`),
    /// then confirms both `record` and `render` recover via `into_inner()`
    /// — preserving whatever counts were already there, rather than
    /// panicking themselves or silently resetting to empty.
    #[test]
    fn metrics_record_and_render_recover_a_poisoned_status_counts_mutex_preserving_existing_counts() {
        let metrics = Metrics::new();
        metrics.record(200, Duration::from_millis(10));

        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        std::thread::scope(|scope| {
            let handle = scope.spawn(|| {
                let _guard = metrics.status_counts.lock().unwrap();
                panic!("deliberately poisoning the mutex for this test");
            });
            let _ = handle.join();
        });
        std::panic::set_hook(previous_hook);

        assert!(metrics.status_counts.lock().is_err(), "sanity check: the mutex really is poisoned at this point");

        // Must not panic, and must keep accumulating onto the recovered
        // counts rather than starting over from empty.
        metrics.record(404, Duration::from_millis(5));

        let rendered = metrics.render();
        assert!(
            rendered.contains("http_requests_total{status=\"200\"} 1"),
            "the count recorded before poisoning must survive recovery: {rendered}"
        );
        assert!(
            rendered.contains("http_requests_total{status=\"404\"} 1"),
            "a new count recorded after recovering from poisoning must still be tracked: {rendered}"
        );
    }

    #[tokio::test]
    async fn metrics_endpoint_reflects_requests_recorded_by_the_middleware() {
        let metrics = Arc::new(Metrics::new());
        let router = apply_metrics(router().merge(metrics_router(metrics.clone())), metrics);
        let addr = spawn(router).await;

        reqwest::get(format!("http://{addr}/healthz")).await.unwrap();
        reqwest::get(format!("http://{addr}/healthz")).await.unwrap();
        reqwest::get(format!("http://{addr}/does-not-exist")).await.unwrap();

        let body = reqwest::get(format!("http://{addr}/metrics")).await.unwrap().text().await.unwrap();
        assert!(body.contains("http_requests_total{status=\"200\"} 2"));
        assert!(body.contains("http_requests_total{status=\"404\"} 1"));
    }

    #[tokio::test]
    async fn generates_a_request_id_when_the_caller_sends_none() {
        let addr = spawn(apply_middleware(router())).await;
        let response = reqwest::get(format!("http://{addr}/healthz")).await.unwrap();
        let id = response.headers().get(CORRELATION_HEADER).expect("middleware should always set this header");
        assert!(Uuid::parse_str(id.to_str().unwrap()).is_ok());
    }

    #[tokio::test]
    async fn reuses_the_callers_inbound_request_id_instead_of_generating_one() {
        let addr = spawn(apply_middleware(router())).await;
        let client = reqwest::Client::new();
        let response = client
            .get(format!("http://{addr}/healthz"))
            .header(CORRELATION_HEADER, "caller-supplied-id")
            .send()
            .await
            .unwrap();
        assert_eq!(response.headers().get(CORRELATION_HEADER).unwrap(), "caller-supplied-id");
    }

    /// Regression test for the exact bug `apply_middleware`'s doc comment
    /// describes: `Router::layer` only wraps routes already present on that
    /// router at the time it's called, while `Router::merge` doesn't share
    /// layers between the two routers being merged. This proves a route
    /// merged in after `router()` (the way `endpoint::build_router`'s
    /// routes are, in `commands::run`) still gets the correlation-ID header
    /// when `apply_middleware` is called last, on the combined router.
    #[tokio::test]
    async fn middleware_applies_to_routes_merged_in_after_the_base_router() {
        let extra = Router::new().route("/extra", get(|| async { "extra" }));
        let addr = spawn(apply_middleware(router().merge(extra))).await;

        let response = reqwest::get(format!("http://{addr}/extra")).await.unwrap();
        assert_eq!(response.status(), 200);
        assert!(
            response.headers().get(CORRELATION_HEADER).is_some(),
            "a route merged in before apply_middleware must still be wrapped by it"
        );
    }

    #[test]
    fn normalize_api_root_treats_blank_and_all_slashes_as_no_prefix() {
        assert_eq!(normalize_api_root(""), None);
        assert_eq!(normalize_api_root("   "), None);
        assert_eq!(normalize_api_root("/"), None);
    }

    #[test]
    fn normalize_api_root_accepts_any_slash_shape() {
        assert_eq!(normalize_api_root("api"), Some("/api".to_string()));
        assert_eq!(normalize_api_root("/api"), Some("/api".to_string()));
        assert_eq!(normalize_api_root("/api/"), Some("/api".to_string()));
        assert_eq!(normalize_api_root("  /api/  "), Some("/api".to_string()));
    }

    #[tokio::test]
    async fn an_empty_api_root_mounts_unprefixed_exactly_like_today() {
        let addr = spawn(apply_middleware(mount_under(router(), ""))).await;
        let response = reqwest::get(format!("http://{addr}/healthz")).await.unwrap();
        assert_eq!(response.status(), 200);
    }

    /// Proves the whole point of `mount_under`: `/healthz` (from `router()`)
    /// moves under the prefix right alongside whatever endpoint routes were
    /// merged in with it, since both go through `mount_under` as one
    /// already-combined router — not something `/healthz` gets to opt out of.
    #[tokio::test]
    async fn a_custom_api_root_nests_healthz_and_endpoint_routes_together() {
        let extra = Router::new().route("/things", get(|| async { "things" }));
        let combined = router().merge(extra);
        let addr = spawn(apply_middleware(mount_under(combined, "/api"))).await;

        let healthz = reqwest::get(format!("http://{addr}/api/healthz")).await.unwrap();
        assert_eq!(healthz.status(), 200);

        let things = reqwest::get(format!("http://{addr}/api/things")).await.unwrap();
        assert_eq!(things.status(), 200);

        let unprefixed = reqwest::get(format!("http://{addr}/healthz")).await.unwrap();
        assert_eq!(unprefixed.status(), 404, "the old unprefixed path must not still work once apiRoot is set");
    }

    #[test]
    fn a_fresh_limiter_starts_with_a_full_bucket_of_burst_size() {
        let limiter = RateLimiter::new(10, 3);
        assert!(limiter.try_acquire().is_ok());
        assert!(limiter.try_acquire().is_ok());
        assert!(limiter.try_acquire().is_ok());
        assert!(limiter.try_acquire().is_err(), "a 4th request beyond burst=3 must be rejected");
    }

    #[test]
    fn a_rejected_request_reports_a_nonzero_retry_after() {
        // 1 request/second means the very next token is at most 1s away.
        let limiter = RateLimiter::new(1, 1);
        assert!(limiter.try_acquire().is_ok());
        let err = limiter.try_acquire().expect_err("the bucket should be empty after the first request");
        assert!(err.retry_after_secs >= 1, "retry-after must never be 0 — an immediate retry would just fail again");
    }

    #[test]
    fn tokens_refill_over_time_up_to_the_burst_cap() {
        // 100/s: fast enough that 50ms of sleep easily refills a token, but
        // slow enough that the microseconds-scale gap between the two
        // back-to-back `try_acquire()` calls below can't accidentally
        // refill one on its own (that would need >= 1/100th of a second to
        // elapse between them, orders of magnitude more than a bare
        // function call plus a mutex lock actually takes).
        let limiter = RateLimiter::new(100, 1);
        assert!(limiter.try_acquire().is_ok());
        assert!(limiter.try_acquire().is_err(), "the single-token bucket should be empty immediately after");

        std::thread::sleep(Duration::from_millis(50));
        assert!(limiter.try_acquire().is_ok(), "50ms at 100/s should easily have refilled one token");
    }

    #[test]
    fn refilling_never_exceeds_the_burst_capacity() {
        let limiter = RateLimiter::new(1_000, 2);
        std::thread::sleep(Duration::from_millis(50));
        // Capacity is 2, however long this thread happened to sleep for —
        // a 3rd immediate request must still be rejected, not "however many
        // tokens accumulated."
        assert!(limiter.try_acquire().is_ok());
        assert!(limiter.try_acquire().is_ok());
        assert!(limiter.try_acquire().is_err());
    }

    /// The fail-open bug this fix specifically guards against: a rate
    /// limiter whose bucket was already exhausted before its mutex got
    /// poisoned must stay exhausted after recovering — `into_inner()`
    /// deliberately keeps whatever `tokens`/`last_refill` state was there,
    /// rather than resetting to a fresh, full bucket (which would hand every
    /// caller a brand-new burst allowance for free).
    #[test]
    fn a_poisoned_rate_limiter_recovers_without_refilling_an_exhausted_bucket() {
        let limiter = RateLimiter::new(10, 3);
        assert!(limiter.try_acquire().is_ok());
        assert!(limiter.try_acquire().is_ok());
        assert!(limiter.try_acquire().is_ok());
        assert!(limiter.try_acquire().is_err(), "the bucket must already be exhausted before poisoning");

        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        std::thread::scope(|scope| {
            let handle = scope.spawn(|| {
                let _guard = limiter.state.lock().unwrap();
                panic!("deliberately poisoning the mutex for this test");
            });
            let _ = handle.join();
        });
        std::panic::set_hook(previous_hook);

        assert!(limiter.state.lock().is_err(), "sanity check: the mutex really is poisoned at this point");

        // Must not panic, and — the actual point of this test — must not
        // have been handed a fresh, full bucket by the recovery path.
        assert!(
            limiter.try_acquire().is_err(),
            "an already-exhausted bucket must still be exhausted immediately after recovering from a poisoned mutex, not refilled to full capacity"
        );
    }

    #[tokio::test]
    async fn a_real_request_over_the_limit_gets_429_with_a_retry_after_header() {
        let limiter = Arc::new(RateLimiter::new(10, 1));
        let addr = spawn(apply_rate_limit(router(), limiter)).await;

        let first = reqwest::get(format!("http://{addr}/healthz")).await.unwrap();
        assert_eq!(first.status(), 200);

        let second = reqwest::get(format!("http://{addr}/healthz")).await.unwrap();
        assert_eq!(second.status(), 429);
        assert!(second.headers().get("retry-after").is_some());
        let body: serde_json::Value = second.json().await.unwrap();
        assert_eq!(body["code"], 429);
        assert_eq!(body["name"], "rate_limit_exceeded");
    }

    #[tokio::test]
    async fn an_allowed_origin_gets_the_access_control_allow_origin_header_echoed_back() {
        let addr = spawn(apply_cors(router(), &["https://allowed.example".to_string()])).await;
        let client = reqwest::Client::new();

        let response = client
            .get(format!("http://{addr}/healthz"))
            .header("origin", "https://allowed.example")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
        assert_eq!(response.headers().get("access-control-allow-origin").unwrap(), "https://allowed.example");
    }

    #[tokio::test]
    async fn an_origin_not_on_the_allowlist_gets_no_cors_header_even_though_the_request_still_succeeds() {
        let addr = spawn(apply_cors(router(), &["https://allowed.example".to_string()])).await;
        let client = reqwest::Client::new();

        let response = client
            .get(format!("http://{addr}/healthz"))
            .header("origin", "https://not-allowed.example")
            .send()
            .await
            .unwrap();

        // The plain request itself isn't blocked server-side — same-origin
        // curl/server-to-server calls always work; it's the *browser* that
        // enforces CORS client-side by refusing to expose this response to
        // JS when the header is missing.
        assert_eq!(response.status(), 200);
        assert!(
            response.headers().get("access-control-allow-origin").is_none(),
            "an origin absent from the allowlist must not be echoed back"
        );
    }

    #[tokio::test]
    async fn a_wildcard_allowed_origin_matches_any_origin() {
        let addr = spawn(apply_cors(router(), &["*".to_string()])).await;
        let client = reqwest::Client::new();

        let response = client
            .get(format!("http://{addr}/healthz"))
            .header("origin", "https://anything.example")
            .send()
            .await
            .unwrap();

        assert_eq!(response.headers().get("access-control-allow-origin").unwrap(), "*");
    }

    #[tokio::test]
    async fn an_options_preflight_request_is_answered_directly_without_reaching_the_route() {
        let addr = spawn(apply_cors(router(), &["https://allowed.example".to_string()])).await;
        let client = reqwest::Client::new();

        let response = client
            .request(reqwest::Method::OPTIONS, format!("http://{addr}/healthz"))
            .header("origin", "https://allowed.example")
            .header("access-control-request-method", "GET")
            .send()
            .await
            .unwrap();

        assert!(response.status().is_success());
        assert_eq!(response.headers().get("access-control-allow-origin").unwrap(), "https://allowed.example");
        assert!(response.headers().get("access-control-allow-methods").is_some());
        // A real route body would be "ok" (see `healthz_returns_ok`) — an
        // empty preflight response proves this never reached the handler.
        assert_eq!(response.text().await.unwrap(), "");
    }

    #[tokio::test]
    async fn an_empty_allowlist_adds_no_cors_header_to_anyone() {
        let addr = spawn(apply_cors(router(), &[])).await;
        let client = reqwest::Client::new();

        let response = client
            .get(format!("http://{addr}/healthz"))
            .header("origin", "https://anything.example")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200, "the route itself must still work with cors on but unconfigured");
        assert!(response.headers().get("access-control-allow-origin").is_none());
    }

    /// No security config, no openapi doc, no endpoint summaries — the
    /// common empty case for the gating tests, which don't care about any
    /// route's body.
    fn no_docs_ui_state() -> (Option<Arc<crate::openapi::OpenApiDocument>>, Arc<crate::security::SecurityConfig>) {
        (None, Arc::new(crate::security::SecurityConfig::default()))
    }

    #[tokio::test]
    async fn docs_ui_public_mode_serves_the_route_with_no_gating() {
        let (doc, security) = no_docs_ui_state();
        let addr = spawn(docs_ui_router(crate::config::DocsUiMode::Public, "docs", doc, security, vec![])).await;
        let response = reqwest::get(format!("http://{addr}/docs")).await.unwrap();
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn docs_ui_page_serves_the_real_console_as_html() {
        let (doc, security) = no_docs_ui_state();
        let addr = spawn(docs_ui_router(crate::config::DocsUiMode::Public, "docs", doc, security, vec![])).await;
        let response = reqwest::get(format!("http://{addr}/docs")).await.unwrap();
        assert_eq!(response.headers().get("content-type").unwrap(), "text/html; charset=utf-8");
        let body = response.text().await.unwrap();
        assert!(body.contains("<!doctype html>"), "must be the real console, not the old placeholder text");
        assert!(body.contains("operations.json"), "the page must actually fetch the operations endpoint");
        assert!(body.contains("endpoints.json"), "the page must actually fetch the sanitized endpoint-config endpoint");
    }

    #[tokio::test]
    async fn docs_ui_localhost_mode_admits_a_real_loopback_peer() {
        let (doc, security) = no_docs_ui_state();
        let addr = spawn_with_connect_info(docs_ui_router(crate::config::DocsUiMode::Localhost, "docs", doc, security, vec![])).await;
        let response = reqwest::get(format!("http://{addr}/docs")).await.unwrap();
        assert_eq!(response.status(), 200, "a real request from 127.0.0.1 must be recognized as loopback and admitted");
    }

    #[tokio::test]
    async fn docs_ui_localhost_mode_fails_closed_when_connect_info_is_unavailable() {
        // The plain `spawn` helper — no `ConnectInfo` in extensions at all,
        // the same gap a misconfigured or forgotten `into_make_service`
        // call site would produce. Must not be treated as "trust it."
        let (doc, security) = no_docs_ui_state();
        let addr = spawn(docs_ui_router(crate::config::DocsUiMode::Localhost, "docs", doc, security, vec![])).await;
        let response = reqwest::get(format!("http://{addr}/docs")).await.unwrap();
        assert_eq!(response.status(), 403);
    }

    #[tokio::test]
    async fn docs_ui_path_is_configurable_and_normalizes_leading_and_trailing_slashes() {
        let (doc, security) = no_docs_ui_state();
        let addr = spawn(docs_ui_router(crate::config::DocsUiMode::Public, "/internal-docs/", doc, security, vec![])).await;

        let page = reqwest::get(format!("http://{addr}/internal-docs")).await.unwrap();
        assert_eq!(page.status(), 200);
        let ops = reqwest::get(format!("http://{addr}/internal-docs/operations.json")).await.unwrap();
        assert_eq!(ops.status(), 200);

        let old_path = reqwest::get(format!("http://{addr}/docs")).await.unwrap();
        assert_eq!(old_path.status(), 404, "the default path must not also be registered once a custom one is configured");
    }

    #[tokio::test]
    async fn docs_ui_path_falls_back_to_docs_when_blank() {
        let (doc, security) = no_docs_ui_state();
        let addr = spawn(docs_ui_router(crate::config::DocsUiMode::Public, "   ", doc, security, vec![])).await;
        let response = reqwest::get(format!("http://{addr}/docs")).await.unwrap();
        assert_eq!(response.status(), 200);
    }

    fn temp_security_dir() -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "frogs-docs-ui-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(root.join("verifiers")).unwrap();
        root
    }

    /// A real `SecurityConfig::load` (not a hand-built struct — `verifier`
    /// is a private module, and this exercises the actual parse path a
    /// project's own `security/` directory goes through) with one
    /// header-based scheme, `apiKeyAuth`, reading `header.X-Api-Key`.
    fn security_config_with_one_header_scheme() -> crate::security::SecurityConfig {
        let dir = temp_security_dir();
        std::fs::write(dir.join("schemes.json"), r#"{ "apiKeyAuth": { "verifier": "api_key.json" } }"#).unwrap();
        std::fs::write(
            dir.join("verifiers/api_key.json"),
            r#"{
                "type": "sql",
                "connection": "anydb",
                "script": "SELECT 1",
                "parameters": [{ "name": "key", "from": "header.X-Api-Key" }],
                "validIf": "row.active = true"
            }"#,
        )
        .unwrap();
        crate::security::SecurityConfig::load(&dir).expect("a well-formed security dir should load")
    }

    fn sample_openapi_doc() -> crate::openapi::OpenApiDocument {
        crate::openapi::OpenApiDocument {
            operations: vec![crate::openapi::Operation {
                path: "/cars/{id}".to_string(),
                method: "get".to_string(),
                http_method: "GET".to_string(),
                operation_id: "getCar".to_string(),
                response_schema: None,
                parameters: vec![crate::openapi::ParameterInfo {
                    name: "id".to_string(),
                    location: "path".to_string(),
                    required: true,
                    schema_type: Some("string".to_string()),
                }],
                request_body: None,
                response_status_codes: vec![200],
                security: Some("apiKeyAuth".to_string()),
                ..Default::default()
            }],
            component_schemas: serde_json::Map::new(),
            security_scheme_types: HashMap::new(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn operations_json_is_empty_when_no_openapi_document_was_loaded() {
        let addr = spawn(docs_ui_router(
            crate::config::DocsUiMode::Public,
            "docs",
            None,
            Arc::new(crate::security::SecurityConfig::default()),
            vec![],
        ))
        .await;
        let body: serde_json::Value = reqwest::get(format!("http://{addr}/docs/operations.json")).await.unwrap().json().await.unwrap();
        assert_eq!(body["operations"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn operations_json_describes_an_operation_and_resolves_its_security_header() {
        let doc = Arc::new(sample_openapi_doc());
        let security = Arc::new(security_config_with_one_header_scheme());
        let addr = spawn(docs_ui_router(crate::config::DocsUiMode::Public, "docs", Some(doc), security, vec![])).await;

        let body: serde_json::Value = reqwest::get(format!("http://{addr}/docs/operations.json")).await.unwrap().json().await.unwrap();
        let op = &body["operations"][0];
        assert_eq!(op["method"], "GET");
        assert_eq!(op["path"], "/cars/{id}");
        assert_eq!(op["operationId"], "getCar");
        assert_eq!(op["parameters"][0]["name"], "id");
        assert_eq!(op["parameters"][0]["in"], "path");
        assert_eq!(op["parameters"][0]["required"], true);
        assert_eq!(op["security"]["scheme"], "apiKeyAuth");
        assert_eq!(
            op["security"]["header"], "X-Api-Key",
            "the header name must be resolved from the verifier's own parameters"
        );
    }

    #[tokio::test]
    async fn operations_json_never_exposes_a_verifiers_own_datasource_details() {
        // The whole point of building this by hand (scheme name + header
        // name only) rather than passing the verifier's `def` through
        // wholesale: a SQL verifier's `connection`/`script` fields must
        // never appear in this payload, security-relevant structure or not.
        let doc = Arc::new(sample_openapi_doc());
        let security = Arc::new(security_config_with_one_header_scheme());
        let addr = spawn(docs_ui_router(crate::config::DocsUiMode::Public, "docs", Some(doc), security, vec![])).await;

        let raw = reqwest::get(format!("http://{addr}/docs/operations.json")).await.unwrap().text().await.unwrap();
        assert!(!raw.contains("anydb"), "the verifier's own connection name must never appear in the docs UI payload");
        assert!(!raw.contains("SELECT 1"), "the verifier's own script must never appear in the docs UI payload");
    }

    #[tokio::test]
    async fn endpoints_json_is_empty_when_no_summaries_were_computed() {
        let (doc, security) = no_docs_ui_state();
        let addr = spawn(docs_ui_router(crate::config::DocsUiMode::Public, "docs", doc, security, vec![])).await;
        let body: serde_json::Value = reqwest::get(format!("http://{addr}/docs/endpoints.json")).await.unwrap().json().await.unwrap();
        assert_eq!(body["endpoints"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn endpoints_json_serves_whatever_summaries_it_was_given() {
        let (doc, security) = no_docs_ui_state();
        let summary = serde_json::json!({ "method": "GET", "path": "/cars/{id}", "operationId": "getCar" });
        let addr = spawn(docs_ui_router(crate::config::DocsUiMode::Public, "docs", doc, security, vec![summary.clone()])).await;
        let body: serde_json::Value = reqwest::get(format!("http://{addr}/docs/endpoints.json")).await.unwrap().json().await.unwrap();
        assert_eq!(body["endpoints"], serde_json::json!([summary]));
    }

    #[tokio::test]
    async fn endpoints_json_is_gated_by_the_same_localhost_mode_as_the_page() {
        let (doc, security) = no_docs_ui_state();
        let addr = spawn(docs_ui_router(crate::config::DocsUiMode::Localhost, "docs", doc, security, vec![])).await;
        let response = reqwest::get(format!("http://{addr}/docs/endpoints.json")).await.unwrap();
        assert_eq!(response.status(), 403, "endpoints.json must be behind the same gate as the console page itself");
    }
}

#[cfg(test)]
mod m2_docs_ui_tests {
    use super::*;
    use crate::openapi::{Operation, ResponseMode, StreamSpec};
    use std::collections::HashSet;

    fn op(security: Option<&str>, mode: ResponseMode) -> Operation {
        Operation {
            path: "/a".to_string(),
            method: "get".to_string(),
            http_method: "GET".to_string(),
            operation_id: "a".to_string(),
            response_status_codes: vec![200],
            security: security.map(str::to_string),
            response_mode: mode,
            ..Default::default()
        }
    }

    fn stream() -> ResponseMode {
        ResponseMode::Stream(StreamSpec {
            status: Some(200),
            media_type: "text/event-stream".to_string(),
            item_schema: None,
            item_encoding: None,
        })
    }

    #[test]
    fn security_deprecated_is_present_only_for_a_deprecated_scheme() {
        let security = crate::security::SecurityConfig::default();
        let deprecated = HashSet::from(["old".to_string()]);

        let old = docs_ui_operation_json(&op(Some("old"), ResponseMode::Single), &security, &deprecated);
        assert_eq!(old["security"]["scheme"], "old");
        assert_eq!(old["security"]["deprecated"], true);

        let fresh = docs_ui_operation_json(&op(Some("fresh"), ResponseMode::Single), &security, &deprecated);
        assert!(fresh["security"].get("deprecated").is_none(), "{fresh}");

        let none = docs_ui_operation_json(&op(None, ResponseMode::Single), &security, &deprecated);
        assert!(none["security"].is_null());
    }

    #[test]
    fn streaming_true_is_present_only_for_a_stream_operation() {
        let security = crate::security::SecurityConfig::default();
        let streaming = docs_ui_operation_json(&op(None, stream()), &security, &HashSet::new());
        assert_eq!(streaming["streaming"], true);
        let single = docs_ui_operation_json(&op(None, ResponseMode::Single), &security, &HashSet::new());
        assert!(single.get("streaming").is_none(), "{single}");
    }

    #[test]
    fn the_request_body_schema_in_the_payload_is_the_dereferenced_media_type_schema() {
        let dir = std::env::temp_dir().join(format!(
            "frogs-server-m2-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("openapi.yaml");
        std::fs::write(
            &path,
            "openapi: 3.2.0\ninfo: { title: t, version: '1' }\ncomponents:\n  mediaTypes:\n    B: { schema: { type: object, required: [vin] } }\npaths:\n  /cars:\n    post:\n      operationId: c\n      requestBody:\n        required: true\n        content:\n          application/json: { $ref: '#/components/mediaTypes/B' }\n      responses:\n        '200': { description: ok }\n",
        )
        .unwrap();
        let doc = crate::openapi::load(&path, crate::openapi::LoadOptions::default()).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let json = docs_ui_operation_json(&doc.operations[0], &crate::security::SecurityConfig::default(), &doc.deprecated_security_schemes);
        assert_eq!(json["requestBody"]["schema"]["type"], "object");
        assert_eq!(json["requestBody"]["required"], true);
    }

    #[test]
    fn the_docs_page_pills_are_fixed_text_set_via_text_content_never_interpolated() {
        assert!(DOCS_UI_HTML.contains(r#"deprecatedPill.textContent = "deprecated";"#));
        assert!(DOCS_UI_HTML.contains(r#"streamingPill.textContent = "streaming (served as single JSON)";"#));
        // The pills are only ever driven by strict-boolean flags, not by spec text.
        assert!(DOCS_UI_HTML.contains("op.streaming === true"));
        assert!(DOCS_UI_HTML.contains("op.security.deprecated === true"));
    }
}

#[cfg(test)]
mod m3_method_tests {
    use super::*;
    use axum::body::Body;
    use axum::routing::any;

    /// `/g` is a GET-only route, `/any` echoes the method the handler actually saw
    /// plus whether the normalizer recorded an original spelling.
    fn app() -> Router {
        Router::new()
            .route("/g", get(|| async { "hi" }))
            .route(
                "/any",
                any(|req: Request| async move {
                    let original = req.extensions().get::<OriginalMethod>().map(|o| o.0.clone()).unwrap_or_else(|| "-".to_string());
                    format!("{}|{}", req.method(), original)
                }),
            )
    }

    async fn send(addr: SocketAddr, method: &str, path: &str) -> (String, Vec<(String, String)>, Vec<u8>, bool) {
        raw_request(addr, format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes()).await
    }

    fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
        headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    fn status(line: &str) -> u16 {
        line.split(' ').nth(1).unwrap().parse().unwrap()
    }

    #[tokio::test]
    async fn lowercase_get_and_query_are_normalized_when_matching_is_case_insensitive() {
        let addr = spawn_served(app(), false).await;
        let (line, _, body, _) = send(addr, "get", "/g").await;
        assert_eq!(status(&line), 200, "{line}");
        assert_eq!(body, b"hi");
        let (line, _, body, _) = send(addr, "query", "/any").await;
        assert_eq!(status(&line), 200, "{line}");
        assert_eq!(String::from_utf8(body).unwrap(), "QUERY|query");
        let (_, _, body, _) = send(addr, "QUERY", "/any").await;
        assert_eq!(String::from_utf8(body).unwrap(), "QUERY|-", "an already-canonical method records no original");
    }

    #[tokio::test]
    async fn lowercase_get_is_405_when_case_sensitive_methods_is_on_and_the_method_reaches_the_router_untouched() {
        let addr = spawn_served(app(), true).await;
        let (line, _, _, _) = send(addr, "get", "/g").await;
        assert_eq!(status(&line), 405, "{line}");
        let (_, _, body, _) = send(addr, "query", "/any").await;
        assert_eq!(String::from_utf8(body).unwrap(), "query|-");
        assert_eq!(status(&send(addr, "GET", "/g").await.0), 200);
    }

    #[tokio::test]
    async fn lowercase_head_is_never_rewritten_it_gets_405_with_an_allow_header_in_both_modes() {
        for case_sensitive in [false, true] {
            let addr = spawn_served(app(), case_sensitive).await;
            let (line, headers, body, _) = send(addr, "head", "/g").await;
            assert_eq!(status(&line), 405, "{case_sensitive}: {line}");
            let allow = header(&headers, "allow").unwrap_or_default();
            assert!(allow.contains("GET") && allow.contains("HEAD"), "{allow}");
            assert!(body.is_empty());
        }
    }

    #[tokio::test]
    async fn uppercase_head_is_a_normal_200_without_a_body() {
        for case_sensitive in [false, true] {
            let addr = spawn_served(app(), case_sensitive).await;
            let (line, _, body, _) = send(addr, "HEAD", "/g").await;
            assert_eq!(status(&line), 200, "{line}");
            assert!(body.is_empty(), "{body:?}");
        }
    }

    #[tokio::test]
    async fn lowercase_connect_is_passed_through_untouched_and_is_not_a_501() {
        for case_sensitive in [false, true] {
            let addr = spawn_served(app(), case_sensitive).await;
            let (line, headers, _, _) = send(addr, "connect", "/g").await;
            let code = status(&line);
            assert_ne!(code, 501, "{line}");
            if code == 405 {
                assert!(header(&headers, "allow").is_some_and(|a| a.contains("GET")), "{headers:?}");
            }
        }
    }

    #[tokio::test]
    async fn exact_connect_is_501_with_no_allow_header_and_the_connection_is_closed_in_both_modes() {
        for case_sensitive in [false, true] {
            let addr = spawn_served(app(), case_sensitive).await;
            // No `Connection: close` from the client: the server must be the one closing.
            let (line, headers, body, closed) = raw_request(addr, b"CONNECT /g HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
            assert_eq!(status(&line), 501, "{line}");
            assert!(header(&headers, "allow").is_none(), "{headers:?}");
            assert_eq!(header(&headers, "connection"), Some("close"));
            assert!(body.is_empty());
            assert!(closed, "the server must drop the connection after a CONNECT 501");
        }
    }

    #[tokio::test]
    async fn mixed_case_methods_on_an_unknown_path_are_404_including_head() {
        let addr = spawn_served(app(), false).await;
        for method in ["Get", "Head", "get", "query"] {
            let (line, _, _, _) = send(addr, method, "/unknown").await;
            assert_eq!(status(&line), 404, "{method}: {line}");
        }
    }

    // ---- fake inner service -------------------------------------------------

    type Seen = (String, Option<String>, bool);

    #[derive(Clone, Default)]
    struct Probe {
        seen: Arc<Mutex<Vec<Seen>>>,
    }

    #[derive(Clone)]
    struct Marker;

    impl tower_service::Service<Request<Body>> for Probe {
        type Response = Response;
        type Error = Infallible;
        type Future = std::future::Ready<Result<Response, Infallible>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: Request<Body>) -> Self::Future {
            let original = req.extensions().get::<OriginalMethod>().map(|o| o.0.clone());
            self.seen.lock().unwrap().push((req.method().as_str().to_string(), original, req.extensions().get::<Marker>().is_some()));
            std::future::ready(Ok(Response::new(Body::empty())))
        }
    }

    async fn call_through(case_sensitive: bool, method: &str) -> (String, Option<String>, bool) {
        use tower_service::Service;
        let probe = Probe::default();
        let mut service = NormalizeMethod {
            inner: probe.clone(),
            case_sensitive,
        };
        let mut req = Request::builder().method(Method::from_bytes(method.as_bytes()).unwrap()).uri("/x").body(Body::empty()).unwrap();
        req.extensions_mut().insert(Marker);
        service.call(req).await.unwrap();
        let seen = probe.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        seen.into_iter().next().unwrap()
    }

    #[tokio::test]
    async fn original_method_is_recorded_only_when_the_method_was_actually_rewritten() {
        assert_eq!(call_through(false, "get").await, ("GET".to_string(), Some("get".to_string()), true));
        assert_eq!(call_through(false, "GET").await, ("GET".to_string(), None, true));
        assert_eq!(call_through(false, "Query").await, ("QUERY".to_string(), Some("Query".to_string()), true));
        assert_eq!(call_through(true, "get").await, ("get".to_string(), None, true));
    }

    #[tokio::test]
    async fn other_request_extensions_survive_normalization() {
        assert!(call_through(false, "post").await.2, "extension inserted before the normalizer must still be there");
    }

    #[tokio::test]
    async fn a_method_longer_than_64_bytes_is_passed_through_unchanged() {
        let long = "a".repeat(65);
        let (seen, original, _) = call_through(false, &long).await;
        assert_eq!(seen, long);
        assert_eq!(original, None);
        let boundary = "a".repeat(64);
        let (seen, original, _) = call_through(false, &boundary).await;
        assert_eq!(seen, boundary.to_ascii_uppercase());
        assert_eq!(original, Some(boundary));
    }

    #[tokio::test]
    async fn head_and_connect_spellings_other_than_exact_uppercase_pass_through_and_exact_connect_never_reaches_the_inner_service() {
        assert_eq!(call_through(false, "head").await, ("head".to_string(), None, true));
        assert_eq!(call_through(false, "Head").await, ("Head".to_string(), None, true));
        assert_eq!(call_through(false, "connect").await, ("connect".to_string(), None, true));

        use tower_service::Service;
        let probe = Probe::default();
        let mut service = NormalizeMethod {
            inner: probe.clone(),
            case_sensitive: false,
        };
        let req = Request::builder().method(Method::CONNECT).uri("/x").body(Body::empty()).unwrap();
        let response = service.call(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        assert!(probe.seen.lock().unwrap().is_empty());
    }

    // ---- CORS preflight / rate-limit through the real wrapper --------------

    #[tokio::test]
    async fn a_cors_preflight_asking_for_query_on_an_extension_path_succeeds() {
        let router = apply_cors(Router::new().route("/any", any(|| async { "x" })), &["https://app.example".to_string()]);
        let addr = spawn_served(router, false).await;
        let response = reqwest::Client::new()
            .request(Method::OPTIONS, format!("http://{addr}/any"))
            .header("origin", "https://app.example")
            .header("access-control-request-method", "QUERY")
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success(), "{}", response.status());
        assert!(response.headers().get("access-control-allow-origin").is_some());
    }

    #[tokio::test]
    async fn cors_headers_are_present_on_a_normalized_lowercase_get_when_case_insensitive() {
        let router = apply_cors(Router::new().route("/g", get(|| async { "hi" })), &["https://app.example".to_string()]);
        let addr = spawn_served(router, false).await;
        let (line, headers, _, _) = raw_request(
            addr,
            b"get /g HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert_eq!(status(&line), 200, "{line}");
        assert!(header(&headers, "access-control-allow-origin").is_some(), "{headers:?}");
    }

    #[tokio::test]
    async fn get_and_normalized_lowercase_get_share_one_per_route_rate_limit_bucket() {
        let limiter = Arc::new(RateLimiter::new(1, 1));
        let route = apply_rate_limit_to_route(get(|| async { "hi" }), limiter);
        let addr = spawn_served(Router::new().route("/g", route), false).await;
        assert_eq!(status(&send(addr, "GET", "/g").await.0), 200);
        assert_eq!(status(&send(addr, "get", "/g").await.0), 429, "the lowercase spelling must not get a fresh bucket");
    }

    // ---- docs UI static assertions -------------------------------------------

    #[test]
    fn docs_ui_cleans_the_method_class_and_defines_the_query_badge_after_the_default_rule() {
        assert!(DOCS_UI_HTML.matches(r#"op.method.toLowerCase().replace(/[^a-z0-9-]/g, "")"#).count() >= 2);
        assert!(DOCS_UI_HTML.contains("--query:"));
        let default_rule = DOCS_UI_HTML.find(".method-badge {").expect("default badge rule");
        let query_rule = DOCS_UI_HTML.find(".method-query {").expect("query rule");
        assert!(default_rule < query_rule);
        assert!(DOCS_UI_HTML.contains("background: var(--muted)"));
        assert!(DOCS_UI_HTML.contains("escapeHtml(op.method)"));
    }

    #[test]
    fn docs_ui_try_it_guard_disables_unsendable_methods_and_explains_why() {
        assert!(DOCS_UI_HTML.contains(r#"["CONNECT", "TRACE", "TRACK"].indexOf(u) >= 0"#));
        assert!(DOCS_UI_HTML.contains(r#"["DELETE", "GET", "HEAD", "OPTIONS", "POST", "PUT"].indexOf(u) >= 0 && m !== u"#));
        assert!(DOCS_UI_HTML.contains("tryButton.disabled = true"));
        assert!(DOCS_UI_HTML.contains("this method can't be sent exactly from a browser"));
    }

    #[test]
    fn the_docs_ui_operation_json_carries_the_wire_method_for_query() {
        let op = crate::openapi::Operation {
            path: "/things".to_string(),
            method: "query".to_string(),
            http_method: "QUERY".to_string(),
            operation_id: "q".to_string(),
            ..Default::default()
        };
        let json = docs_ui_operation_json(&op, &crate::security::SecurityConfig::default(), &std::collections::HashSet::new());
        assert_eq!(json["method"], "QUERY");
    }
}
