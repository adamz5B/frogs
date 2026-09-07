pub mod pidfile;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Request, State};
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
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
        *self.status_counts.lock().unwrap().entry(status).or_insert(0) += 1;

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
        let mut statuses: Vec<(u16, u64)> = self.status_counts.lock().unwrap().iter().map(|(&s, &c)| (s, c)).collect();
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
        let mut state = self.state.lock().unwrap();

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
    let span = tracing::info_span!("request", request_id = %id, %method, %path);

    let mut response = async move {
        let response = next.run(req).await;
        tracing::info!(status = %response.status(), "request completed");
        response
    }
    .instrument(span)
    .await;

    if let Ok(value) = HeaderValue::from_str(&id) {
        response.headers_mut().insert(HeaderName::from_static(CORRELATION_HEADER), value);
    }
    response
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
}
