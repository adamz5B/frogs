use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use axum::http::HeaderMap;
use serde_json::Value;

use super::LoadedVerifier;
use super::cache::VerifierCache;
use super::verifier::{Parameter, VerifierDef};
use crate::sql::{SqlDriver, SqlValue, sql_value_to_json};

/// Every way running a verifier can fail, classified for the same
/// two-code split the design doc calls for: an infra problem behind the
/// verifier itself vs. the credential simply being invalid.
#[derive(Debug)]
pub enum VerifyErrorCause {
    /// The verifier's own datasource couldn't be reached or is
    /// misconfigured (unknown connection, missing script/request file, a
    /// DB/HTTP failure) — not the caller's fault. Classifies to
    /// `auth.verifier_unavailable` (500, `exposeDetail: false`).
    Unavailable(String),
    /// The datasource ran fine, but there was nothing to authorize: no
    /// row matched (e.g. an unknown API key), or `validIf` evaluated to
    /// `false` (e.g. an inactive account). Classifies to
    /// `auth.invalid_credentials` (401, `exposeDetail: true`).
    Invalid,
}

impl VerifyErrorCause {
    pub fn code(&self) -> &'static str {
        match self {
            VerifyErrorCause::Unavailable(_) => "auth.verifier_unavailable",
            VerifyErrorCause::Invalid => "auth.invalid_credentials",
        }
    }

    pub fn message(&self) -> String {
        match self {
            VerifyErrorCause::Unavailable(m) => m.clone(),
            VerifyErrorCause::Invalid => "credentials failed verification".to_string(),
        }
    }
}

/// Runs one scheme's verifier against the caller's request headers — the
/// only parameter source a verifier's own examples in the design doc ever
/// use — and checks its result with `validIf`. `Ok(())` means the request
/// is authorized to proceed.
///
/// `scheme_name` plus the exact bound credential value(s) form the cache
/// key, so a hit for one caller's key never leaks into another's, and a
/// verifier with no `cacheTtlSeconds` never touches the cache at all —
/// every request re-runs the check, exactly as the design doc specifies.
#[allow(clippy::too_many_arguments)]
pub async fn verify(
    scheme_name: &str,
    verifier: &LoadedVerifier,
    drivers: &HashMap<String, Box<dyn SqlDriver>>,
    sql_root: &Path,
    http_root: &Path,
    http_client: &reqwest::Client,
    headers: &HeaderMap,
    cache: &VerifierCache,
) -> Result<(), VerifyErrorCause> {
    let bound = bind_headers(verifier.def.parameters(), headers);
    let ttl = verifier.def.cache_ttl_seconds();
    let key = ttl.map(|_| cache_key(scheme_name, &bound));

    if let Some(key) = &key
        && let Some(valid) = cache.get(key)
    {
        return if valid { Ok(()) } else { Err(VerifyErrorCause::Invalid) };
    }

    let resolved = match &verifier.def {
        VerifierDef::Sql { connection, script, .. } => run_sql(drivers, sql_root, connection, script, &bound).await?,
        VerifierDef::Http { request, .. } => run_http(http_root, http_client, request, &bound).await?,
    };

    let valid = verifier.valid_if.evaluate(&resolved);
    // Only a real answer (valid or not) is worth caching — a datasource
    // failure returns early via `?` above and never reaches here, so a
    // transient DB/HTTP outage is always retried on the next request
    // rather than freezing every caller out (or in) until the TTL passes.
    if let (Some(key), Some(ttl)) = (key, ttl) {
        cache.set(key, valid, Duration::from_secs(ttl));
    }

    if valid { Ok(()) } else { Err(VerifyErrorCause::Invalid) }
}

/// Folds the scheme name and every bound parameter's value into one cache
/// key, sorted by parameter name for a stable key regardless of iteration
/// order — so the same credential against the same scheme always hits the
/// same entry, and a different credential (or a different scheme reusing
/// the same parameter names) never collides with it.
fn cache_key(scheme_name: &str, bound: &HashMap<String, SqlValue>) -> String {
    let mut pairs: Vec<(&String, &SqlValue)> = bound.iter().collect();
    pairs.sort_by_key(|(name, _)| name.as_str());

    let mut key = scheme_name.to_string();
    for (name, value) in pairs {
        key.push('\u{1}');
        key.push_str(name);
        key.push('=');
        key.push_str(&sql_value_cache_repr(value));
    }
    key
}

fn sql_value_cache_repr(value: &SqlValue) -> String {
    match value {
        SqlValue::Null => "\u{2}null".to_string(),
        SqlValue::Bool(b) => b.to_string(),
        SqlValue::Int(n) => n.to_string(),
        SqlValue::Float(f) => f.to_string(),
        SqlValue::Text(s) => s.clone(),
        SqlValue::Timestamp(ts) => ts.to_rfc3339(),
    }
}

async fn run_sql(
    drivers: &HashMap<String, Box<dyn SqlDriver>>,
    sql_root: &Path,
    connection: &str,
    script: &str,
    bound: &HashMap<String, SqlValue>,
) -> Result<Value, VerifyErrorCause> {
    let driver = drivers
        .get(connection)
        .ok_or_else(|| VerifyErrorCause::Unavailable(format!("no connection named '{connection}'")))?;

    let script_path = sql_root.join(connection).join(script);
    let script_contents = std::fs::read_to_string(&script_path).map_err(|e| VerifyErrorCause::Unavailable(format!("failed to read {}: {e}", script_path.display())))?;

    let rows = driver
        .query(&script_contents, bound)
        .await
        .map_err(|e| VerifyErrorCause::Unavailable(e.to_string()))?;

    // Zero rows (e.g. an API key that simply isn't in the table) is the
    // credential's own fault, not the datasource's — `Invalid`, not
    // `Unavailable`, the same distinction `endpoint::resolve` draws between
    // `NotFound` and a real connection/query failure.
    let row = rows.into_iter().next().ok_or(VerifyErrorCause::Invalid)?;
    Ok(Value::Object(row.iter().map(|(k, v)| (k.clone(), sql_value_to_json(v))).collect()))
}

async fn run_http(http_root: &Path, client: &reqwest::Client, request: &str, bound: &HashMap<String, SqlValue>) -> Result<Value, VerifyErrorCause> {
    let request_path = http_root.join(request);
    let contents = std::fs::read_to_string(&request_path).map_err(|e| VerifyErrorCause::Unavailable(format!("failed to read {}: {e}", request_path.display())))?;
    let request_file: crate::http::HttpRequestFile =
        serde_json::from_str(&contents).map_err(|e| VerifyErrorCause::Unavailable(format!("invalid JSON in {}: {e}", request_path.display())))?;

    // Every failure here is a genuine infra problem, not a rejected
    // credential: a token-introspection endpoint (the design doc's own
    // example) reports an invalid/expired token via a normal 200 response
    // body (`{"active": false}`, per RFC 7662), which `validIf` catches
    // afterwards — it never signals "invalid" via an HTTP-level failure.
    // A verifier's own parameters are always `header.*` scalars, never
    // array-typed (see the design doc's own examples), so no array names
    // are ever passed through here.
    crate::http::execute(client, &request_file, bound, &std::collections::HashSet::new())
        .await
        .map_err(|e| VerifyErrorCause::Unavailable(e.to_string()))
}

/// Binds each verifier parameter from the caller's request headers — the
/// only `from` prefix a verifier needs, per the design doc's own examples
/// (`header.X-Api-Key`, `header.Authorization`). `HeaderMap::get` is
/// case-insensitive already, matching HTTP's own header-name semantics. An
/// absent header becomes `SqlValue::Null`, same "say so via a failed
/// check, don't crash" posture `endpoint::resolve`'s `resolve_from` uses.
fn bind_headers(parameters: &[Parameter], headers: &HeaderMap) -> HashMap<String, SqlValue> {
    parameters
        .iter()
        .map(|param| {
            let value = param
                .from
                .strip_prefix("header.")
                .and_then(|name| headers.get(name))
                .and_then(|v| v.to_str().ok())
                .map(|v| SqlValue::Text(v.to_string()))
                .unwrap_or(SqlValue::Null);
            (param.name.clone(), value)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::ValidIf;
    use crate::sql::SqlError;
    use std::path::PathBuf;

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

    fn temp_project_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "frogs-verify-test-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(root.join("sql/db")).unwrap();
        std::fs::create_dir_all(root.join("http")).unwrap();
        std::fs::write(root.join("sql/db/verify.sql"), "SELECT active FROM api_keys WHERE key = :key;").unwrap();
        root
    }

    fn sql_verifier() -> LoadedVerifier {
        let def: VerifierDef = serde_json::from_str(
            r#"{
                "type": "sql",
                "connection": "db",
                "script": "verify.sql",
                "parameters": [{ "name": "key", "from": "header.X-Api-Key" }],
                "validIf": "row.active = true"
            }"#,
        )
        .unwrap();
        LoadedVerifier {
            valid_if: ValidIf::parse(def.valid_if()).unwrap(),
            def,
        }
    }

    fn headers_with(name: &str, value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            axum::http::HeaderValue::from_str(value).unwrap(),
        );
        headers
    }

    fn row(pairs: &[(&str, SqlValue)]) -> HashMap<String, SqlValue> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
    }

    #[tokio::test]
    async fn a_valid_active_key_is_authorized() {
        let root = temp_project_root("valid");
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert(
            "db".to_string(),
            Box::new(FakeDriver {
                rows: vec![row(&[("active", SqlValue::Bool(true))])],
                fail: false,
            }),
        );

        let headers = headers_with("X-Api-Key", "good-key");
        let client = reqwest::Client::new();
        let result = verify(
            "apiKeyAuth",
            &sql_verifier(),
            &drivers,
            &root.join("sql"),
            &root.join("http"),
            &client,
            &headers,
            &VerifierCache::new(),
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn an_inactive_keys_row_is_found_but_invalid() {
        let root = temp_project_root("inactive");
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert(
            "db".to_string(),
            Box::new(FakeDriver {
                rows: vec![row(&[("active", SqlValue::Bool(false))])],
                fail: false,
            }),
        );

        let headers = headers_with("X-Api-Key", "inactive-key");
        let client = reqwest::Client::new();
        let err = verify(
            "apiKeyAuth",
            &sql_verifier(),
            &drivers,
            &root.join("sql"),
            &root.join("http"),
            &client,
            &headers,
            &VerifierCache::new(),
        )
        .await
        .expect_err("an inactive key must fail validIf");

        assert_eq!(err.code(), "auth.invalid_credentials");
    }

    #[tokio::test]
    async fn an_unknown_key_matches_no_row_and_is_invalid_not_unavailable() {
        let root = temp_project_root("unknown");
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(FakeDriver { rows: vec![], fail: false }));

        let headers = headers_with("X-Api-Key", "no-such-key");
        let client = reqwest::Client::new();
        let err = verify(
            "apiKeyAuth",
            &sql_verifier(),
            &drivers,
            &root.join("sql"),
            &root.join("http"),
            &client,
            &headers,
            &VerifierCache::new(),
        )
        .await
        .expect_err("zero rows must be treated as invalid credentials");

        assert_eq!(err.code(), "auth.invalid_credentials");
    }

    #[tokio::test]
    async fn a_missing_header_is_invalid_not_unavailable() {
        let root = temp_project_root("missing-header");
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(FakeDriver { rows: vec![], fail: false }));

        // No X-Api-Key header sent at all — the unauthenticated-request case.
        let headers = HeaderMap::new();
        let client = reqwest::Client::new();
        let err = verify(
            "apiKeyAuth",
            &sql_verifier(),
            &drivers,
            &root.join("sql"),
            &root.join("http"),
            &client,
            &headers,
            &VerifierCache::new(),
        )
        .await
        .expect_err("a request with no credential at all must be rejected");

        assert_eq!(err.code(), "auth.invalid_credentials");
    }

    #[tokio::test]
    async fn a_failing_datasource_is_unavailable_not_invalid() {
        let root = temp_project_root("db-down");
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(FakeDriver { rows: vec![], fail: true }));

        let headers = headers_with("X-Api-Key", "good-key");
        let client = reqwest::Client::new();
        let err = verify(
            "apiKeyAuth",
            &sql_verifier(),
            &drivers,
            &root.join("sql"),
            &root.join("http"),
            &client,
            &headers,
            &VerifierCache::new(),
        )
        .await
        .expect_err("a broken datasource must not be conflated with an invalid credential");

        assert_eq!(err.code(), "auth.verifier_unavailable");
    }

    #[tokio::test]
    async fn an_unknown_connection_name_is_unavailable() {
        let root = temp_project_root("unknown-connection");
        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();

        let headers = headers_with("X-Api-Key", "good-key");
        let client = reqwest::Client::new();
        let err = verify(
            "apiKeyAuth",
            &sql_verifier(),
            &drivers,
            &root.join("sql"),
            &root.join("http"),
            &client,
            &headers,
            &VerifierCache::new(),
        )
        .await
        .expect_err("a connection that isn't configured must fail as unavailable");

        assert_eq!(err.code(), "auth.verifier_unavailable");
    }

    /// A real HTTP token-introspection verifier, run against a real local
    /// server — mirrors `endpoint::resolve`'s own "spin up a real server,
    /// not a mock transport" testing convention.
    #[tokio::test]
    async fn a_real_http_verifier_authorizes_an_active_token() {
        use axum::extract::Query;
        use axum::routing::get;
        use axum::{Json, Router};

        async fn introspect(Query(params): Query<HashMap<String, String>>) -> Json<Value> {
            let active = params.get("token").map(|t| t == "good-token").unwrap_or(false);
            Json(serde_json::json!({ "active": active }))
        }

        let app = Router::new().route("/introspect", get(introspect));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let root = temp_project_root("http-verifier");
        std::fs::write(
            root.join("http/introspect.json"),
            format!(r#"{{ "method": "GET", "url": "http://{addr}/introspect?token={{{{token}}}}" }}"#),
        )
        .unwrap();

        let def: VerifierDef = serde_json::from_str(
            r#"{
                "type": "http",
                "request": "introspect.json",
                "parameters": [{ "name": "token", "from": "header.Authorization" }],
                "validIf": "response.active = true"
            }"#,
        )
        .unwrap();
        let verifier = LoadedVerifier {
            valid_if: ValidIf::parse(def.valid_if()).unwrap(),
            def,
        };

        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        let client = reqwest::Client::new();
        let cache = VerifierCache::new();

        let ok_headers = headers_with("Authorization", "good-token");
        assert!(
            verify("bearerAuth", &verifier, &drivers, &root.join("sql"), &root.join("http"), &client, &ok_headers, &cache,)
                .await
                .is_ok()
        );

        let bad_headers = headers_with("Authorization", "bad-token");
        let err = verify(
            "bearerAuth",
            &verifier,
            &drivers,
            &root.join("sql"),
            &root.join("http"),
            &client,
            &bad_headers,
            &cache,
        )
        .await
        .expect_err("an inactive token must be rejected");
        assert_eq!(err.code(), "auth.invalid_credentials");
    }

    #[tokio::test]
    async fn a_cached_result_is_reused_without_rerunning_the_datasource() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Debug)]
        struct CountingDriver {
            calls: Arc<AtomicUsize>,
        }

        #[async_trait::async_trait]
        impl SqlDriver for CountingDriver {
            async fn query(&self, _script: &str, _params: &HashMap<String, SqlValue>) -> Result<Vec<HashMap<String, SqlValue>>, SqlError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok(vec![row(&[("active", SqlValue::Bool(true))])])
            }
        }

        let root = temp_project_root("cached");
        let calls = Arc::new(AtomicUsize::new(0));
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(CountingDriver { calls: calls.clone() }));

        let def: VerifierDef = serde_json::from_str(
            r#"{
                "type": "sql",
                "connection": "db",
                "script": "verify.sql",
                "parameters": [{ "name": "key", "from": "header.X-Api-Key" }],
                "validIf": "row.active = true",
                "cacheTtlSeconds": 30
            }"#,
        )
        .unwrap();
        let verifier = LoadedVerifier {
            valid_if: ValidIf::parse(def.valid_if()).unwrap(),
            def,
        };

        let headers = headers_with("X-Api-Key", "good-key");
        let client = reqwest::Client::new();
        let cache = VerifierCache::new();

        for _ in 0..3 {
            let result = verify("apiKeyAuth", &verifier, &drivers, &root.join("sql"), &root.join("http"), &client, &headers, &cache).await;
            assert!(result.is_ok());
        }

        assert_eq!(calls.load(Ordering::SeqCst), 1, "the datasource must only run once; the rest should hit the cache");
    }

    #[tokio::test]
    async fn a_different_credential_never_hits_another_callers_cache_entry() {
        // Unlike `FakeDriver` (which returns the same rows regardless of
        // the bound parameters), this driver actually checks the key —
        // needed here since the whole point of the test is that a
        // *different* credential must resolve independently, not reuse the
        // first credential's cached outcome.
        #[derive(Debug)]
        struct KeyAwareDriver;

        #[async_trait::async_trait]
        impl SqlDriver for KeyAwareDriver {
            async fn query(&self, _script: &str, params: &HashMap<String, SqlValue>) -> Result<Vec<HashMap<String, SqlValue>>, SqlError> {
                match params.get("key") {
                    Some(SqlValue::Text(k)) if k == "good-key" => Ok(vec![row(&[("active", SqlValue::Bool(true))])]),
                    _ => Ok(vec![]),
                }
            }
        }

        let root = temp_project_root("cache-isolation");
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(KeyAwareDriver));

        let def: VerifierDef = serde_json::from_str(
            r#"{
                "type": "sql",
                "connection": "db",
                "script": "verify.sql",
                "parameters": [{ "name": "key", "from": "header.X-Api-Key" }],
                "validIf": "row.active = true",
                "cacheTtlSeconds": 30
            }"#,
        )
        .unwrap();
        let verifier = LoadedVerifier {
            valid_if: ValidIf::parse(def.valid_if()).unwrap(),
            def,
        };
        let client = reqwest::Client::new();
        let cache = VerifierCache::new();

        // Prime the cache for "good-key".
        let good_headers = headers_with("X-Api-Key", "good-key");
        verify(
            "apiKeyAuth",
            &verifier,
            &drivers,
            &root.join("sql"),
            &root.join("http"),
            &client,
            &good_headers,
            &cache,
        )
        .await
        .expect("the first, real check for a good key should succeed");

        // A request with no key at all must still be rejected, not
        // accidentally reuse the cached "good-key" entry.
        let no_headers = HeaderMap::new();
        let err = verify("apiKeyAuth", &verifier, &drivers, &root.join("sql"), &root.join("http"), &client, &no_headers, &cache)
            .await
            .expect_err("a missing credential must never hit another caller's cache entry");
        assert_eq!(err.code(), "auth.invalid_credentials");
    }

    /// The end-to-end exploit path this closes: `run_http` templates the
    /// caller's credential value into the verifier's request URL, so a
    /// crafted `Authorization` header must NOT be able to inject an extra
    /// query parameter that changes what the provider authorizes. Here a
    /// fake introspection provider authorizes based on an `admin` query
    /// flag it was never meant to let a caller set — simulating any real
    /// provider whose introspection endpoint happens to accept more than
    /// one query parameter.
    ///
    /// Fixed by `http::execute`'s URL templating now percent-encoding every
    /// substituted value (see `http::tests::
    /// a_parameter_value_with_url_metacharacters_is_percent_encoded`) — the
    /// crafted header's `&admin=true` now arrives as part of one opaque,
    /// percent-encoded `token` value instead of a second query parameter.
    #[tokio::test]
    async fn a_crafted_header_value_must_not_be_able_to_inject_a_query_parameter() {
        use axum::extract::{Query, RawQuery, State};
        use axum::routing::get;
        use axum::{Json, Router};
        use std::sync::{Arc, Mutex};

        // Records the exact, real query string the fake provider received —
        // this is the proof that the outbound request is a well-formed HTTP
        // request (not a malformed call failing for some unrelated reason)
        // that just happens to carry a second, injected query parameter.
        async fn introspect(
            State(received_query): State<Arc<Mutex<Option<String>>>>,
            RawQuery(raw_query): RawQuery,
            Query(params): Query<HashMap<String, String>>,
        ) -> Json<Value> {
            *received_query.lock().unwrap() = raw_query;
            let active = params.get("admin").map(|a| a == "true").unwrap_or(false);
            Json(serde_json::json!({ "active": active }))
        }

        let received_query: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let app = Router::new().route("/introspect", get(introspect)).with_state(received_query.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let root = temp_project_root("url-injection");
        std::fs::write(
            root.join("http/introspect.json"),
            format!(r#"{{ "method": "GET", "url": "http://{addr}/introspect?token={{{{token}}}}" }}"#),
        )
        .unwrap();

        let def: VerifierDef = serde_json::from_str(
            r#"{
                "type": "http",
                "request": "introspect.json",
                "parameters": [{ "name": "token", "from": "header.Authorization" }],
                "validIf": "response.active = true"
            }"#,
        )
        .unwrap();
        let verifier = LoadedVerifier {
            valid_if: ValidIf::parse(def.valid_if()).unwrap(),
            def,
        };

        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        let client = reqwest::Client::new();
        let cache = VerifierCache::new();

        // Not a real token at all — crafted only to append a second query
        // parameter the fake provider happens to trust.
        let malicious_headers = headers_with("Authorization", "not-a-real-token&admin=true");
        let result = verify(
            "bearerAuth",
            &verifier,
            &drivers,
            &root.join("sql"),
            &root.join("http"),
            &client,
            &malicious_headers,
            &cache,
        )
        .await;

        // First, the proof the request still arrived well-formed (not
        // failing for some unrelated reason) and safe: the fake provider
        // received exactly one query parameter — the caller's whole
        // credential value, percent-encoded as one opaque blob — never a
        // second, injected `admin` parameter.
        let raw_query = received_query.lock().unwrap().clone();
        assert_eq!(
            raw_query.as_deref(),
            Some("token=not-a-real-token%26admin%3Dtrue"),
            "expected the verifier's outbound request to carry exactly one, percent-encoded token parameter — \
             instead the provider received: {raw_query:?}"
        );

        // Second, the consequence: with no separate `admin` parameter ever
        // reaching the provider, it has nothing to authorize on, so the
        // crafted header value can't forge authorization.
        assert!(
            result.is_err(),
            "a crafted header value must not be able to forge authorization by injecting a query parameter into \
             the verifier's outbound request"
        );
    }

    #[tokio::test]
    async fn a_non_utf8_header_value_is_treated_as_a_missing_credential_not_a_crash() {
        let root = temp_project_root("non-utf8-header");
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(FakeDriver { rows: vec![], fail: false }));

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::HeaderName::from_bytes(b"X-Api-Key").unwrap(),
            // `HeaderValue::from_bytes` accepts arbitrary opaque bytes (it
            // only rejects NUL/CR/LF) — this is how a header value that
            // fails `.to_str()` actually reaches `bind_headers`.
            axum::http::HeaderValue::from_bytes(&[0xFF, 0xFE, 0xFD]).unwrap(),
        );

        let client = reqwest::Client::new();
        let err = verify(
            "apiKeyAuth",
            &sql_verifier(),
            &drivers,
            &root.join("sql"),
            &root.join("http"),
            &client,
            &headers,
            &VerifierCache::new(),
        )
        .await
        .expect_err("a non-UTF8 header value must be rejected as a missing credential, not panic");

        assert_eq!(err.code(), "auth.invalid_credentials");
    }

    #[tokio::test]
    async fn a_zero_second_ttl_still_goes_through_the_cache_path_but_never_effectively_caches() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Debug)]
        struct CountingDriver {
            calls: Arc<AtomicUsize>,
        }

        #[async_trait::async_trait]
        impl SqlDriver for CountingDriver {
            async fn query(&self, _script: &str, _params: &HashMap<String, SqlValue>) -> Result<Vec<HashMap<String, SqlValue>>, SqlError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok(vec![row(&[("active", SqlValue::Bool(true))])])
            }
        }

        let root = temp_project_root("zero-ttl");
        let calls = Arc::new(AtomicUsize::new(0));
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(CountingDriver { calls: calls.clone() }));

        let def: VerifierDef = serde_json::from_str(
            r#"{
                "type": "sql",
                "connection": "db",
                "script": "verify.sql",
                "parameters": [{ "name": "key", "from": "header.X-Api-Key" }],
                "validIf": "row.active = true",
                "cacheTtlSeconds": 0
            }"#,
        )
        .unwrap();
        let verifier = LoadedVerifier {
            valid_if: ValidIf::parse(def.valid_if()).unwrap(),
            def,
        };

        let headers = headers_with("X-Api-Key", "good-key");
        let client = reqwest::Client::new();
        let cache = VerifierCache::new();

        for _ in 0..3 {
            // A tiny sleep so the previous iteration's zero-TTL entry has
            // definitely expired by the time this iteration's `cache.get`
            // runs — same technique `VerifierCache`'s own expiry test uses.
            std::thread::sleep(std::time::Duration::from_millis(5));
            let result = verify("apiKeyAuth", &verifier, &drivers, &root.join("sql"), &root.join("http"), &client, &headers, &cache).await;
            assert!(result.is_ok());
        }

        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "a 0-second TTL must not effectively cache anything across calls, unlike a real TTL"
        );
    }
}
