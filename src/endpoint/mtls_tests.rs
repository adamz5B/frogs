use super::*;
use crate::server::test_pki::*;
use crate::sql::{SqlError, SqlValue};
use std::sync::atomic::{AtomicUsize, Ordering};

const MTLS_ORDERS: &str = r#"{ "type": "mtls", "validIf": "cert.san.dns = orders.internal.example.com" }"#;
const SQL_FINGERPRINT: &str = r#"{
    "type": "sql", "connection": "db", "script": "verify.sql",
    "parameters": [{ "name": "fp", "from": "cert.fingerprint" }],
    "validIf": "row.active = true"
}"#;
const SQL_API_KEY: &str = r#"{
    "type": "sql", "connection": "db", "script": "verify.sql",
    "parameters": [{ "name": "key", "from": "header.X-Api-Key" }],
    "validIf": "row.active = true"
}"#;
const SECURED_ENDPOINT: &str = r#"{ "operationId": "getSecret", "security": "certAuth", "sources": {}, "response": {} }"#;

fn security_with(verifier_json: &str) -> SecurityConfig {
    let dir = temp_dir("endpoint-sec");
    std::fs::create_dir_all(dir.join("verifiers")).unwrap();
    std::fs::write(dir.join("schemes.json"), r#"{ "certAuth": { "verifier": "cert.json" } }"#).unwrap();
    std::fs::write(dir.join("verifiers/cert.json"), verifier_json).unwrap();
    SecurityConfig::load(&dir).unwrap()
}

fn registry() -> ErrorRegistry {
    let dir = temp_dir("endpoint-errors");
    std::fs::write(
        dir.join("core.json"),
        r#"{
            "auth.invalid_credentials": { "httpStatus": 401, "exposeDetail": true },
            "auth.verifier_unavailable": { "httpStatus": 500, "exposeDetail": false },
            "auth.client_cert_missing": { "httpStatus": 401, "exposeDetail": true },
            "auth.client_cert_expired": { "httpStatus": 401, "exposeDetail": true }
        }"#,
    )
    .unwrap();
    ErrorRegistry::load(&dir).unwrap()
}

#[derive(Debug, Clone, Default)]
struct CountingDriver(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl SqlDriver for CountingDriver {
    async fn query(&self, _script: &str, _params: &HashMap<String, SqlValue>) -> Result<Vec<HashMap<String, SqlValue>>, SqlError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(vec![HashMap::from([("active".to_string(), SqlValue::Bool(true))])])
    }
}

fn identity(spec: &LeafSpec) -> ClientCertIdentity {
    let ca = Ca::root("endpoint test ca");
    ClientCertIdentity::from_der(&build_leaf(&ca, spec).der()).unwrap()
}

async fn resolve(
    endpoint_json: &str,
    security: &SecurityConfig,
    drivers: &HashMap<String, Box<dyn SqlDriver>>,
    mocks: &HashMap<String, MockOutcome>,
    headers: &HeaderMap,
    cert: Option<&ClientCertIdentity>,
) -> (u16, Value) {
    let root = temp_dir("endpoint-resolve");
    std::fs::create_dir_all(root.join("db")).unwrap();
    std::fs::write(root.join("db/verify.sql"), "SELECT 1").unwrap();
    let endpoint: EndpointFile = serde_json::from_str(endpoint_json).unwrap();
    resolve_request(
        &endpoint,
        security,
        &HashMap::new(),
        drivers,
        &root,
        &root,
        &reqwest::Client::new(),
        &registry(),
        &Mutex::new(DiscoveredErrors::default()),
        &root.join("errors.discovered.json"),
        false,
        &VerifierCache::new(),
        headers,
        cert,
        &HashMap::new(),
        &HashMap::new(),
        &Value::Null,
        "",
        mocks,
        None,
        &Map::new(),
        NonZeroU64::new(5_000).unwrap(),
    )
    .await
}

fn no_drivers() -> HashMap<String, Box<dyn SqlDriver>> {
    HashMap::new()
}

fn counting_drivers() -> (HashMap<String, Box<dyn SqlDriver>>, Arc<AtomicUsize>) {
    let driver = CountingDriver::default();
    let calls = driver.0.clone();
    let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
    drivers.insert("db".to_string(), Box::new(driver));
    (drivers, calls)
}

fn name_of(body: &Value) -> &str {
    body["name"].as_str().unwrap_or_default()
}

// ---------------------------------------------------------------------
// resolve_request: missing / expired / mismatched
// ---------------------------------------------------------------------

#[tokio::test]
async fn a_cert_scheme_with_no_identity_is_client_cert_missing() {
    let (status, body) = resolve(SECURED_ENDPOINT, &security_with(MTLS_ORDERS), &no_drivers(), &HashMap::new(), &HeaderMap::new(), None).await;
    assert_eq!((status, name_of(&body)), (401, "auth.client_cert_missing"), "{body}");
}

#[tokio::test]
async fn a_matching_identity_is_served() {
    let id = identity(&LeafSpec::valid());
    let (status, body) = resolve(
        SECURED_ENDPOINT,
        &security_with(MTLS_ORDERS),
        &no_drivers(),
        &HashMap::new(),
        &HeaderMap::new(),
        Some(&id),
    )
    .await;
    assert_eq!(status, 200, "{body}");
}

#[tokio::test]
async fn a_non_matching_identity_is_invalid_credentials() {
    let id = identity(&LeafSpec {
        dns: vec!["other.example".into()],
        ..LeafSpec::valid()
    });
    let (status, body) = resolve(
        SECURED_ENDPOINT,
        &security_with(MTLS_ORDERS),
        &no_drivers(),
        &HashMap::new(),
        &HeaderMap::new(),
        Some(&id),
    )
    .await;
    assert_eq!((status, name_of(&body)), (401, "auth.invalid_credentials"), "{body}");
}

#[tokio::test]
async fn an_expired_identity_is_rejected_before_the_verifier_runs_and_never_calls_the_datasource() {
    let (drivers, calls) = counting_drivers();
    for spec in [LeafSpec::expired(), LeafSpec::not_yet_valid()] {
        let id = identity(&spec);
        let (status, body) = resolve(
            SECURED_ENDPOINT,
            &security_with(SQL_FINGERPRINT),
            &drivers,
            &HashMap::new(),
            &HeaderMap::new(),
            Some(&id),
        )
        .await;
        assert_eq!((status, name_of(&body)), (401, "auth.client_cert_expired"), "{body}");
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "the datasource must never be consulted for an out-of-validity certificate"
    );
}

#[tokio::test]
async fn expiry_and_absence_are_checked_before_a_mocked_verifier_is_consulted() {
    let mocks = HashMap::from([("verifier".to_string(), MockOutcome::Success(serde_json::json!({ "active": true })))]);
    let security = security_with(SQL_FINGERPRINT);

    let expired = identity(&LeafSpec::expired());
    let (status, body) = resolve(SECURED_ENDPOINT, &security, &no_drivers(), &mocks, &HeaderMap::new(), Some(&expired)).await;
    assert_eq!((status, name_of(&body)), (401, "auth.client_cert_expired"), "{body}");

    let (status, body) = resolve(SECURED_ENDPOINT, &security, &no_drivers(), &mocks, &HeaderMap::new(), None).await;
    assert_eq!((status, name_of(&body)), (401, "auth.client_cert_missing"), "{body}");

    let valid = identity(&LeafSpec::valid());
    let (status, body) = resolve(SECURED_ENDPOINT, &security, &no_drivers(), &mocks, &HeaderMap::new(), Some(&valid)).await;
    assert_eq!(status, 200, "{body}");
}

#[tokio::test]
async fn an_sql_cert_verifier_runs_its_datasource_for_a_valid_identity() {
    let (drivers, calls) = counting_drivers();
    let id = identity(&LeafSpec::valid());
    let (status, body) = resolve(
        SECURED_ENDPOINT,
        &security_with(SQL_FINGERPRINT),
        &drivers,
        &HashMap::new(),
        &HeaderMap::new(),
        Some(&id),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_header_only_scheme_is_unaffected_by_the_absence_of_a_certificate() {
    let (drivers, calls) = counting_drivers();
    let mut headers = HeaderMap::new();
    headers.insert("x-api-key", "k".parse().unwrap());
    let (status, body) = resolve(SECURED_ENDPOINT, &security_with(SQL_API_KEY), &drivers, &HashMap::new(), &headers, None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // ...and an expired certificate on the connection is irrelevant to it.
    let expired = identity(&LeafSpec::expired());
    let (status, _) = resolve(SECURED_ENDPOINT, &security_with(SQL_API_KEY), &drivers, &HashMap::new(), &headers, Some(&expired)).await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn spoofed_certificate_headers_never_create_an_identity() {
    let mut headers = HeaderMap::new();
    for name in ["x-forwarded-client-cert", "x-ssl-client-fingerprint", "x-ssl-client-cn", "cert.san.dns", "cert.cn"] {
        headers.insert(
            axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            "orders.internal.example.com".parse().unwrap(),
        );
    }
    for verifier in [MTLS_ORDERS, SQL_FINGERPRINT] {
        let (status, body) = resolve(SECURED_ENDPOINT, &security_with(verifier), &no_drivers(), &HashMap::new(), &headers, None).await;
        assert_eq!((status, name_of(&body)), (401, "auth.client_cert_missing"), "{verifier}: {body}");
    }
}

// ---------------------------------------------------------------------
// mocked verifier values for an mtls scheme (frogs test)
// ---------------------------------------------------------------------

async fn mocked_mtls(value: Value) -> (u16, Value) {
    let mocks = HashMap::from([("verifier".to_string(), MockOutcome::Success(value))]);
    let id = identity(&LeafSpec::valid());
    resolve(SECURED_ENDPOINT, &security_with(MTLS_ORDERS), &no_drivers(), &mocks, &HeaderMap::new(), Some(&id)).await
}

#[tokio::test]
async fn a_mocked_mtls_verifier_value_is_evaluated_with_any_of_semantics() {
    let (status, body) = mocked_mtls(serde_json::json!({ "san": { "dns": ["x.example", "orders.internal.example.com", "z.example"] } })).await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = mocked_mtls(serde_json::json!({ "san": { "dns": "orders.internal.example.com" } })).await;
    assert_eq!(status, 200, "a scalar is a one-element list: {body}");
    let (status, body) = mocked_mtls(serde_json::json!({ "san": { "dns": ["x.example", "y.example"] } })).await;
    assert_eq!((status, name_of(&body)), (401, "auth.invalid_credentials"), "{body}");
}

#[tokio::test]
async fn a_mocked_mtls_verifier_value_of_the_wrong_shape_is_invalid_credentials() {
    for bad in [
        serde_json::json!("orders.internal.example.com"),
        serde_json::json!({ "san": "oops" }),
        serde_json::json!({ "san": { "dns": 7 } }),
        serde_json::json!(true),
        Value::Null,
    ] {
        let (status, body) = mocked_mtls(bad.clone()).await;
        assert_eq!((status, name_of(&body)), (401, "auth.invalid_credentials"), "{bad}: {body}");
    }
}

#[tokio::test]
async fn a_mocked_verifier_failure_surfaces_its_code_for_a_cert_scheme() {
    let mocks = HashMap::from([("verifier".to_string(), MockOutcome::Fail("auth.verifier_unavailable".to_string()))]);
    let id = identity(&LeafSpec::valid());
    let (status, body) = resolve(SECURED_ENDPOINT, &security_with(MTLS_ORDERS), &no_drivers(), &mocks, &HeaderMap::new(), Some(&id)).await;
    assert_eq!((status, name_of(&body)), (500, "auth.verifier_unavailable"), "{body}");
}

#[tokio::test]
async fn a_generic_mocked_verifier_value_for_a_non_mtls_scheme_still_uses_valid_if() {
    let mocks = HashMap::from([("verifier".to_string(), MockOutcome::Success(serde_json::json!({ "active": true })))]);
    let id = identity(&LeafSpec::valid());
    let (status, body) = resolve(SECURED_ENDPOINT, &security_with(SQL_FINGERPRINT), &no_drivers(), &mocks, &HeaderMap::new(), Some(&id)).await;
    assert_eq!(status, 200, "{body}");
    let mocks = HashMap::from([("verifier".to_string(), MockOutcome::Success(serde_json::json!({ "active": false })))]);
    let (status, body) = resolve(SECURED_ENDPOINT, &security_with(SQL_FINGERPRINT), &no_drivers(), &mocks, &HeaderMap::new(), Some(&id)).await;
    assert_eq!((status, name_of(&body)), (401, "auth.invalid_credentials"), "{body}");
}

// ---------------------------------------------------------------------
// enforce_no_real_infrastructure
// ---------------------------------------------------------------------

fn endpoint(json: &str) -> EndpointFile {
    serde_json::from_str(json).unwrap()
}

#[test]
fn a_datasource_backed_verifier_is_still_filled_with_source_not_mocked() {
    let mut mocks = HashMap::new();
    let filled = mock::enforce_no_real_infrastructure(&endpoint(SECURED_ENDPOINT), false, &mut mocks);
    assert_eq!(mocks.get("verifier"), Some(&MockOutcome::Fail(mock::SOURCE_NOT_MOCKED.to_string())));
    assert_eq!(
        filled,
        vec![mock::Unmocked {
            name: "verifier".into(),
            optional: false
        }]
    );
}

#[test]
fn a_datasource_free_verifier_is_not_auto_filled() {
    let mut mocks = HashMap::new();
    let filled = mock::enforce_no_real_infrastructure(&endpoint(SECURED_ENDPOINT), true, &mut mocks);
    assert!(!mocks.contains_key("verifier"));
    assert!(filled.is_empty());
}

#[test]
fn an_explicit_verifier_mock_always_wins_over_the_flag() {
    for flag in [false, true] {
        let mut mocks = HashMap::from([("verifier".to_string(), MockOutcome::Success(serde_json::json!({ "x": 1 })))]);
        let filled = mock::enforce_no_real_infrastructure(&endpoint(SECURED_ENDPOINT), flag, &mut mocks);
        assert_eq!(mocks["verifier"], MockOutcome::Success(serde_json::json!({ "x": 1 })), "flag={flag}");
        assert!(filled.is_empty());
    }
}

#[test]
fn the_datasource_free_flag_does_not_stop_undeclared_sources_being_filled() {
    let ep = endpoint(r#"{ "operationId": "x", "security": "certAuth", "sources": { "car": { "type": "http", "request": "r.json" } }, "response": {} }"#);
    let mut mocks = HashMap::new();
    let filled = mock::enforce_no_real_infrastructure(&ep, true, &mut mocks);
    assert_eq!(mocks.get("car"), Some(&MockOutcome::Fail(mock::SOURCE_NOT_MOCKED.to_string())));
    assert!(!mocks.contains_key("verifier"));
    assert_eq!(filled.len(), 1);
}

#[test]
fn an_endpoint_without_security_is_unaffected_by_the_flag() {
    for flag in [false, true] {
        let mut mocks = HashMap::new();
        assert!(mock::enforce_no_real_infrastructure(&endpoint(r#"{ "operationId": "x", "sources": {}, "response": {} }"#), flag, &mut mocks).is_empty());
        assert!(mocks.is_empty());
    }
}

#[tokio::test]
async fn a_cert_fingerprint_sql_verifier_with_no_mock_is_source_not_mocked_without_dialing_the_driver() {
    let (drivers, calls) = counting_drivers();
    let security = security_with(SQL_FINGERPRINT);
    let ep = endpoint(SECURED_ENDPOINT);
    let mut mocks = HashMap::new();
    mock::enforce_no_real_infrastructure(&ep, false, &mut mocks);
    let id = identity(&LeafSpec::valid());
    let (_status, body) = resolve(SECURED_ENDPOINT, &security, &drivers, &mocks, &HeaderMap::new(), Some(&id)).await;
    assert_eq!(name_of(&body), mock::SOURCE_NOT_MOCKED, "{body}");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

// ---------------------------------------------------------------------
// build_router: route refusal / registration
// ---------------------------------------------------------------------

async fn serve_router(security: SecurityConfig, endpoint_json: &str, client_identity_available: bool) -> (String, PathBuf) {
    let root = temp_dir("endpoint-router");
    let dir = root.join("datasources/endpoints/secret");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("endpoint.get.json"), endpoint_json).unwrap();
    let open = root.join("datasources/endpoints/open");
    std::fs::create_dir_all(&open).unwrap();
    std::fs::write(open.join("endpoint.get.json"), r#"{ "operationId": "open", "sources": {}, "response": {} }"#).unwrap();

    let router = build_router(
        &root,
        Arc::new(HashMap::new()),
        &HashMap::new(),
        Arc::new(registry()),
        Arc::new(security),
        Arc::new(HashMap::new()),
        Arc::new(Mutex::new(DiscoveredErrors::default())),
        false,
        None,
        None,
        NonZeroU64::new(5_000).unwrap(),
        client_identity_available,
        MethodCase::Default,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (format!("http://{addr}"), root)
}

#[tokio::test]
async fn a_cert_dependent_route_is_refused_when_no_identity_can_ever_be_available() {
    for verifier in [MTLS_ORDERS, SQL_FINGERPRINT] {
        let (base, _root) = serve_router(security_with(verifier), SECURED_ENDPOINT, false).await;
        assert_eq!(
            reqwest::get(format!("{base}/secret")).await.unwrap().status(),
            404,
            "{verifier}: the route must not be registered"
        );
        assert_eq!(reqwest::get(format!("{base}/open")).await.unwrap().status(), 200, "unrelated routes are unaffected");
    }
}

#[tokio::test]
async fn a_cert_dependent_route_is_registered_when_identities_are_available() {
    let (base, _root) = serve_router(security_with(MTLS_ORDERS), SECURED_ENDPOINT, true).await;
    let response = reqwest::get(format!("{base}/secret")).await.unwrap();
    assert_eq!(response.status(), 401, "registered, and (over plain HTTP in this test) correctly sees no certificate");
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["name"], "auth.client_cert_missing");
}

#[tokio::test]
async fn a_header_only_scheme_is_registered_regardless_of_identity_availability() {
    for available in [false, true] {
        let (base, _root) = serve_router(security_with(SQL_API_KEY), SECURED_ENDPOINT, available).await;
        assert_ne!(reqwest::get(format!("{base}/secret")).await.unwrap().status(), 404, "available={available}");
    }
}

#[tokio::test]
async fn a_scheme_with_no_verifier_is_still_refused() {
    let (base, _root) = serve_router(SecurityConfig::default(), SECURED_ENDPOINT, true).await;
    assert_eq!(reqwest::get(format!("{base}/secret")).await.unwrap().status(), 404);
}

#[tokio::test]
async fn spoofed_headers_over_plain_http_never_authorize_a_cert_route() {
    let (base, _root) = serve_router(security_with(MTLS_ORDERS), SECURED_ENDPOINT, true).await;
    let response = reqwest::Client::new()
        .get(format!("{base}/secret"))
        .header("X-Forwarded-Client-Cert", "Subject=orders.internal.example.com")
        .header("X-SSL-Client-Fingerprint", "ab".repeat(32))
        .header("cert.san.dns", "orders.internal.example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["name"], "auth.client_cert_missing");
}

// ---------------------------------------------------------------------
// validate_endpoint_files
// ---------------------------------------------------------------------

#[test]
fn validate_endpoint_files_reports_a_cert_dependent_route_only_when_identity_is_unavailable() {
    let root = temp_dir("endpoint-validate");
    let dir = root.join("secret");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("endpoint.get.json"), SECURED_ENDPOINT).unwrap();
    let security = security_with(MTLS_ORDERS);

    let (count, problems) = validate_endpoint_files(&root, &security, &HashMap::new(), false, MethodCase::Default);
    assert_eq!(count, 1);
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains("client certificate") && problems[0].contains("certAuth"), "{problems:?}");

    let (_, problems) = validate_endpoint_files(&root, &security, &HashMap::new(), true, MethodCase::Default);
    assert!(problems.is_empty(), "{problems:?}");

    let (_, problems) = validate_endpoint_files(&root, &security_with(SQL_API_KEY), &HashMap::new(), false, MethodCase::Default);
    assert!(problems.is_empty(), "a header-only scheme never needs clientAuth: {problems:?}");
}

// ---------------------------------------------------------------------
// handle_mocked precedence + mocked cert flow through the mock seam
// ---------------------------------------------------------------------

struct FixedProvider(MockSelection);

impl MockProvider for FixedProvider {
    fn select(&self, _route: &RouteKey, _request: &InboundRequest<'_>) -> MockSelection {
        self.0.clone()
    }
    fn observe(&self, _route: &RouteKey, _selection: &MockSelection, _served: &Served<'_>) {}
}

async fn serve_mocked(verifier: &str, selection: MockSelection) -> String {
    let root = temp_dir("endpoint-mocked");
    let dir = root.join("datasources/endpoints/secret");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("endpoint.get.json"), SECURED_ENDPOINT).unwrap();
    let router = build_router(
        &root,
        Arc::new(HashMap::new()),
        &HashMap::new(),
        Arc::new(registry()),
        Arc::new(security_with(verifier)),
        Arc::new(HashMap::new()),
        Arc::new(Mutex::new(DiscoveredErrors::default())),
        false,
        None,
        Some(Arc::new(FixedProvider(selection))),
        NonZeroU64::new(5_000).unwrap(),
        true,
        MethodCase::Default,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    format!("http://{addr}")
}

fn case(mocks: HashMap<String, MockOutcome>, client_cert: Option<ClientCertIdentity>) -> MockSelection {
    MockSelection::Case {
        case: None,
        mocks,
        scenario: mock::ScenarioChoice {
            name: None,
            source: mock::ScenarioSource::Baseline,
        },
        client_cert: client_cert.map(Box::new),
    }
}

#[tokio::test]
async fn under_the_mock_seam_an_mtls_scheme_runs_for_real_against_the_cases_client_cert() {
    // No verifier mock at all: the datasource-free mtls verifier must not be
    // auto-filled with source_not_mocked, it evaluates the case's identity.
    let ok = ClientCertIdentity::from_identity_json(&serde_json::json!({ "san": { "dns": ["x.example", "orders.internal.example.com"] } })).unwrap();
    let base = serve_mocked(MTLS_ORDERS, case(HashMap::new(), Some(ok))).await;
    assert_eq!(reqwest::get(format!("{base}/secret")).await.unwrap().status(), 200);

    let wrong = ClientCertIdentity::from_identity_json(&serde_json::json!({ "san": { "dns": ["x.example"] } })).unwrap();
    let base = serve_mocked(MTLS_ORDERS, case(HashMap::new(), Some(wrong))).await;
    let response = reqwest::get(format!("{base}/secret")).await.unwrap();
    assert_eq!(response.status(), 401);
    assert_eq!(response.json::<Value>().await.unwrap()["name"], "auth.invalid_credentials");
}

#[tokio::test]
async fn under_the_mock_seam_no_client_cert_means_client_cert_missing_even_with_the_verifier_mocked_successful() {
    let mocks = HashMap::from([("verifier".to_string(), MockOutcome::Success(serde_json::json!({ "active": true })))]);
    let base = serve_mocked(SQL_FINGERPRINT, case(mocks, None)).await;
    let response = reqwest::get(format!("{base}/secret")).await.unwrap();
    assert_eq!(response.status(), 401);
    assert_eq!(response.json::<Value>().await.unwrap()["name"], "auth.client_cert_missing");
}

#[tokio::test]
async fn under_the_mock_seam_an_unmocked_cert_fingerprint_verifier_is_source_not_mocked() {
    let id = identity(&LeafSpec::valid());
    let base = serve_mocked(SQL_FINGERPRINT, case(HashMap::new(), Some(id))).await;
    let response = reqwest::get(format!("{base}/secret")).await.unwrap();
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["name"], mock::SOURCE_NOT_MOCKED, "{body}");
}

#[tokio::test]
async fn under_the_mock_seam_an_expired_case_identity_is_client_cert_expired() {
    let expired = ClientCertIdentity::from_test_fields(crate::security::client_cert::TestIdentityFields {
        not_after: Some(chrono::Utc::now() - chrono::Duration::days(1)),
        san_dns: vec!["orders.internal.example.com".into()],
        ..Default::default()
    });
    let base = serve_mocked(MTLS_ORDERS, case(HashMap::new(), Some(expired))).await;
    let response = reqwest::get(format!("{base}/secret")).await.unwrap();
    assert_eq!(response.status(), 401);
    assert_eq!(response.json::<Value>().await.unwrap()["name"], "auth.client_cert_expired");
}

// ---------------------------------------------------------------------
// handle_mocked identity precedence; inertness under `frogs run`
// ---------------------------------------------------------------------

fn mocked_state(verifier: &str, provider: Arc<dyn MockProvider>) -> RouteState {
    let root = temp_dir("endpoint-precedence");
    RouteState {
        endpoint: endpoint(SECURED_ENDPOINT),
        route: RouteKey {
            method: "get".to_string(),
            path: "/secret".to_string(),
        },
        sql_root: root.join("sql"),
        http_root: root.join("http"),
        drivers: Arc::new(HashMap::new()),
        http_client: reqwest::Client::new(),
        errors: Arc::new(registry()),
        security: Arc::new(security_with(verifier)),
        services: Arc::new(HashMap::new()),
        verifier_cache: Arc::new(VerifierCache::new()),
        discovered_errors: Arc::new(Mutex::new(DiscoveredErrors::default())),
        discovered_errors_path: root.join("errors.discovered.json"),
        debug_mode: false,
        operation: None,
        component_schemas: Arc::new(Map::new()),
        source_call_timeout_ms: NonZeroU64::new(5_000).unwrap(),
        mock_provider: Some(provider),
        response_mode: crate::openapi::ResponseMode::Single,
    }
}

async fn mocked_call(case_cert: Option<ClientCertIdentity>, connection_cert: Option<&ClientCertIdentity>) -> (u16, Value) {
    let provider: Arc<dyn MockProvider> = Arc::new(FixedProvider(case(HashMap::new(), case_cert)));
    let state = mocked_state(MTLS_ORDERS, provider.clone());
    handle_mocked(
        &state,
        provider.as_ref(),
        &HeaderMap::new(),
        connection_cert,
        &HashMap::new(),
        &HashMap::new(),
        &Value::Null,
        "",
    )
    .await
}

#[tokio::test]
async fn a_cases_client_cert_wins_over_the_real_connections_identity() {
    let matching = identity(&LeafSpec::valid());
    let non_matching = ClientCertIdentity::from_identity_json(&serde_json::json!({ "san": { "dns": ["nope.example"] } })).unwrap();

    let (status, body) = mocked_call(Some(non_matching), Some(&matching)).await;
    assert_eq!(
        (status, name_of(&body)),
        (401, "auth.invalid_credentials"),
        "the case's own cert decides, not the connection's: {body}"
    );

    let case_ok = ClientCertIdentity::from_identity_json(&serde_json::json!({ "san": { "dns": ["orders.internal.example.com"] } })).unwrap();
    let other_conn = identity(&LeafSpec {
        dns: vec!["nope.example".into()],
        ..LeafSpec::valid()
    });
    assert_eq!(mocked_call(Some(case_ok), Some(&other_conn)).await.0, 200);
}

#[tokio::test]
async fn without_a_case_client_cert_the_real_connection_identity_is_used_and_without_either_it_is_missing() {
    let matching = identity(&LeafSpec::valid());
    assert_eq!(mocked_call(None, Some(&matching)).await.0, 200);
    let (status, body) = mocked_call(None, None).await;
    assert_eq!((status, name_of(&body)), (401, "auth.client_cert_missing"), "{body}");
}

#[tokio::test]
async fn test_files_and_their_client_cert_are_inert_when_no_mock_provider_is_installed() {
    // `frogs run` passes no provider: a `.test.json` sitting next to the
    // endpoint with a perfectly matching `clientCert` must change nothing.
    let root = temp_dir("endpoint-inert");
    let dir = root.join("datasources/endpoints/secret");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("endpoint.get.json"), SECURED_ENDPOINT).unwrap();
    std::fs::write(
        dir.join("endpoint.get.test.json"),
        r#"{ "cases": [ { "name": "c", "request": {}, "clientCert": { "san": { "dns": "orders.internal.example.com" } }, "mocks": { "verifier": { "active": true } }, "expect": {} } ] }"#,
    )
    .unwrap();
    let router = build_router(
        &root,
        Arc::new(HashMap::new()),
        &HashMap::new(),
        Arc::new(registry()),
        Arc::new(security_with(MTLS_ORDERS)),
        Arc::new(HashMap::new()),
        Arc::new(Mutex::new(DiscoveredErrors::default())),
        false,
        None,
        None,
        NonZeroU64::new(5_000).unwrap(),
        true,
        MethodCase::Default,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let response = reqwest::Client::new()
        .get(format!("http://{addr}/secret"))
        .header("X-Frogs-Scenario", "whatever")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    assert_eq!(response.json::<Value>().await.unwrap()["name"], "auth.client_cert_missing");
}

// ---------------------------------------------------------------------
// M4: extension-method routes with cert-dependent verifiers
// ---------------------------------------------------------------------

const SQL_FINGERPRINT_CACHED: &str = r#"{
    "type": "sql", "connection": "db", "script": "verify.sql",
    "parameters": [{ "name": "fp", "from": "cert.fingerprint" }],
    "validIf": "row.active = true",
    "cacheTtlSeconds": 30
}"#;

async fn serve_extension_router(token: &str, mode: MethodCase, identity: Option<ClientCertIdentity>, calls: Arc<AtomicUsize>) -> (String, PathBuf) {
    let root = temp_dir("endpoint-m4-router");
    std::fs::create_dir_all(root.join("datasources/sql/db")).unwrap();
    std::fs::write(root.join("datasources/sql/db/verify.sql"), "SELECT 1").unwrap();
    for (dir, body) in [
        ("secret", r#"{ "operationId": "s", "security": "certAuth", "sources": {}, "response": {} }"#),
        (
            "limited",
            r#"{ "operationId": "l", "security": "certAuth", "sources": {}, "response": {}, "rateLimit": { "requestsPerSecond": 1, "burst": 1 } }"#,
        ),
    ] {
        let d = root.join("datasources/endpoints").join(dir);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(format!("endpoint.{token}.json")), body).unwrap();
    }
    let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
    drivers.insert("db".to_string(), Box::new(CountingDriver(calls)));
    let mut router = build_router(
        &root,
        Arc::new(drivers),
        &HashMap::new(),
        Arc::new(registry()),
        Arc::new(security_with(SQL_FINGERPRINT_CACHED)),
        Arc::new(HashMap::new()),
        Arc::new(Mutex::new(DiscoveredErrors::default())),
        false,
        None,
        None,
        NonZeroU64::new(5_000).unwrap(),
        true,
        mode,
    );
    if let Some(id) = identity {
        router = router.layer(axum::Extension(Arc::new(id)));
    }
    let addr = crate::server::spawn_served(router, mode == MethodCase::Exact).await;
    (format!("http://{addr}"), root)
}

async fn status_for(base: &str, method: &str, path: &str) -> (u16, Value) {
    let resp = reqwest::Client::new()
        .request(reqwest::Method::from_bytes(method.as_bytes()).unwrap(), format!("{base}{path}"))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn an_extension_route_with_a_cert_verifier_authorizes_caches_and_rate_limits_like_any_other_route() {
    for (token, request, mode) in [("LINK", "LINK", MethodCase::Default), ("~purge", "purge", MethodCase::Exact)] {
        let calls = Arc::new(AtomicUsize::new(0));
        let id = identity(&LeafSpec::valid());
        let (base, root) = serve_extension_router(token, mode, Some(id), calls.clone()).await;

        assert_eq!(status_for(&base, request, "/secret").await.0, 200, "{token}");
        assert_eq!(status_for(&base, request, "/secret").await.0, 200, "{token}");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "{token}: the second request is served from the verifier cache");

        assert_eq!(status_for(&base, request, "/limited").await.0, 200, "{token}: first request inside the burst");
        assert_eq!(
            status_for(&base, request, "/limited").await.0,
            429,
            "{token}: the per-route rate limit applies to extension methods"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[tokio::test]
async fn an_extension_route_with_no_certificate_or_an_expired_one_is_rejected_before_the_datasource() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (base, _root) = serve_extension_router("LINK", MethodCase::Default, None, calls.clone()).await;
    let (status, body) = status_for(&base, "LINK", "/secret").await;
    assert_eq!((status, name_of(&body)), (401, "auth.client_cert_missing"), "{body}");

    let (base, _root) = serve_extension_router("LINK", MethodCase::Default, Some(identity(&LeafSpec::expired())), calls.clone()).await;
    let (status, body) = status_for(&base, "link", "/secret").await;
    assert_eq!((status, name_of(&body)), (401, "auth.client_cert_expired"), "{body}");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn in_exact_mode_the_wrong_spelling_of_a_cert_protected_extension_route_is_405_never_a_bypass() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (base, _root) = serve_extension_router("PURGE", MethodCase::Exact, None, calls.clone()).await;
    assert_eq!(status_for(&base, "purge", "/secret").await.0, 405);
    assert_eq!(status_for(&base, "PURGE", "/secret").await.0, 401, "the real spelling still demands the certificate");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
