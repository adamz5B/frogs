//! Milestone 2 in `endpoint`: the shared `authorize` (certificate precheck, mocks, scope enforcement),
//! the `securityScopes` servability rules and the spec-vs-file scope agreement in `security_check`.

use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::json;

use super::*;
use crate::server::test_pki::*;
use crate::sql::{SqlError, SqlValue};

fn root_dir(name: &str) -> PathBuf {
    let dir = temp_dir(name);
    std::fs::create_dir_all(dir.join("db")).unwrap();
    std::fs::write(dir.join("db/verify.sql"), "SELECT 1").unwrap();
    dir
}

/// A `security/` tree with one scheme, `oauth`, whose verifier is `verifier_json`.
fn security_with(verifier_json: &str) -> SecurityConfig {
    let dir = temp_dir("scope-sec");
    std::fs::create_dir_all(dir.join("verifiers")).unwrap();
    std::fs::write(dir.join("schemes.json"), r#"{ "oauth": { "verifier": "v.json" } }"#).unwrap();
    std::fs::write(dir.join("verifiers/v.json"), verifier_json).unwrap();
    SecurityConfig::load(&dir).unwrap()
}

fn sql_verifier(extra: &str) -> String {
    format!(
        r#"{{ "type": "sql", "connection": "db", "script": "verify.sql", "parameters": [{{ "name": "key", "from": "header.X-Api-Key" }}], "validIf": "row.active = true"{extra} }}"#
    )
}

const SCOPED: &str = r#", "scopesFrom": "row.scope""#;

fn scoped_security() -> SecurityConfig {
    security_with(&sql_verifier(SCOPED))
}

fn unscoped_security() -> SecurityConfig {
    security_with(&sql_verifier(""))
}

#[derive(Debug)]
struct SeqDriver {
    calls: Arc<AtomicUsize>,
    /// One row per call, the last repeated.
    rows: Mutex<Vec<HashMap<String, SqlValue>>>,
}

#[async_trait::async_trait]
impl SqlDriver for SeqDriver {
    async fn query(&self, _script: &str, _params: &HashMap<String, SqlValue>) -> Result<Vec<HashMap<String, SqlValue>>, SqlError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut rows = self.rows.lock().unwrap();
        let row = if rows.len() > 1 { rows.remove(0) } else { rows[0].clone() };
        Ok(vec![row])
    }
}

fn row(scope: SqlValue) -> HashMap<String, SqlValue> {
    HashMap::from([("active".to_string(), SqlValue::Bool(true)), ("scope".to_string(), scope)])
}

fn text(value: &str) -> SqlValue {
    SqlValue::Text(value.to_string())
}

fn drivers(rows: Vec<HashMap<String, SqlValue>>) -> (HashMap<String, Box<dyn SqlDriver>>, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut map: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
    map.insert(
        "db".to_string(),
        Box::new(SeqDriver {
            calls: calls.clone(),
            rows: Mutex::new(rows),
        }),
    );
    (map, calls)
}

fn key_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("x-api-key", "k".parse().unwrap());
    headers
}

fn scopes(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

struct Env {
    root: PathBuf,
    security: SecurityConfig,
    drivers: HashMap<String, Box<dyn SqlDriver>>,
    cache: VerifierCache,
    client: reqwest::Client,
}

impl Env {
    fn new(security: SecurityConfig, drivers: HashMap<String, Box<dyn SqlDriver>>) -> Env {
        Env {
            root: root_dir("scope-authorize"),
            security,
            drivers,
            cache: VerifierCache::new(),
            client: reqwest::Client::new(),
        }
    }

    async fn authorize(
        &self,
        scheme: &str,
        required: &[String],
        headers: &HeaderMap,
        cert: Option<&ClientCertIdentity>,
        mocks: &HashMap<String, MockOutcome>,
    ) -> Result<(), AuthFailure> {
        let ctx = AuthContext {
            security: &self.security,
            drivers: &self.drivers,
            sql_root: &self.root,
            http_root: &self.root,
            http_client: &self.client,
            verifier_cache: &self.cache,
            timeout: NonZeroU64::new(5_000).unwrap(),
        };
        authorize(&ctx, scheme, required, headers, cert, mocks).await
    }
}

fn no_mocks() -> HashMap<String, MockOutcome> {
    HashMap::new()
}

fn mock(value: Value) -> HashMap<String, MockOutcome> {
    HashMap::from([("verifier".to_string(), MockOutcome::Success(value))])
}

fn mock_fail(code: &str) -> HashMap<String, MockOutcome> {
    HashMap::from([("verifier".to_string(), MockOutcome::Fail(code.to_string()))])
}

// ---------------------------------------------------------------- authorize: failure kinds

#[tokio::test]
async fn an_unknown_scheme_is_an_unavailable_unexpected_error_not_an_allow() {
    let env = Env::new(scoped_security(), HashMap::new());
    let failure = env.authorize("nope", &[], &HeaderMap::new(), None, &no_mocks()).await.unwrap_err();
    assert_eq!((failure.kind, failure.code.as_str()), (AuthFailureKind::Unavailable, "unexpected.error"));
}

#[tokio::test]
async fn a_failure_code_maps_to_its_kind_for_real_and_mocked_outcomes_alike() {
    let env = Env::new(scoped_security(), HashMap::new());
    for (code, kind) in [
        ("auth.invalid_credentials", AuthFailureKind::Credentials),
        ("auth.client_cert_missing", AuthFailureKind::CertMissing),
        ("auth.client_cert_expired", AuthFailureKind::CertExpired),
        ("auth.insufficient_scope", AuthFailureKind::InsufficientScope),
        ("auth.verifier_unavailable", AuthFailureKind::Unavailable),
        ("test.source_not_mocked", AuthFailureKind::Unavailable),
        ("some.arbitrary_code", AuthFailureKind::Unavailable),
    ] {
        let failure = env.authorize("oauth", &[], &HeaderMap::new(), None, &mock_fail(code)).await.unwrap_err();
        assert_eq!(failure.kind, kind, "{code}");
        assert_eq!(failure.code, code);
        assert_eq!(failure.message, format!("mocked failure: {code}"));
    }
}

#[tokio::test]
async fn a_mocked_value_that_fails_valid_if_is_invalid_credentials() {
    let env = Env::new(scoped_security(), HashMap::new());
    let failure = env
        .authorize("oauth", &[], &HeaderMap::new(), None, &mock(json!({ "active": false })))
        .await
        .unwrap_err();
    assert_eq!(failure.kind, AuthFailureKind::Credentials);
}

#[tokio::test]
async fn a_certificate_dependent_scheme_is_refused_before_the_datasource_is_touched() {
    let security = security_with(
        r#"{ "type": "sql", "connection": "db", "script": "verify.sql", "parameters": [{ "name": "fp", "from": "cert.fingerprint" }], "validIf": "row.active = true", "scopesFrom": "row.scope" }"#,
    );
    let (map, calls) = drivers(vec![row(text("a"))]);
    let env = Env::new(security, map);
    let none = env.authorize("oauth", &[], &HeaderMap::new(), None, &no_mocks()).await.unwrap_err();
    assert_eq!(none.kind, AuthFailureKind::CertMissing);
    let ca = Ca::root("scope test ca");
    let expired = ClientCertIdentity::from_der(&build_leaf(&ca, &LeafSpec::expired()).der()).unwrap();
    let late = env.authorize("oauth", &[], &HeaderMap::new(), Some(&expired), &no_mocks()).await.unwrap_err();
    assert_eq!(late.kind, AuthFailureKind::CertExpired);
    assert_eq!(calls.load(Ordering::SeqCst), 0, "neither refusal reached the verifier's datasource");
    let valid = ClientCertIdentity::from_der(&build_leaf(&ca, &LeafSpec::valid()).der()).unwrap();
    assert!(env.authorize("oauth", &[], &HeaderMap::new(), Some(&valid), &no_mocks()).await.is_ok());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

// ---------------------------------------------------------------- authorize: scopes

#[tokio::test]
async fn a_credential_holding_every_required_scope_is_authorized_extra_scopes_are_fine() {
    let env = Env::new(scoped_security(), HashMap::new());
    let granted = mock(json!({ "active": true, "scope": "cars.read cars.write admin" }));
    assert!(
        env.authorize("oauth", &scopes(&["cars.read", "cars.write"]), &HeaderMap::new(), None, &granted)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn a_missing_scope_is_insufficient_scope_and_the_detail_names_only_the_configured_scopes() {
    let env = Env::new(scoped_security(), HashMap::new());
    let granted = mock(json!({ "active": true, "scope": "cars.read secret.granted" }));
    let failure = env
        .authorize("oauth", &scopes(&["cars.read", "cars.write"]), &HeaderMap::new(), None, &granted)
        .await
        .unwrap_err();
    assert_eq!(failure.kind, AuthFailureKind::InsufficientScope);
    assert_eq!(failure.code, "auth.insufficient_scope");
    assert_eq!(failure.message, "the credential lacks a required scope (requires: cars.read cars.write)");
    assert!(!failure.message.contains("secret.granted"), "granted scopes never appear in the detail");
}

#[tokio::test]
async fn scope_comparison_is_byte_exact_and_case_sensitive() {
    let env = Env::new(scoped_security(), HashMap::new());
    for granted in ["Cars.Read", "cars.read ", "cars.rea", "cars.read.x"] {
        let result = env
            .authorize(
                "oauth",
                &scopes(&["cars.read"]),
                &HeaderMap::new(),
                None,
                &mock(json!({ "active": true, "scope": granted })),
            )
            .await;
        if granted == "cars.read " {
            assert!(result.is_ok(), "trailing space is just a separator");
        } else {
            assert_eq!(result.unwrap_err().kind, AuthFailureKind::InsufficientScope, "{granted}");
        }
    }
}

#[tokio::test]
async fn an_array_element_with_a_space_is_one_scope_not_two() {
    let env = Env::new(scoped_security(), HashMap::new());
    let granted = mock(json!({ "active": true, "scope": ["cars read"] }));
    // A required scope can never contain a space (is_scope_token), so "cars" and "read" are not granted by "cars read".
    let failure = env.authorize("oauth", &scopes(&["cars"]), &HeaderMap::new(), None, &granted).await.unwrap_err();
    assert_eq!(failure.kind, AuthFailureKind::InsufficientScope);
}

#[tokio::test]
async fn no_scope_claim_a_bad_claim_or_an_over_cap_claim_fails_any_required_scope_but_passes_when_none_are_required() {
    let env = Env::new(scoped_security(), HashMap::new());
    let sixty_five = (0..65).map(|n| format!("s{n}")).collect::<Vec<_>>().join(" ");
    for value in [
        json!({ "active": true }),
        json!({ "active": true, "scope": null }),
        json!({ "active": true, "scope": 7 }),
        json!({ "active": true, "scope": ["a", 1] }),
        json!({ "active": true, "scope": sixty_five }),
    ] {
        let failure = env
            .authorize("oauth", &scopes(&["s0"]), &HeaderMap::new(), None, &mock(value.clone()))
            .await
            .unwrap_err();
        assert_eq!(failure.kind, AuthFailureKind::InsufficientScope, "{value}");
        assert!(
            env.authorize("oauth", &[], &HeaderMap::new(), None, &mock(value.clone())).await.is_ok(),
            "{value}: nothing required, so valid is enough"
        );
    }
}

#[tokio::test]
async fn a_cached_valid_verdict_is_still_scope_checked_and_a_cached_hit_without_scopes_fails() {
    let (map, calls) = drivers(vec![row(text("cars.read"))]);
    let security = security_with(&sql_verifier(&format!(r#", "cacheTtlSeconds": 60{SCOPED}"#)));
    let env = Env::new(security, map);
    let headers = key_headers();
    assert!(env.authorize("oauth", &scopes(&["cars.read"]), &headers, None, &no_mocks()).await.is_ok());
    let hit = env.authorize("oauth", &scopes(&["cars.write"]), &headers, None, &no_mocks()).await.unwrap_err();
    assert_eq!(
        hit.kind,
        AuthFailureKind::InsufficientScope,
        "the second call is a cache hit and is checked against its own required scopes"
    );
    assert!(env.authorize("oauth", &scopes(&["cars.read"]), &headers, None, &no_mocks()).await.is_ok());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_cache_hit_that_stored_no_scopes_fails_a_required_scope_without_calling_the_datasource() {
    let (map, calls) = drivers(vec![row(SqlValue::Int(1))]);
    let security = security_with(&sql_verifier(&format!(r#", "cacheTtlSeconds": 60{SCOPED}"#)));
    let env = Env::new(security, map);
    let headers = key_headers();
    for _ in 0..3 {
        let failure = env.authorize("oauth", &scopes(&["a"]), &headers, None, &no_mocks()).await.unwrap_err();
        assert_eq!(failure.kind, AuthFailureKind::InsufficientScope);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_verifier_with_no_ttl_re_reads_the_scopes_on_every_request() {
    let (map, calls) = drivers(vec![row(text("a")), row(text("a b"))]);
    let env = Env::new(scoped_security(), map);
    let headers = key_headers();
    assert!(env.authorize("oauth", &scopes(&["b"]), &headers, None, &no_mocks()).await.is_err());
    assert!(
        env.authorize("oauth", &scopes(&["b"]), &headers, None, &no_mocks()).await.is_ok(),
        "the second request saw the new scope set"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn an_mtls_scheme_grants_no_scopes_so_any_required_scope_fails() {
    let security = security_with(r#"{ "type": "mtls", "validIf": "cert.cn = client.example.com" }"#);
    let env = Env::new(security, HashMap::new());
    let ca = Ca::root("scope mtls ca");
    let identity = ClientCertIdentity::from_der(&build_leaf(&ca, &LeafSpec::valid()).der()).unwrap();
    assert!(env.authorize("oauth", &[], &HeaderMap::new(), Some(&identity), &no_mocks()).await.is_ok());
    let failure = env
        .authorize("oauth", &scopes(&["a"]), &HeaderMap::new(), Some(&identity), &no_mocks())
        .await
        .unwrap_err();
    assert_eq!(failure.kind, AuthFailureKind::InsufficientScope);
}

#[test]
fn missing_scopes_reports_all_required_scopes_only_when_one_is_absent() {
    let required = scopes(&["a", "b"]);
    assert!(missing_scopes(&[], None).is_none());
    assert!(missing_scopes(&required, Some(&scopes(&["a", "b", "c"]))).is_none());
    assert_eq!(missing_scopes(&required, Some(&scopes(&["a"]))), Some(required.as_slice()));
    assert_eq!(missing_scopes(&required, None), Some(required.as_slice()));
}

// ---------------------------------------------------------------- servability

fn endpoint(extra: &str) -> EndpointFile {
    let tail = if extra.is_empty() { String::new() } else { format!(", {extra}") };
    serde_json::from_str(&format!(r#"{{ "operationId": "x", "sources": {{}}, "response": {{}}{tail} }}"#)).unwrap()
}

fn problems(endpoint: &EndpointFile, security: &SecurityConfig) -> Vec<String> {
    servability_problems(endpoint, security, &HashMap::new(), true)
}

#[test]
fn security_scopes_on_a_scheme_whose_verifier_declares_scopes_from_is_servable() {
    assert!(problems(&endpoint(r#""security": "oauth", "securityScopes": ["cars.read", "cars.write"]"#), &scoped_security()).is_empty());
    assert!(problems(&endpoint(r#""security": "oauth""#), &scoped_security()).is_empty());
    assert!(problems(&endpoint(r#""security": "oauth", "securityScopes": []"#), &unscoped_security()).is_empty());
}

#[test]
fn security_scopes_without_a_security_scheme_make_the_endpoint_unservable() {
    let found = problems(&endpoint(r#""securityScopes": ["a"]"#), &scoped_security());
    assert!(found.iter().any(|p| p.contains("no \"security\" scheme")), "{found:?}");
}

#[test]
fn security_scopes_on_an_mtls_scheme_make_the_endpoint_unservable() {
    let security = security_with(r#"{ "type": "mtls", "validIf": "cert.cn = a" }"#);
    let found = problems(&endpoint(r#""security": "oauth", "securityScopes": ["a"]"#), &security);
    assert!(found.iter().any(|p| p.contains("mtls verifier")), "{found:?}");
}

#[test]
fn security_scopes_on_a_verifier_without_scopes_from_make_the_endpoint_unservable_naming_the_fix() {
    let found = problems(&endpoint(r#""security": "oauth", "securityScopes": ["a"]"#), &unscoped_security());
    assert!(found.iter().any(|p| p.contains("scopesFrom") && p.contains("could not enforce")), "{found:?}");
}

#[test]
fn an_invalid_or_duplicate_scope_token_makes_the_endpoint_unservable() {
    for bad in [r#""""#, r#""a b""#, r#""a\"b""#, &format!("\"{}\"", "x".repeat(129))] {
        let found = problems(&endpoint(&format!(r#""security": "oauth", "securityScopes": [{bad}]"#)), &scoped_security());
        assert!(found.iter().any(|p| p.contains("not a valid scope token")), "{bad}: {found:?}");
    }
    let found = problems(&endpoint(r#""security": "oauth", "securityScopes": ["a", "a"]"#), &scoped_security());
    assert!(found.iter().any(|p| p.contains("more than once")), "{found:?}");
}

#[test]
fn security_scopes_on_an_unknown_scheme_report_the_unknown_scheme_without_panicking() {
    let found = problems(&endpoint(r#""security": "ghost", "securityScopes": ["a"]"#), &scoped_security());
    assert!(found.iter().any(|p| p.contains("no matching entry in security/schemes.json")), "{found:?}");
}

// ---------------------------------------------------------------- spec vs file agreement (FR22)

struct Fx {
    root: PathBuf,
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

impl Fx {
    fn new(paths: &str) -> Fx {
        let root = temp_dir("scope-spec");
        let yaml = format!(
            "openapi: 3.2.0\ninfo: {{ title: t, version: '1' }}\ncomponents:\n  securitySchemes:\n    oauth:\n      type: oauth2\n      flows:\n        clientCredentials:\n          tokenUrl: https://auth.example.com/token\n          scopes: {{ cars.read: r, cars.write: w, admin: a }}\npaths:\n{paths}"
        );
        std::fs::write(root.join("openapi.yaml"), yaml).unwrap();
        Fx { root }
    }

    fn file(&self, folder: &str, token: &str, json: &str) {
        let dir = self.root.join("datasources/endpoints").join(folder);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("endpoint.{token}.json")), json).unwrap();
    }

    fn check(&self, security: &SecurityConfig) -> SecurityCheck {
        let doc = crate::openapi::load(&self.root.join("openapi.yaml"), crate::openapi::LoadOptions::default()).unwrap();
        let tree = tree_for_tests(&self.root.join("datasources/endpoints"));
        let plan = RoutePlan::build(&tree, doc.method_case, &RouteContext::endpoints_only());
        security_check_with_routes(&tree, &doc, &plan, security)
    }
}

const CARS_READ: &str = "  /cars:\n    get:\n      operationId: listCars\n      security: [ { oauth: [cars.read] } ]\n      responses: { '200': { description: ok } }\n";

fn stub(scopes: Option<&str>) -> String {
    let scopes = scopes.map(|s| format!(r#", "securityScopes": {s}"#)).unwrap_or_default();
    format!(r#"{{ "operationId": "listCars", "security": "oauth"{scopes}, "sources": {{}}, "response": {{}} }}"#)
}

#[test]
fn an_old_stub_without_security_scopes_warns_and_starts_when_the_verifier_has_no_scopes_from() {
    let fx = Fx::new(CARS_READ);
    fx.file("cars", "get", &stub(None));
    let check = fx.check(&unscoped_security());
    assert!(check.scope_mismatches.is_empty(), "{:?}", check.scope_mismatches);
    assert!(check.mismatches.is_empty());
    assert_eq!(check.scope_warnings.len(), 1, "{:?}", check.scope_warnings);
    let warning = &check.scope_warnings[0];
    for needle in [
        "endpoint.get.json",
        "oauth",
        "cars.read",
        "declares no securityScopes",
        "add securityScopes to the file and scopesFrom to the verifier",
    ] {
        assert!(warning.contains(needle), "{needle} missing from: {warning}");
    }
}

#[test]
fn an_old_stub_without_security_scopes_is_refused_once_the_verifier_declares_scopes_from() {
    let fx = Fx::new(CARS_READ);
    fx.file("cars", "get", &stub(None));
    let check = fx.check(&scoped_security());
    assert_eq!(check.scope_mismatches.len(), 1, "{:?}", check.scope_warnings);
    let message = &check.scope_mismatches[0];
    assert!(
        message.contains("openapi.yaml requires scopes [cars.read] for scheme 'oauth' but the endpoint file declares no securityScopes"),
        "{message}"
    );
    assert!(check.scope_warnings.is_empty());
}

#[test]
fn a_file_whose_security_scopes_cover_the_spec_passes_silently() {
    for security in [scoped_security(), unscoped_security()] {
        let fx = Fx::new(CARS_READ);
        fx.file("cars", "get", &stub(Some(r#"["cars.read"]"#)));
        let check = fx.check(&security);
        assert!(
            check.scope_mismatches.is_empty() && check.scope_warnings.is_empty(),
            "{:?} {:?}",
            check.scope_mismatches,
            check.scope_warnings
        );
    }
}

#[test]
fn a_file_stricter_than_the_spec_warns_but_never_refuses() {
    let fx = Fx::new(CARS_READ);
    fx.file("cars", "get", &stub(Some(r#"["cars.read", "cars.write"]"#)));
    let check = fx.check(&scoped_security());
    assert!(check.scope_mismatches.is_empty());
    assert_eq!(check.scope_warnings.len(), 1, "{:?}", check.scope_warnings);
    assert!(check.scope_warnings[0].contains("asks for more"), "{}", check.scope_warnings[0]);
}

#[test]
fn a_file_covering_a_different_scope_than_the_spec_requires_is_refused() {
    let fx = Fx::new(CARS_READ);
    fx.file("cars", "get", &stub(Some(r#"["cars.write"]"#)));
    assert_eq!(fx.check(&scoped_security()).scope_mismatches.len(), 1);
}

#[test]
fn with_two_or_alternatives_covering_any_one_of_them_is_enough() {
    let spec = "  /cars:\n    get:\n      operationId: listCars\n      security: [ { oauth: [cars.read] }, { oauth: [admin] } ]\n      responses: { '200': { description: ok } }\n";
    let fx = Fx::new(spec);
    fx.file("cars", "get", &stub(Some(r#"["admin"]"#)));
    assert!(fx.check(&scoped_security()).scope_mismatches.is_empty());
    let none = Fx::new(spec);
    none.file("cars", "get", &stub(None));
    let check = none.check(&scoped_security());
    assert_eq!(check.scope_mismatches.len(), 1);
    assert!(check.scope_mismatches[0].contains("[cars.read] or [admin]"), "{}", check.scope_mismatches[0]);
}

#[test]
fn an_unparseable_spec_scope_list_is_refused_when_scopes_are_enforceable_and_ignored_otherwise() {
    let spec = "  /cars:\n    get:\n      operationId: listCars\n      security: [ { oauth: [ 'cars read' ] } ]\n      responses: { '200': { description: ok } }\n";
    let fx = Fx::new(spec);
    fx.file("cars", "get", &stub(None));
    let enforceable = fx.check(&scoped_security());
    assert_eq!(enforceable.scope_mismatches.len(), 1, "{:?}", enforceable.scope_warnings);
    assert!(
        enforceable.scope_mismatches[0].contains("not an array of valid scope tokens"),
        "{}",
        enforceable.scope_mismatches[0]
    );
    let unenforceable = fx.check(&unscoped_security());
    assert!(unenforceable.scope_mismatches.is_empty());
}

#[test]
fn a_spec_that_requires_no_scopes_never_produces_a_scope_finding() {
    let spec = "  /cars:\n    get:\n      operationId: listCars\n      security: [ { oauth: [] } ]\n      responses: { '200': { description: ok } }\n";
    for security in [scoped_security(), unscoped_security()] {
        let fx = Fx::new(spec);
        fx.file("cars", "get", &stub(None));
        let check = fx.check(&security);
        assert!(check.scope_mismatches.is_empty() && check.scope_warnings.is_empty());
    }
}

/// `/items/special` is secured with scopes and has no file of its own; the open `/items/{id}` file
/// answers it, with the right scheme but no scopes.
const SHADOW_SPEC: &str = "  /items/{id}:\n    get:\n      operationId: getItem\n      parameters: [ { name: id, in: path, required: true, schema: { type: string } } ]\n      security: [ { oauth: [] } ]\n      responses: { '200': { description: ok } }\n  /items/special:\n    get:\n      operationId: getSpecial\n      security: [ { oauth: [admin] } ]\n      responses: { '200': { description: ok } }\n";

fn param_file() -> &'static str {
    r#"{ "operationId": "getItem", "security": "oauth", "sources": {}, "response": {} }"#
}

#[test]
fn a_sibling_param_file_with_the_right_scheme_but_no_scopes_shadowing_a_scoped_operation_is_refused_when_enforceable() {
    let fx = Fx::new(SHADOW_SPEC);
    fx.file("items/{id}", "get", param_file());
    let check = fx.check(&scoped_security());
    assert_eq!(check.shadowed.len(), 1, "shadowed={:?} warnings={:?}", check.shadowed.len(), check.scope_warnings);
    assert!(check.shadowed[0].message().contains("admin"), "{}", check.shadowed[0].message());
}

#[test]
fn the_same_sibling_shadow_is_only_a_warning_when_the_verifier_cannot_enforce_scopes() {
    let fx = Fx::new(SHADOW_SPEC);
    fx.file("items/{id}", "get", param_file());
    let check = fx.check(&unscoped_security());
    assert!(check.shadowed.is_empty(), "{:?}", check.shadowed.iter().map(|s| s.message()).collect::<Vec<_>>());
    assert!(check.scope_warnings.iter().any(|w| w.contains("admin")), "{:?}", check.scope_warnings);
}

#[test]
fn a_sibling_param_file_that_declares_the_required_scopes_is_not_a_shadow() {
    let fx = Fx::new(SHADOW_SPEC);
    fx.file(
        "items/{id}",
        "get",
        r#"{ "operationId": "getItem", "security": "oauth", "securityScopes": ["admin"], "sources": {}, "response": {} }"#,
    );
    let check = fx.check(&scoped_security());
    assert!(check.shadowed.is_empty(), "{:?}", check.shadowed.iter().map(|s| s.message()).collect::<Vec<_>>());
}

#[test]
fn a_literal_file_standing_in_for_a_scoped_template_operation_is_refused_when_enforceable_and_warned_otherwise() {
    let spec = "  /cars/{vin}:\n    get:\n      operationId: getCar\n      parameters: [ { name: vin, in: path, required: true, schema: { type: string } } ]\n      security: [ { oauth: [cars.read] } ]\n      responses: { '200': { description: ok } }\n";
    let literal = r#"{ "operationId": "getCar", "security": "oauth", "sources": {}, "response": {} }"#;
    let fx = Fx::new(spec);
    fx.file("cars/ABC123", "get", literal);
    let enforceable = fx.check(&scoped_security());
    assert_eq!(enforceable.template_instances.len(), 1, "{:?}", enforceable.scope_warnings);
    let unenforceable = fx.check(&unscoped_security());
    assert!(unenforceable.template_instances.is_empty());
    assert!(
        unenforceable.scope_warnings.iter().any(|w| w.contains("cars.read")),
        "{:?}",
        unenforceable.scope_warnings
    );
}
