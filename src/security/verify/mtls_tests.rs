use super::*;
use crate::security::ValidIf;
use crate::server::test_pki::*;
use crate::sql::SqlError;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

fn timeout() -> NonZeroU64 {
    NonZeroU64::new(5_000).unwrap()
}

fn loaded(json: &str) -> LoadedVerifier {
    let def: VerifierDef = serde_json::from_str(json).unwrap();
    let mtls = matches!(def, VerifierDef::Mtls { .. }).then(|| super::super::MtlsCondition::compile(def.valid_if()).unwrap());
    LoadedVerifier {
        valid_if: ValidIf::parse(def.valid_if()).unwrap(),
        def,
        mtls,
    }
}

fn mtls_verifier(valid_if: &str) -> LoadedVerifier {
    loaded(&format!(r#"{{ "type": "mtls", "validIf": "{valid_if}" }}"#))
}

fn sql_cert_verifier(params: &str, ttl: Option<u64>) -> LoadedVerifier {
    let ttl = ttl.map(|t| format!(r#", "cacheTtlSeconds": {t}"#)).unwrap_or_default();
    loaded(&format!(
        r#"{{ "type": "sql", "connection": "db", "script": "verify.sql", "parameters": {params}, "validIf": "row.active = true"{ttl} }}"#
    ))
}

fn identity(spec: &LeafSpec) -> ClientCertIdentity {
    let ca = Ca::root("verify test ca");
    ClientCertIdentity::from_der(&build_leaf(&ca, spec).der()).unwrap()
}

fn project(script: &str) -> PathBuf {
    let root = temp_dir("verify");
    std::fs::create_dir_all(root.join("sql/db")).unwrap();
    std::fs::create_dir_all(root.join("http")).unwrap();
    std::fs::write(root.join("sql/db/verify.sql"), script).unwrap();
    root
}

fn row(pairs: &[(&str, SqlValue)]) -> HashMap<String, SqlValue> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
}

#[derive(Debug, Clone, Default)]
struct RecordingDriver {
    calls: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<HashMap<String, SqlValue>>>>,
}

#[async_trait::async_trait]
impl SqlDriver for RecordingDriver {
    async fn query(&self, _script: &str, params: &HashMap<String, SqlValue>) -> Result<Vec<HashMap<String, SqlValue>>, SqlError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.seen.lock().unwrap().push(params.clone());
        Ok(vec![row(&[("active", SqlValue::Bool(true))])])
    }
}

/// Fails with an error message that echoes every bound parameter — the worst
/// case for secret leakage a real driver error can produce.
#[derive(Debug)]
struct EchoingFailDriver;

#[async_trait::async_trait]
impl SqlDriver for EchoingFailDriver {
    async fn query(&self, _script: &str, params: &HashMap<String, SqlValue>) -> Result<Vec<HashMap<String, SqlValue>>, SqlError> {
        Err(SqlError::QueryFailed(format!("syntax error near bound values {params:?}")))
    }
}

#[derive(Debug)]
struct SlowDriver;

#[async_trait::async_trait]
impl SqlDriver for SlowDriver {
    async fn query(&self, _script: &str, _params: &HashMap<String, SqlValue>) -> Result<Vec<HashMap<String, SqlValue>>, SqlError> {
        tokio::time::sleep(Duration::from_secs(5)).await;
        Ok(vec![])
    }
}

fn drivers_of(driver: impl SqlDriver + 'static) -> HashMap<String, Box<dyn SqlDriver>> {
    let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
    drivers.insert("db".to_string(), Box::new(driver));
    drivers
}

async fn run_verify(
    verifier: &LoadedVerifier,
    drivers: &HashMap<String, Box<dyn SqlDriver>>,
    root: &Path,
    headers: &HeaderMap,
    cert: Option<&ClientCertIdentity>,
    cache: &VerifierCache,
    call_timeout: NonZeroU64,
) -> Result<(), VerifyErrorCause> {
    verify(
        "certScheme",
        verifier,
        drivers,
        &root.join("sql"),
        &root.join("http"),
        &reqwest::Client::new(),
        headers,
        cert,
        cache,
        call_timeout,
    )
    .await
}

// ---------------------------------------------------------------------
// the datasource-free mtls verifier
// ---------------------------------------------------------------------

#[tokio::test]
async fn an_mtls_verifier_authorizes_a_certificate_whose_third_dns_san_matches() {
    let verifier = mtls_verifier("cert.san.dns = orders.internal.example.com");
    let id = identity(&LeafSpec::valid());
    let root = project("");
    let result = run_verify(&verifier, &HashMap::new(), &root, &HeaderMap::new(), Some(&id), &VerifierCache::new(), timeout()).await;
    assert!(result.is_ok(), "{result:?}");
}

#[tokio::test]
async fn an_mtls_verifier_rejects_a_non_matching_certificate_as_invalid_credentials() {
    let verifier = mtls_verifier("cert.san.dns = someone-else.example");
    let id = identity(&LeafSpec::valid());
    let root = project("");
    let err = run_verify(&verifier, &HashMap::new(), &root, &HeaderMap::new(), Some(&id), &VerifierCache::new(), timeout())
        .await
        .unwrap_err();
    assert_eq!(err.code(), "auth.invalid_credentials");
}

#[tokio::test]
async fn an_mtls_verifier_given_no_certificate_is_invalid_not_a_panic() {
    let verifier = mtls_verifier("cert.cn = anyone");
    let root = project("");
    let err = run_verify(&verifier, &HashMap::new(), &root, &HeaderMap::new(), None, &VerifierCache::new(), timeout())
        .await
        .unwrap_err();
    assert_eq!(err.code(), "auth.invalid_credentials");
}

#[tokio::test]
async fn an_mtls_verifier_needs_no_datasource_and_never_touches_the_cache() {
    let verifier = mtls_verifier("cert.san.uri = spiffe://example.org/ns/orders");
    let id = identity(&LeafSpec::valid());
    let root = project("");
    let cache = VerifierCache::new();
    // No drivers at all, no sql/http files: it must still succeed.
    let result = run_verify(&verifier, &HashMap::new(), &root.join("nowhere"), &HeaderMap::new(), Some(&id), &cache, timeout()).await;
    assert!(result.is_ok());
    assert!(cache.get(&cache_key("certScheme", Some(id.fingerprint()), &HashMap::new())).is_none());
}

#[tokio::test]
async fn an_mtls_verifier_ignores_spoofed_certificate_headers() {
    let verifier = mtls_verifier("cert.cn = victim.example");
    let id = identity(&LeafSpec::valid());
    let mut headers = HeaderMap::new();
    for name in ["x-forwarded-client-cert", "x-ssl-client-fingerprint", "x-ssl-client-cn", "cert.cn", "cert.san.dns"] {
        headers.insert(axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(), "victim.example".parse().unwrap());
    }
    let root = project("");
    let err = run_verify(&verifier, &HashMap::new(), &root, &headers, Some(&id), &VerifierCache::new(), timeout())
        .await
        .unwrap_err();
    assert_eq!(
        err.code(),
        "auth.invalid_credentials",
        "headers must never substitute for the connection's certificate"
    );
}

// ---------------------------------------------------------------------
// real SQLite-backed verifier on cert.fingerprint
// ---------------------------------------------------------------------

async fn sqlite_drivers() -> HashMap<String, Box<dyn SqlDriver>> {
    let mut settings = HashMap::new();
    settings.insert("database".to_string(), serde_json::Value::String(":memory:".to_string()));
    let config = crate::config::ConnectionConfig {
        driver: "sqlite".to_string(),
        settings,
    };
    let driver = crate::sql::sqlite::SqliteDriver::connect(&config).await.unwrap();
    drivers_of(driver)
}

#[tokio::test]
async fn a_sqlite_backed_verifier_authorizes_only_the_allowlisted_fingerprint() {
    let allowed = identity(&LeafSpec::valid());
    let stranger = identity(&LeafSpec::valid());
    let root = project(&format!("SELECT 1 AS active FROM (SELECT '{}' AS fp) WHERE fp = :fingerprint", allowed.fingerprint()));
    let verifier = sql_cert_verifier(r#"[{ "name": "fingerprint", "from": "cert.fingerprint" }]"#, None);
    let drivers = sqlite_drivers().await;

    let ok = run_verify(
        &verifier_with_valid_if(&verifier, "row.active = 1"),
        &drivers,
        &root,
        &HeaderMap::new(),
        Some(&allowed),
        &VerifierCache::new(),
        timeout(),
    )
    .await;
    assert!(ok.is_ok(), "{ok:?}");

    let err = run_verify(
        &verifier_with_valid_if(&verifier, "row.active = 1"),
        &drivers,
        &root,
        &HeaderMap::new(),
        Some(&stranger),
        &VerifierCache::new(),
        timeout(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), "auth.invalid_credentials", "an unlisted certificate matches no row");
}

fn verifier_with_valid_if(verifier: &LoadedVerifier, valid_if: &str) -> LoadedVerifier {
    let mut json = match &verifier.def {
        VerifierDef::Sql {
            connection,
            script,
            parameters,
            cache_ttl_seconds,
            ..
        } => serde_json::json!({
            "type": "sql",
            "connection": connection,
            "script": script,
            "parameters": parameters.iter().map(|p| serde_json::json!({ "name": p.name, "from": p.from })).collect::<Vec<_>>(),
            "validIf": valid_if,
            "cacheTtlSeconds": cache_ttl_seconds,
        }),
        _ => panic!("sql verifier expected"),
    };
    if json["cacheTtlSeconds"].is_null() {
        json.as_object_mut().unwrap().remove("cacheTtlSeconds");
    }
    loaded(&json.to_string())
}

// ---------------------------------------------------------------------
// bind_credentials
// ---------------------------------------------------------------------

#[test]
fn cert_parameters_bind_the_connections_certificate_fields_as_text() {
    let id = identity(&LeafSpec::valid());
    let verifier = sql_cert_verifier(
        r#"[{ "name": "fp", "from": "cert.fingerprint" }, { "name": "cn", "from": "cert.cn" }, { "name": "iss", "from": "cert.issuer" }, { "name": "ser", "from": "cert.serial" }]"#,
        None,
    );
    let bound = bind_credentials(verifier.def.parameters(), &HeaderMap::new(), Some(&id));
    assert_eq!(bound["fp"], SqlValue::Text(id.fingerprint().to_string()));
    assert_eq!(bound["cn"], SqlValue::Text("client.example.com".into()));
    assert_eq!(bound["iss"], SqlValue::Text("CN=verify test ca".into()));
    assert!(matches!(&bound["ser"], SqlValue::Text(s) if !s.is_empty()));
}

#[test]
fn cert_parameters_bind_null_without_a_certificate_or_for_an_absent_field() {
    let verifier = sql_cert_verifier(r#"[{ "name": "fp", "from": "cert.fingerprint" }, { "name": "cn", "from": "cert.cn" }]"#, None);
    let none = bind_credentials(verifier.def.parameters(), &HeaderMap::new(), None);
    assert_eq!(none["fp"], SqlValue::Null);
    assert_eq!(none["cn"], SqlValue::Null);

    let no_cn = identity(&LeafSpec {
        cn: Vec::new(),
        ..LeafSpec::valid()
    });
    let bound = bind_credentials(verifier.def.parameters(), &HeaderMap::new(), Some(&no_cn));
    assert_eq!(bound["cn"], SqlValue::Null);
    assert!(matches!(bound["fp"], SqlValue::Text(_)));
}

#[test]
fn a_header_can_never_stand_in_for_a_cert_parameter() {
    let verifier = sql_cert_verifier(
        r#"[{ "name": "fp", "from": "cert.fingerprint" }, { "name": "san", "from": "header.cert.san.dns" }]"#,
        None,
    );
    let mut headers = HeaderMap::new();
    for name in ["cert.fingerprint", "x-ssl-client-fingerprint", "x-forwarded-client-cert"] {
        headers.insert(axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(), "evil".parse().unwrap());
    }
    let bound = bind_credentials(verifier.def.parameters(), &headers, None);
    assert_eq!(bound["fp"], SqlValue::Null, "no certificate means Null, whatever headers say");

    let id = identity(&LeafSpec::valid());
    let bound = bind_credentials(verifier.def.parameters(), &headers, Some(&id));
    assert_eq!(bound["fp"], SqlValue::Text(id.fingerprint().to_string()));
}

#[test]
fn header_parameters_still_bind_exactly_as_before() {
    let verifier = loaded(
        r#"{ "type": "sql", "connection": "db", "script": "verify.sql", "parameters": [{ "name": "key", "from": "header.X-Api-Key" }], "validIf": "row.active = true" }"#,
    );
    let mut headers = HeaderMap::new();
    headers.insert("x-api-key", "k".parse().unwrap());
    assert_eq!(bind_credentials(verifier.def.parameters(), &headers, None)["key"], SqlValue::Text("k".into()));
    assert_eq!(bind_credentials(verifier.def.parameters(), &HeaderMap::new(), None)["key"], SqlValue::Null);
}

// ---------------------------------------------------------------------
// cache behaviour
// ---------------------------------------------------------------------

#[tokio::test]
async fn two_certificates_with_the_same_cn_never_share_a_cached_decision() {
    // The verifier binds only cert.cn — the fingerprint must still be folded
    // into the key so cert B can't ride on cert A's cached "yes".
    let verifier = sql_cert_verifier(r#"[{ "name": "cn", "from": "cert.cn" }]"#, Some(60));
    let (a, b) = (identity(&LeafSpec::valid()), identity(&LeafSpec::valid()));
    assert_eq!(a.bind_value(CertField::Cn), b.bind_value(CertField::Cn));
    assert_ne!(a.fingerprint(), b.fingerprint());

    let driver = RecordingDriver::default();
    let calls = driver.calls.clone();
    let drivers = drivers_of(driver);
    let root = project("SELECT 1");
    let cache = VerifierCache::new();

    run_verify(&verifier, &drivers, &root, &HeaderMap::new(), Some(&a), &cache, timeout()).await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    run_verify(&verifier, &drivers, &root, &HeaderMap::new(), Some(&b), &cache, timeout()).await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2, "certificate B must trigger its own datasource call");
    run_verify(&verifier, &drivers, &root, &HeaderMap::new(), Some(&a), &cache, timeout()).await.unwrap();
    run_verify(&verifier, &drivers, &root, &HeaderMap::new(), Some(&b), &cache, timeout()).await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2, "repeat calls with the same certificates are served from the cache");
}

#[tokio::test]
async fn a_cache_hit_for_one_scheme_name_is_not_reused_by_another_scheme_with_the_same_parameters() {
    let verifier = sql_cert_verifier(r#"[{ "name": "cn", "from": "cert.cn" }]"#, Some(60));
    let id = identity(&LeafSpec::valid());
    let driver = RecordingDriver::default();
    let calls = driver.calls.clone();
    let drivers = drivers_of(driver);
    let root = project("SELECT 1");
    let cache = VerifierCache::new();
    let client = reqwest::Client::new();
    for scheme in ["schemeA", "schemeB", "schemeA"] {
        verify(
            scheme,
            &verifier,
            &drivers,
            &root.join("sql"),
            &root.join("http"),
            &client,
            &HeaderMap::new(),
            Some(&id),
            &cache,
            timeout(),
        )
        .await
        .unwrap();
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2, "A, B each miss once; the second A hits");
}

fn key(scheme: &str, fp: Option<&str>, pairs: &[(&str, SqlValue)]) -> String {
    let bound: HashMap<String, SqlValue> = pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
    cache_key(scheme, fp, &bound)
}

fn text(s: &str) -> SqlValue {
    SqlValue::Text(s.to_string())
}

#[test]
fn cache_keys_are_v2_prefixed_fixed_width_lowercase_hex() {
    let k = key("s", None, &[("a", text("b"))]);
    assert!(k.starts_with("v2:"));
    assert_eq!(k.len(), 3 + 64);
    assert!(k[3..].chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()), "{k}");
    // Fixed width regardless of how large the credential is.
    assert_eq!(key("s", None, &[("a", text(&"x".repeat(100_000)))]).len(), 3 + 64);
}

#[test]
fn cache_keys_are_deterministic_and_independent_of_parameter_order() {
    let a = key("s", Some("fp"), &[("x", text("1")), ("y", text("2")), ("z", text("3"))]);
    let b = key("s", Some("fp"), &[("z", text("3")), ("x", text("1")), ("y", text("2"))]);
    assert_eq!(a, b);
}

#[test]
fn a_name_containing_the_old_delimiter_cannot_alias_a_two_parameter_split() {
    let ambiguous_cn = "x\u{1}cert.fingerprint=abc";
    let one = key("s", Some("fp"), &[("cn", text(ambiguous_cn))]);
    // Under the old "scheme \u{1}name=value" join, this is the same string.
    let split = key("s", Some("fp"), &[("cn", text("x")), ("cert.fingerprint", text("abc"))]);
    assert_ne!(one, split);

    let one = key("s", None, &[("cn", text("x\u{1}fp=abc"))]);
    let split = key("s", None, &[("cn", text("x")), ("fp", text("abc"))]);
    assert_ne!(one, split);
}

#[test]
fn a_header_value_with_the_old_delimiter_and_pair_differs_from_two_real_parameters() {
    let one = key("s", None, &[("key", text("v\u{1}k=v2"))]);
    let two = key("s", None, &[("key", text("v")), ("k", text("v2"))]);
    assert_ne!(one, two);
}

#[test]
fn length_prefixing_separates_adjacent_names_and_values() {
    assert_ne!(key("s", None, &[("ab", text("c"))]), key("s", None, &[("a", text("bc"))]));
    assert_ne!(key("ab", None, &[("c", text("d"))]), key("a", None, &[("bc", text("d"))]));
    assert_ne!(key("s", None, &[("a", text("b")), ("c", text("d"))]), key("s", None, &[("a", text("bcd"))]));
}

#[test]
fn null_empty_text_and_other_types_never_collide() {
    let null = key("s", None, &[("a", SqlValue::Null)]);
    let empty = key("s", None, &[("a", text(""))]);
    assert_ne!(null, empty);

    let variants = [
        key("s", None, &[("a", SqlValue::Bool(true))]),
        key("s", None, &[("a", text("true"))]),
        key("s", None, &[("a", SqlValue::Int(1))]),
        key("s", None, &[("a", text("1"))]),
        key("s", None, &[("a", SqlValue::Float(1.0))]),
        key("s", None, &[("a", text("1"))]),
    ];
    for i in 0..variants.len() {
        for j in (i + 1)..variants.len() {
            // variants[3] and [5] are the same text "1" on purpose.
            if (i, j) == (3, 5) {
                assert_eq!(variants[i], variants[j]);
            } else {
                assert_ne!(variants[i], variants[j], "variants {i} and {j} collided");
            }
        }
    }
}

#[test]
fn the_same_parameters_under_different_scheme_names_differ() {
    assert_ne!(key("schemeA", None, &[("k", text("v"))]), key("schemeB", None, &[("k", text("v"))]));
}

#[test]
fn the_certificate_fingerprint_is_part_of_the_key_for_cert_dependent_verifiers_only() {
    let a = key("s", Some("aaaa"), &[("cn", text("same"))]);
    let b = key("s", Some("bbbb"), &[("cn", text("same"))]);
    assert_ne!(a, b);
    assert_ne!(
        key("s", Some(""), &[]),
        key("s", None, &[]),
        "a cert-dependent verifier with no cert must not share a key with a header-only one"
    );
    // A header-only verifier (fingerprint = None) never varies with a cert.
    assert_eq!(key("s", None, &[("k", text("v"))]), key("s", None, &[("k", text("v"))]));
}

// ---------------------------------------------------------------------
// error redaction
// ---------------------------------------------------------------------

#[tokio::test]
async fn a_datasource_error_for_a_cert_verifier_is_a_fixed_message_and_logs_nothing_sensitive_at_info() {
    let id = identity(&LeafSpec {
        cn: vec!["very-secret-cn-77".into()],
        ..LeafSpec::valid()
    });
    let verifier = sql_cert_verifier(r#"[{ "name": "fp", "from": "cert.fingerprint" }, { "name": "cn", "from": "cert.cn" }]"#, None);
    let drivers = drivers_of(EchoingFailDriver);
    let root = project("SELECT 1");

    let logs = LogBuffer::default();
    let guard = logs.install(tracing::Level::INFO);
    let err = run_verify(&verifier, &drivers, &root, &HeaderMap::new(), Some(&id), &VerifierCache::new(), timeout())
        .await
        .unwrap_err();
    drop(guard);

    assert_eq!(err.code(), "auth.verifier_unavailable");
    let message = err.message();
    assert_eq!(message, "verifier datasource error (connection 'db')");
    assert!(!message.contains(id.fingerprint()) && !message.contains("very-secret-cn-77"), "{message}");
    let log_text = logs.text();
    assert!(
        !log_text.contains(id.fingerprint()) && !log_text.contains("very-secret-cn-77"),
        "INFO log leaked: {log_text}"
    );
}

#[tokio::test]
async fn the_raw_detail_of_a_cert_verifier_error_is_only_available_at_debug() {
    let id = identity(&LeafSpec::valid());
    let verifier = sql_cert_verifier(r#"[{ "name": "fp", "from": "cert.fingerprint" }]"#, None);
    let drivers = drivers_of(EchoingFailDriver);
    let root = project("SELECT 1");
    let logs = LogBuffer::default();
    let guard = logs.install(tracing::Level::DEBUG);
    let _ = run_verify(&verifier, &drivers, &root, &HeaderMap::new(), Some(&id), &VerifierCache::new(), timeout()).await;
    drop(guard);
    assert!(
        logs.text().contains("syntax error near bound values"),
        "debug logging should still carry the raw detail for operators: {}",
        logs.text()
    );
}

#[tokio::test]
async fn a_header_only_verifiers_driver_error_text_is_unchanged() {
    let verifier = loaded(
        r#"{ "type": "sql", "connection": "db", "script": "verify.sql", "parameters": [{ "name": "key", "from": "header.X-Api-Key" }], "validIf": "row.active = true" }"#,
    );
    let drivers = drivers_of(EchoingFailDriver);
    let root = project("SELECT 1");
    let mut headers = HeaderMap::new();
    headers.insert("x-api-key", "k".parse().unwrap());
    let err = run_verify(&verifier, &drivers, &root, &headers, None, &VerifierCache::new(), timeout())
        .await
        .unwrap_err();
    assert!(err.message().contains("syntax error near bound values"), "{}", err.message());
}

#[tokio::test]
async fn a_cert_verifiers_missing_script_error_does_not_leak_a_filesystem_path() {
    let id = identity(&LeafSpec::valid());
    let verifier = sql_cert_verifier(r#"[{ "name": "fp", "from": "cert.fingerprint" }]"#, None);
    let drivers = drivers_of(RecordingDriver::default());
    let root = temp_dir("verify-noscript");
    let err = run_verify(&verifier, &drivers, &root, &HeaderMap::new(), Some(&id), &VerifierCache::new(), timeout())
        .await
        .unwrap_err();
    assert_eq!(err.code(), "auth.verifier_unavailable");
    assert!(!err.message().contains(&root.display().to_string()), "{}", err.message());
    assert!(err.message().contains("verify.sql"));
}

#[tokio::test]
async fn a_cert_verifiers_timeout_message_is_fixed_and_never_cached() {
    let id = identity(&LeafSpec::valid());
    let verifier = sql_cert_verifier(r#"[{ "name": "fp", "from": "cert.fingerprint" }]"#, Some(60));
    let drivers = drivers_of(SlowDriver);
    let root = project("SELECT 1");
    let cache = VerifierCache::new();
    let err = run_verify(&verifier, &drivers, &root, &HeaderMap::new(), Some(&id), &cache, NonZeroU64::new(50).unwrap())
        .await
        .unwrap_err();
    assert_eq!(err.code(), "auth.verifier_unavailable");
    assert_eq!(err.message(), "verifier query did not complete within 50ms");
    let key = cache_key(
        "certScheme",
        Some(id.fingerprint()),
        &bind_credentials(verifier.def.parameters(), &HeaderMap::new(), Some(&id)),
    );
    assert!(cache.get(&key).is_none());
}

// ---------------------------------------------------------------------
// generic ValidIf is unchanged
// ---------------------------------------------------------------------

#[test]
fn the_generic_valid_if_still_compares_whole_json_values_so_an_array_never_equals_a_scalar() {
    let valid_if = ValidIf::parse("row.tags = a").unwrap();
    assert!(valid_if.evaluate(&serde_json::json!({ "tags": "a" })));
    assert!(
        !valid_if.evaluate(&serde_json::json!({ "tags": ["a"] })),
        "generic ValidIf must NOT gain any-of array semantics"
    );
    assert!(!valid_if.evaluate(&serde_json::json!({ "tags": ["a", "b"] })));
    let numeric = ValidIf::parse("row.active = 1").unwrap();
    assert!(numeric.evaluate(&serde_json::json!({ "active": 1 })));
    assert!(!numeric.evaluate(&serde_json::json!({ "active": "1" })));
}
