use std::collections::HashMap;
use std::path::PathBuf;

use axum::http::HeaderMap;
use serde_json::Value;

use super::schema::{TestCase, TestFile};
use super::session::{LoadedTestFile, MockSession, ReportConfig};
use super::validate::validate_corpus;
use super::{ReportFormat, load};
use crate::endpoint::EndpointFile;
use crate::endpoint::mock::{InboundRequest, MockProvider, MockSelection, RouteKey};
use crate::security::MtlsCondition;
use crate::server::test_pki::temp_dir;

fn route() -> RouteKey {
    RouteKey {
        method: "get".to_string(),
        path: "/orders".to_string(),
    }
}

fn case_json(extra: &str) -> String {
    format!(r#"{{ "name": "c", "request": {{}}, "expect": {{}}{extra} }}"#)
}

fn case_with(extra: &str) -> TestCase {
    serde_json::from_str(&case_json(extra)).unwrap_or_else(|e| panic!("{extra}: {e}"))
}

fn write_and_load(cases: &str) -> Result<TestFile, super::TestLoadError> {
    let dir = temp_dir("testing");
    let path = dir.join("endpoint.get.test.json");
    std::fs::write(&path, format!(r#"{{ "cases": [{cases}] }}"#)).unwrap();
    load(&path)
}

fn matches(case: &TestCase, expr: &str) -> bool {
    MtlsCondition::compile(expr)
        .unwrap()
        .matches(&case.client_cert.as_ref().expect("clientCert present").to_identity())
}

// ----- schema -----

#[test]
fn a_san_dns_array_is_any_of_so_a_condition_matching_only_the_second_entry_holds() {
    let case = case_with(r#", "clientCert": { "san": { "dns": ["a.example", "b.example", "c.example"] } }"#);
    assert!(matches(&case, "cert.san.dns = b.example"));
    assert!(matches(&case, "cert.san.dns = c.example"));
    assert!(!matches(&case, "cert.san.dns = d.example"));
}

#[test]
fn a_san_string_is_the_same_as_a_one_element_array() {
    let scalar = case_with(r#", "clientCert": { "san": { "dns": "a.example", "uri": "spiffe://x/y", "email": "u@example.com" } }"#);
    let list = case_with(r#", "clientCert": { "san": { "dns": ["a.example"], "uri": ["spiffe://x/y"], "email": ["u@example.com"] } }"#);
    assert_eq!(
        scalar.client_cert.as_ref().unwrap().to_identity().to_json(),
        list.client_cert.as_ref().unwrap().to_identity().to_json()
    );
    assert!(matches(&scalar, "cert.san.uri = spiffe://x/y"));
}

#[test]
fn every_scalar_field_flows_into_the_identity() {
    let case = case_with(
        r#", "clientCert": { "cn": "svc", "subject": "CN=svc", "issuer": "CN=ca", "serial": "0A:0b", "fingerprint": "AB:cd", "notAfter": "2999-01-01T00:00:00Z" }"#,
    );
    assert!(matches(&case, "cert.cn = svc"));
    assert!(matches(&case, "cert.subject = CN=svc"));
    assert!(matches(&case, "cert.issuer = CN=ca"));
    assert!(matches(&case, "cert.serial = 0a0b"));
    assert!(matches(&case, "cert.fingerprint = abcd"));
    assert!(matches(&case, "cert.notAfter = 2999-01-01T00:00:00Z"));
}

#[test]
fn a_not_after_in_the_past_is_expired_and_an_absent_one_never_is() {
    let past = case_with(r#", "clientCert": { "notAfter": "2001-01-01T00:00:00Z" }"#)
        .client_cert
        .unwrap()
        .to_identity();
    assert!(!past.is_valid_at(chrono::Utc::now()));
    let future = case_with(r#", "clientCert": { "notAfter": "2999-01-01T00:00:00Z" }"#)
        .client_cert
        .unwrap()
        .to_identity();
    assert!(future.is_valid_at(chrono::Utc::now()));
    let absent = case_with(r#", "clientCert": { "cn": "x" }"#).client_cert.unwrap().to_identity();
    assert!(absent.is_valid_at(chrono::Utc::now()));
}

#[test]
fn client_cert_is_omitted_from_serialization_when_absent_and_round_trips_when_present() {
    let without = case_with("");
    assert!(without.client_cert.is_none());
    assert!(!serde_json::to_string(&without).unwrap().contains("clientCert"));

    let with = case_with(r#", "clientCert": { "cn": "svc", "san": { "dns": ["a.example", "b.example"], "uri": "spiffe://x" } }"#);
    let text = serde_json::to_string(&with).unwrap();
    assert!(text.contains("clientCert"), "{text}");
    let back: TestCase = serde_json::from_str(&text).unwrap();
    assert_eq!(back.client_cert, with.client_cert);
    assert!(!text.contains("\"issuer\""), "unset fields stay omitted: {text}");
}

#[test]
fn unknown_fields_and_wrong_types_inside_client_cert_fail_to_parse() {
    for bad in [
        r#", "clientCert": { "commonName": "x" }"#,
        r#", "clientCert": { "san": { "ip": "1.2.3.4" } }"#,
        r#", "clientCert": { "san": { "dns": 5 } }"#,
        r#", "clientCert": { "san": { "dns": [1] } }"#,
        r#", "clientCert": { "cn": 5 }"#,
        r#", "clientCert": "oops""#,
    ] {
        assert!(serde_json::from_str::<TestCase>(&case_json(bad)).is_err(), "{bad} should not parse");
    }
}

#[test]
fn load_rejects_a_control_character_in_any_client_cert_value_naming_the_case() {
    for (what, cert) in [
        ("cn", r#"{ "cn": "a\u0001b" }"#),
        ("subject", r#"{ "subject": "CN=a\u007fb" }"#),
        ("san.dns", r#"{ "san": { "dns": ["ok.example", "a\u0001b.example"] } }"#),
        ("san.email", r#"{ "san": { "email": "a\u0085@example.com" } }"#),
    ] {
        let err = write_and_load(&format!(r#"{{ "name": "bad case", "request": {{}}, "expect": {{}}, "clientCert": {cert} }}"#))
            .expect_err(what)
            .to_string();
        assert!(err.contains("control character") && err.contains("bad case"), "{what}: {err}");
    }
}

#[test]
fn load_rejects_a_non_rfc3339_not_after() {
    let err = write_and_load(r#"{ "name": "n", "request": {}, "expect": {}, "clientCert": { "notAfter": "tomorrow" } }"#)
        .unwrap_err()
        .to_string();
    assert!(err.contains("notAfter") && err.contains("RFC 3339"), "{err}");
}

#[test]
fn load_accepts_a_wholly_valid_client_cert() {
    let file = write_and_load(
        r#"{ "name": "n", "request": {}, "expect": {}, "clientCert": { "cn": "ok", "notAfter": "2999-01-01T00:00:00+02:00", "san": { "dns": ["a.example"] } } }"#,
    )
    .unwrap();
    assert!(file.cases[0].client_cert.is_some());
}

// ----- session selection -----

fn loaded(cases_json: &str, endpoint: Option<EndpointFile>) -> LoadedTestFile {
    LoadedTestFile {
        route: route(),
        path: PathBuf::from("unused"),
        file: serde_json::from_str(cases_json).unwrap(),
        endpoint,
    }
}

fn select_with(session: &MockSession, headers: &HeaderMap) -> MockSelection {
    let (path, query, body) = (HashMap::new(), HashMap::new(), Value::Null);
    session.select(
        &route(),
        &InboundRequest {
            path_params: &path,
            query_params: &query,
            headers,
            body: &body,
        },
    )
}

fn session(cases_json: &str) -> std::sync::Arc<MockSession> {
    MockSession::new(
        vec![loaded(cases_json, None)],
        None,
        ReportConfig {
            format: ReportFormat::Text,
            file: None,
        },
    )
    .unwrap()
}

#[test]
fn select_carries_the_matched_cases_client_cert_as_an_identity() {
    let session =
        session(r#"{ "cases": [ { "name": "c", "request": {}, "expect": {}, "clientCert": { "cn": "svc", "san": { "dns": ["x.example", "y.example"] } } } ] }"#);
    match select_with(&session, &HeaderMap::new()) {
        MockSelection::Case { client_cert, .. } => {
            let identity = client_cert.expect("the case's clientCert must reach the selection");
            assert!(MtlsCondition::compile("cert.san.dns = y.example").unwrap().matches(&identity));
            assert!(MtlsCondition::compile("cert.cn = svc").unwrap().matches(&identity));
        }
        other => panic!("expected Case, got {other:?}"),
    }
}

#[test]
fn select_has_no_identity_for_a_case_without_client_cert() {
    let session = session(r#"{ "cases": [ { "name": "c", "request": {}, "expect": {} } ] }"#);
    match select_with(&session, &HeaderMap::new()) {
        MockSelection::Case { client_cert, .. } => assert!(client_cert.is_none()),
        other => panic!("expected Case, got {other:?}"),
    }
}

#[test]
fn client_cert_is_not_a_matching_constraint_it_rides_along_with_whichever_case_matched() {
    let session = session(
        r#"{ "cases": [
            { "name": "first", "request": {}, "expect": {}, "clientCert": { "cn": "one" } },
            { "name": "second", "request": {}, "expect": {}, "clientCert": { "cn": "two" } }
        ] }"#,
    );
    match select_with(&session, &HeaderMap::new()) {
        MockSelection::Case { case, client_cert, .. } => {
            assert_eq!(case.unwrap().name, "first");
            assert!(MtlsCondition::compile("cert.cn = one").unwrap().matches(&client_cert.unwrap()));
        }
        other => panic!("expected Case, got {other:?}"),
    }
}

#[test]
fn a_request_header_can_never_supply_the_client_cert() {
    let session = session(r#"{ "cases": [ { "name": "c", "request": {}, "expect": {} } ] }"#);
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-client-cert", "Subject=evil".parse().unwrap());
    headers.insert("clientcert", "{\"cn\":\"evil\"}".parse().unwrap());
    match select_with(&session, &headers) {
        MockSelection::Case { client_cert, .. } => assert!(client_cert.is_none()),
        other => panic!("expected Case, got {other:?}"),
    }
}

// ----- corpus validation -----

fn endpoint(json: &str) -> EndpointFile {
    serde_json::from_str(json).unwrap()
}

#[test]
fn the_corpus_warns_about_a_client_cert_on_an_endpoint_without_security_and_only_then() {
    let cases = r#"{ "cases": [ { "name": "c", "request": {}, "expect": {}, "clientCert": { "cn": "x" } } ] }"#;
    let unsecured = r#"{ "operationId": "o", "sources": {}, "response": {} }"#;
    let secured = r#"{ "operationId": "o", "security": "certAuth", "sources": {}, "response": {} }"#;

    let warnings = validate_corpus(&[loaded(cases, Some(endpoint(unsecured)))], &HashMap::from([(route(), endpoint(unsecured))]));
    assert_eq!(warnings.iter().filter(|w| w.contains("clientCert")).count(), 1, "{warnings:?}");
    assert!(warnings.iter().any(|w| w.contains("no security scheme")), "{warnings:?}");

    let warnings = validate_corpus(&[loaded(cases, Some(endpoint(secured)))], &HashMap::from([(route(), endpoint(secured))]));
    assert!(warnings.iter().all(|w| !w.contains("clientCert")), "{warnings:?}");
}
