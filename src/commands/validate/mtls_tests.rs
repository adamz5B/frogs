use super::*;
use crate::server::test_pki::*;
use std::fs;

fn tls_dir(pki: &Pki) -> PathBuf {
    ensure_crypto_provider();
    let dir = temp_dir("validate-tls");
    write_basic_tls_files(&dir, pki);
    dir
}

fn problems_for(dir: &Path, client_auth: Option<&str>) -> usize {
    validate_tls("test", &tls_config(client_auth), dir)
}

// ----- validate_tls: what counts as a problem -----

#[test]
fn tls_off_has_nothing_to_validate() {
    assert_eq!(validate_tls("test", &TlsConfig::default(), &temp_dir("validate-tls")), 0);
}

#[test]
fn a_complete_valid_tls_setup_with_and_without_client_auth_has_no_problems() {
    let dir = tls_dir(&Pki::new());
    assert_eq!(problems_for(&dir, None), 0);
    assert_eq!(problems_for(&dir, Some(r#"{ "mode": "off" }"#)), 0);
    assert_eq!(problems_for(&dir, Some(r#"{ "mode": "required", "caPath": "client-ca.pem" }"#)), 0);
}

#[test]
fn missing_server_cert_files_are_a_problem_now_that_validate_dry_runs_them() {
    assert_eq!(problems_for(&temp_dir("validate-tls"), None), 1);
}

#[test]
fn structural_errors_are_one_problem_each() {
    let dir = tls_dir(&Pki::new());
    assert_eq!(problems_for(&dir, Some(r#"{ "mode": "off", "caPath": "client-ca.pem" }"#)), 1);
    assert_eq!(problems_for(&dir, Some(r#"{ "mode": "required" }"#)), 1, "missing caPath");
    assert_eq!(
        problems_for(&dir, Some(r#"{ "mode": "required", "caPath": "client-ca.pem", "crlPolicy": "bestEffort" }"#)),
        1,
        "policy without crls"
    );
    let off_tls: TlsConfig = serde_json::from_str(r#"{ "mode": "off", "clientAuth": { "mode": "required", "caPath": "client-ca.pem" } }"#).unwrap();
    assert_eq!(validate_tls("test", &off_tls, &dir), 1, "clientAuth over plain HTTP");
}

#[test]
fn unreadable_ca_and_crl_files_are_problems() {
    let dir = tls_dir(&Pki::new());
    assert_eq!(problems_for(&dir, Some(r#"{ "mode": "required", "caPath": "absent.pem" }"#)), 1);
    fs::write(dir.join("junk.crl"), "junk").unwrap();
    assert_eq!(
        problems_for(&dir, Some(r#"{ "mode": "required", "caPath": "client-ca.pem", "crlPaths": ["junk.crl"] }"#)),
        1
    );
}

#[test]
fn an_already_expired_crl_is_a_problem_under_fail_closed() {
    let pki = Pki::new();
    let dir = tls_dir(&pki);
    fs::write(dir.join("old.crl"), pki.client_ca.crl_pem(&[], now_unix() - 10 * DAY, now_unix() - DAY)).unwrap();
    assert_eq!(
        problems_for(&dir, Some(r#"{ "mode": "required", "caPath": "client-ca.pem", "crlPaths": ["old.crl"] }"#)),
        1
    );
    assert_eq!(
        problems_for(
            &dir,
            Some(r#"{ "mode": "required", "caPath": "client-ca.pem", "crlPaths": ["old.crl"], "crlPolicy": "failClosed" }"#)
        ),
        1,
        "explicit failClosed is the same as the default"
    );
}

// ----- warnings are printed but never counted -----

#[test]
fn an_expired_crl_under_best_effort_is_only_a_warning() {
    let pki = Pki::new();
    let dir = tls_dir(&pki);
    fs::write(dir.join("old.crl"), pki.client_ca.crl_pem(&[], now_unix() - 10 * DAY, now_unix() - DAY)).unwrap();
    assert_eq!(
        problems_for(
            &dir,
            Some(r#"{ "mode": "required", "caPath": "client-ca.pem", "crlPaths": ["old.crl"], "crlPolicy": "bestEffort" }"#)
        ),
        0
    );
}

#[test]
fn a_crl_expiring_within_a_week_is_only_a_warning_under_either_policy() {
    let pki = Pki::new();
    let dir = tls_dir(&pki);
    fs::write(dir.join("soon.crl"), pki.client_ca.crl_pem(&[], now_unix() - DAY, now_unix() + 3 * DAY)).unwrap();
    for policy in ["failClosed", "bestEffort"] {
        let block = format!(r#"{{ "mode": "required", "caPath": "client-ca.pem", "crlPaths": ["soon.crl"], "crlPolicy": "{policy}" }}"#);
        assert_eq!(problems_for(&dir, Some(&block)), 0, "{policy}");
    }
}

#[test]
fn no_crls_and_a_disabled_eku_requirement_are_only_warnings() {
    let dir = tls_dir(&Pki::new());
    assert_eq!(problems_for(&dir, Some(r#"{ "mode": "required", "caPath": "client-ca.pem" }"#)), 0, "no crlPaths");
    assert_eq!(
        problems_for(&dir, Some(r#"{ "mode": "optional", "caPath": "client-ca.pem", "requireClientAuthEku": false }"#)),
        0
    );
}

// ----- validate_api: the project-level cross-checks -----

const MTLS_VERIFIER: &str = r#"{ "type": "mtls", "validIf": "cert.san.dns = orders.internal.example.com" }"#;
const API_KEY_VERIFIER: &str =
    r#"{ "type": "sql", "connection": "db", "script": "v.sql", "parameters": [{ "name": "k", "from": "header.X-Api-Key" }], "validIf": "row.active = true" }"#;
const SECURED_ENDPOINT: &str = r#"{ "operationId": "getOrders", "security": "certAuth", "sources": {}, "response": {} }"#;

fn openapi_with_mutual_tls() -> &'static str {
    "openapi: 3.1.0\ninfo: { title: t, version: '1' }\n\
     paths:\n  /orders:\n    get:\n      operationId: getOrders\n      security: [{ certAuth: [] }]\n      responses: { '200': { description: ok } }\n\
     components:\n  securitySchemes:\n    certAuth: { type: mutualTLS }\n"
}

/// An API project with one cert-protected endpoint. `client_auth` is the
/// `tls.clientAuth` block (or none, with TLS entirely off).
fn api_project(verifier: &str, client_auth: Option<&str>) -> PathBuf {
    ensure_crypto_provider();
    let root = temp_dir("validate-api");
    fs::write(root.join(MANIFEST_FILE), openapi_with_mutual_tls()).unwrap();
    let api = root.join("api");
    for dir in ["config", "security/verifiers", "datasources/endpoints/orders"] {
        fs::create_dir_all(api.join(dir)).unwrap();
    }
    let server = match client_auth {
        Some(block) => {
            write_basic_tls_files(&api, &Pki::new());
            format!(r#"{{ "tls": {{ "mode": "manual", "manual": {{ "certPath": "cert.pem", "keyPath": "key.pem" }}, "clientAuth": {block} }} }}"#)
        }
        None => "{}".to_string(),
    };
    fs::write(api.join("config/server.json"), server).unwrap();
    fs::write(api.join("security/schemes.json"), r#"{ "certAuth": { "verifier": "cert.json" } }"#).unwrap();
    fs::write(api.join("security/verifiers/cert.json"), verifier).unwrap();
    fs::write(api.join("datasources/endpoints/orders/endpoint.get.json"), SECURED_ENDPOINT).unwrap();
    root
}

#[tokio::test]
async fn a_cert_dependent_route_with_client_auth_off_is_one_problem() {
    let root = api_project(MTLS_VERIFIER, None);
    assert_eq!(validate_api(&root).await, 1);
}

#[tokio::test]
async fn a_cert_dependent_route_with_client_auth_enabled_is_clean() {
    let root = api_project(MTLS_VERIFIER, Some(r#"{ "mode": "optional", "caPath": "client-ca.pem" }"#));
    assert_eq!(validate_api(&root).await, 0);
}

#[tokio::test]
async fn required_mode_with_probes_enabled_is_a_note_not_a_problem() {
    let root = api_project(MTLS_VERIFIER, Some(r#"{ "mode": "required", "caPath": "client-ca.pem" }"#));
    // readyz is on by default, so the probes note applies — and must not be counted.
    assert_eq!(validate_api(&root).await, 0);
}

#[tokio::test]
async fn a_mutual_tls_operation_whose_verifier_ignores_the_certificate_is_one_problem() {
    let root = api_project(API_KEY_VERIFIER, Some(r#"{ "mode": "optional", "caPath": "client-ca.pem" }"#));
    assert_eq!(
        validate_api(&root).await,
        1,
        "an apiKey-style verifier on a mutualTLS operation authorizes nobody in particular"
    );
}

#[tokio::test]
async fn a_broken_client_auth_block_inside_a_project_is_counted_once() {
    let root = api_project(MTLS_VERIFIER, Some(r#"{ "mode": "optional", "caPath": "does-not-exist.pem" }"#));
    assert_eq!(validate_api(&root).await, 1);
}

#[tokio::test]
async fn an_expired_fail_closed_crl_in_a_project_is_counted() {
    let pki = Pki::new();
    let root = api_project(MTLS_VERIFIER, Some(r#"{ "mode": "optional", "caPath": "client-ca.pem", "crlPaths": ["old.crl"] }"#));
    // Regenerate the TLS files from this test's PKI so the CRL's issuer is the configured CA.
    write_basic_tls_files(&root.join("api"), &pki);
    fs::write(root.join("api/old.crl"), pki.client_ca.crl_pem(&[], now_unix() - 10 * DAY, now_unix() - DAY)).unwrap();
    assert_eq!(validate_api(&root).await, 1);
}

#[test]
fn validate_web_dry_runs_a_standalone_web_projects_tls_and_ignores_it_when_an_api_role_exists() {
    ensure_crypto_provider();
    let root = temp_dir("validate-web");
    fs::write(
        root.join("webserve.json"),
        r#"{ "startPage": "index.html", "tls": { "mode": "manual", "manual": { "certPath": "missing.pem", "keyPath": "missing.key" } } }"#,
    )
    .unwrap();
    assert_eq!(validate_web(&root), 1, "web-only: the certs are dry-run");

    fs::write(root.join(MANIFEST_FILE), "openapi: 3.0.3\ninfo: { title: t, version: '1' }\npaths: {}\n").unwrap();
    assert_eq!(
        validate_web(&root),
        0,
        "with an API role, server.json's tls is authoritative and webserve.json's is ignored"
    );
}

#[test]
fn validate_web_reports_client_auth_structure_errors() {
    let root = temp_dir("validate-web");
    fs::write(
        root.join("webserve.json"),
        r#"{ "startPage": "index.html", "tls": { "mode": "off", "clientAuth": { "mode": "required", "caPath": "ca.pem" } } }"#,
    )
    .unwrap();
    assert_eq!(validate_web(&root), 1);
}
