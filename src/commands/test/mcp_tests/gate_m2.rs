//! MCP Milestone 2 under `frogs test`: the `accessScheme` gate runs the real `authorize` with the
//! reserved `verifier` mock read from `api/datasources/mcp-gate.test.json`, and never dials anything.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};

use crate::endpoint::mock::MockProvider as _;

use super::*;

const GATE_SERVER: &str = r#"{ "features": { "mcp": true, "requestValidation": false, "metrics": false, "readyzCheck": false }, "mcp": { "accessScheme": "oauth" } }"#;

const SQL_GATE: &str = r#"{ "type": "sql", "connection": "db", "script": "verify.sql", "parameters": [ { "name": "k", "from": "header.Authorization" } ], "validIf": "row.active = true", "scopesFrom": "row.scope" }"#;
const MTLS_GATE: &str = r#"{ "type": "mtls", "validIf": "cert.cn = client.example.com" }"#;

fn gate_project(verifier_json: &str, gate_file: Option<&str>) -> PathBuf {
    let root = project(GATE_SERVER);
    let api = root.join("api");
    std::fs::create_dir_all(api.join("security/verifiers")).unwrap();
    std::fs::write(api.join("security/schemes.json"), r#"{ "oauth": { "verifier": "v.json" } }"#).unwrap();
    std::fs::write(api.join("security/verifiers/v.json"), verifier_json).unwrap();
    std::fs::write(api.join("datasources/sql/db/verify.sql"), "SELECT 'REAL' AS active;").unwrap();
    if let Some(contents) = gate_file {
        std::fs::write(api.join("datasources/mcp-gate.test.json"), contents).unwrap();
    }
    root
}

fn list() -> Value {
    json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" })
}

async fn counting_listener() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = accepted.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { break };
            counter.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });
    (addr, accepted)
}

/// An http-verifier gate whose request file points at `addr`.
fn http_gate_project(addr: SocketAddr, gate_file: Option<&str>) -> PathBuf {
    let root = project(GATE_SERVER);
    let api = root.join("api");
    std::fs::create_dir_all(api.join("security/verifiers")).unwrap();
    std::fs::create_dir_all(api.join("datasources/http")).unwrap();
    std::fs::write(api.join("security/schemes.json"), r#"{ "oauth": { "verifier": "v.json" } }"#).unwrap();
    std::fs::write(
        api.join("security/verifiers/v.json"),
        r#"{ "type": "http", "request": "introspect.json", "parameters": [ { "name": "token", "from": "header.Authorization" } ], "validIf": "response.active = true", "scopesFrom": "response.scope" }"#,
    )
    .unwrap();
    std::fs::write(
        api.join("datasources/http/introspect.json"),
        format!(r#"{{ "method": "GET", "url": "http://{addr}/introspect?token={{{{token}}}}", "timeoutMs": 2000 }}"#),
    )
    .unwrap();
    if let Some(contents) = gate_file {
        std::fs::write(api.join("datasources/mcp-gate.test.json"), contents).unwrap();
    }
    root
}

const FIXED_DENIAL: &str = r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32600,"message":"Unauthorized"}}"#;
const FIXED_LIST_OUTAGE: &str = r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32603,"message":"Internal error"}}"#;

#[tokio::test]
async fn a_gate_mock_value_that_satisfies_valid_if_lets_the_list_and_the_call_through_without_credentials() {
    let root = gate_project(SQL_GATE, Some(r#"{ "verifier": { "active": true, "scope": "cars.read" } }"#));
    let (addr, _session) = serve(&root).await;
    let (status, listed) = post_mcp(addr, &[], list()).await;
    assert_eq!(status, 200, "{listed}");
    assert_eq!(listed["result"]["tools"][0]["name"], "getCar");
    let (status, reply) = post_mcp(addr, &[], call("H1")).await;
    assert_eq!(status, 200);
    assert_eq!(serde_json::from_str::<Value>(&text(&reply)).unwrap(), json!({ "maker": "Honda" }));
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn a_gate_mock_value_failing_valid_if_or_a_mocked_invalid_credentials_failure_is_the_fixed_401() {
    for file in [r#"{ "verifier": { "active": false } }"#, r#"{ "verifier": { "fail": "auth.invalid_credentials" } }"#] {
        let root = gate_project(SQL_GATE, Some(file));
        let (addr, _session) = serve(&root).await;
        let (status, body) = post_mcp(addr, &[], list()).await;
        assert_eq!(status, 401, "{file}");
        assert_eq!(body.to_string(), FIXED_DENIAL, "{file}");
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[tokio::test]
async fn a_mocked_verifier_outage_and_an_absent_gate_file_are_both_the_fixed_outage_never_an_allow() {
    let outage = gate_project(SQL_GATE, Some(r#"{ "verifier": { "fail": "auth.verifier_unavailable" } }"#));
    let (addr, _s) = serve(&outage).await;
    let (status, body) = post_mcp(addr, &[], list()).await;
    assert_eq!(status, 200, "legacy era answers errors with 200");
    assert_eq!(body.to_string(), FIXED_LIST_OUTAGE);

    let absent = gate_project(SQL_GATE, None);
    let (addr, _s) = serve(&absent).await;
    let (status, body) = post_mcp(addr, &[], list()).await;
    assert_eq!(status, 200);
    assert_eq!(body.to_string(), FIXED_LIST_OUTAGE, "no gate file: the gate fails closed");
    let (_, call_reply) = post_mcp(addr, &[], call("H1")).await;
    assert_eq!(call_reply["result"]["isError"], true, "{call_reply}");
    assert_eq!(text(&call_reply), r#"{"code":500,"name":"auth.verifier_unavailable"}"#);
    let unknown_call = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": "nope", "arguments": {} } });
    let (_, unknown) = post_mcp(addr, &[], unknown_call).await;
    assert_eq!(unknown, call_reply, "a known and an unknown tool name are indistinguishable behind the gate");
    let _ = std::fs::remove_dir_all(&outage);
    let _ = std::fs::remove_dir_all(&absent);
}

#[tokio::test]
async fn a_sql_gate_never_runs_the_real_script_and_the_unopenable_database_is_never_touched() {
    // verify.sql selects 'REAL'; the connection points at a database that cannot be opened.
    let root = gate_project(SQL_GATE, None);
    let (addr, _s) = serve(&root).await;
    for _ in 0..3 {
        let (_, body) = post_mcp(addr, &[("Authorization", "anything")], list()).await;
        assert_eq!(body.to_string(), FIXED_LIST_OUTAGE);
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn an_http_gate_with_no_gate_file_makes_zero_outbound_connections() {
    let (listener, accepted) = counting_listener().await;
    let root = http_gate_project(listener, None);
    let (addr, _s) = serve(&root).await;
    for _ in 0..3 {
        let (status, body) = post_mcp(addr, &[("Authorization", "tok")], list()).await;
        assert_eq!(status, 200);
        assert_eq!(body.to_string(), FIXED_LIST_OUTAGE);
        let _ = post_mcp(addr, &[("Authorization", "tok")], call("H1")).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(accepted.load(Ordering::SeqCst), 0, "frogs test must never reach the verifier's real upstream");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn an_http_gate_with_a_gate_file_is_answered_from_the_file_and_still_makes_no_outbound_connection() {
    let (listener, accepted) = counting_listener().await;
    let root = http_gate_project(listener, Some(r#"{ "verifier": { "active": true } }"#));
    let (addr, _s) = serve(&root).await;
    let (status, listed) = post_mcp(addr, &[], list()).await;
    assert_eq!(status, 200, "{listed}");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(accepted.load(Ordering::SeqCst), 0);
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn an_mtls_gate_runs_for_real_and_a_present_gate_file_is_ignored() {
    for file in [None, Some(r#"{ "verifier": { "cn": "client.example.com" } }"#)] {
        let root = gate_project(MTLS_GATE, file);
        let (addr, _s) = serve(&root).await;
        let (status, body) = post_mcp(addr, &[], list()).await;
        assert_eq!(status, 401, "no certificate on this connection: {file:?}");
        assert_eq!(body.to_string(), FIXED_DENIAL, "{file:?}");
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[tokio::test]
async fn a_scoped_tool_behind_the_gate_follows_the_cases_verifier_mock_for_its_own_scopes() {
    let root = gate_project(SQL_GATE, Some(r#"{ "verifier": { "active": true, "scope": "cars.read" } }"#));
    let api = root.join("api");
    let secured = ENDPOINT.replace(
        r#""mcp": { "expose": true },"#,
        r#""mcp": { "expose": true }, "security": "oauth", "securityScopes": ["cars.write"],"#,
    );
    std::fs::write(api.join("datasources/endpoints/cars/{vin}/endpoint.get.json"), secured).unwrap();
    let spec = SPEC
        .replace("      operationId: getCar\n", "      operationId: getCar\n      security: [ { oauth: [cars.write] } ]\n")
        .replace(
            "paths:",
            "components:\n  securitySchemes:\n    oauth: { type: oauth2, flows: { clientCredentials: { tokenUrl: 'https://a.example/t', scopes: { cars.write: w } } } }\npaths:",
        );
    std::fs::write(root.join("openapi.yaml"), spec).unwrap();
    std::fs::write(
        api.join("datasources/endpoints/cars/{vin}/endpoint.get.test.json"),
        r#"{ "cases": [
            { "name": "has scope", "request": { "path": { "vin": "H1" } }, "mocks": { "verifier": { "active": true, "scope": "cars.write" }, "car": { "maker": "Honda" } }, "expect": { "status": 200 } },
            { "name": "lacks scope", "request": { "path": { "vin": "L1" } }, "mocks": { "verifier": { "active": true, "scope": "cars.read" }, "car": { "maker": "Honda" } }, "expect": { "status": 403 } }
        ] }"#,
    )
    .unwrap();
    let (addr, _s) = serve(&root).await;
    let (status, reply) = post_mcp(addr, &[], call("H1")).await;
    assert_eq!(status, 200, "{reply}");
    let (status, reply) = post_mcp(addr, &[], call("L1")).await;
    assert_eq!(status, 403, "{reply}");
    assert_eq!(reply["error"]["data"]["name"], "auth.insufficient_scope");
    let _ = std::fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------- install_gate_mock directly

fn session() -> Arc<MockSession> {
    MockSession::new(
        Vec::new(),
        None,
        crate::testing::ReportConfig {
            format: ReportFormat::Text,
            file: None,
        },
    )
    .unwrap()
}

#[test]
fn the_startup_note_names_the_gate_file_or_says_the_gate_fails_closed_or_runs_for_real() {
    let with_file = gate_project(SQL_GATE, Some(r#"{ "verifier": { "active": true } }"#));
    let config = Config::load(&with_file.join("api")).unwrap();
    let s = session();
    let note = install_gate_mock(&with_file.join("api"), &config, &s).expect("a note");
    assert!(
        note.starts_with("MCP: accessScheme 'oauth' gate mock: ") && note.contains("mcp-gate.test.json"),
        "{note}"
    );
    assert!(matches!(s.gate_verifier_mock(), Some(crate::endpoint::MockOutcome::Success(_))));

    let absent = gate_project(SQL_GATE, None);
    let config = Config::load(&absent.join("api")).unwrap();
    let s = session();
    assert_eq!(
        install_gate_mock(&absent.join("api"), &config, &s).unwrap(),
        "MCP: accessScheme 'oauth' gate mock: none (gate fails closed)"
    );
    assert!(s.gate_verifier_mock().is_none());

    let mtls = gate_project(MTLS_GATE, Some(r#"{ "verifier": {} }"#));
    let config = Config::load(&mtls.join("api")).unwrap();
    let s = session();
    assert_eq!(
        install_gate_mock(&mtls.join("api"), &config, &s).unwrap(),
        "MCP: accessScheme 'oauth' gate mock: none (mtls gate runs for real)"
    );
    assert!(s.gate_verifier_mock().is_none(), "the file is ignored for an mtls gate");
    for root in [with_file, absent, mtls] {
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[test]
fn a_fail_value_in_the_gate_file_is_read_as_a_mocked_failure() {
    let root = gate_project(SQL_GATE, Some(r#"{ "verifier": { "fail": "auth.invalid_credentials" } }"#));
    let config = Config::load(&root.join("api")).unwrap();
    let s = session();
    install_gate_mock(&root.join("api"), &config, &s);
    assert!(matches!(s.gate_verifier_mock(), Some(crate::endpoint::MockOutcome::Fail(code)) if code == "auth.invalid_credentials"));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn nothing_is_read_or_noted_without_an_access_scheme() {
    let root = project(MCP_ON);
    std::fs::write(root.join("api/datasources/mcp-gate.test.json"), "{ not even json").unwrap();
    let config = Config::load(&root.join("api")).unwrap();
    let s = session();
    assert!(
        install_gate_mock(&root.join("api"), &config, &s).is_none(),
        "no accessScheme: the file is never opened"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn frogs_test_refuses_a_stub_that_does_not_cover_the_specs_scopes_once_the_verifier_enforces_scopes() {
    let root = gate_project(SQL_GATE, Some(r#"{ "verifier": { "active": true } }"#));
    let api = root.join("api");
    let secured = ENDPOINT.replace(r#""mcp": { "expose": true },"#, r#""mcp": { "expose": true }, "security": "oauth","#);
    std::fs::write(api.join("datasources/endpoints/cars/{vin}/endpoint.get.json"), &secured).unwrap();
    let spec = SPEC
        .replace("      operationId: getCar\n", "      operationId: getCar\n      security: [ { oauth: [cars.write] } ]\n")
        .replace(
            "paths:",
            "components:\n  securitySchemes:\n    oauth: { type: oauth2, flows: { clientCredentials: { tokenUrl: 'https://a.example/t', scopes: { cars.write: w } } } }\npaths:",
        );
    std::fs::write(root.join("openapi.yaml"), spec).unwrap();
    let err = build_mock_router(&root, &opts()).await.err().expect("refused");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
    assert!(crate::exit_codes::is_config_refusal(&err), "{err}");

    // The same stub, with the scope declared, starts.
    let covered = secured.replace(r#""security": "oauth","#, r#""security": "oauth", "securityScopes": ["cars.write"],"#);
    std::fs::write(api.join("datasources/endpoints/cars/{vin}/endpoint.get.json"), covered).unwrap();
    let _ = build_mock_router(&root, &opts()).await.expect("covered stub starts");
    let _ = std::fs::remove_dir_all(&root);
}
