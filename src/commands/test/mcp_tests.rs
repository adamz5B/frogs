//! `frogs test` mounts the same `/mcp` router, and a tool call goes through the mock provider:
//! case selection, the no-real-infrastructure guarantee and the report all apply.

use super::*;

fn tempdir() -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "frogs-commands-test-mcp-{}-{}-{n}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn opts() -> TestServerOptions {
    TestServerOptions {
        port: None,
        bind: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        scenario: None,
        report: ReportFormat::Text,
        report_file: None,
    }
}

const SPEC: &str = "openapi: 3.2.0
info: { title: Cars, version: '3' }
paths:
  /cars/{vin}:
    get:
      operationId: getCar
      parameters:
        - { name: vin, in: path, required: true, schema: { type: string } }
      responses: { '200': { description: ok } }
";

const ENDPOINT: &str = r#"{
    "operationId": "getCar",
    "mcp": { "expose": true },
    "sources": { "car": { "type": "sql", "connection": "db", "script": "car.sql", "cardinality": "one", "parameters": [ { "name": "vin", "from": "path.vin" } ] } },
    "response": { "maker": "sources.car.maker" }
}"#;

const CASES: &str = r#"{ "cases": [
    { "name": "honda", "request": { "path": { "vin": "H1" } }, "mocks": { "car": { "maker": "Honda" } }, "expect": { "status": 200, "body": { "maker": "Honda" } } },
    { "name": "unmocked", "request": { "path": { "vin": "U1" } }, "expect": { "status": 200 } },
    { "name": "bmw baseline", "request": { "path": { "vin": "S1" } }, "mocks": { "car": { "maker": "Baseline" } }, "expect": { "status": 200 } },
    { "name": "bmw scenario", "scenario": "premium", "request": { "path": { "vin": "S1" } }, "mocks": { "car": { "maker": "Premium" } }, "expect": { "status": 200 } }
] }"#;

fn project(server_json: &str) -> PathBuf {
    let root = tempdir();
    let api = root.join("api");
    for dir in ["config/errors", "security", "datasources/sql/db", "datasources/endpoints/cars/{vin}"] {
        std::fs::create_dir_all(api.join(dir)).unwrap();
    }
    std::fs::write(root.join("openapi.yaml"), SPEC).unwrap();
    std::fs::write(api.join("config/server.json"), server_json).unwrap();
    std::fs::write(api.join("config/errors/core.json"), "{}").unwrap();
    // Never openable: a real dial would fail loudly, proving the mock path never reaches the driver.
    std::fs::write(
        api.join("config/connections.json"),
        r#"{ "db": { "driver": "sqlite", "database": "/does/not/exist/db.sqlite" } }"#,
    )
    .unwrap();
    std::fs::write(api.join("security/schemes.json"), "{}").unwrap();
    std::fs::write(api.join("datasources/sql/db/car.sql"), "SELECT 'REAL' AS maker;").unwrap();
    std::fs::write(api.join("datasources/endpoints/cars/{vin}/endpoint.get.json"), ENDPOINT).unwrap();
    std::fs::write(api.join("datasources/endpoints/cars/{vin}/endpoint.get.test.json"), CASES).unwrap();
    root
}

const MCP_ON: &str = r#"{ "features": { "mcp": true, "requestValidation": false, "metrics": false, "readyzCheck": false } }"#;

async fn serve(root: &Path) -> (std::net::SocketAddr, Arc<MockSession>) {
    let (router, session, server_config) = build_mock_router(root, &opts()).await.expect("mock router builds");
    (crate::server::spawn_served(router, server_config.case_sensitive_methods()).await, session)
}

async fn post_mcp(addr: std::net::SocketAddr, extra: &[(&str, &str)], body: serde_json::Value) -> (u16, serde_json::Value) {
    let text = body.to_string();
    let mut head = format!(
        "POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        text.len()
    );
    for (k, v) in extra {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("Connection: close\r\n\r\n");
    head.push_str(&text);
    let (status_line, _headers, raw, _closed) = crate::server::raw_request(addr, head.as_bytes()).await;
    let status = status_line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let body = String::from_utf8_lossy(&raw).into_owned();
    let json = match (body.find('{'), body.rfind('}')) {
        (Some(a), Some(b)) => serde_json::from_str(&body[a..=b]).unwrap_or(serde_json::Value::Null),
        _ => serde_json::Value::Null,
    };
    (status, json)
}

fn call(vin: &str) -> serde_json::Value {
    serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": "getCar", "arguments": { "vin": vin } } })
}

fn text(reply: &serde_json::Value) -> String {
    reply["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("no text: {reply}"))
        .to_string()
}

#[tokio::test]
async fn a_tool_call_under_frogs_test_is_answered_from_the_matching_mock_case() {
    let root = project(MCP_ON);
    let (addr, _session) = serve(&root).await;
    let (status, reply) = post_mcp(addr, &[], call("H1")).await;
    assert_eq!(status, 200);
    assert_eq!(reply["result"].get("isError"), None, "{reply}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&text(&reply)).unwrap(),
        serde_json::json!({ "maker": "Honda" })
    );
    let (_, list) = post_mcp(addr, &[], serde_json::json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" })).await;
    assert_eq!(list["result"]["tools"][0]["name"], "getCar");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn a_source_the_matched_case_did_not_mock_is_a_not_mocked_tool_error_and_never_dials_the_real_driver() {
    let root = project(MCP_ON);
    let (addr, session) = serve(&root).await;
    let (status, reply) = post_mcp(addr, &[], call("U1")).await;
    assert_eq!(status, 200, "a mock-layer failure is a tool error, not a transport error");
    assert_eq!(reply["result"]["isError"], true, "{reply}");
    assert!(!text(&reply).contains("REAL"), "the real script must never have run: {}", text(&reply));
    assert_eq!(session.summary().not_mocked, 1, "the report records the not-mocked verdict");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn a_call_matching_no_case_is_a_tool_error_with_the_no_matching_case_status() {
    let root = project(MCP_ON);
    let (addr, session) = serve(&root).await;
    let (status, reply) = post_mcp(addr, &[], call("NOPE")).await;
    assert_eq!(status, 200);
    assert_eq!(reply["result"]["isError"], true, "{reply}");
    assert_eq!(reply["result"]["_meta"]["frogs/httpStatus"], 404);
    assert_eq!(session.summary().unmatched, 1);
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn the_scenario_header_is_passed_through_to_case_selection_over_mcp() {
    let root = project(MCP_ON);
    let (addr, _session) = serve(&root).await;
    let (_, baseline) = post_mcp(addr, &[], call("S1")).await;
    assert!(text(&baseline).contains("Baseline"), "{baseline}");
    let (_, scenario) = post_mcp(addr, &[("X-Frogs-Scenario", "premium")], call("S1")).await;
    assert!(text(&scenario).contains("Premium"), "{scenario}");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn the_report_counts_mcp_tool_calls_like_any_other_request() {
    let root = project(MCP_ON);
    let (addr, session) = serve(&root).await;
    let _ = post_mcp(addr, &[], call("H1")).await;
    let summary = session.summary();
    assert_eq!(summary.requests, 1);
    assert_eq!(summary.passed, 1, "{summary:?}");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn without_features_mcp_the_mock_server_has_no_mcp_route() {
    let root = project(r#"{ "features": { "requestValidation": false, "metrics": false, "readyzCheck": false } }"#);
    let (addr, _session) = serve(&root).await;
    let (status, _) = post_mcp(addr, &[], serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" })).await;
    assert_eq!(status, 404);
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn an_mcp_misconfiguration_refuses_the_mock_server_too() {
    let root = project(r#"{ "features": { "mcp": true, "requestValidation": false, "metrics": false, "readyzCheck": false }, "mcp": { "accessScheme": "x" } }"#);
    let err = build_mock_router(&root, &opts()).await.err().expect("refused");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("MCP problem"), "{err}");
    let _ = std::fs::remove_dir_all(&root);
}

mod gate_m2;
