//! `frogs mcp` driven in process through `serve_streams`: real temp-dir projects, real JSON-RPC lines in, real lines out.

use std::path::Path;
use std::sync::Mutex;

use super::*;

// ---- harness

#[derive(Clone)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn tempdir() -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "frogs-mcp-authoring-{}-{}-{n}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

const SERVER_JSON: &str = r#"{ "features": { "requestValidation": false, "metrics": false, "readyzCheck": false } }"#;
const DEBUG_SERVER_JSON: &str = r#"{ "debugMode": true, "features": { "requestValidation": false, "metrics": false, "readyzCheck": false } }"#;

const SPEC: &str = "openapi: 3.2.0
info: { title: Cars, version: '3' }
paths:
  /cars:
    post:
      operationId: createCar
      responses: { '201': { description: ok } }
  /cars/{vin}:
    get:
      operationId: getCar
      parameters:
        - { name: vin, in: path, required: true, schema: { type: string } }
      responses: { '200': { description: ok } }
";

const GET_ENDPOINT: &str = r#"{
    "operationId": "getCar",
    "sources": { "car": { "type": "sql", "connection": "db", "script": "car.sql", "cardinality": "one", "parameters": [ { "name": "vin", "from": "path.vin" } ] } },
    "response": { "maker": "sources.car.maker" }
}"#;

const POST_ENDPOINT: &str = r#"{
    "operationId": "createCar",
    "successStatus": 201,
    "sources": { "create": { "type": "http", "request": "upstream.json" } },
    "response": { "vin": "sources.create.vin" }
}"#;

const GET_CASES: &str = r#"{ "cases": [
    { "name": "passes", "request": { "path": { "vin": "H1" } }, "mocks": { "car": { "maker": "Honda" } }, "expect": { "status": 200, "body": { "maker": "Honda" } } },
    { "name": "fails", "request": { "path": { "vin": "F1" } }, "mocks": { "car": { "maker": "Honda" } }, "expect": { "status": 200, "body": { "maker": "Wrong" } } },
    { "name": "no path value", "request": {}, "mocks": { "car": { "maker": "Honda" } }, "expect": { "status": 200 } },
    { "name": "dupA", "request": { "path": { "vin": "D1" } }, "mocks": { "car": { "maker": "A" } }, "expect": { "status": 200 } },
    { "name": "dupB", "request": { "path": { "vin": "D1" } }, "mocks": { "car": { "maker": "B" } }, "expect": { "status": 200 } },
    { "name": "baseline", "request": { "path": { "vin": "S1" } }, "mocks": { "car": { "maker": "Baseline" } }, "expect": { "status": 200, "body": { "maker": "Baseline" } } },
    { "name": "premium", "scenario": "premium", "request": { "path": { "vin": "S1" } }, "mocks": { "car": { "maker": "Premium" } }, "expect": { "status": 200, "body": { "maker": "Premium" } } },
    { "name": "read back", "request": { "path": { "vin": "{{memory.vin}}" } }, "mocks": { "car": { "maker": "FromMemory" } }, "expect": { "status": 200, "body": { "maker": "FromMemory" } } }
] }"#;

const POST_CASES: &str = r#"{ "cases": [
    { "name": "create", "request": { "body": { "maker": "Honda" } }, "mocks": { "create": { "vin": "NEW123" } }, "expect": { "status": 201 }, "save": { "vin": "response.body.vin" } }
] }"#;

fn write(root: &Path, relative: &str, contents: &str) {
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

/// A complete API project. The sqlite database it names does not exist and must never be created by a read-only tool.
fn project_with(server_json: &str, connections_json: &str) -> PathBuf {
    let root = tempdir();
    write(&root, "openapi.yaml", SPEC);
    write(&root, "api/config/server.json", server_json);
    write(&root, "api/config/errors/core.json", "{}");
    write(&root, "api/config/connections.json", connections_json);
    write(&root, "api/security/schemes.json", "{}");
    write(&root, "api/datasources/sql/db/car.sql", "SELECT 'REAL' AS maker;");
    write(
        &root,
        "api/datasources/http/upstream.json",
        r#"{ "method": "GET", "url": "http://127.0.0.1:9/never" }"#,
    );
    write(&root, "api/datasources/endpoints/cars/{vin}/endpoint.get.json", GET_ENDPOINT);
    write(&root, "api/datasources/endpoints/cars/{vin}/endpoint.get.test.json", GET_CASES);
    write(
        &root,
        "api/datasources/endpoints/cars/{vin}/endpoint.get.reference.json",
        r#"{ "marker": "REFERENCE-OF-GET-CAR" }"#,
    );
    write(&root, "api/datasources/endpoints/cars/endpoint.post.json", POST_ENDPOINT);
    write(&root, "api/datasources/endpoints/cars/endpoint.post.test.json", POST_CASES);
    root
}

/// The standard fixture: its sqlite connection names `<root>/never-created.sqlite`, which must stay absent.
fn project() -> PathBuf {
    let root = tempdir();
    let db = root.join("never-created.sqlite").display().to_string().replace('\\', "/");
    write(&root, "openapi.yaml", SPEC);
    write(&root, "api/config/server.json", SERVER_JSON);
    write(&root, "api/config/errors/core.json", "{}");
    write(
        &root,
        "api/config/connections.json",
        &format!(r#"{{ "db": {{ "driver": "sqlite", "database": "{db}" }} }}"#),
    );
    write(&root, "api/security/schemes.json", "{}");
    write(&root, "api/datasources/sql/db/car.sql", "SELECT 'REAL' AS maker;");
    write(
        &root,
        "api/datasources/http/upstream.json",
        r#"{ "method": "GET", "url": "http://127.0.0.1:9/never" }"#,
    );
    write(&root, "api/datasources/endpoints/cars/{vin}/endpoint.get.json", GET_ENDPOINT);
    write(&root, "api/datasources/endpoints/cars/{vin}/endpoint.get.test.json", GET_CASES);
    write(
        &root,
        "api/datasources/endpoints/cars/{vin}/endpoint.get.reference.json",
        r#"{ "marker": "REFERENCE-OF-GET-CAR" }"#,
    );
    write(&root, "api/datasources/endpoints/cars/endpoint.post.json", POST_ENDPOINT);
    write(&root, "api/datasources/endpoints/cars/endpoint.post.test.json", POST_CASES);
    root
}

fn server(root: &Path, allow_connections: bool) -> Arc<Server> {
    Server::new(AuthoringOptions {
        root: root.to_path_buf(),
        allow_connections,
    })
}

async fn drive_bytes(server: &Arc<Server>, input: Vec<u8>) -> Vec<Value> {
    let out = SharedBuf(Arc::new(Mutex::new(Vec::new())));
    serve_streams(server.clone(), io::Cursor::new(input), out.clone(), std::future::pending::<()>())
        .await
        .expect("the stream ends cleanly on EOF");
    let bytes = out.0.lock().unwrap().clone();
    let text = String::from_utf8(bytes).expect("stdout is UTF-8");
    assert!(text.is_empty() || text.ends_with('\n'), "every output line is newline-terminated");
    text.lines()
        .map(|line| serde_json::from_str(line).unwrap_or_else(|e| panic!("stdout line is not JSON ({e}): {line}")))
        .collect()
}

async fn drive(server: &Arc<Server>, lines: &[Value]) -> Vec<Value> {
    let mut input = Vec::new();
    for line in lines {
        input.extend_from_slice(line.to_string().as_bytes());
        input.push(b'\n');
    }
    drive_bytes(server, input).await
}

fn request(id: i64, method: &str, params: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
}

fn ping(id: i64) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "method": "ping" })
}

fn modern_meta() -> Value {
    json!({ "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {} })
}

fn call(id: i64, name: &str, arguments: Value) -> Value {
    request(id, "tools/call", json!({ "name": name, "arguments": arguments }))
}

fn modern_call(id: i64, name: &str, arguments: Value) -> Value {
    request(id, "tools/call", json!({ "name": name, "arguments": arguments, "_meta": modern_meta() }))
}

fn answer(out: &[Value], id: i64) -> &Value {
    let matches: Vec<&Value> = out.iter().filter(|v| v["id"] == id).collect();
    assert_eq!(matches.len(), 1, "id {id} must be answered exactly once: {out:?}");
    matches[0]
}

fn tool_text(response: &Value) -> Value {
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("no tool text: {response}"));
    serde_json::from_str(text).unwrap()
}

async fn one(server: &Arc<Server>, line: Value) -> Value {
    let id = line["id"].as_i64().unwrap();
    let out = drive(server, &[line]).await;
    answer(&out, id).clone()
}

fn cleanup(root: &Path) {
    let _ = std::fs::remove_dir_all(root);
}

// ---- every method, both eras

#[tokio::test]
async fn legacy_initialize_echoes_a_supported_client_version_and_declares_a_non_listchanged_tools_capability() {
    let root = project();
    let s = server(&root, false);
    for version in protocol::LEGACY_VERSIONS {
        let response = one(
            &s,
            request(
                1,
                "initialize",
                json!({ "protocolVersion": version, "capabilities": {}, "clientInfo": { "name": "t", "version": "1" } }),
            ),
        )
        .await;
        assert_eq!(response["result"]["protocolVersion"], version);
        assert_eq!(response["result"]["capabilities"], json!({ "tools": { "listChanged": false } }));
        assert_eq!(response["result"]["serverInfo"], json!({ "name": "frogs", "version": env!("CARGO_PKG_VERSION") }));
        assert!(response["result"].get("resultType").is_none());
    }
    cleanup(&root);
}

#[tokio::test]
async fn legacy_initialize_with_an_unknown_or_missing_version_answers_the_newest_legacy_version() {
    let root = project();
    let s = server(&root, false);
    let unknown = one(&s, request(1, "initialize", json!({ "protocolVersion": "1999-01-01" }))).await;
    assert_eq!(unknown["result"]["protocolVersion"], "2025-11-25");
    let missing = one(&s, json!({ "jsonrpc": "2.0", "id": 2, "method": "initialize" })).await;
    assert_eq!(missing["result"]["protocolVersion"], "2025-11-25");
    cleanup(&root);
}

#[tokio::test]
async fn initialize_stays_legacy_even_when_the_client_sends_modern_meta() {
    let root = project();
    let s = server(&root, false);
    let response = one(&s, request(1, "initialize", json!({ "protocolVersion": "2025-11-25", "_meta": modern_meta() }))).await;
    assert_eq!(response["result"]["protocolVersion"], "2025-11-25");
    assert!(response["result"].get("resultType").is_none(), "{response}");
    cleanup(&root);
}

#[tokio::test]
async fn legacy_ping_answers_an_empty_object() {
    let root = project();
    let s = server(&root, false);
    assert_eq!(one(&s, ping(1)).await["result"], json!({}));
    cleanup(&root);
}

#[tokio::test]
async fn modern_server_discover_lists_versions_capabilities_server_info_and_the_private_cache_scope() {
    let root = project();
    let s = server(&root, false);
    let response = one(&s, request(1, "server/discover", json!({ "_meta": modern_meta() }))).await;
    let result = &response["result"];
    let versions = result["supportedVersions"].as_array().unwrap();
    for v in protocol::MODERN_VERSIONS.iter().chain(protocol::LEGACY_VERSIONS.iter()) {
        assert!(versions.iter().any(|x| x == v), "{v} missing from {versions:?}");
    }
    assert_eq!(result["capabilities"], json!({ "tools": {} }));
    assert_eq!(result["_meta"][protocol::META_SERVER_INFO_KEY]["name"], "frogs");
    assert_eq!(result["cacheScope"], "private");
    assert_eq!(result["resultType"], "complete");
    assert!(result["ttlMs"].is_number());
    cleanup(&root);
}

#[tokio::test]
async fn tools_list_names_exactly_the_five_read_only_tools_in_both_eras() {
    let root = project();
    let s = server(&root, false);
    let legacy = one(&s, request(1, "tools/list", json!({}))).await;
    let modern = one(&s, request(2, "tools/list", json!({ "_meta": modern_meta() }))).await;
    for (response, is_modern) in [(&legacy, false), (&modern, true)] {
        let tools = response["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["project_describe", "endpoint_reference", "errors_discovered", "validate", "test_run"]);
        for tool in tools {
            assert_eq!(tool["annotations"]["readOnlyHint"], true, "{tool}");
            assert_eq!(tool["annotations"]["destructiveHint"], false, "{tool}");
            assert_eq!(tool["inputSchema"]["additionalProperties"], false, "{tool}");
        }
        assert_eq!(response["result"].get("resultType").is_some(), is_modern, "{response}");
    }
    assert_eq!(modern["result"]["resultType"], "complete");
    cleanup(&root);
}

#[tokio::test]
async fn the_validate_tool_advertises_check_connections_and_open_world_only_with_allow_connections() {
    let root = project();
    for allow in [false, true] {
        let s = server(&root, allow);
        let response = one(&s, request(1, "tools/list", json!({}))).await;
        let tools = response["result"]["tools"].as_array().unwrap();
        let validate = tools.iter().find(|t| t["name"] == "validate").unwrap();
        assert_eq!(validate["inputSchema"]["properties"].get("checkConnections").is_some(), allow, "{validate}");
        assert_eq!(validate["annotations"]["openWorldHint"], allow, "{validate}");
        let describe = tools.iter().find(|t| t["name"] == "project_describe").unwrap();
        assert_eq!(describe["annotations"]["openWorldHint"], false);
    }
    cleanup(&root);
}

#[tokio::test]
async fn tools_call_returns_compact_json_text_content_in_both_eras_and_only_modern_adds_result_type() {
    let root = project();
    let s = server(&root, false);
    let legacy = one(&s, call(1, "errors_discovered", json!({}))).await;
    let modern = one(&s, modern_call(2, "errors_discovered", json!({}))).await;
    assert_eq!(legacy["result"]["content"][0]["type"], "text");
    assert!(legacy["result"].get("structuredContent").is_none());
    assert!(legacy["result"].get("isError").is_none());
    assert!(legacy["result"].get("resultType").is_none());
    assert_eq!(modern["result"]["resultType"], "complete");
    assert_eq!(tool_text(&legacy), tool_text(&modern));
    assert!(!legacy["result"]["content"][0]["text"].as_str().unwrap().contains('\n'), "compact JSON");
    cleanup(&root);
}

#[tokio::test]
async fn methods_outside_the_eras_menu_are_method_not_found() {
    let root = project();
    let s = server(&root, false);
    // modern ping, legacy server/discover, and plainly unknown methods
    let cases = [
        request(1, "ping", json!({ "_meta": modern_meta() })),
        request(2, "server/discover", json!({})),
        request(3, "resources/list", json!({})),
        request(4, "prompts/list", json!({ "_meta": modern_meta() })),
        json!({ "jsonrpc": "2.0", "id": 5, "method": "" }),
    ];
    let out = drive(&s, &cases).await;
    for id in 1..=5 {
        assert_eq!(answer(&out, id)["error"]["code"], protocol::METHOD_NOT_FOUND, "id {id}: {out:?}");
    }
    cleanup(&root);
}

#[tokio::test]
async fn modern_requests_must_carry_client_capabilities_and_unsupported_versions_are_32022() {
    let root = project();
    let s = server(&root, false);
    let no_caps = one(
        &s,
        request(1, "tools/list", json!({ "_meta": { "io.modelcontextprotocol/protocolVersion": "2026-07-28" } })),
    )
    .await;
    assert_eq!(no_caps["error"]["code"], protocol::INVALID_PARAMS);
    let bad = one(
        &s,
        request(2, "tools/list", json!({ "_meta": { "io.modelcontextprotocol/protocolVersion": "2999-01-01" } })),
    )
    .await;
    assert_eq!(bad["error"]["code"], protocol::UNSUPPORTED_VERSION);
    assert_eq!(bad["error"]["data"]["requested"], "2999-01-01");
    assert!(bad["error"]["data"]["supported"].is_array());
    cleanup(&root);
}

// ---- argument and envelope handling

#[tokio::test]
async fn an_unknown_tool_an_unknown_argument_a_missing_argument_and_a_wrong_type_are_all_invalid_params() {
    let root = project();
    let s = server(&root, false);
    let cases = [
        call(1, "no_such_tool", json!({})),
        call(2, "project_describe", json!({ "surprise": 1 })),
        call(3, "endpoint_reference", json!({ "path": "/cars/{vin}" })),
        call(4, "endpoint_reference", json!({ "path": 5, "method": "get" })),
        call(5, "errors_discovered", json!({ "x": null })),
        call(6, "test_run", json!({ "nope": "x" })),
        call(7, "validate", json!({ "checkConnections": "yes" })),
        request(8, "tools/call", json!({ "arguments": {} })),
        request(9, "tools/call", json!({ "name": 7, "arguments": {} })),
        call(10, "endpoint_reference", json!({ "path": "/cars/{vin}", "method": "ge t" })),
        call(11, "test_run", json!({ "method": "get /" })),
    ];
    let out = drive(&s, &cases).await;
    for id in 1..=11 {
        assert_eq!(answer(&out, id)["error"]["code"], protocol::INVALID_PARAMS, "id {id}: {out:?}");
    }
    cleanup(&root);
}

#[tokio::test]
async fn overlong_path_method_and_scenario_arguments_are_invalid_params() {
    let root = project();
    let s = server(&root, false);
    let long_path = format!("/{}", "a".repeat(1024));
    let cases = [
        call(1, "endpoint_reference", json!({ "path": long_path, "method": "get" })),
        call(2, "endpoint_reference", json!({ "path": "/cars", "method": "g".repeat(33) })),
        call(3, "test_run", json!({ "path": long_path })),
        call(4, "test_run", json!({ "scenario": "s".repeat(257) })),
        call(5, "test_run", json!({ "method": "g".repeat(33) })),
    ];
    let out = drive(&s, &cases).await;
    for id in 1..=5 {
        assert_eq!(answer(&out, id)["error"]["code"], protocol::INVALID_PARAMS, "id {id}: {out:?}");
    }
    cleanup(&root);
}

#[tokio::test]
async fn check_connections_without_allow_connections_is_invalid_params() {
    let root = project();
    let s = server(&root, false);
    let response = one(&s, call(1, "validate", json!({ "checkConnections": true }))).await;
    assert_eq!(response["error"]["code"], protocol::INVALID_PARAMS);
    cleanup(&root);
}

#[tokio::test]
async fn a_notification_is_never_answered_and_never_dispatched() {
    let root = project();
    let s = server(&root, false);
    let lines = [
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        json!({ "jsonrpc": "2.0", "method": "tools/call", "params": { "name": "no_such_tool" } }),
        json!({ "jsonrpc": "2.0", "method": "ping" }),
    ];
    assert!(drive(&s, &lines).await.is_empty());
    cleanup(&root);
}

#[tokio::test]
async fn duplicate_keys_batches_and_null_ids_are_invalid_requests_with_a_null_id_and_do_not_stop_the_server() {
    let root = project();
    let s = server(&root, false);
    let mut input = Vec::new();
    input.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"method\":\"tools/list\"}\n");
    input.extend_from_slice(b"[{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}]\n");
    input.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"id\":null,\"method\":\"ping\"}\n");
    input.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"ping\"}\n");
    let out = drive_bytes(&s, input).await;
    assert_eq!(out.len(), 4, "{out:?}");
    let errors: Vec<&Value> = out.iter().filter(|v| v.get("error").is_some()).collect();
    assert_eq!(errors.len(), 3);
    for error in errors {
        assert_eq!(error["error"]["code"], protocol::INVALID_REQUEST, "{error}");
        assert_eq!(error["id"], Value::Null);
    }
    assert_eq!(answer(&out, 9)["result"], json!({}));
    cleanup(&root);
}

#[tokio::test]
async fn invalid_json_and_invalid_utf8_are_parse_errors_and_the_next_line_is_still_served() {
    let root = project();
    let s = server(&root, false);
    let mut input = b"{not json\n".to_vec();
    input.extend_from_slice(b"\xff\xfe\xfd\n");
    input.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"ping\"}\n");
    let out = drive_bytes(&s, input).await;
    assert_eq!(out.len(), 3, "{out:?}");
    assert_eq!(
        out.iter().filter(|v| v["error"]["code"] == protocol::PARSE_ERROR && v["id"].is_null()).count(),
        2,
        "{out:?}"
    );
    assert_eq!(answer(&out, 3)["result"], json!({}));
    cleanup(&root);
}

#[tokio::test]
async fn an_oversized_line_is_answered_invalid_request_with_a_null_id_and_the_following_line_is_served() {
    let root = project();
    let s = server(&root, false);
    let mut input = vec![b'a'; MAX_MCP_REQUEST_BYTES + 10];
    input.push(b'\n');
    input.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"ping\"}\n");
    let out = drive_bytes(&s, input).await;
    assert_eq!(out.len(), 2, "{out:?}");
    let too_large = out.iter().find(|v| v["id"].is_null()).expect("an id-null error");
    assert_eq!(too_large["error"]["code"], protocol::INVALID_REQUEST);
    assert_eq!(answer(&out, 4)["result"], json!({}));
    cleanup(&root);
}

#[tokio::test]
async fn crlf_line_endings_and_blank_lines_are_tolerated_and_a_final_line_without_a_newline_is_still_served() {
    let root = project();
    let s = server(&root, false);
    let input = b"\r\n\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\r\n   \n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}".to_vec();
    let out = drive_bytes(&s, input).await;
    assert_eq!(out.len(), 2, "{out:?}");
    answer(&out, 1);
    answer(&out, 2);
    cleanup(&root);
}

#[tokio::test]
async fn more_requests_than_the_in_flight_limit_are_each_answered_exactly_once() {
    let root = project();
    let s = server(&root, false);
    let lines: Vec<Value> = (1..=40).map(|i| call(i, "project_describe", json!({}))).collect();
    let out = drive(&s, &lines).await;
    assert_eq!(out.len(), 40);
    for id in 1..=40 {
        assert!(answer(&out, id)["result"]["content"].is_array());
    }
    cleanup(&root);
}

// ---- resilience: the server never exits on a tool-level problem

#[tokio::test]
async fn a_broken_server_json_is_a_tool_error_and_the_server_keeps_serving_then_recovers_when_it_is_fixed() {
    let root = project();
    let s = server(&root, false);
    write(&root, "api/config/server.json", "{ not json");
    let out = drive(
        &s,
        &[
            call(1, "project_describe", json!({})),
            ping(2),
            call(3, "validate", json!({})),
            call(4, "test_run", json!({})),
        ],
    )
    .await;
    assert_eq!(answer(&out, 1)["result"]["isError"], true, "{out:?}");
    assert_eq!(answer(&out, 2)["result"], json!({}));
    assert!(tool_text(answer(&out, 1))["error"]["message"].as_str().unwrap().contains("server.json"));
    // validate and test_run may report this as a tool error or as findings, but never as a transport error
    assert!(answer(&out, 3).get("error").is_none(), "{out:?}");
    assert!(answer(&out, 4).get("error").is_none(), "{out:?}");

    write(&root, "api/config/server.json", SERVER_JSON);
    let fixed = one(&s, call(5, "project_describe", json!({}))).await;
    assert!(fixed["result"].get("isError").is_none(), "every call re-reads config: {fixed}");
    cleanup(&root);
}

#[tokio::test]
async fn a_project_root_deleted_after_startup_is_a_tool_error_for_every_tool_and_ping_still_works() {
    let root = project();
    let s = server(&root, false);
    cleanup(&root);
    let lines = [
        call(1, "project_describe", json!({})),
        call(2, "endpoint_reference", json!({ "path": "/cars/{vin}", "method": "get" })),
        call(3, "errors_discovered", json!({})),
        call(4, "validate", json!({})),
        call(5, "test_run", json!({})),
        ping(6),
    ];
    let out = drive(&s, &lines).await;
    for id in 1..=5 {
        let response = answer(&out, id);
        assert_eq!(response["result"]["isError"], true, "id {id}: {response}");
        assert_eq!(tool_text(response)["error"]["kind"], "precondition");
    }
    assert_eq!(answer(&out, 6)["result"], json!({}));
}

#[tokio::test]
async fn a_panicking_tool_is_an_internal_error_for_its_id_only_and_the_server_keeps_answering() {
    let root = project();
    let s = server(&root, false);
    let out = drive(&s, &[call(1, "__test_panic", json!({})), ping(2), call(3, "__test_panic", json!({}))]).await;
    assert_eq!(answer(&out, 1)["error"]["code"], protocol::INTERNAL_ERROR);
    assert_eq!(answer(&out, 3)["error"]["code"], protocol::INTERNAL_ERROR);
    assert_eq!(answer(&out, 2)["result"], json!({}));
    // the read lock was released by the unwinding task: a later tool call still runs
    let after = one(&s, call(4, "project_describe", json!({}))).await;
    assert!(after["result"]["content"].is_array(), "{after}");
    cleanup(&root);
}

#[tokio::test]
async fn the_shutdown_signal_ends_the_loop_cleanly_even_though_stdin_never_closes() {
    struct Forever;
    impl io::Read for Forever {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            std::thread::sleep(Duration::from_secs(3600));
            Ok(0)
        }
    }
    let root = project();
    let s = server(&root, false);
    let out = SharedBuf(Arc::new(Mutex::new(Vec::new())));
    let result = tokio::time::timeout(
        Duration::from_secs(20),
        serve_streams(s, io::BufReader::new(Forever), out, tokio::time::sleep(Duration::from_millis(100))),
    )
    .await
    .expect("shutdown must not wait for the stdin thread");
    assert!(result.is_ok());
    cleanup(&root);
}

#[tokio::test]
async fn a_broken_stdout_never_hangs_or_panics_the_loop() {
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let root = project();
    let s = server(&root, false);
    let mut input = Vec::new();
    for i in 1..=5 {
        input.extend_from_slice(format!("{{\"jsonrpc\":\"2.0\",\"id\":{i},\"method\":\"ping\"}}\n").as_bytes());
    }
    let result = tokio::time::timeout(
        Duration::from_secs(20),
        serve_streams(s, io::Cursor::new(input), Broken, std::future::pending::<()>()),
    )
    .await
    .expect("a dead stdout must not hang the server");
    // either the writer noticed first (Err) or the loop had already drained; both are acceptable, a hang or panic is not
    let _ = result;
    cleanup(&root);
}

mod tools_part;

mod writes_part;
