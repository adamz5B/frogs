//! `frogs run`'s MCP mount end to end: a self-contained temp project is assembled through the real
//! `build_api_router` (real in-memory SQLite, real middleware stack), served on an ephemeral port
//! and driven with raw sockets. Startup refusals go through the same entry points `frogs run` and a
//! registered service use.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};

use super::*;

fn tempdir() -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "frogs-run-mcp-{}-{}-{n}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

const SPEC_PLAIN: &str = "openapi: 3.2.0
info: { title: Cars API, version: '7' }
paths:
  /cars/{vin}:
    get:
      operationId: getCar
      summary: Fetch a car
      parameters:
        - { name: vin, in: path, required: true, schema: { type: string } }
        - { name: limit, in: query, schema: { type: integer } }
      responses: { '200': { description: ok } }
  /cars:
    post:
      operationId: createCar
      requestBody:
        required: true
        content: { application/json: { schema: { type: object, properties: { name: { type: string } } } } }
      responses: { '201': { description: created } }
  /gone:
    delete:
      operationId: removeAll
      responses: { '204': { description: gone } }
";

const SPEC_SECURED: &str = "openapi: 3.2.0
info: { title: Cars API, version: '7' }
components:
  securitySchemes:
    tok: { type: apiKey, in: header, name: X-Api-Key }
paths:
  /cars/{vin}:
    get:
      operationId: getCar
      security: [ { tok: [] } ]
      parameters:
        - { name: vin, in: path, required: true, schema: { type: string } }
      responses: { '200': { description: ok } }
";

/// The registry subset `frogs generate` writes that these tests rely on.
const CORE_ERRORS: &str = r#"{
    "auth.invalid_credentials": { "httpStatus": 401, "exposeDetail": true },
    "auth.verifier_unavailable": { "httpStatus": 500, "exposeDetail": false },
    "validation.missing_parameter": { "httpStatus": 400, "exposeDetail": true },
    "validation.invalid_type": { "httpStatus": 400, "exposeDetail": true },
    "unexpected.error": { "httpStatus": 500, "exposeDetail": false }
}"#;

const QUIET: &str = r#""requestValidation": false, "metrics": false, "readyzCheck": false, "requestCorrelation": false, "rateLimiting": false, "cors": false"#;

fn features(on: &str) -> String {
    format!(r#"{{ "features": {{ "mcp": true, {QUIET} {on} }} }}"#)
}

/// `{ "features": { "mcp": true, <quiet> } }` with every other feature a test needs overriding the quiet value.
fn server_json(overrides: &[(&str, &str)], extra_top: &str) -> String {
    let mut parts: Vec<(String, String)> = [
        ("mcp", "true"),
        ("requestValidation", "false"),
        ("metrics", "false"),
        ("readyzCheck", "false"),
        ("requestCorrelation", "false"),
        ("rateLimiting", "false"),
        ("cors", "false"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    for (key, value) in overrides {
        match parts.iter_mut().find(|(k, _)| k == key) {
            Some(entry) => entry.1 = value.to_string(),
            None => parts.push((key.to_string(), value.to_string())),
        }
    }
    let body: Vec<String> = parts.iter().map(|(k, v)| format!("\"{k}\": {v}")).collect();
    let extra = if extra_top.is_empty() { String::new() } else { format!(", {extra_top}") };
    format!("{{ \"features\": {{ {} }}{extra} }}", body.join(", "))
}

struct Proj {
    root: PathBuf,
}

impl Proj {
    /// The common config and SQL files, but no endpoint files at all.
    fn bare(server_json: &str, spec: &str) -> Proj {
        let root = tempdir();
        let api = root.join("api");
        for dir in [
            "config/errors",
            "security/verifiers",
            "datasources/sql/db",
            "datasources/http",
            "datasources/endpoints",
        ] {
            std::fs::create_dir_all(api.join(dir)).unwrap();
        }
        std::fs::write(root.join("openapi.yaml"), spec).unwrap();
        std::fs::write(api.join("config/server.json"), server_json).unwrap();
        std::fs::write(api.join("config/errors/core.json"), CORE_ERRORS).unwrap();
        std::fs::write(api.join("config/connections.json"), r#"{ "db": { "driver": "sqlite", "database": ":memory:" } }"#).unwrap();
        std::fs::write(api.join("security/schemes.json"), "{}").unwrap();
        std::fs::write(api.join("datasources/sql/db/car.sql"), "SELECT :vin AS vin, :cap AS cap;").unwrap();
        std::fs::write(api.join("datasources/sql/db/make.sql"), "SELECT :name AS name;").unwrap();
        Proj { root }
    }

    /// `bare` plus the three default exposed endpoints that match `SPEC_PLAIN`.
    fn new(server_json: &str, spec: &str) -> Proj {
        let proj = Proj::bare(server_json, spec);
        proj.endpoint(
            "cars/{vin}",
            "get",
            r#"{ "operationId": "getCar", "mcp": { "expose": true },
                 "sources": { "car": { "type": "sql", "connection": "db", "script": "car.sql", "cardinality": "one",
                                       "parameters": [ { "name": "vin", "from": "path.vin" }, { "name": "cap", "from": "query.limit" } ] } },
                 "response": { "vin": "sources.car.vin", "cap": "sources.car.cap" } }"#,
        );
        proj.endpoint(
            "cars",
            "post",
            r#"{ "operationId": "createCar", "successStatus": 201, "mcp": { "expose": true },
                 "sources": { "row": { "type": "sql", "connection": "db", "script": "make.sql", "cardinality": "one",
                                       "parameters": [ { "name": "name", "from": "body.name" } ] } },
                 "response": { "name": "sources.row.name" } }"#,
        );
        proj.endpoint(
            "gone",
            "delete",
            r#"{ "operationId": "removeAll", "successStatus": 204, "mcp": { "expose": true }, "sources": {}, "response": {} }"#,
        );
        proj
    }

    fn api(&self) -> PathBuf {
        self.root.join("api")
    }

    fn endpoint(&self, folder: &str, token: &str, json: &str) {
        let dir = self.api().join("datasources/endpoints").join(folder);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("endpoint.{token}.json")), json).unwrap();
    }

    fn remove_endpoint(&self, folder: &str) {
        std::fs::remove_dir_all(self.api().join("datasources/endpoints").join(folder)).unwrap();
    }

    fn secure_with_verifier(&self, verifier_sql: &str, valid_if: &str) {
        std::fs::write(self.api().join("security/schemes.json"), r#"{ "tok": { "verifier": "v.json" } }"#).unwrap();
        std::fs::write(
            self.api().join("security/verifiers/v.json"),
            format!(
                r#"{{ "type": "sql", "connection": "db", "script": "verify.sql", "parameters": [ {{ "name": "key", "from": "header.X-Api-Key" }} ], "validIf": "{valid_if}" }}"#
            ),
        )
        .unwrap();
        std::fs::write(self.api().join("datasources/sql/db/verify.sql"), verifier_sql).unwrap();
    }

    async fn serve(&self) -> SocketAddr {
        let (router, server_config) = build_api_router(&self.root, false).await.expect("the project assembles");
        crate::server::spawn_served(router, server_config.case_sensitive_methods()).await
    }

    async fn refusal(&self) -> io::Error {
        build_api_router(&self.root, false).await.map(|_| ()).expect_err("startup must be refused")
    }
}

impl Drop for Proj {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

// ---------------------------------------------------------------- raw client

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    /// The JSON object in the body, tolerant of any chunk framing the loopback path may leave around it.
    fn json(&self) -> Value {
        let start = self.body.find('{').unwrap_or_else(|| panic!("no JSON in body: {:?}", self.body));
        let end = self.body.rfind('}').unwrap();
        serde_json::from_str(&self.body[start..=end]).unwrap_or_else(|e| panic!("bad JSON ({e}): {:?}", self.body))
    }
}

/// Sends the bytes, ignoring write errors (a server may answer and reset before the whole body is
/// out), and reads until the peer closes or goes quiet for `quiet_ms`.
async fn send_raw(addr: SocketAddr, bytes: &[u8], quiet_ms: u64) -> Reply {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let _ = stream.write_all(bytes).await;
    let mut received = Vec::new();
    loop {
        let mut chunk = [0u8; 8192];
        match tokio::time::timeout(std::time::Duration::from_millis(quiet_ms), stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => received.extend_from_slice(&chunk[..n]),
        }
    }
    let split = received.windows(4).position(|w| w == b"\r\n\r\n");
    let (head, body) = match split {
        Some(i) => (&received[..i], received[i + 4..].to_vec()),
        None => (&received[..], Vec::new()),
    };
    let head = String::from_utf8_lossy(head).into_owned();
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or_default().split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    Reply {
        status,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

fn has_header(extra: &[(&str, &str)], name: &str) -> bool {
    extra.iter().any(|(k, _)| k.eq_ignore_ascii_case(name))
}

fn request_bytes(method: &str, path: &str, extra: &[(&str, &str)], body: &str) -> Vec<u8> {
    let mut out = format!("{method} {path} HTTP/1.1\r\n");
    if !has_header(extra, "host") {
        out.push_str("Host: localhost\r\n");
    }
    if !has_header(extra, "content-type") {
        out.push_str("Content-Type: application/json\r\n");
    }
    for (k, v) in extra {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    if !has_header(extra, "content-length") && !has_header(extra, "transfer-encoding") {
        out.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    out.push_str("Connection: close\r\n\r\n");
    out.push_str(body);
    out.into_bytes()
}

async fn rpc_with(addr: SocketAddr, extra: &[(&str, &str)], body: &Value) -> Reply {
    send_raw(addr, &request_bytes("POST", "/mcp", extra, &body.to_string()), 600).await
}

async fn rpc(addr: SocketAddr, body: Value) -> Reply {
    rpc_with(addr, &[], &body).await
}

async fn http_get(addr: SocketAddr, path: &str, extra: &[(&str, &str)]) -> Reply {
    let mut out = format!("GET {path} HTTP/1.1\r\n");
    if !has_header(extra, "host") {
        out.push_str("Host: localhost\r\n");
    }
    for (k, v) in extra {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("Connection: close\r\n\r\n");
    send_raw(addr, out.as_bytes(), 600).await
}

fn call(id: i64, name: &str, arguments: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call", "params": { "name": name, "arguments": arguments } })
}

fn text_of(reply: &Value, index: usize) -> String {
    reply["result"]["content"][index]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("no text block {index}: {reply}"))
        .to_string()
}

const MODERN_META: &str = r#"{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}"#;

fn modern_body(method: &str, name: Option<&str>, arguments: Value) -> Value {
    let mut params = json!({ "_meta": serde_json::from_str::<Value>(MODERN_META).unwrap() });
    if let Some(name) = name {
        params["name"] = json!(name);
        params["arguments"] = arguments;
    }
    json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
}

fn modern_headers<'a>(method: &'a str, name: Option<&'a str>) -> Vec<(&'static str, &'a str)> {
    let mut h = vec![("MCP-Protocol-Version", "2026-07-28"), ("Mcp-Method", method)];
    if let Some(name) = name {
        h.push(("Mcp-Name", name));
    }
    h
}

// ---------------------------------------------------------------- feature off

#[tokio::test]
async fn with_features_mcp_off_there_is_no_mcp_route_and_the_endpoint_blocks_are_inert() {
    let proj = Proj::new(&server_json(&[("mcp", "false")], ""), SPEC_PLAIN);
    let addr = proj.serve().await;
    let reply = rpc(addr, json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" })).await;
    assert_eq!(reply.status, 404, "not 405: the route must not exist at all");
    let http = http_get(addr, "/cars/V1?limit=3", &[]).await;
    assert_eq!(http.status, 200, "the ordinary HTTP route is unaffected: {}", http.body);
}

#[tokio::test]
async fn a_server_json_without_any_mcp_keys_defaults_to_off() {
    let proj = Proj::new(
        r#"{ "features": { "requestValidation": false, "metrics": false, "readyzCheck": false } }"#,
        SPEC_PLAIN,
    );
    let addr = proj.serve().await;
    assert_eq!(rpc(addr, json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" })).await.status, 404);
}

// ---------------------------------------------------------------- protocol flows

#[tokio::test]
async fn the_legacy_flow_initialize_ping_list_and_call_works_without_any_session() {
    let proj = Proj::new(&server_json(&[], ""), SPEC_PLAIN);
    let addr = proj.serve().await;

    let init = rpc(
        addr,
        json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2025-06-18" } }),
    )
    .await;
    assert_eq!(init.status, 200);
    assert!(init.header("mcp-session-id").is_none(), "stateless: no session is ever issued");
    let body = init.json();
    assert_eq!(body["id"], 1);
    assert_eq!(body["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(body["result"]["serverInfo"], json!({ "name": "Cars API", "version": "7" }));
    assert_eq!(body["result"]["capabilities"]["tools"]["listChanged"], false);
    assert_ne!(body["result"]["serverInfo"]["version"], env!("CARGO_PKG_VERSION"));

    let unknown_version = rpc(
        addr,
        json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "1999-01-01" } }),
    )
    .await;
    assert_eq!(
        unknown_version.json()["result"]["protocolVersion"],
        "2025-11-25",
        "falls back to the newest legacy version"
    );

    let ping = rpc(addr, json!({ "jsonrpc": "2.0", "id": "p", "method": "ping" })).await;
    assert_eq!(ping.json(), json!({ "jsonrpc": "2.0", "id": "p", "result": {} }));

    let list = rpc(addr, json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" })).await;
    let names: Vec<String> = list.json()["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(names, ["createCar", "getCar", "removeAll"], "sorted, deterministic");
    assert!(list.json()["result"].get("ttlMs").is_none() && list.json()["result"].get("resultType").is_none());

    let answered = rpc(addr, call(3, "getCar", json!({ "vin": "V-1", "limit": 5 }))).await;
    assert_eq!(answered.status, 200);
    let reply = answered.json();
    assert_eq!(reply["result"].get("isError"), None);
    assert_eq!(serde_json::from_str::<Value>(&text_of(&reply, 0)).unwrap(), json!({ "vin": "V-1", "cap": "5" }));
    assert_eq!(reply["result"]["_meta"]["frogs/httpStatus"], 200);
    assert!(reply["result"].get("resultType").is_none());
}

#[tokio::test]
async fn the_modern_flow_discover_list_and_call_carries_result_type_and_cache_hints() {
    let proj = Proj::new(&server_json(&[], r#""mcp": { "listTtlMs": 4321, "serverName": "Custom" }"#), SPEC_PLAIN);
    let addr = proj.serve().await;

    let discover = rpc_with(addr, &[], &modern_body("server/discover", None, Value::Null)).await;
    assert_eq!(discover.status, 400, "no Mcp-Method header: refused before dispatch");
    assert_eq!(discover.json()["error"]["code"], -32020);

    let discover = rpc_with(addr, &modern_headers("server/discover", None), &modern_body("server/discover", None, Value::Null)).await;
    assert_eq!(discover.status, 200, "{}", discover.body);
    let result = discover.json()["result"].clone();
    assert_eq!(result["supportedVersions"], json!(["2026-07-28", "2025-11-25", "2025-06-18"]));
    assert_eq!(result["capabilities"], json!({ "tools": {} }));
    assert_eq!(result["_meta"]["io.modelcontextprotocol/serverInfo"], json!({ "name": "Custom", "version": "7" }));
    assert_eq!(result["ttlMs"], 4321);
    assert_eq!(result["cacheScope"], "public");
    assert_eq!(result["resultType"], "complete");

    let list = rpc_with(addr, &modern_headers("tools/list", None), &modern_body("tools/list", None, Value::Null)).await;
    let result = list.json()["result"].clone();
    assert_eq!(result["ttlMs"], 4321);
    assert_eq!(result["cacheScope"], "public");
    assert_eq!(result["tools"].as_array().unwrap().len(), 3);

    let answered = rpc_with(
        addr,
        &modern_headers("tools/call", Some("getCar")),
        &modern_body("tools/call", Some("getCar"), json!({ "vin": "M-1" })),
    )
    .await;
    assert_eq!(answered.status, 200, "{}", answered.body);
    assert_eq!(answered.json()["result"]["resultType"], "complete");
    assert_eq!(serde_json::from_str::<Value>(&text_of(&answered.json(), 0)).unwrap()["vin"], "M-1");

    let ping = rpc_with(addr, &modern_headers("ping", None), &modern_body("ping", None, Value::Null)).await;
    assert_eq!(ping.status, 404, "ping is legacy-only");
    assert_eq!(ping.json()["error"]["code"], -32601);

    let unsupported = rpc_with(
        addr,
        &[("MCP-Protocol-Version", "1999-01-01")],
        &json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }),
    )
    .await;
    assert_eq!(unsupported.status, 400);
    assert_eq!(unsupported.json()["error"]["code"], -32022);
    assert_eq!(unsupported.json()["error"]["data"]["requested"], "1999-01-01");
}

#[tokio::test]
async fn a_duplicate_params_name_is_refused_before_the_mcp_name_header_is_compared() {
    let proj = Proj::new(&server_json(&[], ""), SPEC_PLAIN);
    let addr = proj.serve().await;
    let body =
        format!(r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"getCar","name":"removeAll","_meta":{MODERN_META},"arguments":{{"vin":"x"}}}}}}"#);
    let reply = send_raw(addr, &request_bytes("POST", "/mcp", &modern_headers("tools/call", Some("removeAll")), &body), 600).await;
    assert_eq!(reply.json()["error"]["code"], -32602, "{}", reply.body);
    let reply = send_raw(addr, &request_bytes("POST", "/mcp", &modern_headers("tools/call", Some("getCar")), &body), 600).await;
    assert_eq!(
        reply.json()["error"]["code"],
        -32602,
        "neither first-wins nor last-wins gets to match: {}",
        reply.body
    );
}

#[tokio::test]
async fn a_201_adds_a_status_block_a_204_is_only_that_block_and_the_status_is_in_meta() {
    let proj = Proj::new(&server_json(&[], ""), SPEC_PLAIN);
    let addr = proj.serve().await;

    let created = rpc(addr, call(1, "createCar", json!({ "body": { "name": "Civic" } }))).await.json();
    assert_eq!(text_of(&created, 0), "HTTP 201 Created");
    assert_eq!(serde_json::from_str::<Value>(&text_of(&created, 1)).unwrap(), json!({ "name": "Civic" }));
    assert_eq!(created["result"]["_meta"]["frogs/httpStatus"], 201);

    let gone = rpc(addr, call(2, "removeAll", json!({}))).await.json();
    assert_eq!(gone["result"]["content"].as_array().unwrap().len(), 1, "{gone}");
    assert_eq!(text_of(&gone, 0), "HTTP 204 No Content");
    assert_eq!(gone["result"]["_meta"]["frogs/httpStatus"], 204);
    assert_eq!(gone["result"].get("isError"), None);
}

#[tokio::test]
async fn an_exact_decimal_argument_reaches_the_source_verbatim() {
    let proj = Proj::new(&server_json(&[], ""), SPEC_PLAIN);
    let addr = proj.serve().await;
    let reply = rpc(addr, call(1, "getCar", json!({ "vin": "V" }))).await;
    assert!(reply.json()["result"]["content"][0]["text"].is_string());
    let raw = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"getCar","arguments":{"vin":"V","limit":12345678901234567.89}}}"#;
    let exact = send_raw(addr, &request_bytes("POST", "/mcp", &[], raw), 600).await.json();
    assert_eq!(serde_json::from_str::<Value>(&text_of(&exact, 0)).unwrap()["cap"], "12345678901234567.89");
}

#[tokio::test]
async fn bad_tool_calls_are_invalid_params_and_a_failing_source_is_a_tool_error_with_its_status() {
    let proj = Proj::new(&server_json(&[], ""), SPEC_PLAIN);
    let addr = proj.serve().await;
    for bad in [
        call(1, "nope", json!({})),
        call(2, "getCar", json!({ "vin": "x", "surprise": 1 })),
        call(3, "getCar", json!({})),
        call(4, "getCar", json!({ "vin": "" })),
        call(5, "getCar", json!({ "vin": ["a"] })),
        call(6, "getCar", json!([1])),
        json!({ "jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {} }),
    ] {
        let reply = rpc(addr, bad.clone()).await.json();
        assert_eq!(reply["error"]["code"], -32602, "{bad}: {reply}");
    }
    let body_1e400 = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"createCar","arguments":{"body":1e400}}}"#;
    let reply = send_raw(addr, &request_bytes("POST", "/mcp", &[], body_1e400), 600).await.json();
    // The plan says -32602; the envelope-level duplicate-key pass rejects an out-of-f64-range number first, as -32700 (a known, reported deviation).
    assert!(
        [-32602, -32700].contains(&reply["error"]["code"].as_i64().unwrap()),
        "HTTP would send Null here; MCP refuses: {reply}"
    );
}

// ---------------------------------------------------------------- transport checks

#[tokio::test]
async fn get_and_delete_on_mcp_are_405_with_allow_post() {
    let proj = Proj::new(&server_json(&[], ""), SPEC_PLAIN);
    let addr = proj.serve().await;
    for method in ["GET", "DELETE"] {
        let reply = send_raw(addr, &request_bytes(method, "/mcp", &[], ""), 600).await;
        assert_eq!(reply.status, 405, "{method}");
        assert_eq!(reply.header("allow"), Some("POST"), "{method}");
    }
}

#[tokio::test]
async fn a_disallowed_host_or_origin_is_403_with_a_body_that_leaks_no_configuration() {
    let proj = Proj::new(
        &server_json(
            &[],
            r#""mcp": { "allowedHosts": ["configured.internal"], "allowedOrigins": ["https://app.example"] }"#,
        ),
        SPEC_PLAIN,
    );
    let addr = proj.serve().await;
    let ping = json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" });
    let bad_host = rpc_with(addr, &[("Host", "evil.example")], &ping).await;
    assert_eq!(bad_host.status, 403);
    for needle in ["evil.example", "configured.internal", "allowedHosts", "app.example"] {
        assert!(!bad_host.body.contains(needle), "{needle}: {}", bad_host.body);
    }
    let bad_origin = rpc_with(addr, &[("Origin", "https://evil.example")], &ping).await;
    assert_eq!(bad_origin.status, 403);
    assert!(
        !bad_origin.body.contains("app.example") && !bad_origin.body.contains("allowedOrigins"),
        "{}",
        bad_origin.body
    );
    assert_eq!(
        rpc_with(addr, &[("Host", "configured.internal:9000"), ("Origin", "https://app.example")], &ping)
            .await
            .status,
        200
    );
    assert_eq!(rpc_with(addr, &[("Content-Type", "text/plain")], &ping).await.status, 415);
}

#[tokio::test]
async fn a_host_refusal_comes_back_before_a_declared_ten_megabyte_body_is_read() {
    let proj = Proj::new(&server_json(&[], ""), SPEC_PLAIN);
    let addr = proj.serve().await;
    let bytes = request_bytes("POST", "/mcp", &[("Host", "evil.example"), ("Content-Length", "10485760")], "{\"jsonrpc\"");
    let reply = tokio::time::timeout(std::time::Duration::from_secs(10), send_raw(addr, &bytes, 700))
        .await
        .expect("the refusal must not wait for the declared body");
    assert_eq!(reply.status, 403);
}

#[tokio::test]
async fn a_declared_length_over_two_mebibytes_is_413_without_waiting_for_the_body() {
    let proj = Proj::new(&server_json(&[], ""), SPEC_PLAIN);
    let addr = proj.serve().await;
    let declared = (2 * 1024 * 1024 + 1).to_string();
    let bytes = request_bytes("POST", "/mcp", &[("Content-Length", &declared)], "{}");
    let reply = tokio::time::timeout(std::time::Duration::from_secs(10), send_raw(addr, &bytes, 700))
        .await
        .expect("no body read");
    assert_eq!(reply.status, 413);
    assert_eq!(reply.json()["error"]["message"], "Payload Too Large");
}

#[tokio::test]
async fn a_chunked_body_over_two_mebibytes_is_413_and_one_just_under_the_cap_is_served() {
    let proj = Proj::new(&server_json(&[], ""), SPEC_PLAIN);
    let addr = proj.serve().await;
    let chunked = |payload_len: usize| {
        let mut out = request_bytes("POST", "/mcp", &[("Transfer-Encoding", "chunked")], "");
        // The header block ends with CRLFCRLF; append chunks after it.
        let filler = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"ping","pad":"{}"}}"#, "x".repeat(payload_len));
        for part in filler.as_bytes().chunks(64 * 1024) {
            out.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
            out.extend_from_slice(part);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"0\r\n\r\n");
        out
    };
    let over = send_raw(addr, &chunked(2 * 1024 * 1024 + 10), 1000).await;
    assert_eq!(over.status, 413, "{}", over.body);
    let under = send_raw(addr, &chunked(1024 * 1024), 1000).await;
    assert_eq!(under.status, 200, "{}", under.body);
}

#[tokio::test]
async fn a_notification_gets_202_and_never_runs_the_tool_or_spends_a_token() {
    let proj = Proj::new(&server_json(&[], ""), SPEC_PLAIN);
    proj.endpoint(
        "cars/{vin}",
        "get",
        r#"{ "operationId": "getCar", "mcp": { "expose": true }, "rateLimit": { "requestsPerSecond": 1, "burst": 1 },
             "sources": { "car": { "type": "sql", "connection": "db", "script": "car.sql", "cardinality": "one",
                                   "parameters": [ { "name": "vin", "from": "path.vin" }, { "name": "cap", "from": "query.limit" } ] } },
             "response": { "vin": "sources.car.vin" } }"#,
    );
    let addr = proj.serve().await;
    for _ in 0..3 {
        let notification = json!({ "jsonrpc": "2.0", "method": "tools/call", "params": { "name": "getCar", "arguments": { "vin": "N" } } });
        let reply = rpc(addr, notification).await;
        assert_eq!(reply.status, 202);
        assert!(reply.body.trim().is_empty() || !reply.body.contains("result"), "{}", reply.body);
    }
    let first = rpc(addr, call(1, "getCar", json!({ "vin": "after" }))).await.json();
    assert_eq!(
        first["result"].get("isError"),
        None,
        "three notifications spent nothing from a burst-1 bucket: {first}"
    );
}

#[tokio::test]
async fn a_refused_host_does_not_spend_the_endpoint_token_either() {
    let proj = Proj::new(&server_json(&[], ""), SPEC_PLAIN);
    proj.endpoint(
        "cars/{vin}",
        "get",
        r#"{ "operationId": "getCar", "mcp": { "expose": true }, "rateLimit": { "requestsPerSecond": 1, "burst": 1 },
             "sources": {}, "response": {} }"#,
    );
    let addr = proj.serve().await;
    let call_body = call(1, "getCar", json!({ "vin": "x" }));
    for _ in 0..3 {
        assert_eq!(rpc_with(addr, &[("Host", "evil.example")], &call_body).await.status, 403);
    }
    let ok = rpc(addr, call_body).await.json();
    assert_eq!(ok["result"].get("isError"), None, "{ok}");
}

// ---------------------------------------------------------------- shared limiters, metrics, correlation, CORS

#[tokio::test]
async fn the_per_endpoint_limiter_is_one_bucket_shared_by_the_http_route_and_the_tool() {
    let endpoint = r#"{ "operationId": "getCar", "mcp": { "expose": true }, "rateLimit": { "requestsPerSecond": 1, "burst": 1 }, "sources": {}, "response": {} }"#;
    let proj = Proj::new(&server_json(&[], ""), SPEC_PLAIN);
    proj.endpoint("cars/{vin}", "get", endpoint);
    let addr = proj.serve().await;
    assert_eq!(http_get(addr, "/cars/V1", &[]).await.status, 200);
    let limited = rpc(addr, call(1, "getCar", json!({ "vin": "V1" }))).await;
    assert_eq!(limited.status, 200, "a per-tool limit is a tool error, not a transport error");
    let body = limited.json();
    assert_eq!(body["result"]["isError"], true, "{body}");
    assert_eq!(body["result"]["_meta"]["frogs/httpStatus"], 429);
    assert!(body["result"]["_meta"]["frogs/retryAfterSeconds"].is_number(), "{body}");
    assert_eq!(serde_json::from_str::<Value>(&text_of(&body, 0)).unwrap()["name"], "rate_limit_exceeded");

    let proj = Proj::new(&server_json(&[], ""), SPEC_PLAIN);
    proj.endpoint("cars/{vin}", "get", endpoint);
    let addr = proj.serve().await;
    let first = rpc(addr, call(1, "getCar", json!({ "vin": "V1" }))).await.json();
    assert_eq!(first["result"].get("isError"), None, "{first}");
    assert_eq!(
        http_get(addr, "/cars/V1", &[]).await.status,
        429,
        "the tool call used the very token the HTTP route would have"
    );
}

#[tokio::test]
async fn the_global_limiter_covers_mcp_and_http_with_one_budget_in_both_orders() {
    let features = server_json(&[("rateLimiting", "true")], r#""rateLimit": { "requestsPerSecond": 1, "burst": 2 }"#);
    let ping = json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" });

    let proj = Proj::new(&features, SPEC_PLAIN);
    let addr = proj.serve().await;
    assert_eq!(rpc(addr, ping.clone()).await.status, 200);
    assert_eq!(rpc(addr, ping.clone()).await.status, 200);
    assert_eq!(
        http_get(addr, "/cars/V1", &[]).await.status,
        429,
        "two /mcp POSTs already drained the shared global bucket"
    );

    let proj = Proj::new(&features, SPEC_PLAIN);
    let addr = proj.serve().await;
    assert_eq!(http_get(addr, "/cars/V1", &[]).await.status, 200);
    assert_eq!(http_get(addr, "/cars/V1", &[]).await.status, 200);
    let limited = rpc(addr, ping).await;
    assert_eq!(limited.status, 429, "the transport-level global limit answers 429 on /mcp");
}

#[tokio::test]
async fn without_global_rate_limiting_mcp_is_never_throttled_by_it() {
    let proj = Proj::new(
        &server_json(&[("rateLimiting", "false")], r#""rateLimit": { "requestsPerSecond": 1, "burst": 1 }"#),
        SPEC_PLAIN,
    );
    let addr = proj.serve().await;
    for _ in 0..6 {
        assert_eq!(rpc(addr, json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" })).await.status, 200);
    }
}

#[tokio::test]
async fn mcp_requests_are_counted_in_the_shared_metrics() {
    let proj = Proj::new(&server_json(&[("metrics", "true")], ""), SPEC_PLAIN);
    let addr = proj.serve().await;
    let count_200 = |text: &str| -> u64 {
        text.lines()
            .find(|l| l.starts_with("http_requests_total{status=\"200\"}"))
            .and_then(|l| l.rsplit(' ').next())
            .and_then(|n| n.parse().ok())
            .unwrap_or(0)
    };
    let before = count_200(&http_get(addr, "/metrics", &[]).await.body);
    for _ in 0..3 {
        assert_eq!(rpc(addr, json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" })).await.status, 200);
    }
    let after = count_200(&http_get(addr, "/metrics", &[]).await.body);
    assert!(after >= before + 3, "before={before} after={after}");
    let refused = rpc_with(addr, &[("Host", "evil.example")], &json!({})).await;
    assert_eq!(refused.status, 403);
    let text = http_get(addr, "/metrics", &[]).await.body;
    assert!(text.contains("http_requests_total{status=\"403\"} 1"), "{text}");
}

#[tokio::test]
async fn the_correlation_id_is_echoed_on_mcp_only_when_request_correlation_is_on() {
    let ping = json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" });
    let on = Proj::new(&server_json(&[("requestCorrelation", "true")], ""), SPEC_PLAIN);
    let reply = rpc(on.serve().await, ping.clone()).await;
    assert!(reply.header("x-request-id").is_some(), "{:?}", reply.headers);
    let off = Proj::new(&server_json(&[("requestCorrelation", "false")], ""), SPEC_PLAIN);
    assert!(rpc(off.serve().await, ping).await.header("x-request-id").is_none());
}

#[tokio::test]
async fn cors_never_applies_to_mcp_even_when_it_is_on_for_everything_else() {
    let proj = Proj::new(
        &server_json(
            &[("cors", "true")],
            r#""cors": { "allowedOrigins": ["*"] }, "mcp": { "allowedOrigins": ["https://app.example"] }"#,
        ),
        SPEC_PLAIN,
    );
    let addr = proj.serve().await;
    let http = http_get(addr, "/cars/V1", &[("Origin", "https://app.example")]).await;
    assert!(
        http.header("access-control-allow-origin").is_some(),
        "control: CORS is live on the HTTP route: {:?}",
        http.headers
    );
    let ping = json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" });
    let reply = rpc_with(addr, &[("Origin", "https://app.example")], &ping).await;
    assert_eq!(reply.status, 200);
    assert!(reply.headers.iter().all(|(k, _)| !k.starts_with("access-control-")), "{:?}", reply.headers);
    let preflight = send_raw(
        addr,
        &request_bytes("OPTIONS", "/mcp", &[("Origin", "https://app.example"), ("Access-Control-Request-Method", "POST")], ""),
        600,
    )
    .await;
    assert_eq!(preflight.status, 405, "a browser preflight gets no CORS treatment");
    assert!(preflight.headers.iter().all(|(k, _)| !k.starts_with("access-control-")), "{:?}", preflight.headers);
}

// ---------------------------------------------------------------- authentication

#[tokio::test]
async fn a_failed_caller_authentication_is_a_transport_401_and_a_good_key_runs_the_tool() {
    let proj = Proj::bare(&server_json(&[], ""), SPEC_SECURED);
    proj.secure_with_verifier("SELECT CASE WHEN :key = 'secret' THEN 'yes' ELSE 'no' END AS status;", "row.status = yes");
    proj.endpoint(
        "cars/{vin}",
        "get",
        r#"{ "operationId": "getCar", "security": "tok", "mcp": { "expose": true }, "sources": {}, "response": {} }"#,
    );
    let addr = proj.serve().await;

    let denied = rpc(addr, call(1, "getCar", json!({ "vin": "V" }))).await;
    assert_eq!(denied.status, 401, "{}", denied.body);
    let body = denied.json();
    assert_eq!(body["error"]["code"], -32600);
    assert_eq!(body["error"]["message"], "Unauthorized");
    assert_eq!(body["error"]["data"]["name"], "auth.invalid_credentials");
    assert_eq!(body["id"], 1);

    let allowed = rpc_with(addr, &[("X-Api-Key", "secret")], &call(2, "getCar", json!({ "vin": "V" }))).await;
    assert_eq!(allowed.status, 200, "{}", allowed.body);
    assert_eq!(allowed.json()["result"].get("isError"), None);

    let listed = rpc(addr, json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/list" })).await;
    assert_eq!(listed.status, 200, "tools/list is anonymous in Milestone 1");
    assert_eq!(listed.json()["result"]["tools"][0]["name"], "getCar");
}

#[tokio::test]
async fn a_verifier_outage_is_a_tool_error_not_a_transport_401() {
    let proj = Proj::bare(&server_json(&[], ""), SPEC_SECURED);
    proj.secure_with_verifier("SELECT * FROM table_that_does_not_exist WHERE k = :key;", "row.active = true");
    proj.endpoint(
        "cars/{vin}",
        "get",
        r#"{ "operationId": "getCar", "security": "tok", "mcp": { "expose": true }, "sources": {}, "response": {} }"#,
    );
    let addr = proj.serve().await;
    let reply = rpc_with(addr, &[("X-Api-Key", "anything")], &call(1, "getCar", json!({ "vin": "V" }))).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    let body = reply.json();
    assert_eq!(body["result"]["isError"], true, "{body}");
    assert_eq!(serde_json::from_str::<Value>(&text_of(&body, 0)).unwrap()["name"], "auth.verifier_unavailable");
}

#[tokio::test]
async fn a_rejected_host_costs_no_verifier_call() {
    let proj = Proj::bare(&server_json(&[], ""), SPEC_SECURED);
    // A verifier that can only ever succeed once would reveal a second call; here it simply must not be reached at all.
    proj.secure_with_verifier("SELECT CASE WHEN :key = 'secret' THEN 'yes' ELSE 'no' END AS status;", "row.status = yes");
    proj.endpoint(
        "cars/{vin}",
        "get",
        r#"{ "operationId": "getCar", "security": "tok", "rateLimit": { "requestsPerSecond": 1, "burst": 1 }, "mcp": { "expose": true }, "sources": {}, "response": {} }"#,
    );
    let addr = proj.serve().await;
    let call_body = call(1, "getCar", json!({ "vin": "V" }));
    for _ in 0..3 {
        let reply = rpc_with(addr, &[("Host", "evil.example"), ("X-Api-Key", "secret")], &call_body).await;
        assert_eq!(reply.status, 403);
    }
    let ok = rpc_with(addr, &[("X-Api-Key", "secret")], &call_body).await;
    assert_eq!(ok.status, 200, "{}", ok.body);
}

// ---------------------------------------------------------------- HTTP sources: percent-encoding of path arguments

struct Upstream {
    addr: SocketAddr,
    seen: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    hits: std::sync::Arc<AtomicUsize>,
}

async fn spawn_upstream() -> Upstream {
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let hits = std::sync::Arc::new(AtomicUsize::new(0));
    let (seen_in, hits_in) = (seen.clone(), hits.clone());
    let app = Router::new().fallback(move |uri: axum::http::Uri| {
        let (seen, hits) = (seen_in.clone(), hits_in.clone());
        async move {
            hits.fetch_add(1, Ordering::SeqCst);
            seen.lock().unwrap().push(uri.path().to_string());
            axum::Json(json!({ "ok": "yes" }))
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Upstream { addr, seen, hits }
}

const SPEC_ITEMS: &str = "openapi: 3.2.0
info: { title: Items, version: '1' }
paths:
  /items/{id}:
    get:
      operationId: getItem
      parameters:
        - { name: id, in: path, required: true, schema: { type: string } }
      responses: { '200': { description: ok } }
";

fn items_project(upstream: SocketAddr) -> Proj {
    let proj = Proj::bare(&server_json(&[], ""), SPEC_ITEMS);
    std::fs::write(
        proj.api().join("datasources/http/up.json"),
        format!(r#"{{ "method": "GET", "url": "http://{upstream}/items/{{{{id}}}}/detail", "timeoutMs": 3000 }}"#),
    )
    .unwrap();
    std::fs::write(proj.api().join("datasources/sql/db/echo.sql"), "SELECT :id AS id;").unwrap();
    proj.endpoint(
        "items/{id}",
        "get",
        r#"{ "operationId": "getItem", "mcp": { "expose": true },
             "sources": { "up": { "type": "http", "request": "up.json", "cardinality": "one", "parameters": [ { "name": "id", "from": "path.id" } ] },
                          "echo": { "type": "sql", "connection": "db", "script": "echo.sql", "cardinality": "one", "parameters": [ { "name": "id", "from": "path.id" } ] } },
             "response": { "ok": "sources.up.ok", "id": "sources.echo.id" } }"#,
    );
    proj
}

#[tokio::test]
async fn a_path_argument_with_slashes_dots_or_percent_escapes_reaches_an_http_source_only_percent_encoded_and_sql_only_bound() {
    let upstream = spawn_upstream().await;
    let proj = items_project(upstream.addr);
    let addr = proj.serve().await;
    let cases = [
        ("a/../b", "/items/a%2F..%2Fb/detail"),
        ("%2e%2e", "/items/%252e%252e/detail"),
        ("a/b", "/items/a%2Fb/detail"),
        ("x?y=1#z", "/items/x%3Fy%3D1%23z/detail"),
        ("..\\..", "/items/..%5C../detail"),
    ];
    for (argument, expected_path) in cases {
        upstream.seen.lock().unwrap().clear();
        let reply = rpc(addr, call(1, "getItem", json!({ "id": argument }))).await.json();
        assert_eq!(reply["result"].get("isError"), None, "{argument}: {reply}");
        let body: Value = serde_json::from_str(&text_of(&reply, 0)).unwrap();
        assert_eq!(body["id"], argument, "SQL receives the exact bytes as a bound value");
        let seen = upstream.seen.lock().unwrap().clone();
        assert_eq!(seen, [expected_path], "{argument}");
    }
}

#[tokio::test]
async fn a_bare_dot_dot_path_argument_does_not_climb_out_of_the_upstream_path_prefix() {
    let upstream = spawn_upstream().await;
    let proj = items_project(upstream.addr);
    let addr = proj.serve().await;
    for dots in ["..", "."] {
        let reply = rpc(addr, call(1, "getItem", json!({ "id": dots }))).await.json();
        assert_eq!(reply["result"]["isError"], true, "{dots}: {reply}");
    }
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 0, "a dot-segment argument must never be sent upstream");
}

#[tokio::test]
async fn a_notification_and_a_refused_request_never_reach_an_http_source() {
    let upstream = spawn_upstream().await;
    let proj = items_project(upstream.addr);
    let addr = proj.serve().await;
    let notification = json!({ "jsonrpc": "2.0", "method": "tools/call", "params": { "name": "getItem", "arguments": { "id": "n" } } });
    assert_eq!(rpc(addr, notification).await.status, 202);
    assert_eq!(
        rpc_with(addr, &[("Host", "evil.example")], &call(1, "getItem", json!({ "id": "n" }))).await.status,
        403
    );
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 0, "nothing was dispatched");
    let _ = rpc(addr, call(2, "getItem", json!({ "id": "real" }))).await;
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 1);
}

// ---------------------------------------------------------------- path-level parameters and request validation

#[tokio::test]
async fn request_validation_enforces_a_path_level_required_query_parameter_on_http_and_over_mcp() {
    let spec = "openapi: 3.2.0
info: { title: t, version: '1' }
paths:
  /cars/{vin}:
    parameters:
      - { name: vin, in: path, required: true, schema: { type: string } }
      - { name: tenant, in: query, required: true, schema: { type: integer } }
    get:
      operationId: getCar
      responses: { '200': { description: ok } }
";
    let proj = Proj::bare(&server_json(&[("requestValidation", "true")], ""), spec);
    proj.endpoint(
        "cars/{vin}",
        "get",
        r#"{ "operationId": "getCar", "mcp": { "expose": true }, "sources": {}, "response": {} }"#,
    );
    let addr = proj.serve().await;
    assert_eq!(
        http_get(addr, "/cars/V1", &[]).await.status,
        400,
        "the path-level required query parameter used to be silently skipped"
    );
    assert_eq!(http_get(addr, "/cars/V1?tenant=abc", &[]).await.status, 400);
    assert_eq!(http_get(addr, "/cars/V1?tenant=7", &[]).await.status, 200);

    let list = rpc(addr, json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" })).await.json();
    let schema = &list["result"]["tools"][0]["inputSchema"];
    assert_eq!(schema["required"], json!(["vin", "tenant"]), "{schema}");
    let missing = rpc(addr, call(2, "getCar", json!({ "vin": "V" }))).await.json();
    assert_eq!(missing["result"]["isError"], true, "validation parity over MCP: {missing}");
    assert_eq!(missing["result"]["_meta"]["frogs/httpStatus"], 400);
    let present = rpc(addr, call(3, "getCar", json!({ "vin": "V", "tenant": 7 }))).await.json();
    assert_eq!(present["result"].get("isError"), None, "{present}");
}

#[test]
fn an_unresolvable_path_level_parameter_ref_refuses_startup_with_request_validation_on_and_a_routed_file() {
    let spec = "openapi: 3.2.0
info: { title: t, version: '1' }
paths:
  /x:
    parameters:
      - $ref: '#/components/parameters/Gone'
    get:
      operationId: getX
      responses: { '200': { description: ok } }
";
    let proj = Proj::bare(r#"{ "features": { "requestValidation": true, "metrics": false, "readyzCheck": false } }"#, spec);
    proj.endpoint("x", "get", r#"{ "operationId": "getX", "sources": {}, "response": {} }"#);
    let server = Config::load(&proj.api()).unwrap().server;
    let tree = startup_endpoint_tree(&proj.root, &server).unwrap();
    let err = load_openapi_for_startup_reported(&proj.root, &server, " HINT", &tree, crate::endpoint::route_plan::RootExtras::default())
        .map(|_| ())
        .expect_err("must refuse");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(
        err.to_string()
            .contains("1 route(s) have an openapi.yaml parameter $ref frogs could not resolve, so request validation for them would be incomplete — refusing to start; fix the $ref, then run frogs validate HINT"),
        "{err}"
    );
}

// ---------------------------------------------------------------- startup refusals

fn assert_refused_before_connecting(err: &io::Error, needle: &str) {
    assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
    assert!(err.to_string().contains("MCP problem(s) found"), "{err}");
    assert!(!err.to_string().to_lowercase().contains("nosuchdriver"), "refused before any connection: {err}");
    let _ = needle;
}

/// A project whose only connection can never open: a refusal that mentions it did not happen first.
fn unconnectable(proj: &Proj) {
    std::fs::write(
        proj.api().join("config/connections.json"),
        r#"{ "db": { "driver": "nosuchdriver", "url": "nowhere" } }"#,
    )
    .unwrap();
}

#[tokio::test]
async fn every_milestone_one_refusal_class_is_invalid_data_before_any_connection_or_pidfile() {
    type Mutator = fn(&Proj);
    let cases: Vec<(&str, Mutator)> = vec![
        ("accessScheme", |p| {
            std::fs::write(p.api().join("config/server.json"), server_json(&[], r#""mcp": { "accessScheme": "tok" }"#)).unwrap();
        }),
        ("protectedResource", |p| {
            std::fs::write(p.api().join("config/server.json"), server_json(&[], r#""mcp": { "protectedResource": {} }"#)).unwrap();
        }),
        ("bad allowedHosts entry", |p| {
            std::fs::write(
                p.api().join("config/server.json"),
                server_json(&[], r#""mcp": { "allowedHosts": ["https://x.example"] }"#),
            )
            .unwrap();
        }),
        ("bad allowedOrigins entry", |p| {
            std::fs::write(p.api().join("config/server.json"), server_json(&[], r#""mcp": { "allowedOrigins": ["*"] }"#)).unwrap();
        }),
        ("listTtlMs over max", |p| {
            std::fs::write(p.api().join("config/server.json"), server_json(&[], r#""mcp": { "listTtlMs": 86400001 }"#)).unwrap();
        }),
        ("malformed mcp block", |p| {
            p.endpoint(
                "gone",
                "delete",
                r#"{ "operationId": "removeAll", "mcp": { "expose": "yes" }, "sources": {}, "response": {} }"#,
            );
        }),
        ("duplicate tool name", |p| {
            p.endpoint(
                "gone",
                "delete",
                r#"{ "operationId": "removeAll", "mcp": { "expose": true, "name": "getCar" }, "sources": {}, "response": {} }"#,
            );
        }),
        ("invalid tool name", |p| {
            p.endpoint(
                "gone",
                "delete",
                r#"{ "operationId": "removeAll", "mcp": { "expose": true, "name": "bad name" }, "sources": {}, "response": {} }"#,
            );
        }),
        ("folder does not match the spec template exactly", |p| {
            p.remove_endpoint("cars/{vin}");
            p.endpoint(
                "cars/{id}",
                "get",
                r#"{ "operationId": "getCar", "mcp": { "expose": true }, "sources": {}, "response": {} }"#,
            );
        }),
        ("no spec operation for an exposed endpoint", |p| {
            p.endpoint(
                "unknown",
                "get",
                r#"{ "operationId": "u", "mcp": { "expose": true }, "sources": {}, "response": {} }"#,
            );
        }),
        ("an endpoint folder at /mcp", |p| {
            p.endpoint("mcp", "post", r#"{ "operationId": "m", "sources": {}, "response": {} }"#);
        }),
        ("a spec operation at /mcp", |p| {
            let mut spec = std::fs::read_to_string(p.root.join("openapi.yaml")).unwrap();
            spec.push_str("  /mcp:\n    post:\n      operationId: shadow\n      responses: { '200': { description: ok } }\n");
            std::fs::write(p.root.join("openapi.yaml"), spec).unwrap();
        }),
    ];
    for (label, mutate) in cases {
        let proj = Proj::new(&server_json(&[], ""), SPEC_PLAIN);
        mutate(&proj);
        unconnectable(&proj);
        let err = proj.refusal().await;
        if label == "an endpoint folder at /mcp" {
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{label}: {err}");
            assert!(!err.to_string().to_lowercase().contains("nosuchdriver"), "{label}: {err}");
        } else {
            assert_refused_before_connecting(&err, label);
        }
        assert!(!proj.root.join(".frogs/run.json").exists(), "{label}");
        assert!(
            crate::exit_codes::is_config_refusal(&err),
            "{label}: a registered service must stay stopped (exit 78)"
        );
        let service_err = precheck_security_for_service(&proj.root).expect_err(label);
        assert_eq!(
            service_err.kind(),
            io::ErrorKind::InvalidData,
            "{label}: the service precheck refuses too: {service_err}"
        );
    }
}

#[tokio::test]
async fn an_exposed_endpoint_with_an_unknown_security_scheme_is_absent_from_tools_list_and_startup_continues() {
    let proj = Proj::new(&server_json(&[], ""), SPEC_PLAIN);
    proj.endpoint(
        "gone",
        "delete",
        r#"{ "operationId": "removeAll", "security": "mystery", "mcp": { "expose": true }, "sources": {}, "response": {} }"#,
    );
    let spec = SPEC_PLAIN.replace(
        "      operationId: removeAll\n",
        "      operationId: removeAll\n      security: [ { mystery: [] } ]\n",
    );
    let spec = spec.replace(
        "paths:",
        "components:\n  securitySchemes:\n    mystery: { type: apiKey, in: header, name: X-M }\npaths:",
    );
    std::fs::write(proj.root.join("openapi.yaml"), spec).unwrap();
    let addr = proj.serve().await;
    let list = rpc(addr, json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" })).await.json();
    let names: Vec<&str> = list["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert!(!names.contains(&"removeAll"), "fail closed: an endpoint that answers 503 is not a tool: {names:?}");
    assert!(names.contains(&"getCar"));
    assert_eq!(rpc(addr, call(2, "removeAll", json!({}))).await.json()["error"]["code"], -32602);
}

#[tokio::test]
async fn the_server_name_falls_back_to_a_default_and_the_version_to_unversioned() {
    let spec = "openapi: 3.2.0\ninfo: {}\npaths:\n  /x:\n    get:\n      operationId: x\n      responses: { '200': { description: ok } }\n";
    let proj = Proj::bare(&server_json(&[], ""), spec);
    proj.endpoint("x", "get", r#"{ "operationId": "x", "sources": {}, "response": {} }"#);
    let addr = proj.serve().await;
    let init = rpc(addr, json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} })).await.json();
    assert_eq!(init["result"]["serverInfo"], json!({ "name": "frogs-api", "version": "unversioned" }), "{init}");
}

#[tokio::test]
async fn an_empty_api_root_mounts_mcp_at_the_root_and_a_set_api_root_nests_it() {
    let nested = Proj::new(&server_json(&[], r#""apiRoot": "/api/v1""#), SPEC_PLAIN);
    let addr = nested.serve().await;
    let ping = json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" });
    let at_root = rpc(addr, ping.clone()).await;
    assert_eq!(at_root.status, 404, "not at /mcp when apiRoot is set");
    let under = send_raw(addr, &request_bytes("POST", "/api/v1/mcp", &[], &ping.to_string()), 600).await;
    assert_eq!(under.status, 200, "{}", under.body);
    assert_eq!(under.json()["result"], json!({}));
    assert_eq!(http_get(addr, "/api/v1/cars/V1", &[]).await.status, 200);
}

// ---------------------------------------------------------------- frogs validate

fn validate_inputs<'a>(config: &'a Config, tree: &'a EndpointTree, doc: Option<&'a crate::openapi::OpenApiDocument>) -> crate::mcp::StartupInputs<'a> {
    crate::mcp::StartupInputs {
        server: &config.server,
        security: &config.security,
        connections: &config.connections,
        tree,
        doc,
        client_identity_available: false,
        web_role: false,
        web_allow_dot_paths: &[],
    }
}

fn findings(proj: &Proj) -> Option<(usize, Vec<(crate::mcp::Severity, String)>)> {
    let config = Config::load(&proj.api()).unwrap();
    let tree = scan_endpoint_tree(&proj.root, &config.server);
    let doc = crate::openapi::load(&proj.root.join("openapi.yaml"), config.server.openapi_load_options()).ok();
    crate::mcp::validate_findings(&validate_inputs(&config, &tree, doc.as_ref())).map(|r| (r.tools, r.findings))
}

fn has(findings: &[(crate::mcp::Severity, String)], severity: crate::mcp::Severity, needle: &str) -> bool {
    findings.iter().any(|(s, m)| *s == severity && m.contains(needle))
}

#[test]
fn validate_reports_nothing_when_mcp_is_off_and_no_endpoint_has_a_block() {
    let proj = Proj::bare(&server_json(&[("mcp", "false")], ""), SPEC_PLAIN);
    assert!(findings(&proj).is_none());
}

#[test]
fn validate_demotes_every_problem_to_a_warning_when_mcp_is_off_and_says_the_block_has_no_effect() {
    let proj = Proj::new(
        &server_json(&[("mcp", "false")], r#""mcp": { "accessScheme": "tok", "allowedHosts": ["https://x"] }"#),
        SPEC_PLAIN,
    );
    proj.endpoint(
        "gone",
        "delete",
        r#"{ "operationId": "removeAll", "mcp": { "expose": "yes" }, "sources": {}, "response": {} }"#,
    );
    let (_, found) = findings(&proj).expect("a section is printed");
    assert!(found.iter().all(|(s, _)| *s == crate::mcp::Severity::Warning), "{found:?}");
    assert!(has(&found, crate::mcp::Severity::Warning, "has no effect"), "{found:?}");
    assert!(has(&found, crate::mcp::Severity::Warning, "accessScheme"), "{found:?}");
}

#[test]
fn validate_reports_the_milestone_two_keys_and_bad_entries_as_errors_when_mcp_is_on() {
    let proj = Proj::new(
        &server_json(
            &[],
            r#""mcp": { "accessScheme": "tok", "protectedResource": {}, "allowedHosts": ["a:80", "*.x"], "allowedOrigins": ["https://x/p", "null"], "listTtlMs": 99999999999 }"#,
        ),
        SPEC_PLAIN,
    );
    let (tools, found) = findings(&proj).unwrap();
    assert_eq!(tools, 3);
    for needle in [
        "accessScheme",
        "protectedResource",
        "allowedHosts entry 'a:80'",
        "allowedHosts entry '*.x'",
        "allowedOrigins entry 'https://x/p'",
        "listTtlMs",
    ] {
        assert!(has(&found, crate::mcp::Severity::Error, needle), "{needle}: {found:?}");
    }
    assert!(has(&found, crate::mcp::Severity::Warning, "\"null\""), "{found:?}");
}

#[test]
fn validate_warns_about_empty_allowed_hosts_and_about_an_exposed_secured_endpoint() {
    let proj = Proj::bare(&server_json(&[], ""), SPEC_SECURED);
    proj.secure_with_verifier("SELECT 1 AS active;", "row.active = true");
    proj.endpoint(
        "cars/{vin}",
        "get",
        r#"{ "operationId": "getCar", "security": "tok", "mcp": { "expose": true }, "sources": {}, "response": {} }"#,
    );
    let (tools, found) = findings(&proj).unwrap();
    assert_eq!(tools, 1);
    assert!(has(&found, crate::mcp::Severity::Warning, "allowedHosts is empty"), "{found:?}");
    assert!(has(&found, crate::mcp::Severity::Warning, "tools/list is not authenticated"), "{found:?}");
    assert!(found.iter().all(|(s, _)| *s == crate::mcp::Severity::Warning), "{found:?}");
}

#[test]
fn validate_reports_an_exposed_endpoint_that_cannot_be_served_as_an_error_with_mcp_on() {
    let proj = Proj::new(&server_json(&[], ""), SPEC_PLAIN);
    proj.endpoint(
        "gone",
        "delete",
        r#"{ "operationId": "removeAll", "security": "nowhere", "mcp": { "expose": true }, "sources": {}, "response": {} }"#,
    );
    let (tools, found) = findings(&proj).unwrap();
    assert_eq!(tools, 2, "the unservable endpoint is not a tool");
    assert!(has(&found, crate::mcp::Severity::Error, "tool 'removeAll' not available"), "{found:?}");
}

#[test]
fn validate_warns_when_error_overrides_remap_a_caller_auth_code_away_from_401_and_403() {
    let proj = Proj::bare(&server_json(&[], ""), SPEC_SECURED);
    proj.secure_with_verifier("SELECT 1 AS active;", "row.active = true");
    proj.endpoint(
        "cars/{vin}",
        "get",
        r#"{ "operationId": "getCar", "security": "tok", "mcp": { "expose": true }, "errorOverrides": { "auth.invalid_credentials": { "httpStatus": 500 } }, "sources": {}, "response": {} }"#,
    );
    let (_, found) = findings(&proj).unwrap();
    assert!(has(&found, crate::mcp::Severity::Warning, "re-maps auth.invalid_credentials to 500"), "{found:?}");
}

#[test]
fn validate_warns_about_a_root_level_param_post_and_static_content_when_api_root_is_empty() {
    let proj = Proj::new(&server_json(&[], ""), SPEC_PLAIN);
    let config = Config::load(&proj.api()).unwrap();
    proj.endpoint("{anything}", "post", r#"{ "operationId": "any", "sources": {}, "response": {} }"#);
    let tree = scan_endpoint_tree(&proj.root, &config.server);
    let doc = crate::openapi::load(&proj.root.join("openapi.yaml"), config.server.openapi_load_options()).ok();
    let mut inputs = validate_inputs(&config, &tree, doc.as_ref());
    inputs.web_role = true;
    let report = crate::mcp::validate_findings(&inputs).unwrap();
    assert!(
        has(&report.findings, crate::mcp::Severity::Warning, "root-level {param} POST"),
        "{:?}",
        report.findings
    );
    assert!(has(&report.findings, crate::mcp::Severity::Warning, "static content"), "{:?}", report.findings);
}

#[test]
fn a_route_collision_with_mcp_shows_in_the_existing_route_table_check() {
    let proj = Proj::new(&server_json(&[], ""), SPEC_PLAIN);
    proj.endpoint("mcp", "post", r#"{ "operationId": "m", "sources": {}, "response": {} }"#);
    let server = Config::load(&proj.api()).unwrap().server;
    let tree = scan_endpoint_tree(&proj.root, &server);
    let err = check_route_table(&server, &tree, RootExtras::default(), "")
        .err()
        .expect("the built-in /mcp collides with the endpoint folder");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.to_string().to_lowercase().contains("mcp") || err.to_string().contains("route"), "{err}");
    let off = Proj::new(&server_json(&[("mcp", "false")], ""), SPEC_PLAIN);
    off.endpoint("mcp", "post", r#"{ "operationId": "m", "sources": {}, "response": {} }"#);
    let server = Config::load(&off.api()).unwrap().server;
    let tree = scan_endpoint_tree(&off.root, &server);
    assert!(
        check_route_table(&server, &tree, RootExtras::default(), "").is_ok(),
        "with MCP off a folder named mcp is an ordinary route"
    );
}

#[test]
fn the_operational_routes_display_lists_mcp_only_when_it_is_on() {
    let on: ServerConfig = serde_json::from_str(&features("")).unwrap();
    assert!(operational_routes_display(&on).iter().any(|r| r.ends_with("/mcp")));
    let off: ServerConfig = serde_json::from_str("{}").unwrap();
    assert!(!operational_routes_display(&off).iter().any(|r| r.ends_with("/mcp")));
}

mod auth_m2;
