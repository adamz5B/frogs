//! MCP Milestone 2 end to end through the real `build_api_router`: the `accessScheme` gate, the
//! `WWW-Authenticate` challenges, per-endpoint scopes, the RFC 9728 metadata route and every new
//! startup refusal. The verifier is a real `frogs` HTTP verifier talking to a counting fake
//! introspection endpoint, so "the verifier was not called" is a measured fact.

use std::collections::HashMap;
use std::sync::Arc;

use super::*;

// ---------------------------------------------------------------- fixtures

struct Introspection {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
}

impl Introspection {
    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

/// `good` holds cars.read + cars.write, `reader` only cars.read, `bare` is active with no scope claim,
/// `down` is an upstream 500, anything else (including no token at all) is inactive.
async fn spawn_introspection() -> Introspection {
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let app = Router::new().route(
        "/introspect",
        axum::routing::get(move |axum::extract::Query(query): axum::extract::Query<HashMap<String, String>>| {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                let token = query.get("token").cloned().unwrap_or_default();
                match token.as_str() {
                    "good" => (axum::http::StatusCode::OK, axum::Json(json!({ "active": true, "scope": "cars.read cars.write" }))),
                    "reader" => (axum::http::StatusCode::OK, axum::Json(json!({ "active": true, "scope": "cars.read" }))),
                    "bare" => (axum::http::StatusCode::OK, axum::Json(json!({ "active": true }))),
                    "down" => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, axum::Json(json!({}))),
                    _ => (axum::http::StatusCode::OK, axum::Json(json!({ "active": false }))),
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Introspection { addr, hits }
}

const SPEC_OAUTH: &str = "openapi: 3.2.0
info: { title: Cars API, version: '7' }
components:
  securitySchemes:
    oauth:
      type: oauth2
      flows:
        clientCredentials:
          tokenUrl: 'https://auth.example.com/token'
          scopes: { cars.read: r, cars.write: w }
paths:
  /cars/{vin}:
    get:
      operationId: getCar
      security: [ { oauth: [cars.read] } ]
      parameters:
        - { name: vin, in: path, required: true, schema: { type: string } }
      responses: { '200': { description: ok } }
  /cars:
    post:
      operationId: createCar
      security: [ { oauth: [cars.write] } ]
      responses: { '200': { description: ok } }
  /open:
    get:
      operationId: listOpen
      responses: { '200': { description: ok } }
";

const MCP_FULL: &str = r#"{ "accessScheme": "oauth", "protectedResource": { "resource": "http://localhost/mcp", "authorizationServers": ["https://auth.example.com"], "scopesSupported": ["cars.read", "cars.write"] } }"#;
const MCP_PROTECTED_ONLY: &str = r#"{ "protectedResource": { "resource": "http://localhost/mcp", "authorizationServers": ["https://auth.example.com"], "scopesSupported": ["cars.read", "cars.write"] } }"#;
const MCP_GATE_ONLY: &str = r#"{ "accessScheme": "oauth" }"#;

const METADATA_URL: &str = "http://localhost/.well-known/oauth-protected-resource/mcp";
const METADATA_PATH: &str = "/.well-known/oauth-protected-resource/mcp";

fn challenge_401_default() -> String {
    format!("Bearer resource_metadata=\"{METADATA_URL}\", scope=\"cars.read cars.write\"")
}

/// A project with the OAuth verifier, two secured exposed tools (getCar needs cars.read, createCar needs
/// cars.write) and one open one. `cache_ttl` is the verifier's `cacheTtlSeconds`.
fn oauth_project(introspection: &Introspection, mcp: &str, top: &str, cache_ttl: Option<u64>) -> Proj {
    let extra = format!("{top}\"mcp\": {mcp}");
    let proj = Proj::bare(&server_json(&[], &extra), SPEC_OAUTH);
    let ttl = cache_ttl.map(|t| format!(r#", "cacheTtlSeconds": {t}"#)).unwrap_or_default();
    std::fs::write(proj.api().join("security/schemes.json"), r#"{ "oauth": { "verifier": "v.json" } }"#).unwrap();
    std::fs::write(
        proj.api().join("security/verifiers/v.json"),
        format!(
            r#"{{ "type": "http", "request": "introspect.json", "parameters": [ {{ "name": "token", "from": "header.Authorization" }} ], "validIf": "response.active = true", "scopesFrom": "response.scope"{ttl} }}"#
        ),
    )
    .unwrap();
    std::fs::write(
        proj.api().join("datasources/http/introspect.json"),
        format!(
            r#"{{ "method": "GET", "url": "http://{}/introspect?token={{{{token}}}}", "timeoutMs": 3000 }}"#,
            introspection.addr
        ),
    )
    .unwrap();
    proj.endpoint(
        "cars/{vin}",
        "get",
        r#"{ "operationId": "getCar", "security": "oauth", "securityScopes": ["cars.read"], "mcp": { "expose": true }, "sources": {}, "response": {} }"#,
    );
    proj.endpoint(
        "cars",
        "post",
        r#"{ "operationId": "createCar", "security": "oauth", "securityScopes": ["cars.write"], "mcp": { "expose": true }, "sources": {}, "response": {} }"#,
    );
    proj.endpoint(
        "open",
        "get",
        r#"{ "operationId": "listOpen", "mcp": { "expose": true }, "sources": {}, "response": {} }"#,
    );
    proj
}

fn list_legacy(id: i64) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "method": "tools/list" })
}

fn auth(token: &str) -> Vec<(&'static str, String)> {
    vec![("Authorization", token.to_string())]
}

async fn rpc_auth(addr: SocketAddr, token: &str, body: &Value) -> Reply {
    let header = auth(token);
    let pairs: Vec<(&str, &str)> = header.iter().map(|(k, v)| (*k, v.as_str())).collect();
    rpc_with(addr, &pairs, body).await
}

async fn modern(addr: SocketAddr, token: Option<&str>, method: &str, name: Option<&str>, arguments: Value) -> Reply {
    let mut headers = modern_headers(method, name);
    if let Some(token) = token {
        headers.push(("Authorization", token));
    }
    rpc_with(addr, &headers, &modern_body(method, name, arguments)).await
}

fn names(reply: &Reply) -> Vec<String> {
    reply.json()["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect()
}

/// What must be identical between two responses that may not differ in any way a caller can observe.
fn observable(reply: &Reply) -> (u16, String, Option<String>, Option<String>) {
    (
        reply.status,
        reply.body.clone(),
        reply.header("www-authenticate").map(str::to_string),
        reply.header("content-type").map(str::to_string),
    )
}

// ---------------------------------------------------------------- the gate: denial

#[tokio::test]
async fn a_gated_tools_list_without_credentials_is_the_fixed_401_with_the_exact_challenge_in_both_eras() {
    let introspection = spawn_introspection().await;
    let proj = oauth_project(&introspection, MCP_FULL, "", None);
    let addr = proj.serve().await;
    let expected = r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32600,"message":"Unauthorized"}}"#;

    let legacy = rpc(addr, list_legacy(2)).await;
    assert_eq!(legacy.status, 401, "{}", legacy.body);
    assert_eq!(legacy.json().to_string(), expected);
    assert_eq!(legacy.header("www-authenticate"), Some(challenge_401_default().as_str()));

    let modern_reply = modern(addr, None, "tools/list", None, json!({})).await;
    assert_eq!(modern_reply.status, 401, "{}", modern_reply.body);
    assert_eq!(modern_reply.json().to_string(), expected.replace("\"id\":2", "\"id\":1"));
    assert_eq!(modern_reply.header("www-authenticate"), Some(challenge_401_default().as_str()));
}

#[tokio::test]
async fn a_rejected_credential_at_the_gate_is_the_same_fixed_401_and_a_good_one_lists_the_tools() {
    let introspection = spawn_introspection().await;
    let proj = oauth_project(&introspection, MCP_FULL, "", None);
    let addr = proj.serve().await;
    let none = rpc(addr, list_legacy(2)).await;
    let bad = rpc_auth(addr, "wrong", &list_legacy(2)).await;
    assert_eq!(observable(&none), observable(&bad), "no credential and a bad credential are indistinguishable");
    let ok = rpc_auth(addr, "good", &list_legacy(3)).await;
    assert_eq!(ok.status, 200, "{}", ok.body);
    assert_eq!(names(&ok), ["createCar", "getCar", "listOpen"]);
}

#[tokio::test]
async fn a_gated_tools_call_with_a_known_or_an_unknown_name_is_byte_identical_under_denial() {
    let introspection = spawn_introspection().await;
    let proj = oauth_project(&introspection, MCP_FULL, "", None);
    let addr = proj.serve().await;
    for era_modern in [false, true] {
        let (known, unknown) = if era_modern {
            (
                modern(addr, None, "tools/call", Some("getCar"), json!({ "vin": "V" })).await,
                modern(addr, None, "tools/call", Some("noSuchTool"), json!({})).await,
            )
        } else {
            (
                rpc(addr, call(1, "getCar", json!({ "vin": "V" }))).await,
                rpc(addr, call(1, "noSuchTool", json!({}))).await,
            )
        };
        assert_eq!(known.status, 401);
        assert_eq!(observable(&known), observable(&unknown), "modern={era_modern}");
        let body = known.json();
        assert!(body["error"].get("data").is_none() && body["error"].get("detail").is_none(), "{body}");
    }
}

#[tokio::test]
async fn the_gate_denial_has_no_data_even_under_debug_mode_and_with_invalid_credentials_remapped_everywhere() {
    let introspection = spawn_introspection().await;
    let proj = oauth_project(&introspection, MCP_FULL, r#""debugMode": true, "#, None);
    std::fs::write(
        proj.api().join("config/errors/core.json"),
        CORE_ERRORS.replace(
            r#""auth.invalid_credentials": { "httpStatus": 401"#,
            r#""auth.invalid_credentials": { "httpStatus": 500"#,
        ),
    )
    .unwrap();
    proj.endpoint(
        "cars/{vin}",
        "get",
        r#"{ "operationId": "getCar", "security": "oauth", "securityScopes": ["cars.read"], "mcp": { "expose": true },
             "errorOverrides": { "auth.invalid_credentials": { "httpStatus": 418, "exposeDetail": true } }, "sources": {}, "response": {} }"#,
    );
    let addr = proj.serve().await;
    for token in ["", "wrong"] {
        let reply = if token.is_empty() {
            rpc(addr, call(9, "getCar", json!({ "vin": "V" }))).await
        } else {
            rpc_auth(addr, token, &call(9, "getCar", json!({ "vin": "V" }))).await
        };
        assert_eq!(reply.status, 401, "registry and errorOverrides cannot change the gate's status: {}", reply.body);
        assert_eq!(
            reply.json().to_string(),
            r#"{"jsonrpc":"2.0","id":9,"error":{"code":-32600,"message":"Unauthorized"}}"#
        );
    }
    assert!(
        !proj.api().join("config/errors.discovered.json").exists(),
        "a gate failure never writes the discovery scratch file"
    );
}

#[tokio::test]
async fn a_gated_server_without_a_protected_resource_denies_with_the_same_body_and_no_challenge() {
    let introspection = spawn_introspection().await;
    let proj = oauth_project(&introspection, MCP_GATE_ONLY, "", None);
    let addr = proj.serve().await;
    let reply = rpc(addr, list_legacy(2)).await;
    assert_eq!(reply.status, 401);
    assert_eq!(
        reply.json().to_string(),
        r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32600,"message":"Unauthorized"}}"#
    );
    assert!(reply.header("www-authenticate").is_none());
}

#[tokio::test]
async fn a_gate_denial_spends_no_per_tool_rate_limit_token_and_never_reaches_the_tool_verifier() {
    let introspection = spawn_introspection().await;
    let proj = oauth_project(&introspection, MCP_FULL, "", None);
    proj.endpoint(
        "open",
        "get",
        r#"{ "operationId": "listOpen", "rateLimit": { "requestsPerSecond": 1, "burst": 1 }, "mcp": { "expose": true }, "sources": {}, "response": {} }"#,
    );
    let addr = proj.serve().await;
    for _ in 0..4 {
        assert_eq!(rpc(addr, call(1, "listOpen", json!({}))).await.status, 401);
    }
    let ok = rpc_auth(addr, "good", &call(2, "listOpen", json!({}))).await;
    assert_eq!(ok.status, 200, "the single token was still there: {}", ok.body);
    assert_eq!(ok.json()["result"].get("isError"), None, "{}", ok.body);
    let second = rpc_auth(addr, "good", &call(3, "listOpen", json!({}))).await;
    assert_eq!(second.json()["result"]["_meta"]["frogs/httpStatus"], 429, "and now it is spent");
}

// ---------------------------------------------------------------- the gate: scope of the gate, outage, no verifier calls

#[tokio::test]
async fn discover_initialize_ping_notifications_and_unknown_methods_never_call_the_verifier() {
    let introspection = spawn_introspection().await;
    let proj = oauth_project(&introspection, MCP_FULL, "", None);
    let addr = proj.serve().await;

    let init = rpc(
        addr,
        json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2025-06-18" } }),
    )
    .await;
    assert_eq!(init.status, 200);
    assert_eq!(rpc(addr, json!({ "jsonrpc": "2.0", "id": 2, "method": "ping" })).await.status, 200);
    let discover = modern(addr, None, "server/discover", None, json!({})).await;
    assert_eq!(discover.status, 200, "{}", discover.body);
    assert_eq!(
        discover.json()["result"]["cacheScope"],
        "public",
        "discover stays public even when tools/list is private"
    );
    let note = rpc(addr, json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })).await;
    assert_eq!(note.status, 202);
    let note_call = rpc(addr, json!({ "jsonrpc": "2.0", "method": "tools/call", "params": { "name": "getCar" } })).await;
    assert_eq!(note_call.status, 202, "a notification is never dispatched, whatever its method");
    let unknown = rpc(addr, json!({ "jsonrpc": "2.0", "id": 3, "method": "no/such" })).await;
    assert_eq!(unknown.json()["error"]["code"], -32601);
    assert_eq!(introspection.hits(), 0, "none of those touched the verifier");

    assert_eq!(rpc(addr, list_legacy(4)).await.status, 401);
    assert_eq!(introspection.hits(), 1, "a gated tools/list is exactly one verifier call");
    assert_eq!(rpc(addr, call(5, "getCar", json!({ "vin": "V" }))).await.status, 401);
    assert_eq!(
        introspection.hits(),
        2,
        "a gated tools/call that is denied never reaches the tool, so exactly one more"
    );
}

#[tokio::test]
async fn a_passing_gate_then_a_secured_tool_costs_two_verifier_calls_without_a_cache_and_one_with_one() {
    let introspection = spawn_introspection().await;
    let proj = oauth_project(&introspection, MCP_FULL, "", None);
    let addr = proj.serve().await;
    assert_eq!(rpc_auth(addr, "good", &call(1, "getCar", json!({ "vin": "V" }))).await.status, 200);
    assert_eq!(introspection.hits(), 2);

    let cached_introspection = spawn_introspection().await;
    let cached = oauth_project(&cached_introspection, MCP_FULL, "", Some(60));
    let cached_addr = cached.serve().await;
    assert_eq!(rpc_auth(cached_addr, "good", &call(1, "getCar", json!({ "vin": "V" }))).await.status, 200);
    assert_eq!(rpc_auth(cached_addr, "good", &call(2, "getCar", json!({ "vin": "V" }))).await.status, 200);
    assert_eq!(cached_introspection.hits(), 1, "the gate and the tool share one cached verdict");
}

#[tokio::test]
async fn the_verifier_cache_is_shared_between_the_http_route_and_the_mcp_gate() {
    let introspection = spawn_introspection().await;
    let proj = oauth_project(&introspection, MCP_FULL, "", Some(60));
    let addr = proj.serve().await;
    let http = http_get(addr, "/cars/V", &[("Authorization", "good")]).await;
    assert_eq!(http.status, 200, "{}", http.body);
    assert_eq!(introspection.hits(), 1);
    assert_eq!(rpc_auth(addr, "good", &list_legacy(1)).await.status, 200);
    assert_eq!(introspection.hits(), 1, "the MCP gate hit the verdict the HTTP route cached");
}

#[tokio::test]
async fn a_verifier_outage_at_the_gate_is_the_fixed_internal_error_for_a_list_and_the_fixed_tool_error_for_a_call() {
    let introspection = spawn_introspection().await;
    let proj = oauth_project(&introspection, MCP_FULL, r#""debugMode": true, "#, None);
    let addr = proj.serve().await;

    let legacy_list = rpc_auth(addr, "down", &list_legacy(4)).await;
    assert_eq!(legacy_list.status, 200, "legacy answers errors with 200");
    assert_eq!(
        legacy_list.json().to_string(),
        r#"{"jsonrpc":"2.0","id":4,"error":{"code":-32603,"message":"Internal error"}}"#
    );
    let modern_list = modern(addr, Some("down"), "tools/list", None, json!({})).await;
    assert_eq!(modern_list.status, 500, "{}", modern_list.body);
    assert_eq!(modern_list.json()["error"], json!({ "code": -32603, "message": "Internal error" }));

    let known = rpc_auth(addr, "down", &call(5, "getCar", json!({ "vin": "V" }))).await;
    let unknown = rpc_auth(addr, "down", &call(5, "noSuchTool", json!({}))).await;
    assert_eq!(known.status, 200);
    assert_eq!(
        observable(&known),
        observable(&unknown),
        "known and unknown names are byte-identical during an outage"
    );
    let body = known.json();
    assert_eq!(body["result"]["isError"], true);
    assert_eq!(body["result"]["_meta"]["frogs/httpStatus"], 500);
    assert_eq!(body["result"]["content"].as_array().unwrap().len(), 1);
    assert_eq!(
        text_of(&body, 0),
        r#"{"code":500,"name":"auth.verifier_unavailable"}"#,
        "no verifier detail even under debugMode"
    );
    assert!(known.header("www-authenticate").is_none());
    assert!(!proj.api().join("config/errors.discovered.json").exists());
}

#[tokio::test]
async fn an_unreachable_verifier_datasource_is_an_outage_not_an_allow_and_the_registry_cannot_turn_it_into_a_401() {
    let introspection = spawn_introspection().await;
    let proj = oauth_project(&introspection, MCP_FULL, "", None);
    std::fs::write(
        proj.api().join("datasources/http/introspect.json"),
        r#"{ "method": "GET", "url": "http://127.0.0.1:1/introspect?token={{token}}", "timeoutMs": 300 }"#,
    )
    .unwrap();
    let addr = proj.serve().await;
    // A slow refused connect on some platforms must not race the reader: wait generously.
    let request = request_bytes("POST", "/mcp", &[("Authorization", "good")], &list_legacy(1).to_string());
    let reply = send_raw(addr, &request, 4000).await;
    assert_eq!(reply.json()["error"]["code"], -32603, "{}", reply.body);
}

// ---------------------------------------------------------------- scopes over MCP and HTTP

#[tokio::test]
async fn a_credential_lacking_the_tools_scope_gets_a_transport_403_with_the_insufficient_scope_challenge() {
    let introspection = spawn_introspection().await;
    let proj = oauth_project(&introspection, MCP_FULL, "", None);
    let addr = proj.serve().await;
    let denied = rpc_auth(addr, "reader", &call(1, "createCar", json!({}))).await;
    assert_eq!(denied.status, 403, "{}", denied.body);
    assert_eq!(
        denied.header("www-authenticate"),
        Some(format!("Bearer error=\"insufficient_scope\", scope=\"cars.write\", resource_metadata=\"{METADATA_URL}\"").as_str())
    );
    let body = denied.json();
    assert_eq!(body["error"]["code"], -32600);
    assert_eq!(body["error"]["message"], "Forbidden");
    assert_eq!(body["error"]["data"]["name"], "auth.insufficient_scope");
    let detail = body["error"]["data"]["detail"].as_str().unwrap_or_default();
    assert!(
        detail.contains("cars.write") && !detail.contains("cars.read"),
        "only the configured scope is named: {detail}"
    );

    let modern_denied = modern(addr, Some("reader"), "tools/call", Some("createCar"), json!({})).await;
    assert_eq!(modern_denied.status, 403);
    assert_eq!(modern_denied.header("www-authenticate"), denied.header("www-authenticate"));

    let allowed = rpc_auth(addr, "good", &call(2, "createCar", json!({}))).await;
    assert_eq!(allowed.status, 200, "{}", allowed.body);
    let own = rpc_auth(addr, "reader", &call(3, "getCar", json!({ "vin": "V" }))).await;
    assert_eq!(own.status, 200, "reader holds cars.read: {}", own.body);
}

#[tokio::test]
async fn a_credential_with_no_scope_claim_at_all_fails_every_scoped_tool_with_403() {
    let introspection = spawn_introspection().await;
    let proj = oauth_project(&introspection, MCP_FULL, "", None);
    let addr = proj.serve().await;
    assert_eq!(rpc_auth(addr, "bare", &call(1, "getCar", json!({ "vin": "V" }))).await.status, 403);
    assert_eq!(
        rpc_auth(addr, "bare", &call(2, "listOpen", json!({}))).await.status,
        200,
        "an unscoped open tool still works"
    );
}

#[tokio::test]
async fn an_http_route_answers_403_auth_insufficient_scope_without_the_scope_and_200_with_it() {
    let introspection = spawn_introspection().await;
    let proj = oauth_project(&introspection, MCP_PROTECTED_ONLY, "", None);
    let addr = proj.serve().await;
    let post = |token: &'static str| async move { send_raw(addr, &request_bytes("POST", "/cars", &[("Authorization", token)], "{}"), 600).await };
    let denied = post("reader").await;
    assert_eq!(denied.status, 403, "{}", denied.body);
    assert_eq!(denied.json()["name"], "auth.insufficient_scope");
    assert!(denied.header("www-authenticate").is_none(), "no challenge on ordinary HTTP routes");
    assert_eq!(post("good").await.status, 200);
    assert_eq!(post("wrong").await.status, 401);
    assert_eq!(http_get(addr, "/cars/V", &[("Authorization", "reader")]).await.status, 200);
}

#[tokio::test]
async fn an_ungated_secured_tool_denied_for_bad_credentials_carries_its_own_scope_in_the_401_challenge() {
    let introspection = spawn_introspection().await;
    let proj = oauth_project(&introspection, MCP_PROTECTED_ONLY, "", None);
    let addr = proj.serve().await;
    let reply = rpc_auth(addr, "wrong", &call(1, "createCar", json!({}))).await;
    assert_eq!(reply.status, 401);
    assert_eq!(
        reply.header("www-authenticate"),
        Some(format!("Bearer resource_metadata=\"{METADATA_URL}\", scope=\"cars.write\"").as_str())
    );
    assert_eq!(
        reply.json()["error"]["data"]["name"],
        "auth.invalid_credentials",
        "per-tool bodies keep their Milestone 1 shape"
    );
    let open = rpc(addr, call(2, "listOpen", json!({}))).await;
    assert_eq!(open.status, 200, "no gate: an open tool needs nothing");
}

#[tokio::test]
async fn an_api_key_scheme_tool_also_gets_the_default_challenge_and_without_a_protected_resource_none_at_all() {
    for (mcp, expect_challenge) in [(MCP_PROTECTED_ONLY, true), ("{}", false)] {
        let proj = Proj::bare(&server_json(&[], &format!("\"mcp\": {mcp}")), SPEC_SECURED);
        proj.secure_with_verifier("SELECT CASE WHEN :key = 'secret' THEN 'yes' ELSE 'no' END AS status;", "row.status = yes");
        proj.endpoint(
            "cars/{vin}",
            "get",
            r#"{ "operationId": "getCar", "security": "tok", "mcp": { "expose": true }, "sources": {}, "response": {} }"#,
        );
        let addr = proj.serve().await;
        let reply = rpc(addr, call(1, "getCar", json!({ "vin": "V" }))).await;
        assert_eq!(reply.status, 401);
        match (reply.header("www-authenticate"), expect_challenge) {
            (Some(value), true) => assert_eq!(value, format!("Bearer resource_metadata=\"{METADATA_URL}\", scope=\"cars.read cars.write\"")),
            (None, false) => {}
            (other, _) => panic!("challenge {other:?}, expected one = {expect_challenge}"),
        }
    }
}

#[tokio::test]
async fn an_operator_remapped_403_for_invalid_credentials_gets_no_challenge() {
    let introspection = spawn_introspection().await;
    let proj = oauth_project(&introspection, MCP_PROTECTED_ONLY, "", None);
    proj.endpoint(
        "cars/{vin}",
        "get",
        r#"{ "operationId": "getCar", "security": "oauth", "securityScopes": ["cars.read"], "mcp": { "expose": true },
             "errorOverrides": { "auth.invalid_credentials": { "httpStatus": 403 } }, "sources": {}, "response": {} }"#,
    );
    let addr = proj.serve().await;
    let reply = rpc_auth(addr, "wrong", &call(1, "getCar", json!({ "vin": "V" }))).await;
    assert_eq!(reply.status, 403);
    assert!(reply.header("www-authenticate").is_none(), "{:?}", reply.headers);
}

// ---------------------------------------------------------------- the metadata route over the wire

#[tokio::test]
async fn the_metadata_document_is_served_at_the_suffixed_origin_root_path_and_never_varies_with_the_host() {
    let introspection = spawn_introspection().await;
    let proj = oauth_project(&introspection, MCP_FULL, "", None);
    let addr = proj.serve().await;
    let expected = json!({
        "resource": "http://localhost/mcp",
        "authorization_servers": ["https://auth.example.com"],
        "scopes_supported": ["cars.read", "cars.write"],
        "bearer_methods_supported": ["header"]
    });
    let reply = http_get(addr, METADATA_PATH, &[]).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(reply.header("content-type"), Some("application/json"));
    assert_eq!(reply.json(), expected);
    for host in ["evil.example", "localhost:9999", "api.example.com"] {
        let hostile = http_get(addr, METADATA_PATH, &[("Host", host)]).await;
        assert_eq!(hostile.status, 200, "{host}");
        assert_eq!(hostile.body, reply.body, "{host}: identical bytes");
    }
    assert_eq!(introspection.hits(), 0, "the metadata route is public and never authenticates");
    assert_eq!(
        http_get(addr, "/.well-known/oauth-protected-resource", &[]).await.status,
        404,
        "the unsuffixed document is not served"
    );
}

#[tokio::test]
async fn the_metadata_route_answers_head_with_no_body_and_405_with_allow_for_every_other_method() {
    let introspection = spawn_introspection().await;
    let proj = oauth_project(&introspection, MCP_FULL, "", None);
    let addr = proj.serve().await;
    let head = send_raw(addr, &request_bytes("HEAD", METADATA_PATH, &[], ""), 600).await;
    assert_eq!(head.status, 200);
    assert!(head.body.trim().is_empty(), "{:?}", head.body);
    for method in ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "QUERY", "PURGE"] {
        let reply = send_raw(addr, &request_bytes(method, METADATA_PATH, &[], "{}"), 600).await;
        assert_eq!(reply.status, 405, "{method}");
        assert_eq!(reply.header("allow"), Some("GET, HEAD"), "{method}");
    }
}

#[tokio::test]
async fn the_metadata_route_is_404_when_no_protected_resource_is_configured_or_mcp_is_off() {
    let introspection = spawn_introspection().await;
    let gate_only = oauth_project(&introspection, MCP_GATE_ONLY, "", None);
    assert_eq!(http_get(gate_only.serve().await, METADATA_PATH, &[]).await.status, 404);

    let off = oauth_project(&introspection, MCP_FULL, "", None);
    std::fs::write(
        off.api().join("config/server.json"),
        server_json(&[("mcp", "false")], &format!("\"mcp\": {MCP_FULL}")),
    )
    .unwrap();
    let addr = off.serve().await;
    assert_eq!(http_get(addr, METADATA_PATH, &[]).await.status, 404);
    assert_eq!(rpc(addr, list_legacy(1)).await.status, 404);
}

#[tokio::test]
async fn under_an_api_root_the_metadata_path_carries_the_api_root_suffix_at_the_origin_root_and_mcp_is_nested() {
    let introspection = spawn_introspection().await;
    let mcp = r#"{ "accessScheme": "oauth", "protectedResource": { "resource": "http://localhost/api/mcp", "authorizationServers": ["https://auth.example.com"] } }"#;
    let proj = oauth_project(&introspection, mcp, r#""apiRoot": "/api", "#, None);
    let addr = proj.serve().await;
    let reply = http_get(addr, "/.well-known/oauth-protected-resource/api/mcp", &[]).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(reply.json()["resource"], "http://localhost/api/mcp");
    assert!(reply.json().get("scopes_supported").is_none());
    assert_eq!(http_get(addr, "/api/.well-known/oauth-protected-resource/api/mcp", &[]).await.status, 404);
    let unauth = send_raw(addr, &request_bytes("POST", "/api/mcp", &[], &list_legacy(1).to_string()), 600).await;
    assert_eq!(unauth.status, 401);
    assert_eq!(
        unauth.header("www-authenticate"),
        Some("Bearer resource_metadata=\"http://localhost/.well-known/oauth-protected-resource/api/mcp\"")
    );
}

#[tokio::test]
async fn the_resource_host_joins_the_mcp_host_allowlist() {
    let introspection = spawn_introspection().await;
    let mcp = r#"{ "protectedResource": { "resource": "https://Public.Example.com/mcp", "authorizationServers": ["https://auth.example.com"] } }"#;
    let proj = oauth_project(&introspection, mcp, "", None);
    let addr = proj.serve().await;
    let body = call(1, "listOpen", json!({}));
    assert_eq!(rpc_with(addr, &[("Host", "public.example.com")], &body).await.status, 200);
    assert_eq!(rpc_with(addr, &[("Host", "PUBLIC.example.com:8443")], &body).await.status, 200);
    assert_eq!(rpc_with(addr, &[("Host", "evil.example")], &body).await.status, 403);
}

// ---------------------------------------------------------------- a project with the gate and a stray gate-test file under frogs run

#[tokio::test]
async fn frogs_run_ignores_an_mcp_gate_test_file_and_still_enforces_the_gate() {
    let introspection = spawn_introspection().await;
    let proj = oauth_project(&introspection, MCP_FULL, "", None);
    std::fs::write(
        proj.api().join("datasources/mcp-gate.test.json"),
        r#"{ "verifier": { "active": true, "scope": "cars.read cars.write" } }"#,
    )
    .unwrap();
    let addr = proj.serve().await;
    let denied = rpc(addr, list_legacy(1)).await;
    assert_eq!(denied.status, 401, "{}", denied.body);
    assert_eq!(introspection.hits(), 1, "the real verifier ran");
    assert_eq!(rpc_auth(addr, "good", &list_legacy(2)).await.status, 200);
}

// ---------------------------------------------------------------- token passthrough

fn passthrough_project(introspection: &Introspection, mcp: &str, endpoint_json: &str) -> Proj {
    let proj = oauth_project(introspection, mcp, "", None);
    std::fs::write(proj.api().join("datasources/sql/db/echo.sql"), "SELECT :a AS a;").unwrap();
    proj.endpoint("open", "get", endpoint_json);
    proj
}

fn bound_header_endpoint(header: &str) -> String {
    format!(
        r#"{{ "operationId": "listOpen", "mcp": {{ "expose": true }},
              "sources": {{ "echo": {{ "type": "sql", "connection": "db", "script": "echo.sql", "cardinality": "one", "parameters": [ {{ "name": "a", "from": "header.{header}" }} ] }} }},
              "response": {{ "a": "sources.echo.a" }} }}"#
    )
}

#[tokio::test]
async fn binding_a_credential_header_to_a_source_is_refused_while_a_protected_resource_is_set() {
    let introspection = spawn_introspection().await;
    for header in ["Authorization", "authorization", "Proxy-Authorization", "Cookie", "COOKIE"] {
        let proj = passthrough_project(&introspection, MCP_PROTECTED_ONLY, &bound_header_endpoint(header));
        let err = proj.refusal().await;
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{header}: {err}");
        assert!(crate::exit_codes::is_config_refusal(&err), "{header}");
    }
}

#[tokio::test]
async fn a_header_the_endpoints_own_verifier_consumes_is_also_a_passthrough_but_an_unrelated_header_is_fine() {
    let introspection = spawn_introspection().await;
    let secured = |header: &str| {
        format!(
            r#"{{ "operationId": "getCar", "security": "oauth", "securityScopes": ["cars.read"], "mcp": {{ "expose": true }},
                  "sources": {{ "echo": {{ "type": "sql", "connection": "db", "script": "echo.sql", "cardinality": "one", "parameters": [ {{ "name": "a", "from": "header.{header}" }} ] }} }},
                  "response": {{ "a": "sources.echo.a" }} }}"#
        )
    };
    let proj = oauth_project(&introspection, MCP_PROTECTED_ONLY, "", None);
    std::fs::write(proj.api().join("datasources/sql/db/echo.sql"), "SELECT :a AS a;").unwrap();
    std::fs::write(
        proj.api().join("security/verifiers/v.json"),
        r#"{ "type": "http", "request": "introspect.json", "parameters": [ { "name": "token", "from": "header.X-Api-Key" } ], "validIf": "response.active = true", "scopesFrom": "response.scope" }"#,
    )
    .unwrap();
    proj.endpoint("cars/{vin}", "get", &secured("X-Api-Key"));
    assert_eq!(proj.refusal().await.kind(), io::ErrorKind::InvalidData, "X-Api-Key is this endpoint's own credential");

    proj.endpoint("cars/{vin}", "get", &secured("X-Request-Source"));
    let addr = proj.serve().await;
    let reply = rpc_with(addr, &[("X-Api-Key", "good"), ("X-Request-Source", "web")], &call(1, "getCar", json!({ "vin": "V" }))).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
}

#[tokio::test]
async fn the_gate_verifiers_header_counts_as_a_credential_for_every_exposed_tool() {
    let introspection = spawn_introspection().await;
    // The gate's verifier reads X-Gate-Token; an open tool binding it would hand that credential upstream.
    let proj = passthrough_project(&introspection, MCP_FULL, &bound_header_endpoint("X-Gate-Token"));
    std::fs::write(
        proj.api().join("security/verifiers/v.json"),
        r#"{ "type": "http", "request": "introspect.json", "parameters": [ { "name": "token", "from": "header.X-Gate-Token" } ], "validIf": "response.active = true", "scopesFrom": "response.scope" }"#,
    )
    .unwrap();
    assert_eq!(proj.refusal().await.kind(), io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn forwarding_the_callers_credential_through_an_http_request_files_forward_auth_is_refused() {
    let introspection = spawn_introspection().await;
    let upstream = spawn_upstream().await;
    let endpoint = r#"{ "operationId": "listOpen", "mcp": { "expose": true },
        "sources": { "up": { "type": "http", "request": "up.json", "cardinality": "one", "parameters": [] } }, "response": { "ok": "sources.up.ok" } }"#;
    let proj = passthrough_project(&introspection, MCP_PROTECTED_ONLY, endpoint);
    std::fs::write(
        proj.api().join("datasources/http/up.json"),
        format!(
            r#"{{ "method": "GET", "url": "http://{}/x", "auth": {{ "type": "forward", "header": "Authorization" }} }}"#,
            upstream.addr
        ),
    )
    .unwrap();
    assert_eq!(proj.refusal().await.kind(), io::ErrorKind::InvalidData);

    std::fs::write(
        proj.api().join("datasources/http/up.json"),
        format!(r#"{{ "method": "GET", "url": "http://{}/x" }}"#, upstream.addr),
    )
    .unwrap();
    let addr = proj.serve().await;
    assert_eq!(
        rpc_auth(addr, "good", &call(1, "listOpen", json!({}))).await.status,
        200,
        "the same source without forward auth is fine"
    );
}

#[tokio::test]
async fn an_unreadable_http_request_file_fails_closed_while_a_protected_resource_is_set() {
    let introspection = spawn_introspection().await;
    let endpoint = r#"{ "operationId": "listOpen", "mcp": { "expose": true },
        "sources": { "up": { "type": "http", "request": "missing.json", "cardinality": "one", "parameters": [] } }, "response": { "ok": "sources.up.ok" } }"#;
    let proj = passthrough_project(&introspection, MCP_PROTECTED_ONLY, endpoint);
    assert_eq!(proj.refusal().await.kind(), io::ErrorKind::InvalidData);
    std::fs::write(proj.api().join("datasources/http/missing.json"), "{ not json").unwrap();
    assert_eq!(
        proj.refusal().await.kind(),
        io::ErrorKind::InvalidData,
        "an unparseable file cannot be proven safe either"
    );
}

#[tokio::test]
async fn the_verifier_files_own_authorization_binding_is_never_a_passthrough_and_neither_is_a_server_without_a_protected_resource() {
    let introspection = spawn_introspection().await;
    // The shipped fixture's verifier reads header.Authorization: it must start fine under MCP_FULL.
    let proj = oauth_project(&introspection, MCP_FULL, "", None);
    proj.serve().await;
    // Without protectedResource the same exposed Authorization binding is allowed (Milestone 1 behaviour).
    let no_resource = passthrough_project(&introspection, MCP_GATE_ONLY, &bound_header_endpoint("Authorization"));
    no_resource.serve().await;
}

#[tokio::test]
async fn a_non_exposed_endpoint_may_bind_authorization_even_with_a_protected_resource() {
    let introspection = spawn_introspection().await;
    let endpoint = bound_header_endpoint("Authorization").replace(r#""mcp": { "expose": true },"#, "");
    let proj = passthrough_project(&introspection, MCP_PROTECTED_ONLY, &endpoint);
    proj.serve().await;
}

// ---------------------------------------------------------------- startup refusals

fn write_server(proj: &Proj, extra: &str) {
    std::fs::write(proj.api().join("config/server.json"), server_json(&[], extra)).unwrap();
}

fn mcp_with(resource: &str, servers: &str, scopes: &str) -> String {
    format!(
        r#""mcp": {{ "accessScheme": "oauth", "protectedResource": {{ "resource": "{resource}", "authorizationServers": {servers}, "scopesSupported": {scopes} }} }}"#
    )
}

async fn assert_every_entry_point_refuses(label: &str, proj: &Proj) {
    unconnectable(proj);
    let err = proj.refusal().await;
    assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{label}: {err}");
    assert!(
        !err.to_string().to_lowercase().contains("nosuchdriver"),
        "{label}: refused before any connection: {err}"
    );
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

#[tokio::test]
async fn every_milestone_two_refusal_is_invalid_data_before_any_connection_or_pidfile_via_both_entry_points() {
    type Mutator = fn(&Proj);
    let cases: Vec<(&str, Mutator)> = vec![
        ("public http resource", |p| {
            write_server(p, &mcp_with("http://api.example.com/mcp", r#"["https://a.example"]"#, "[]"))
        }),
        ("resource path mismatch", |p| {
            write_server(p, &mcp_with("https://api.example.com/other", r#"["https://a.example"]"#, "[]"))
        }),
        ("resource with a trailing slash", |p| {
            write_server(p, &mcp_with("https://api.example.com/mcp/", r#"["https://a.example"]"#, "[]"))
        }),
        ("authorization server over http", |p| {
            write_server(p, &mcp_with("http://localhost/mcp", r#"["http://a.example"]"#, "[]"))
        }),
        ("no authorization servers", |p| write_server(p, &mcp_with("http://localhost/mcp", "[]", "[]"))),
        ("an invalid scope token", |p| {
            write_server(p, &mcp_with("http://localhost/mcp", r#"["https://a.example"]"#, r#"["a b"]"#))
        }),
        ("unknown accessScheme", |p| {
            write_server(p, r#""mcp": { "accessScheme": "ghost" }"#);
        }),
        ("a non-string accessScheme", |p| {
            write_server(p, r#""mcp": { "accessScheme": 5 }"#);
        }),
        ("an over-long challenge", |p| {
            let many: Vec<String> = (0..40).map(|n| format!("\"{}{n}\"", "s".repeat(100))).collect();
            write_server(p, &mcp_with("http://localhost/mcp", r#"["https://a.example"]"#, &format!("[{}]", many.join(","))));
        }),
        ("token passthrough", |p| {
            write_server(p, &format!("\"mcp\": {MCP_PROTECTED_ONLY}"));
            std::fs::write(p.api().join("datasources/sql/db/echo.sql"), "SELECT :a AS a;").unwrap();
            p.endpoint("open", "get", &bound_header_endpoint("Cookie"));
        }),
    ];
    for (label, mutate) in cases {
        let introspection = spawn_introspection().await;
        let proj = oauth_project(&introspection, MCP_FULL, "", None);
        mutate(&proj);
        assert_every_entry_point_refuses(label, &proj).await;
    }
}

#[tokio::test]
async fn a_cert_dependent_access_scheme_is_refused_when_tls_client_auth_is_off() {
    let introspection = spawn_introspection().await;
    let proj = oauth_project(&introspection, MCP_GATE_ONLY, "", None);
    std::fs::write(
        proj.api().join("security/verifiers/v.json"),
        r#"{ "type": "mtls", "validIf": "cert.cn = client.example.com" }"#,
    )
    .unwrap();
    assert_every_entry_point_refuses("mtls gate without clientAuth", &proj).await;
}

#[tokio::test]
async fn an_unscoped_stub_is_refused_once_the_verifier_declares_scopes_from_and_only_warned_before() {
    let introspection = spawn_introspection().await;
    let stub = r#"{ "operationId": "getCar", "security": "oauth", "mcp": { "expose": true }, "sources": {}, "response": {} }"#;
    // The verifier has no scopesFrom: unenforceable, the spec's scopes are only a warning, so it starts.
    let before = oauth_project(&introspection, MCP_GATE_ONLY, "", None);
    std::fs::write(
        before.api().join("security/verifiers/v.json"),
        r#"{ "type": "http", "request": "introspect.json", "parameters": [ { "name": "token", "from": "header.Authorization" } ], "validIf": "response.active = true" }"#,
    )
    .unwrap();
    before.endpoint("cars/{vin}", "get", stub);
    before.endpoint(
        "cars",
        "post",
        r#"{ "operationId": "createCar", "security": "oauth", "mcp": { "expose": true }, "sources": {}, "response": {} }"#,
    );
    before.serve().await;

    // scopesFrom declared: the same stub no longer covers the spec's [cars.read].
    let after = oauth_project(&introspection, MCP_GATE_ONLY, "", None);
    after.endpoint("cars/{vin}", "get", stub);
    assert_every_entry_point_refuses("a stub that does not cover the spec's scopes", &after).await;
}

#[tokio::test]
async fn a_malformed_scopes_from_in_a_verifier_fails_the_config_load_that_every_startup_path_begins_with() {
    // `Config::load_or_exit` turns this error into a process exit, so the load itself is what is observable in-process.
    let introspection = spawn_introspection().await;
    let proj = oauth_project(&introspection, MCP_GATE_ONLY, "", None);
    std::fs::write(
        proj.api().join("security/verifiers/v.json"),
        r#"{ "type": "http", "request": "introspect.json", "parameters": [], "validIf": "response.active = true", "scopesFrom": "" }"#,
    )
    .unwrap();
    let err = Config::load(&proj.api()).expect_err("the load must fail");
    assert!(err.to_string().to_lowercase().contains("scopesfrom"), "{err}");
}

#[tokio::test]
async fn security_scopes_the_verifier_cannot_enforce_make_the_route_503_and_the_tool_unavailable_while_startup_continues() {
    let introspection = spawn_introspection().await;
    let proj = oauth_project(&introspection, MCP_GATE_ONLY, "", None);
    std::fs::write(
        proj.api().join("security/verifiers/v.json"),
        r#"{ "type": "http", "request": "introspect.json", "parameters": [ { "name": "token", "from": "header.Authorization" } ], "validIf": "response.active = true" }"#,
    )
    .unwrap();
    // The files carry securityScopes, the verifier has no scopesFrom: frogs could not enforce them. Keep the spec in
    // agreement so only the servability rule is in play.
    std::fs::write(
        proj.root.join("openapi.yaml"),
        SPEC_OAUTH
            .replace("[ { oauth: [cars.read] } ]", "[ { oauth: [] } ]")
            .replace("[ { oauth: [cars.write] } ]", "[ { oauth: [] } ]"),
    )
    .unwrap();
    let addr = proj.serve().await;
    let route = http_get(addr, "/cars/V", &[("Authorization", "good")]).await;
    assert_eq!(route.status, 503, "{}", route.body);
    assert_eq!(route.json()["name"], "endpoint.unavailable");
    let listed = rpc_auth(addr, "good", &list_legacy(1)).await;
    assert_eq!(names(&listed), ["listOpen"], "an unservable endpoint is not a tool");
}

#[tokio::test]
async fn an_endpoint_folder_at_the_metadata_path_with_an_empty_api_root_is_refused_like_any_builtin_overlap() {
    let introspection = spawn_introspection().await;
    let proj = oauth_project(&introspection, MCP_FULL, "", None);
    proj.endpoint(
        ".well-known/oauth-protected-resource/mcp",
        "get",
        r#"{ "operationId": "shadow", "sources": {}, "response": {} }"#,
    );
    unconnectable(&proj);
    let err = proj.refusal().await;
    assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
    assert!(!err.to_string().to_lowercase().contains("nosuchdriver"), "{err}");
    assert!(crate::exit_codes::is_config_refusal(&err));
    assert_eq!(
        precheck_security_for_service(&proj.root).expect_err("service precheck").kind(),
        io::ErrorKind::InvalidData
    );
}

#[tokio::test]
async fn a_secured_spec_operation_at_the_metadata_path_is_refused_and_an_open_one_is_not_a_security_problem() {
    let introspection = spawn_introspection().await;
    let proj = oauth_project(&introspection, MCP_FULL, "", None);
    let mut spec = std::fs::read_to_string(proj.root.join("openapi.yaml")).unwrap();
    spec.push_str(&format!(
        "  {METADATA_PATH}:\n    get:\n      operationId: wk\n      security: [ {{ oauth: [] }} ]\n      responses: {{ '200': {{ description: ok }} }}\n"
    ));
    std::fs::write(proj.root.join("openapi.yaml"), spec).unwrap();
    assert_every_entry_point_refuses("a secured operation at the metadata path", &proj).await;
}

#[tokio::test]
async fn a_document_level_security_default_inherited_by_an_operation_at_the_metadata_path_is_refused_too() {
    let introspection = spawn_introspection().await;
    let proj = oauth_project(&introspection, MCP_FULL, "", None);
    let spec = std::fs::read_to_string(proj.root.join("openapi.yaml")).unwrap();
    let mut with_default = spec.replace(
        "paths:
",
        "security: [ { oauth: [] } ]
paths:
",
    );
    with_default.push_str(&format!(
        "  {METADATA_PATH}:
    get:
      operationId: wk
      responses: {{ '200': {{ description: ok }} }}
"
    ));
    std::fs::write(proj.root.join("openapi.yaml"), with_default).unwrap();
    assert_every_entry_point_refuses("an inherited-security operation at the metadata path", &proj).await;
}

#[tokio::test]
async fn with_a_non_empty_api_root_a_file_at_the_origin_root_well_known_path_cannot_collide() {
    let introspection = spawn_introspection().await;
    let mcp = r#"{ "accessScheme": "oauth", "protectedResource": { "resource": "http://localhost/api/mcp", "authorizationServers": ["https://auth.example.com"] } }"#;
    let proj = oauth_project(&introspection, mcp, r#""apiRoot": "/api", "#, None);
    proj.endpoint(
        ".well-known/oauth-protected-resource/api/mcp",
        "get",
        r#"{ "operationId": "shadow", "sources": {}, "response": {} }"#,
    );
    let mut spec = std::fs::read_to_string(proj.root.join("openapi.yaml")).unwrap();
    spec.push_str("  /.well-known/oauth-protected-resource/api/mcp:\n    get:\n      operationId: wk\n      responses: { '200': { description: ok } }\n");
    std::fs::write(proj.root.join("openapi.yaml"), spec).unwrap();
    let addr = proj.serve().await;
    assert_eq!(
        http_get(addr, "/.well-known/oauth-protected-resource/api/mcp", &[]).await.status,
        200,
        "the metadata route, not the nested endpoint"
    );
}

// ---------------------------------------------------------------- validate

#[tokio::test]
async fn validate_reports_the_new_findings_as_errors_with_mcp_on_and_as_warnings_with_it_off() {
    let introspection = spawn_introspection().await;
    let bad = mcp_with("http://api.example.com/mcp", r#"["https://a.example"]"#, "[]");
    let on = oauth_project(&introspection, MCP_FULL, "", None);
    write_server(&on, &bad);
    let (_, found) = findings(&on).expect("an mcp section");
    assert!(has(&found, crate::mcp::Severity::Error, "must use https"), "{found:?}");

    let off = oauth_project(&introspection, MCP_FULL, "", None);
    std::fs::write(off.api().join("config/server.json"), server_json(&[("mcp", "false")], &bad)).unwrap();
    let (_, found) = findings(&off).expect("an mcp section");
    assert!(!found.iter().any(|(severity, _)| *severity == crate::mcp::Severity::Error), "{found:?}");
    assert!(has(&found, crate::mcp::Severity::Warning, "has no effect"), "{found:?}");
}

#[tokio::test]
async fn validate_warns_about_audience_a_missing_gate_scope_gaps_and_a_missing_cache_ttl() {
    let introspection = spawn_introspection().await;
    let proj = oauth_project(&introspection, MCP_FULL, "", None);
    let (tools, found) = findings(&proj).expect("an mcp section");
    assert_eq!(tools, 3);
    assert!(
        has(
            &found,
            crate::mcp::Severity::Warning,
            "frogs does not check token audience: the verifier for scheme 'oauth' must reject tokens not issued for http://localhost/mcp"
        ),
        "{found:?}"
    );
    assert!(has(&found, crate::mcp::Severity::Warning, "no cacheTtlSeconds"), "{found:?}");
    assert!(!found.iter().any(|(severity, _)| *severity == crate::mcp::Severity::Error), "{found:?}");

    let ungated = oauth_project(&introspection, MCP_PROTECTED_ONLY, "", None);
    let (_, found) = findings(&ungated).expect("an mcp section");
    assert!(
        has(&found, crate::mcp::Severity::Warning, "without mcp.accessScheme: tools/list is anonymous"),
        "{found:?}"
    );
    assert!(!has(&found, crate::mcp::Severity::Warning, "nothing on /mcp requires a token"), "{found:?}");

    let open_only = oauth_project(&introspection, MCP_PROTECTED_ONLY, "", None);
    open_only.remove_endpoint("cars/{vin}");
    open_only.remove_endpoint("cars");
    let (_, found) = findings(&open_only).expect("an mcp section");
    assert!(has(&found, crate::mcp::Severity::Warning, "nothing on /mcp requires a token"), "{found:?}");
}

#[tokio::test]
async fn validate_warns_when_an_allow_dot_paths_entry_is_shadowed_by_the_metadata_route() {
    use crate::mcp::{Severity, StartupInputs};
    let introspection = spawn_introspection().await;
    let proj = oauth_project(&introspection, MCP_FULL, "", None);
    let config = Config::load(&proj.api()).expect("config loads");
    let tree = crate::commands::run::scan_endpoint_tree(&proj.root, &config.server);
    let doc = crate::openapi::load(&proj.root.join("openapi.yaml"), config.server.openapi_load_options()).ok();
    let dot = [".well-known".to_string()];
    let inputs = StartupInputs {
        server: &config.server,
        security: &config.security,
        connections: &config.connections,
        tree: &tree,
        doc: doc.as_ref(),
        client_identity_available: false,
        web_role: true,
        web_allow_dot_paths: &dot,
    };
    let report = crate::mcp::validate_findings(&inputs).unwrap();
    assert!(
        report.findings.iter().any(|(s, m)| *s == Severity::Warning && m.contains("allowDotPaths covers")),
        "{:?}",
        report.findings
    );
    let unrelated = [".other".to_string()];
    let inputs = StartupInputs {
        web_allow_dot_paths: &unrelated,
        ..inputs
    };
    let report = crate::mcp::validate_findings(&inputs).unwrap();
    assert!(!report.findings.iter().any(|(_, m)| m.contains("allowDotPaths covers")), "{:?}", report.findings);
}
