//! `frogs mcp` end to end over real pipes: the process is spawned, spoken to in newline-delimited JSON-RPC, and
//! its stdout is held to the transport contract (nothing but one compact JSON-RPC response per line). Not gated
//! behind `e2e-tests`: it only needs the binary cargo already built (precedent: `tests/mcp_gate_file_exit.rs`).

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{Value, json};

fn project() -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "frogs-mcp-stdio-{}-{}-{n}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    let api = root.join("api");
    for dir in ["config/errors", "security", "datasources/sql/db", "datasources/endpoints/cars/{vin}"] {
        std::fs::create_dir_all(api.join(dir)).unwrap();
    }
    std::fs::write(
        root.join("openapi.yaml"),
        "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths:\n  /cars/{vin}:\n    get:\n      operationId: getCar\n      parameters:\n        - { name: vin, in: path, required: true, schema: { type: string } }\n      responses: { '200': { description: ok } }\n",
    )
    .unwrap();
    std::fs::write(
        api.join("config/server.json"),
        r#"{ "features": { "requestValidation": false, "metrics": false, "readyzCheck": false } }"#,
    )
    .unwrap();
    std::fs::write(api.join("config/errors/core.json"), "{}").unwrap();
    let db = root.join("never-created.sqlite").display().to_string().replace('\\', "/");
    std::fs::write(
        api.join("config/connections.json"),
        format!(r#"{{ "db": {{ "driver": "sqlite", "database": "{db}" }} }}"#),
    )
    .unwrap();
    std::fs::write(api.join("security/schemes.json"), "{}").unwrap();
    std::fs::write(api.join("datasources/sql/db/car.sql"), "SELECT 'REAL' AS maker;").unwrap();
    let endpoint = api.join("datasources/endpoints/cars/{vin}");
    std::fs::write(
        endpoint.join("endpoint.get.json"),
        r#"{ "operationId": "getCar", "sources": { "car": { "type": "sql", "connection": "db", "script": "car.sql", "cardinality": "one", "parameters": [ { "name": "vin", "from": "path.vin" } ] } }, "response": { "maker": "sources.car.maker" } }"#,
    )
    .unwrap();
    std::fs::write(
        endpoint.join("endpoint.get.test.json"),
        r#"{ "cases": [ { "name": "honda", "request": { "path": { "vin": "H1" } }, "mocks": { "car": { "maker": "Honda" } }, "expect": { "status": 200, "body": { "maker": "Honda" } } } ] }"#,
    )
    .unwrap();
    std::fs::write(endpoint.join("endpoint.get.reference.json"), r#"{ "marker": "REF" }"#).unwrap();
    root
}

fn line(id: i64, method: &str, params: Value) -> Vec<u8> {
    let mut bytes = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }).to_string().into_bytes();
    bytes.push(b'\n');
    bytes
}

fn tool(id: i64, name: &str, arguments: Value) -> Vec<u8> {
    line(id, "tools/call", json!({ "name": name, "arguments": arguments }))
}

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// Spawns `frogs mcp`, feeds it `input` from a thread (so a large input can never deadlock against the output pipe),
/// closes stdin, and waits for the process to exit by itself.
fn run_mcp(args: &[&str], root: &Path, envs: &[(&str, &str)], input: Vec<u8>) -> Run {
    let mut command = Command::new(env!("CARGO_BIN_EXE_frogs"));
    command
        .arg("mcp")
        .args(args)
        .current_dir(root)
        .env_remove("RUST_LOG")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in envs {
        command.env(key, value);
    }
    let mut child = command.spawn().expect("the frogs binary should run");
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
        // dropping stdin closes it: the EOF that must end the server with exit 0
    });
    let output = child.wait_with_output().expect("the process should exit once stdin is closed");
    let _ = writer.join();
    Run {
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn responses(run: &Run) -> Vec<Value> {
    assert!(
        run.stdout.is_empty() || run.stdout.ends_with('\n'),
        "stdout ends with a newline: {:?}",
        run.stdout.chars().rev().take(20).collect::<String>()
    );
    run.stdout
        .lines()
        .map(|text| {
            let value: Value = serde_json::from_str(text).unwrap_or_else(|e| panic!("a stdout line is not JSON ({e}): {text:.200}"));
            assert_eq!(value["jsonrpc"], "2.0", "{text:.200}");
            assert!(
                value.get("result").is_some() ^ value.get("error").is_some(),
                "exactly one of result/error: {text:.200}"
            );
            assert!(value.get("id").is_some(), "a response always has an id member: {text:.200}");
            value
        })
        .collect()
}

fn tool_text(response: &Value) -> Value {
    serde_json::from_str(
        response["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("no tool text: {response}")),
    )
    .unwrap()
}

#[test]
fn a_full_session_answers_every_id_exactly_once_keeps_stdout_pure_json_rpc_and_exits_0_on_stdin_close() {
    let root = project();
    let mut input = Vec::new();
    input.extend(line(
        1,
        "initialize",
        json!({ "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": { "name": "t", "version": "1" } }),
    ));
    input.extend(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n");
    input.extend(line(2, "tools/list", json!({})));
    input.extend(tool(3, "project_describe", json!({})));
    input.extend(tool(4, "endpoint_reference", json!({ "path": "/cars/{vin}", "method": "get" })));
    input.extend(tool(5, "errors_discovered", json!({})));
    input.extend(tool(6, "validate", json!({})));
    input.extend(tool(7, "test_run", json!({})));
    input.extend(b"{this is not json\n");
    let mut overlong = vec![b'x'; 3 * 1024 * 1024];
    overlong.push(b'\n');
    input.extend(overlong);
    input.extend(line(8, "ping", json!({})));
    input.extend(tool(9, "no_such_tool", json!({})));

    let run = run_mcp(&[], &root, &[], input);
    assert_eq!(run.code, Some(0), "stdin EOF must end the server cleanly; stderr: {}", run.stderr);
    let all = responses(&run);

    let mut by_id: HashMap<i64, Vec<&Value>> = HashMap::new();
    let mut id_less = Vec::new();
    for response in &all {
        match response["id"].as_i64() {
            Some(id) => by_id.entry(id).or_default().push(response),
            None => {
                assert!(response["id"].is_null(), "an unattributable error has a null id: {response}");
                id_less.push(response);
            }
        }
    }
    for id in 1..=9 {
        assert_eq!(by_id.get(&id).map_or(0, Vec::len), 1, "id {id} must be answered exactly once: {all:?}");
    }
    assert_eq!(by_id.len(), 9, "no response carries an id that was never sent: {all:?}");
    let mut null_codes: Vec<i64> = id_less.iter().map(|r| r["error"]["code"].as_i64().unwrap()).collect();
    null_codes.sort();
    assert_eq!(null_codes, [-32700, -32600], "malformed line -> parse error, overlong line -> invalid request");

    assert_eq!(by_id[&1][0]["result"]["serverInfo"]["name"], "frogs");
    let tools = by_id[&2][0]["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 5);
    let describe = tool_text(by_id[&3][0]);
    assert_eq!(describe["roles"]["api"], true);
    assert_eq!(describe["connections"], json!([{ "name": "db", "driver": "sqlite" }]));
    assert_eq!(tool_text(by_id[&4][0])["reference"], json!({ "marker": "REF" }));
    assert_eq!(tool_text(by_id[&5][0]), json!({ "corrupt": false, "entries": [] }));
    let validated = tool_text(by_id[&6][0]);
    assert_eq!(validated["connections"], "skipped");
    let tested = tool_text(by_id[&7][0]);
    assert_eq!(tested["entries"][0]["verdict"], "pass", "{tested}");
    assert_eq!(by_id[&8][0]["result"], json!({}));
    assert_eq!(by_id[&9][0]["error"]["code"], -32602);

    assert!(!root.join("never-created.sqlite").exists(), "nothing opened the sqlite database");
    assert!(!root.join(".frogs").exists(), "no pidfile or runtime state was written");
    assert!(!root.join("api/config/errors.discovered.json").exists());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn the_modern_era_works_over_stdio_with_no_headers() {
    let root = project();
    let meta = json!({ "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {} });
    let mut input = Vec::new();
    input.extend(line(1, "server/discover", json!({ "_meta": meta })));
    input.extend(line(2, "tools/list", json!({ "_meta": meta })));
    input.extend(line(3, "tools/call", json!({ "name": "project_describe", "arguments": {}, "_meta": meta })));
    let run = run_mcp(&[], &root, &[], input);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    let all = responses(&run);
    assert_eq!(all.len(), 3);
    for response in &all {
        assert_eq!(response["result"]["resultType"], "complete", "{response}");
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn an_immediately_closed_stdin_exits_0_with_nothing_on_stdout() {
    let root = project();
    let run = run_mcp(&[], &root, &[], Vec::new());
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(run.stdout, "");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn the_project_flag_picks_the_project_and_a_missing_project_is_the_only_startup_exit() {
    let root = project();
    let elsewhere = std::env::temp_dir();
    let run = run_mcp(&["--project", root.to_str().unwrap()], &elsewhere, &[], tool(1, "project_describe", json!({})));
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    let described = tool_text(&responses(&run)[0]);
    assert_eq!(described["roles"]["api"], true);

    let empty = std::env::temp_dir().join(format!("frogs-mcp-stdio-empty-{}", std::process::id()));
    std::fs::create_dir_all(&empty).unwrap();
    let missing = run_mcp(&["--project", empty.to_str().unwrap()], &empty, &[], line(1, "ping", json!({})));
    assert_eq!(missing.code, Some(1));
    assert_eq!(missing.stdout, "", "a startup refusal writes nothing to stdout");
    assert!(!missing.stderr.is_empty());
    let _ = std::fs::remove_dir_all(&empty);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_connection_failure_in_validate_never_leaks_the_database_password_into_the_tool_result() {
    const SECRET: &str = "hunter2-very-secret-pw";
    let root = project();
    std::fs::write(
        root.join("api/config/connections.json"),
        r#"{ "db": { "driver": "postgres", "host": "127.0.0.1", "port": 1, "database": "vehicles", "user": "svc", "passwordEnv": "FROGS_TEST_PG_SECRET" } }"#,
    )
    .unwrap();
    let mut input = Vec::new();
    input.extend(tool(1, "validate", json!({ "checkConnections": true })));
    input.extend(tool(2, "project_describe", json!({})));
    let run = run_mcp(&["--allow-connections"], &root, &[("FROGS_TEST_PG_SECRET", SECRET)], input);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert!(!run.stdout.contains(SECRET), "the password reached stdout: {}", run.stdout);
    let all = responses(&run);
    let validated = tool_text(all.iter().find(|r| r["id"] == 1).unwrap());
    assert_eq!(validated["connections"], "checked");
    assert_eq!(validated["ok"], false, "127.0.0.1:1 refuses the connection: {validated}");
    let described = all.iter().find(|r| r["id"] == 2).unwrap().to_string();
    assert!(!described.contains("passwordEnv") && !described.contains("FROGS_TEST_PG_SECRET"), "{described}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_password_embedded_in_a_connection_hostname_is_redacted_from_the_validate_result() {
    // A URL-shaped value in a driver error is the shape redaction targets; build one through the host setting.
    const SECRET: &str = "embedded-pw-9f3";
    let root = project();
    std::fs::write(
        root.join("api/config/connections.json"),
        format!(r#"{{ "db": {{ "driver": "postgres", "host": "svc:{SECRET}@127.0.0.1", "port": 1, "database": "vehicles", "user": "svc" }} }}"#),
    )
    .unwrap();
    let run = run_mcp(&["--allow-connections"], &root, &[], tool(1, "validate", json!({ "checkConnections": true })));
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert!(!run.stdout.contains(SECRET), "the password reached stdout: {}", run.stdout);
    let _ = std::fs::remove_dir_all(&root);
}
