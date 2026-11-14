//! `frogs mcp --allow-writes` end to end over real pipes: a fresh OpenAPI-only project is generated and its
//! discovered error codes frozen through the two writing tools. Stdout must stay pure JSON-RPC (the CLI-side
//! printing of `generate`/`freeze` must be silent under MCP), every id answered once, exit 0, and every file created
//! inside the project folder only.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{Value, json};

const SPEC: &str = "openapi: 3.2.0
info: { title: t, version: '1' }
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

/// `<parent>/project`, with `parent` holding nothing else, so anything written outside the project shows up there.
fn fresh_project() -> (PathBuf, PathBuf) {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let parent = std::env::temp_dir().join(format!(
        "frogs-mcp-writes-{}-{}-{n}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    let root = parent.join("project");
    std::fs::create_dir_all(root.join("api/config")).unwrap();
    std::fs::write(root.join("openapi.yaml"), SPEC).unwrap();
    std::fs::write(
        root.join("api/config/errors.discovered.json"),
        r#"{ "datasource.sql.unknown:PoolTimedOut": { "_discovered": true, "httpStatus": 500, "exposeDetail": false, "occurrences": 3, "firstSeen": "2026-07-16T10:03:00Z", "lastSeen": "2026-07-16T10:41:00Z", "sampleMessage": "pool timed out" } }"#,
    )
    .unwrap();
    (parent, root)
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

fn run_mcp(args: &[&str], root: &Path, input: Vec<u8>) -> Run {
    let mut child = Command::new(env!("CARGO_BIN_EXE_frogs"))
        .arg("mcp")
        .args(args)
        .current_dir(root)
        .env_remove("RUST_LOG")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the frogs binary should run");
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let output = child.wait_with_output().expect("the process should exit once stdin is closed");
    let _ = writer.join();
    Run {
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn responses(run: &Run) -> HashMap<i64, Value> {
    let mut by_id = HashMap::new();
    for text in run.stdout.lines() {
        let value: Value = serde_json::from_str(text).unwrap_or_else(|e| panic!("a stdout line is not JSON ({e}): {text:.200}"));
        assert_eq!(value["jsonrpc"], "2.0", "{text:.200}");
        assert!(value.get("result").is_some() ^ value.get("error").is_some(), "{text:.200}");
        let id = value["id"].as_i64().unwrap_or_else(|| panic!("a response without a numeric id: {text:.200}"));
        assert!(by_id.insert(id, value).is_none(), "id {id} answered twice");
    }
    by_id
}

fn tool_text(response: &Value) -> Value {
    serde_json::from_str(
        response["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("no tool text: {response}")),
    )
    .unwrap()
}

fn files(dir: &Path, root: &Path, out: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        out.push(path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/"));
        if path.is_dir() {
            files(&path, root, out);
        }
    }
}

#[test]
fn a_write_session_generates_then_freezes_with_pure_json_rpc_on_stdout_and_exit_0() {
    let (parent, root) = fresh_project();
    let mut input = Vec::new();
    input.extend(line(
        1,
        "initialize",
        json!({ "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": { "name": "t", "version": "1" } }),
    ));
    input.extend(line(2, "tools/list", json!({})));
    input.extend(tool(3, "generate", json!({})));
    input.extend(tool(4, "errors_freeze", json!({})));
    input.extend(tool(8, "generate", json!({ "role": "web" })));
    input.extend(tool(9, "generate", json!({ "role": "nope" })));
    input.extend(line(10, "ping", json!({})));

    let run = run_mcp(&["--allow-writes"], &root, input);
    assert_eq!(run.code, Some(0), "stdin EOF must end the server cleanly; stderr: {}", run.stderr);
    let by_id = responses(&run);
    assert_eq!(by_id.len(), 7, "every request answered exactly once: {:?}", by_id.keys());

    let names: Vec<&str> = by_id[&2]["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        [
            "project_describe",
            "endpoint_reference",
            "errors_discovered",
            "validate",
            "test_run",
            "generate",
            "errors_freeze"
        ]
    );

    let generated = tool_text(&by_id[&3]);
    assert_eq!(generated["ok"], true, "{generated}");
    assert_eq!(generated["created"].as_array().unwrap().len(), 2);
    let frozen = tool_text(&by_id[&4]);
    assert_eq!(frozen["written"]["codes"], json!(["datasource.sql.unknown:PoolTimedOut"]));
    assert_eq!(frozen["purged"], true);
    assert_eq!(by_id[&8]["result"]["isError"], true, "no web assets in this project");
    assert_eq!(by_id[&9]["error"]["code"], -32602);
    assert_eq!(by_id[&10]["result"], json!({}));

    // the files really exist, and only inside the project
    for expected in [
        "api/config/server.json",
        "api/datasources/endpoints/cars/endpoint.post.json",
        "api/datasources/endpoints/cars/endpoint.post.reference.json",
        "api/datasources/endpoints/cars/{vin}/endpoint.get.json",
    ] {
        assert!(root.join(expected).is_file(), "{expected} missing");
    }
    let dated = format!("discovered-{}.json", chrono::Utc::now().format("%Y-%m-%d"));
    assert!(root.join("api/config/errors").join(&dated).is_file());
    assert_eq!(std::fs::read_to_string(root.join("api/config/errors.discovered.json")).unwrap(), "{}");
    // a second process sees the finished project: reads find both endpoints, a repeat generate changes nothing
    let mut again = Vec::new();
    again.extend(tool(1, "project_describe", json!({})));
    again.extend(tool(2, "generate", json!({})));
    again.extend(tool(3, "errors_freeze", json!({})));
    let second = run_mcp(&["--allow-writes"], &root, again);
    assert_eq!(second.code, Some(0), "{}", second.stderr);
    let second_ids = responses(&second);
    assert_eq!(tool_text(&second_ids[&2])["unchanged"], 2);
    assert_eq!(tool_text(&second_ids[&2])["created"], json!([]));
    assert_eq!(tool_text(&second_ids[&3])["written"], Value::Null);

    let siblings: Vec<String> = std::fs::read_dir(&parent)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(siblings, ["project"], "nothing was written next to the project");
    let mut listing = Vec::new();
    files(&root, &root, &mut listing);
    assert!(!listing.iter().any(|f| f.starts_with(".frogs")), "no runtime state: {listing:?}");

    let _ = std::fs::remove_dir_all(&parent);
}

#[test]
fn the_same_session_without_allow_writes_refuses_both_writing_tools_and_creates_nothing() {
    let (parent, root) = fresh_project();
    let mut before = Vec::new();
    files(&root, &root, &mut before);
    let mut input = Vec::new();
    input.extend(line(1, "tools/list", json!({})));
    input.extend(tool(2, "generate", json!({})));
    input.extend(tool(3, "errors_freeze", json!({})));
    let run = run_mcp(&[], &root, input);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    let by_id = responses(&run);
    assert_eq!(by_id[&1]["result"]["tools"].as_array().unwrap().len(), 5);
    assert_eq!(by_id[&2]["error"]["code"], -32602);
    assert_eq!(by_id[&3]["error"]["code"], -32602);
    let mut after = Vec::new();
    files(&root, &root, &mut after);
    before.sort();
    after.sort();
    assert_eq!(before, after);
    let _ = std::fs::remove_dir_all(&parent);
}
