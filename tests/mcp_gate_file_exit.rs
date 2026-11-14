//! A malformed `api/datasources/mcp-gate.test.json` is a startup error for `frogs test` (exit 1), so a
//! typo can never silently become "no gate file". The process exits itself, so these run the real
//! binary against a scratch project; every case here fails before any port is bound.

use std::path::PathBuf;
use std::process::Command;

fn project(gate_file: &str) -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "frogs-gate-file-exit-{}-{}-{n}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    let api = root.join("api");
    for dir in ["config/errors", "security/verifiers", "datasources/sql/db", "datasources/endpoints/things"] {
        std::fs::create_dir_all(api.join(dir)).unwrap();
    }
    std::fs::write(
        root.join("openapi.yaml"),
        "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths:\n  /things:\n    get:\n      operationId: getThings\n      responses: { '200': { description: ok } }\n",
    )
    .unwrap();
    std::fs::write(
        api.join("config/server.json"),
        r#"{ "features": { "mcp": true, "requestValidation": false, "metrics": false, "readyzCheck": false }, "mcp": { "accessScheme": "oauth" } }"#,
    )
    .unwrap();
    std::fs::write(api.join("config/errors/core.json"), "{}").unwrap();
    std::fs::write(api.join("config/connections.json"), r#"{ "db": { "driver": "sqlite", "database": ":memory:" } }"#).unwrap();
    std::fs::write(api.join("security/schemes.json"), r#"{ "oauth": { "verifier": "v.json" } }"#).unwrap();
    std::fs::write(
        api.join("security/verifiers/v.json"),
        r#"{ "type": "sql", "connection": "db", "script": "verify.sql", "parameters": [ { "name": "k", "from": "header.Authorization" } ], "validIf": "row.active = true" }"#,
    )
    .unwrap();
    std::fs::write(api.join("datasources/sql/db/verify.sql"), "SELECT 1 AS active;").unwrap();
    std::fs::write(
        api.join("datasources/endpoints/things/endpoint.get.json"),
        r#"{ "operationId": "getThings", "mcp": { "expose": true }, "sources": {}, "response": {} }"#,
    )
    .unwrap();
    std::fs::write(
        api.join("datasources/endpoints/things/endpoint.get.test.json"),
        r#"{ "cases": [ { "name": "ok", "request": {}, "expect": { "status": 200 } } ] }"#,
    )
    .unwrap();
    std::fs::write(api.join("datasources/mcp-gate.test.json"), gate_file).unwrap();
    root
}

fn run_frogs_test(root: &std::path::Path) -> (i32, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_frogs"))
        .args(["test", "--port", "0"])
        .current_dir(root)
        .output()
        .expect("the frogs binary should run");
    (
        output.status.code().expect("the process should exit, not be killed by a signal"),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn a_gate_file_that_is_not_json_exits_1_naming_the_file() {
    let root = project("{ not json");
    let (code, stderr) = run_frogs_test(&root);
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("mcp-gate.test.json"), "{stderr}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_gate_file_with_a_second_key_or_a_typo_in_the_key_exits_1() {
    for contents in [
        r#"{ "verifier": { "active": true }, "extra": 1 }"#,
        r#"{ "verifer": { "active": true } }"#,
        r#"{}"#,
        r#"[]"#,
        r#""verifier""#,
    ] {
        let root = project(contents);
        let (code, stderr) = run_frogs_test(&root);
        assert_eq!(code, 1, "{contents}: {stderr}");
        assert!(stderr.contains("exactly one key"), "{contents}: {stderr}");
        let _ = std::fs::remove_dir_all(&root);
    }
}
