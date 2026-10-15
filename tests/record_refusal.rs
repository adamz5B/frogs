//! `frogs test record` exits the process on a refusal, so the only honest way
//! to test the "refuses before it ever connects" ordering is to run the real
//! binary against a scratch project.

use std::path::PathBuf;
use std::process::Command;

fn scratch() -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "frogs-record-refusal-{}-{}-{n}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    root
}

fn case_insensitive_fs(dir: &std::path::Path) -> bool {
    std::fs::write(dir.join("probe_a"), b"").unwrap();
    let insensitive = dir.join("PROBE_A").exists();
    std::fs::remove_file(dir.join("probe_a")).unwrap();
    eprintln!("case-insensitive filesystem: {insensitive}");
    insensitive
}

fn project(server_json: &str) -> PathBuf {
    let root = scratch();
    let api = root.join("api");
    for dir in ["config/errors", "security", "datasources/endpoints/things"] {
        std::fs::create_dir_all(api.join(dir)).unwrap();
    }
    std::fs::write(root.join("openapi.yaml"), "openapi: 3.1.0\ninfo: { title: t, version: '1' }\npaths: {}\n").unwrap();
    std::fs::write(api.join("config/server.json"), server_json).unwrap();
    std::fs::write(api.join("config/errors/core.json"), "{}").unwrap();
    // A driver that does not exist: reaching `connect_all` would surface a
    // connection error instead of the refusal under test.
    std::fs::write(api.join("config/connections.json"), r#"{ "db": { "driver": "nosuchdriver", "database": "x" } }"#).unwrap();
    std::fs::write(api.join("security/schemes.json"), "{}").unwrap();
    std::fs::write(
        api.join("datasources/endpoints/things/endpoint.get.json"),
        r#"{ "operationId": "x", "sources": {}, "response": {} }"#,
    )
    .unwrap();
    root
}

fn record(root: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_frogs"))
        .args(["test", "record", "/things", "get"])
        .current_dir(root)
        .output()
        .expect("the frogs binary should run")
}

#[test]
fn recording_next_to_a_case_variant_test_file_refuses_before_connecting() {
    let root = project("{}");
    case_insensitive_fs(&root);
    let dir = root.join("api/datasources/endpoints/things");
    std::fs::write(dir.join("endpoint.GET.test.json"), r#"{ "cases": [] }"#).unwrap();

    let out = record(&root);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(stderr.contains("rename or remove it by hand"), "stderr was: {stderr}");
    assert!(!stderr.to_lowercase().contains("nosuchdriver"), "the connect step ran first: {stderr}");
    assert_eq!(std::fs::read_to_string(dir.join("endpoint.GET.test.json")).unwrap(), r#"{ "cases": [] }"#);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn recording_under_strict_refuses_an_unsafe_spec_before_connecting() {
    let root = project(r#"{ "strictOpenApi": true }"#);
    std::fs::write(
        root.join("openapi.yaml"),
        "openapi: 3.1.0\ninfo: { title: t, version: '1' }\npaths:\n  /a/..:\n    get:\n      operationId: x\n      responses: { '200': { description: ok } }\n",
    )
    .unwrap();
    let out = record(&root);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(!stderr.to_lowercase().contains("nosuchdriver"), "the connect step ran first: {stderr}");
    assert!(!root.join("api/datasources/endpoints/things/endpoint.get.test.json").exists());
    let _ = std::fs::remove_dir_all(&root);
}
