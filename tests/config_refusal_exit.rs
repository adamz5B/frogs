//! A configuration refusal must exit with a code a service supervisor can
//! tell apart from a crash. The process exits itself, so these run the real
//! binary against a scratch project that cannot start.

use std::path::PathBuf;
use std::process::Command;

fn project(server_json: &str, unroutable_folder: bool) -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "frogs-config-refusal-{}-{}-{n}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    let api = root.join("api");
    for dir in ["config/errors", "security", "datasources/endpoints/things"] {
        std::fs::create_dir_all(api.join(dir)).unwrap();
    }
    std::fs::write(root.join("openapi.yaml"), "openapi: 3.1.0\ninfo: { title: t, version: '1' }\npaths: {}\n").unwrap();
    std::fs::write(api.join("config/server.json"), server_json).unwrap();
    std::fs::write(api.join("config/errors/core.json"), "{}").unwrap();
    std::fs::write(api.join("config/connections.json"), "{}").unwrap();
    std::fs::write(api.join("security/schemes.json"), "{}").unwrap();
    let endpoint = r#"{ "operationId": "x", "sources": {}, "response": {} }"#;
    std::fs::write(api.join("datasources/endpoints/things/endpoint.get.json"), endpoint).unwrap();
    if unroutable_folder {
        // '%' in a folder name is refused unconditionally by the route table.
        let dir = api.join("datasources/endpoints/a%41");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("endpoint.get.json"), endpoint).unwrap();
    }
    root
}

fn exit_code(root: &std::path::Path, args: &[&str]) -> i32 {
    Command::new(env!("CARGO_BIN_EXE_frogs"))
        .args(args)
        .current_dir(root)
        .output()
        .expect("the frogs binary should run")
        .status
        .code()
        .expect("the process should exit, not be killed by a signal")
}

#[test]
fn a_route_table_refusal_exits_78_when_service_managed_and_1_otherwise() {
    let root = project("{}", true);
    assert_eq!(exit_code(&root, &["run", "--service-managed"]), 78);
    assert_eq!(exit_code(&root, &["run"]), 1, "an interactive run keeps the plain failure code");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_malformed_server_json_exits_78_when_service_managed() {
    let root = project("{ not json", false);
    assert_eq!(exit_code(&root, &["run", "--service-managed"]), 78);
    assert_eq!(exit_code(&root, &["run"]), 1);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn the_hidden_config_refusal_exit_flag_overrides_the_code() {
    let root = project("{}", true);
    assert_eq!(exit_code(&root, &["run", "--service-managed", "--config-refusal-exit", "0"]), 0);
    assert_eq!(exit_code(&root, &["run", "--service-managed", "--config-refusal-exit", "3"]), 3);
    let _ = std::fs::remove_dir_all(&root);
}
