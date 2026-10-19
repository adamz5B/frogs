//! End-to-end checks of OpenAPI 3.2 M4 (`additionalOperations`, method case)
//! through the real `frogs` binary: a live `frogs run` answering real sockets,
//! the startup refusal order, and the generate -> switch mode -> run workflow.
//!
//! Built only with `--features e2e-tests` (see that feature in Cargo.toml):
//! `cargo test --locked --features e2e-tests --test m4_end_to_end`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn scratch() -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "frogs-m4-binary-{}-{}-{n}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    root
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn literal_stub(status: u16) -> String {
    format!(r#"{{ "operationId": "x", "successStatus": {status}, "sources": {{}}, "response": {{}} }}"#)
}

const EMPTY_SPEC: &str = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths: {}\n";

fn server_json(port: u16, case_sensitive: bool) -> String {
    format!(r#"{{ "port": {port}, "caseSensitiveMethods": {case_sensitive}, "features": {{ "requestValidation": false, "requestCorrelation": false }} }}"#)
}

/// A project with one route folder `x`; `files` are `(file name, contents)` placed in it.
fn project(spec: &str, server: &str, files: &[(&str, String)]) -> PathBuf {
    let root = scratch();
    let api = root.join("api");
    for dir in ["config/errors", "security", "datasources/endpoints/x"] {
        std::fs::create_dir_all(api.join(dir)).unwrap();
    }
    std::fs::write(root.join("openapi.yaml"), spec).unwrap();
    std::fs::write(api.join("config/server.json"), server).unwrap();
    std::fs::write(api.join("config/errors/core.json"), "{}").unwrap();
    std::fs::write(api.join("config/connections.json"), "{}").unwrap();
    std::fs::write(api.join("security/schemes.json"), "{}").unwrap();
    for (name, contents) in files {
        std::fs::write(api.join("datasources/endpoints/x").join(name), contents).unwrap();
    }
    root
}

fn frogs(root: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_frogs"))
        .args(args)
        .current_dir(root)
        .output()
        .expect("the frogs binary should run")
}

/// A running `frogs run`; killed (and reaped) on drop so a failing assertion never leaks the process.
struct Running {
    child: Child,
    root: PathBuf,
    port: u16,
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn log_of(root: &Path) -> String {
    std::fs::read_to_string(root.join("run.log")).unwrap_or_default()
}

fn start(root: PathBuf, port: u16) -> Running {
    let log = std::fs::File::create(root.join("run.log")).unwrap();
    let err = log.try_clone().unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_frogs"))
        .arg("run")
        .current_dir(&root)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("the frogs binary should start");
    let mut running = Running { child, root, port };
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = running.child.try_wait().unwrap() {
            panic!("frogs run exited early ({status}); log:\n{}", log_of(&running.root));
        }
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return running;
        }
        assert!(Instant::now() < deadline, "frogs run never listened on {port}; log:\n{}", log_of(&running.root));
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn status_of(port: u16, method: &str, path: &str) -> u16 {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(stream, "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
    let mut received = Vec::new();
    let _ = stream.read_to_end(&mut received);
    let text = String::from_utf8_lossy(&received);
    let line = text.lines().next().unwrap_or_default();
    line.split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("no status line for {method}: {line:?}"))
}

fn stop_cleanly(mut running: Running) {
    let out = frogs(&running.root, &["stop"]);
    assert!(out.status.success(), "frogs stop: {}", String::from_utf8_lossy(&out.stderr));
    let deadline = Instant::now() + Duration::from_secs(15);
    while running.child.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "frogs run did not exit after frogs stop");
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(TcpStream::connect(("127.0.0.1", running.port)).is_err(), "the port must be released after stop");
}

#[test]
fn a_live_default_mode_server_answers_purge_in_any_spelling_from_endpoint_upper_purge() {
    let port = free_port();
    let root = project(EMPTY_SPEC, &server_json(port, false), &[("endpoint.PURGE.json", literal_stub(201))]);
    let running = start(root, port);
    for method in ["PURGE", "purge", "Purge"] {
        assert_eq!(status_of(port, method, "/x"), 201, "{method}");
    }
    assert_eq!(status_of(port, "GET", "/x"), 405);
    assert_eq!(status_of(port, "UNLINK", "/x"), 405);
    stop_cleanly(running);
}

#[test]
fn a_live_exact_mode_server_answers_only_the_exact_spelling_from_endpoint_tilde_purge() {
    let port = free_port();
    let root = project(EMPTY_SPEC, &server_json(port, true), &[("endpoint.~purge.json", literal_stub(201))]);
    let running = start(root, port);
    assert_eq!(status_of(port, "purge", "/x"), 201);
    assert_eq!(status_of(port, "PURGE", "/x"), 405);
    assert_eq!(status_of(port, "Purge", "/x"), 405);
    stop_cleanly(running);
}

#[test]
fn a_live_default_mode_server_ignores_a_file_generated_under_the_other_mode() {
    let port = free_port();
    let root = project(EMPTY_SPEC, &server_json(port, false), &[("endpoint.~purge.json", literal_stub(201))]);
    let running = start(root, port);
    assert_eq!(status_of(port, "PURGE", "/x"), 404);
    assert_eq!(status_of(port, "purge", "/x"), 404);
    stop_cleanly(running);
}

const DUPLICATE_KEYS: &str = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths:\n  /x:\n    additionalOperations:\n      purge:\n        operationId: a\n        responses: { '200': { description: ok } }\n      PURGE:\n        operationId: b\n        responses: { '200': { description: ok } }\n";

#[test]
fn duplicate_case_variant_keys_with_an_existing_stub_stop_the_binary_before_the_pidfile_and_the_port() {
    let port = free_port();
    let root = project(DUPLICATE_KEYS, &server_json(port, false), &[("endpoint.PURGE.json", literal_stub(201))]);
    // Occupy the port ourselves: a binary that got as far as binding would die with an address-in-use error instead.
    let hold = TcpListener::bind(("127.0.0.1", port)).unwrap();
    let out = frogs(&root, &["run"]);
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(1), "{text}");
    assert!(text.contains("declares ambiguously") || text.contains("differing only in case"), "{text}");
    assert!(
        !text.to_lowercase().contains("address") && !text.to_lowercase().contains("in use"),
        "it must refuse before binding: {text}"
    );
    assert!(!root.join(".frogs/run.json").exists(), "no pidfile may be written for a refused start");
    drop(hold);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn duplicate_case_variant_keys_alone_do_not_stop_a_non_strict_server_from_starting() {
    let port = free_port();
    let root = project(DUPLICATE_KEYS, &server_json(port, false), &[]);
    let running = start(root, port);
    assert_eq!(status_of(port, "PURGE", "/x"), 404, "nothing ambiguous is ever served");
    stop_cleanly(running);
}

#[test]
fn switching_the_mode_through_generate_refuses_until_the_file_is_renamed_by_hand_and_then_run_serves_the_new_route() {
    let port = free_port();
    let spec = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths:\n  /x:\n    additionalOperations:\n      purge:\n        operationId: p\n        responses: { '200': { description: ok } }\n";
    let root = project(spec, &server_json(port, false), &[]);
    let endpoints = root.join("api/datasources/endpoints/x");

    let first = frogs(&root, &["generate"]);
    assert!(first.status.success(), "{}", String::from_utf8_lossy(&first.stderr));
    assert!(endpoints.join("endpoint.PURGE.json").is_file());
    // Replace the generated stub with a servable literal one, as a user would.
    std::fs::write(endpoints.join("endpoint.PURGE.json"), literal_stub(200)).unwrap();

    std::fs::write(root.join("api/config/server.json"), server_json(port, true)).unwrap();
    let blocked = frogs(&root, &["generate"]);
    let stderr = String::from_utf8_lossy(&blocked.stderr);
    assert_eq!(blocked.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("STILL BEING SERVED"), "{stderr}");
    assert!(endpoints.join("endpoint.PURGE.json").is_file(), "nothing is renamed automatically");
    assert!(!endpoints.join("endpoint.~purge.json").exists());
    assert!(!root.join("api/datasources/endpoints/x/_endpoint.PURGE.json").exists(), "and nothing is orphaned");

    std::fs::rename(endpoints.join("endpoint.PURGE.json"), endpoints.join("endpoint.~purge.json")).unwrap();
    let _ = std::fs::remove_file(endpoints.join("endpoint.PURGE.reference.json"));
    let second = frogs(&root, &["generate"]);
    assert!(second.status.success(), "{}", String::from_utf8_lossy(&second.stderr));
    // generate may re-normalise a stub it has no recorded hash for (pretty-printing, response shape), but it keeps the file and its settings.
    let kept: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(endpoints.join("endpoint.~purge.json")).unwrap()).unwrap();
    assert_eq!(kept["successStatus"], 200, "{kept}");
    assert!(!endpoints.join("endpoint.PURGE.json").exists());

    let running = start(root, port);
    assert_eq!(status_of(port, "purge", "/x"), 200);
    assert_eq!(status_of(port, "PURGE", "/x"), 405);
    stop_cleanly(running);
}

#[test]
fn validate_prints_the_method_case_line_for_each_setting() {
    for (server, expected) in [
        (r#"{ "caseSensitiveMethods": true }"#, "method case: exact (caseSensitiveMethods: true)"),
        (r#"{ "caseSensitiveMethods": false }"#, "method case: case-insensitive (caseSensitiveMethods: false)"),
        ("{}", "method case: case-insensitive (default)"),
    ] {
        let root = project(EMPTY_SPEC, server, &[]);
        let out = frogs(&root, &["validate"]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.contains(expected), "{server}: stdout was:\n{stdout}");
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[test]
fn validate_exits_non_zero_for_a_wrong_mode_file_and_for_a_mode_switch_mismatch_even_without_strict() {
    let wrong_mode = project(EMPTY_SPEC, r#"{ "caseSensitiveMethods": false }"#, &[("endpoint.~purge.json", literal_stub(201))]);
    let out = frogs(&wrong_mode, &["validate"]);
    assert!(!out.status.success(), "{}", String::from_utf8_lossy(&out.stdout));
    let _ = std::fs::remove_dir_all(&wrong_mode);

    let spec = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths:\n  /x:\n    additionalOperations:\n      purge:\n        operationId: p\n        responses: { '200': { description: ok } }\n";
    let mismatch = project(spec, r#"{ "caseSensitiveMethods": true }"#, &[("endpoint.PURGE.json", literal_stub(201))]);
    let out = frogs(&mismatch, &["validate"]);
    assert!(!out.status.success(), "{}", String::from_utf8_lossy(&out.stdout));
    assert!(String::from_utf8_lossy(&out.stdout).contains("STILL BEING SERVED"));
    let _ = std::fs::remove_dir_all(&mismatch);

    let clean = project(spec, r#"{ "caseSensitiveMethods": true }"#, &[("endpoint.~purge.json", literal_stub(201))]);
    let out = frogs(&clean, &["validate"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stdout));
    let _ = std::fs::remove_dir_all(&clean);
}
