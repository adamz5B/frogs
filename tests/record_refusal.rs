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

#[test]
fn recording_refuses_a_security_mismatch_even_with_strict_off_before_connecting() {
    let root = project("{}");
    std::fs::write(
        root.join("openapi.yaml"),
        "openapi: 3.2.0\ninfo: { title: t, version: '1' }\ncomponents:\n  securitySchemes:\n    a: { type: apiKey, in: header, name: k }\npaths:\n  /things:\n    get:\n      operationId: x\n      security: [ { a: [] } ]\n      responses: { '200': { description: ok } }\n",
    )
    .unwrap();
    let out = record(&root);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(stderr.contains("openapi.yaml requires security ('a')"), "stderr was: {stderr}");
    assert!(!stderr.to_lowercase().contains("nosuchdriver"), "the connect step ran first: {stderr}");
    let _ = std::fs::remove_dir_all(&root);
}

fn record_with(root: &std::path::Path, method: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_frogs"))
        .args(["test", "record", "/things", method])
        .current_dir(root)
        .output()
        .expect("the frogs binary should run")
}

#[test]
fn recording_with_a_dotted_or_unknown_method_argument_exits_1_before_connecting() {
    let root = project("{}");
    for bad in ["", "../get", "g\u{1b}[31met"] {
        let out = record_with(&root, bad);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{bad:?}: {stderr}");
        assert!(stderr.contains("is not a valid method token"), "{bad:?}: {stderr}");
        assert!(!stderr.contains('\u{1b}'), "the argument must be sanitised before it is echoed: {stderr:?}");
        assert!(!stderr.to_lowercase().contains("nosuchdriver"), "the connect step ran: {stderr}");
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn recording_accepts_any_case_of_a_known_method_past_the_allowlist() {
    let root = project("{}");
    for ok in ["QUERY", "Get", "get"] {
        let out = record_with(&root, ok);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!stderr.contains("is not a valid method token"), "{ok}: {stderr}");
    }
    let _ = std::fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------- links (endpointSymlinks)

/// A directory link: a real symlink where the OS allows it, else (Windows) a junction.
fn link_dir(target: &std::path::Path, link: &std::path::Path) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link).is_ok()
    }
    #[cfg(windows)]
    {
        if std::os::windows::fs::symlink_dir(target, link).is_ok() {
            return true;
        }
        let backslashed = |p: &std::path::Path| p.to_string_lossy().replace('/', "\\");
        Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(backslashed(link))
            .arg(backslashed(target))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

fn unlink(link: &std::path::Path) {
    if std::fs::remove_dir(link).is_err() {
        let _ = std::fs::remove_file(link);
    }
}

const STUB: &str = r#"{ "operationId": "x", "sources": {}, "response": {} }"#;

fn list(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map(|entries| entries.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect())
        .unwrap_or_default();
    names.sort();
    names
}

#[test]
fn recording_refuses_before_connecting_when_the_api_folder_is_a_link_to_outside_the_project() {
    let root = project("{}");
    let outside = scratch();
    let moved = outside.join("api");
    std::fs::rename(root.join("api"), &moved).unwrap();
    if !link_dir(&moved, &root.join("api")) {
        eprintln!("skipping: cannot create a link here");
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
        return;
    }
    let before = list(&moved.join("datasources/endpoints/things"));
    let out = record(&root);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(!stderr.to_lowercase().contains("nosuchdriver"), "the connect step ran first: {stderr}");
    assert_eq!(
        list(&moved.join("datasources/endpoints/things")),
        before,
        "nothing may be written outside the project"
    );
    unlink(&root.join("api"));
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&outside);
}

#[test]
fn recording_into_an_outside_linked_endpoint_folder_refuses_before_connecting_under_follow_and_finds_no_target_under_contained() {
    for mode in ["follow", "contained", "refuse"] {
        let root = project(&format!(r#"{{ "endpointSymlinks": "{mode}" }}"#));
        let outside = scratch();
        std::fs::write(outside.join("endpoint.get.json"), STUB).unwrap();
        let things = root.join("api/datasources/endpoints/things");
        std::fs::remove_dir_all(&things).unwrap();
        if !link_dir(&outside, &things) {
            eprintln!("skipping: cannot create a link here");
            let _ = std::fs::remove_dir_all(&root);
            let _ = std::fs::remove_dir_all(&outside);
            return;
        }
        let out = record(&root);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{mode}: {stderr}");
        assert!(!stderr.to_lowercase().contains("nosuchdriver"), "{mode}: the connect step ran first: {stderr}");
        assert_eq!(list(&outside), vec!["endpoint.get.json"], "{mode}: nothing may be written outside the project");
        unlink(&things);
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }
}

#[test]
fn recording_through_an_in_project_link_gets_past_the_write_gate_under_contained() {
    let root = project("{}");
    let shared = root.join("shared");
    std::fs::create_dir_all(&shared).unwrap();
    std::fs::write(shared.join("endpoint.get.json"), STUB).unwrap();
    let things = root.join("api/datasources/endpoints/things");
    std::fs::remove_dir_all(&things).unwrap();
    if !link_dir(&shared, &things) {
        eprintln!("skipping: cannot create a link here");
        let _ = std::fs::remove_dir_all(&root);
        return;
    }
    let out = record(&root);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.to_lowercase().contains("nosuchdriver"),
        "the gate must let a contained in-project link through to the connect step: {stderr}"
    );
    unlink(&things);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn recording_under_strict_refuses_before_connecting_when_an_outside_link_exists() {
    let root = project(r#"{ "strictOpenApi": true }"#);
    let outside = scratch();
    let link = root.join("api/datasources/endpoints/ext");
    if !link_dir(&outside, &link) {
        eprintln!("skipping: cannot create a link here");
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
        return;
    }
    let out = record(&root);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(!stderr.to_lowercase().contains("nosuchdriver"), "{stderr}");
    unlink(&link);
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&outside);
}

#[test]
fn validate_and_test_never_print_the_content_of_an_unparseable_file_reached_through_a_link() {
    let root = project("{}");
    let shared = root.join("shared");
    std::fs::create_dir_all(&shared).unwrap();
    std::fs::write(
        shared.join("endpoint.get.json"),
        r#"{ "operationId": "x", "sources": "TOPSECRET-123", "response": {} }"#,
    )
    .unwrap();
    std::fs::write(shared.join("endpoint.get.test.json"), r#"{ "cases": "TOPSECRET-123" }"#).unwrap();
    let link = root.join("api/datasources/endpoints/linked");
    if !link_dir(&shared, &link) {
        eprintln!("skipping: cannot create a link here");
        let _ = std::fs::remove_dir_all(&root);
        return;
    }
    for args in [["validate"].as_slice(), ["test"].as_slice()] {
        let out = Command::new(env!("CARGO_BIN_EXE_frogs"))
            .args(args)
            .current_dir(&root)
            .output()
            .expect("the frogs binary should run");
        let everything = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(!everything.contains("TOPSECRET"), "{args:?} leaked linked file content: {everything}");
        assert!(!out.status.success(), "{args:?}: {everything}");
    }
    unlink(&link);
    let _ = std::fs::remove_dir_all(&root);
}
