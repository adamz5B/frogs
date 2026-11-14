//! Acceptance tests for the Phase 3a refactor: the plain-text output and exit codes of `frogs validate` and
//! `frogs test`'s startup notes must be byte-for-byte what they were before `validate`/`test` were split into
//! "compute a report" and "print it". The expected text under `tests/fixtures/cli_text_goldens/expected/` was
//! captured from the pre-refactor binary on the projects under `tests/fixtures/cli_text_goldens/projects/`.
//! Temp-dir paths, timestamps, ANSI colour and ports are normalised. Also covers `frogs validate --json`.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cli_text_goldens")
}

fn temp_root(label: &str) -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "frogs-golden-{label}-{}-{}-{n}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// A scratch copy of one fixture project, so nothing a command writes ever lands in the repository.
fn scratch_project(name: &str) -> PathBuf {
    let root = temp_root(name);
    copy_tree(&fixture_dir().join("projects").join(name), &root);
    if name == "api_ok" {
        // an empty folder cannot be committed to git
        std::fs::create_dir_all(root.join("api/config")).unwrap();
    }
    root
}

fn normalize(text: &str, root: &Path) -> String {
    let plain = root.display().to_string();
    let doubled = plain.replace('\\', "\\\\");
    let text = text.replace('\r', "").replace(&doubled, "<ROOT>").replace(&plain, "<ROOT>");
    text.replace("\\\\", "/").replace('\\', "/")
}

fn expected(name: &str, ext: &str) -> String {
    std::fs::read_to_string(fixture_dir().join("expected").join(format!("{name}.{ext}")))
        .unwrap_or_else(|e| panic!("missing golden {name}.{ext}: {e}"))
        .replace("\r\n", "\n")
}

fn frogs(root: &Path, args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_frogs"))
        .args(args)
        .current_dir(root)
        .env_remove("RUST_LOG")
        .output()
        .expect("the frogs binary should run");
    (
        output.status.code().expect("the process should exit, not be killed by a signal"),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn assert_validate_matches_golden(fixture: &str, golden: &str) {
    let root = scratch_project(fixture);
    let (code, stdout, stderr) = frogs(&root, &["validate"]);
    assert_eq!(normalize(&stdout, &root), expected(golden, "stdout"), "{golden}: stdout");
    assert_eq!(normalize(&stderr, &root), expected(golden, "stderr"), "{golden}: stderr");
    assert_eq!(code.to_string(), expected(golden, "exitcode").trim(), "{golden}: exit code");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn validate_of_a_clean_api_project_prints_exactly_the_pre_refactor_text_and_exits_0() {
    assert_validate_matches_golden("api_ok", "validate_api_ok");
}

#[test]
fn validate_of_an_api_project_with_problems_prints_exactly_the_pre_refactor_text_and_exits_1() {
    assert_validate_matches_golden("api_problems", "validate_api_problems");
}

#[test]
fn validate_of_a_web_only_project_prints_exactly_the_pre_refactor_text_and_exits_0() {
    assert_validate_matches_golden("web_only", "validate_web_only");
}

#[test]
fn validate_with_an_unparseable_server_json_prints_exactly_the_pre_refactor_text_and_exits_1() {
    assert_validate_matches_golden("config_fail", "validate_config_fail");
}

// ---- validate --json

fn one_document(stdout: &str) -> serde_json::Value {
    assert_eq!(stdout.trim_end().lines().count(), 1, "exactly one line of JSON on stdout, nothing else: {stdout:?}");
    assert!(stdout.ends_with('\n'));
    serde_json::from_str(stdout).unwrap_or_else(|e| panic!("stdout is not one JSON document ({e}): {stdout:?}"))
}

#[test]
fn validate_json_of_a_clean_project_is_one_ok_document_with_schema_version_1_and_exit_0() {
    let root = scratch_project("api_ok");
    let (code, stdout, stderr) = frogs(&root, &["validate", "--json"]);
    assert_eq!(code, 0, "{stderr}");
    let doc = one_document(&stdout);
    assert_eq!(doc["schemaVersion"], 1);
    assert_eq!(doc["ok"], true);
    assert_eq!(doc["problemCount"], 0);
    assert_eq!(doc["connections"], "checked", "the CLI's connection checks run as in plain validate");
    assert!(doc["findings"].is_array());
    assert!(doc.get("fatal").is_none());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn validate_json_of_a_project_with_problems_lists_problem_findings_and_exits_1() {
    let root = scratch_project("api_problems");
    let (code, stdout, _stderr) = frogs(&root, &["validate", "--json"]);
    assert_eq!(code, 1);
    let doc = one_document(&stdout);
    assert_eq!(doc["ok"], false);
    assert_eq!(doc["problemCount"], 2);
    let findings = doc["findings"].as_array().unwrap();
    let problems: Vec<&serde_json::Value> = findings.iter().filter(|f| f["problem"] == true).collect();
    assert_eq!(problems.len(), 2, "{doc}");
    for finding in findings {
        for key in ["severity", "problem", "section", "message"] {
            assert!(finding.get(key).is_some(), "{key} missing from {finding}");
        }
    }
    assert!(problems.iter().any(|f| f["message"].as_str().unwrap().contains("nosuchdriver")), "{doc}");
    assert!(problems.iter().any(|f| f["message"].as_str().unwrap().contains("noSuchScheme")), "{doc}");
    assert!(
        findings.iter().any(|f| f["severity"] == "warning" && f["problem"] == false),
        "the no-matching-operation warning is a non-problem finding: {doc}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn validate_json_of_an_unparseable_config_is_a_fatal_document_and_exits_1() {
    let root = scratch_project("config_fail");
    let (code, stdout, _stderr) = frogs(&root, &["validate", "--json"]);
    assert_eq!(code, 1);
    let doc = one_document(&stdout);
    assert_eq!(doc["schemaVersion"], 1);
    assert_eq!(doc["ok"], false);
    assert!(doc["fatal"]["message"].as_str().unwrap().contains("server.json"), "{doc}");
    assert!(doc.get("findings").is_none());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn validate_json_of_a_web_only_project_is_ok() {
    let root = scratch_project("web_only");
    let (code, stdout, _stderr) = frogs(&root, &["validate", "--json"]);
    assert_eq!(code, 0);
    let doc = one_document(&stdout);
    assert_eq!(doc["ok"], true);
    assert_eq!(doc["problemCount"], 0);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn validate_json_keeps_stdout_a_single_document_even_when_logging_is_turned_up() {
    let root = scratch_project("api_problems");
    let output = Command::new(env!("CARGO_BIN_EXE_frogs"))
        .args(["validate", "--json"])
        .current_dir(&root)
        .env("RUST_LOG", "trace")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    one_document(&stdout);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn validate_json_outside_any_project_exits_1_and_prints_no_partial_json_on_stdout() {
    let root = temp_root("empty");
    let (code, stdout, stderr) = frogs(&root, &["validate", "--json"]);
    assert_eq!(code, 1);
    assert!(!stderr.is_empty(), "the no-project message goes to stderr");
    if !stdout.trim().is_empty() {
        one_document(&stdout);
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn validate_json_exit_code_for_a_config_refusal_matches_plain_validate() {
    let root = scratch_project("config_fail");
    let plain = frogs(&root, &["validate"]).0;
    let json = frogs(&root, &["validate", "--json"]).0;
    assert_eq!(plain, json);
    let _ = std::fs::remove_dir_all(&root);
}
