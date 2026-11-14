//! `generate_report`: the FR21 result shape, the role-mismatch errors, and the write hardening (a dangling or
//! case-twin `webserve.json`). The report function never prints and never exits.

use std::fs;
use std::path::{Path, PathBuf};

use super::*;
use crate::commands::report::ErrorKind;
use crate::openapi::fs_os_tests::{link_dangling_file, link_file};

fn tempdir() -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "frogs-generate-report-{}-{}-{n}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

const CARS: &str = "  /cars:
    get:
      operationId: listCars
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: object
                properties:
                  maker: { type: string }
                  year: { type: integer }
";

const CARS_WITH_PRICE: &str = "  /cars:
    get:
      operationId: listCars
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: object
                properties:
                  maker: { type: string }
                  year: { type: integer }
                  price: { type: number }
";

const VIN: &str = "  /cars/{vin}:
    get:
      operationId: getCar
      parameters:
        - { name: vin, in: path, required: true, schema: { type: string } }
      responses:
        '200': { description: ok, content: { application/json: { schema: { type: object, properties: { vin: { type: string } } } } } }
";

fn spec(paths: &[&str]) -> String {
    format!("openapi: 3.0.3\ninfo: {{ title: t, version: '1' }}\npaths:\n{}", paths.concat())
}

fn api_project() -> PathBuf {
    let root = tempdir();
    fs::write(root.join("openapi.yaml"), spec(&[CARS, VIN])).unwrap();
    root
}

fn web_project() -> PathBuf {
    let root = tempdir();
    fs::write(root.join("index.html"), "<html></html>").unwrap();
    root
}

fn snapshot(dir: &Path, root: &Path, out: &mut Vec<String>) {
    let mut entries: Vec<_> = fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()).collect();
    entries.sort();
    for path in entries {
        out.push(path.strip_prefix(root).unwrap().display().to_string());
        if path.is_dir() {
            snapshot(&path, root, out);
        }
    }
}

#[test]
fn a_fresh_api_project_reports_both_stubs_created_and_the_scaffold_lines_without_failing() {
    let root = api_project();
    let report = generate_report(&root, None).expect("a clean generate succeeds");
    let mut created = report.created.clone();
    created.sort();
    assert_eq!(
        created,
        [
            "api/datasources/endpoints/cars/endpoint.get.json",
            "api/datasources/endpoints/cars/{vin}/endpoint.get.json"
        ]
    );
    assert!(report.migrated.is_empty() && report.orphaned.is_empty() && report.restored.is_empty());
    assert_eq!(report.unchanged, 0);
    assert!(!report.failed && !report.strict_aborted && report.errors.is_empty());
    assert!(report.lines.iter().any(|l| l.message.starts_with("project root:")));
    assert!(
        report.lines.iter().any(|l| l.message.starts_with("wrote config/server.json")),
        "{:?}",
        report.lines.iter().map(|l| &l.message).collect::<Vec<_>>()
    );
    assert!(root.join("api/datasources/endpoints/cars/endpoint.get.reference.json").is_file());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_second_run_reports_everything_unchanged_and_creates_nothing() {
    let root = api_project();
    generate_report(&root, None).unwrap();
    let report = generate_report(&root, None).unwrap();
    assert!(report.created.is_empty() && report.migrated.is_empty() && report.orphaned.is_empty());
    assert_eq!(report.unchanged, 2);
    assert!(!report.failed);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_spec_change_reports_a_migration_with_its_backup_an_orphan_with_its_new_name_and_later_a_restore() {
    let root = api_project();
    generate_report(&root, None).unwrap();

    fs::write(root.join("openapi.yaml"), spec(&[CARS_WITH_PRICE])).unwrap();
    let report = generate_report(&root, None).unwrap();
    assert_eq!(report.migrated.len(), 1, "{:?}", report.migrated);
    let (stub, backup) = &report.migrated[0];
    assert_eq!(stub, "api/datasources/endpoints/cars/endpoint.get.json");
    assert!(backup.starts_with("api/datasources/endpoints/cars/_backups/endpoint.get."), "{backup}");
    assert!(root.join(backup).is_file(), "the backup really exists inside the project");
    assert_eq!(
        report.orphaned,
        [(
            "api/datasources/endpoints/cars/{vin}/endpoint.get.json".to_string(),
            "api/datasources/endpoints/cars/{vin}/_endpoint.get.json".to_string()
        )]
    );
    assert!(root.join("api/datasources/endpoints/cars/{vin}/_endpoint.get.json").is_file());
    assert!(
        !root.join("api/datasources/endpoints/cars/{vin}/endpoint.get.json").exists(),
        "orphaning renames, nothing is deleted"
    );

    fs::write(root.join("openapi.yaml"), spec(&[CARS_WITH_PRICE, VIN])).unwrap();
    let back = generate_report(&root, None).unwrap();
    assert_eq!(back.restored, ["api/datasources/endpoints/cars/{vin}/endpoint.get.json"]);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_strict_failure_is_an_ok_report_marked_failed_and_aborted_with_no_endpoint_files_written() {
    let root = tempdir();
    fs::write(
        root.join("openapi.yaml"),
        spec(&["  /cars:batchGet:\n    get:\n      operationId: x\n      responses: { '200': { description: ok } }\n"]),
    )
    .unwrap();
    fs::create_dir_all(root.join("api/config")).unwrap();
    fs::write(root.join("api/config/server.json"), r#"{ "strictOpenApi": true }"#).unwrap();
    let report = generate_report(&root, None).expect("a strict abort is data, not an Err");
    assert!(report.failed && report.strict_aborted);
    assert!(!report.errors.is_empty());
    assert!(report.created.is_empty());
    assert!(!root.join("api/datasources/endpoints").exists(), "nothing is generated under strict");
    assert!(
        report.lines.iter().any(|l| l.severity == crate::commands::report::Severity::Error),
        "{:?}",
        report.lines
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn asking_for_the_api_role_on_a_web_only_project_is_a_command_error_that_writes_nothing() {
    let root = web_project();
    let mut before = Vec::new();
    snapshot(&root, &root, &mut before);
    let error = generate_report(&root, Some(Role::Api)).expect_err("--role api needs an openapi.yaml");
    assert_eq!(error.kind, ErrorKind::Precondition);
    assert_eq!(error.exit_code, 1);
    assert!(error.message.contains("--role api"), "{}", error.message);
    let mut after = Vec::new();
    snapshot(&root, &root, &mut after);
    assert_eq!(before, after);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn asking_for_the_web_role_on_an_api_only_project_is_a_command_error_that_writes_nothing() {
    let root = api_project();
    let error = generate_report(&root, Some(Role::Web)).expect_err("--role web needs web assets");
    assert_eq!(error.kind, ErrorKind::Precondition);
    assert!(error.message.contains("--role web"), "{}", error.message);
    assert!(!root.join("api").exists(), "nothing was scaffolded");
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn the_web_role_alone_on_a_both_roles_project_writes_only_webserve_json() {
    let root = api_project();
    fs::write(root.join("index.html"), "<html></html>").unwrap();
    let report = generate_report(&root, Some(Role::Web)).unwrap();
    assert!(root.join("webserve.json").is_file());
    assert!(!root.join("api").exists(), "the api side was not generated");
    assert!(report.created.is_empty());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_web_only_project_gets_a_webserve_json_and_a_second_run_leaves_it_unchanged() {
    let root = web_project();
    generate_report(&root, None).unwrap();
    let first = fs::read_to_string(root.join("webserve.json")).unwrap();
    assert!(first.contains("index.html"));
    let report = generate_report(&root, None).unwrap();
    assert!(report.lines.iter().any(|l| l.message.contains("left unchanged")));
    assert_eq!(fs::read_to_string(root.join("webserve.json")).unwrap(), first);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_dangling_webserve_json_link_is_refused_and_its_target_is_never_created() {
    let root = web_project();
    let outside = tempdir();
    let target = outside.join("created-through-link.json");
    if !link_dangling_file(&target, &root.join("webserve.json")) {
        eprintln!("skipping: could not create a file symlink");
        let _ = fs::remove_dir_all(&root);
        return;
    }
    let result = generate_report(&root, None);
    assert!(result.is_err(), "writing through a dangling link must be refused: {result:?}");
    assert!(!target.exists(), "the link target must not be created");
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&outside);
}

#[test]
fn a_webserve_json_link_to_a_file_outside_the_project_is_never_written_through() {
    let root = web_project();
    let outside = tempdir();
    let target = outside.join("victim.json");
    fs::write(&target, "untouched").unwrap();
    if !link_file(&target, &root.join("webserve.json")) {
        eprintln!("skipping: could not create a file symlink");
        let _ = fs::remove_dir_all(&root);
        return;
    }
    let _ = generate_report(&root, None);
    assert_eq!(fs::read_to_string(&target).unwrap(), "untouched");
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&outside);
}

#[test]
fn a_case_twin_of_webserve_json_is_never_joined_by_a_second_file_with_different_content() {
    let root = web_project();
    fs::write(root.join("WebServe.json"), r#"{ "startPage": "index.html", "marker": "mine" }"#).unwrap();
    let _ = generate_report(&root, None);
    let twins: Vec<String> = fs::read_dir(&root)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.eq_ignore_ascii_case("webserve.json"))
        .collect();
    assert_eq!(twins, ["WebServe.json"], "no second case-variant file may be created: {twins:?}");
    assert!(
        fs::read_to_string(root.join("WebServe.json")).unwrap().contains("mine"),
        "the existing file is untouched"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_project_with_neither_marker_is_a_command_error() {
    let root = tempdir();
    let error = generate_report(&root, None).expect_err("nothing to generate");
    assert_eq!(error.kind, ErrorKind::Precondition);
    let _ = fs::remove_dir_all(&root);
}
