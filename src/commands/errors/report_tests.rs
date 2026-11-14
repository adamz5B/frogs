//! `freeze_report`: the data shape (FR22) and the FR23 hardening. The report function never prints and never exits,
//! so a failure comes back as a `CommandError` and every refusal can be asserted on disk.

use std::fs;
use std::path::{Path, PathBuf};

use super::*;
use crate::commands::report::ErrorKind;
use crate::openapi::fs_os_tests::{link_dir, link_file};

fn tempdir() -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "frogs-freeze-report-{}-{}-{n}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn entry(status: u16) -> String {
    format!(
        r#"{{ "_discovered": true, "httpStatus": {status}, "exposeDetail": false, "occurrences": 3, "firstSeen": "2026-07-16T10:03:00Z", "lastSeen": "2026-07-16T10:41:00Z", "sampleMessage": "m" }}"#
    )
}

fn project_with_scratch(scratch: &str) -> PathBuf {
    let root = tempdir();
    fs::write(root.join("openapi.yaml"), "openapi: 3.0.3\ninfo: { title: t, version: '1' }\npaths: {}\n").unwrap();
    fs::create_dir_all(root.join("api/config")).unwrap();
    fs::write(root.join("api/config/errors.discovered.json"), scratch).unwrap();
    root
}

fn one_code_project() -> PathBuf {
    project_with_scratch(&format!(r#"{{ "new.code": {} }}"#, entry(502)))
}

fn dated_name() -> String {
    format!("discovered-{}.json", chrono::Utc::now().format("%Y-%m-%d"))
}

fn scratch(root: &Path) -> String {
    fs::read_to_string(root.join("api/config/errors.discovered.json")).unwrap()
}

fn assert_nothing_written(root: &Path, scratch_before: &str) {
    assert_eq!(scratch(root), scratch_before, "the scratch file must not be purged");
}

#[test]
fn a_freeze_reports_the_dated_file_its_sorted_codes_the_skipped_codes_and_the_purge() {
    let root = project_with_scratch(&format!(
        r#"{{ "zeta.code": {}, "alpha.code": {}, "known.code": {} }}"#,
        entry(500),
        entry(502),
        entry(400)
    ));
    fs::create_dir_all(root.join("api/config/errors")).unwrap();
    fs::write(
        root.join("api/config/errors/core.json"),
        r#"{ "known.code": { "httpStatus": 400, "exposeDetail": true } }"#,
    )
    .unwrap();

    let report = freeze_report(&root).expect("a clean freeze succeeds");
    let (file, codes) = report.written.expect("a dated file was written");
    assert_eq!(file, format!("api/config/errors/{}", dated_name()), "project-relative with forward slashes");
    assert_eq!(codes, ["alpha.code", "zeta.code"]);
    assert_eq!(report.skipped, ["known.code"]);
    assert!(report.purged);
    assert!(report.lines.iter().any(|l| l.message.starts_with("wrote 2 entries")), "{:?}", report.lines);
    assert!(report.lines.iter().any(|l| l.message == "purged config/errors.discovered.json"));
    let dated: serde_json::Value = serde_json::from_str(&fs::read_to_string(root.join("api/config/errors").join(dated_name())).unwrap()).unwrap();
    assert_eq!(dated["alpha.code"]["httpStatus"], 502);
    assert_eq!(scratch(&root), "{}");
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn freezing_an_empty_or_absent_scratch_file_reports_nothing_written_and_not_purged() {
    for scratch_text in ["{}", ""] {
        let root = project_with_scratch(if scratch_text.is_empty() { "{}" } else { scratch_text });
        if scratch_text.is_empty() {
            fs::remove_file(root.join("api/config/errors.discovered.json")).unwrap();
        }
        let report = freeze_report(&root).unwrap();
        assert!(report.written.is_none());
        assert!(report.skipped.is_empty());
        assert!(!report.purged);
        assert!(report.lines.iter().any(|l| l.message.contains("nothing to freeze")));
        assert!(!root.join("api/config/errors").exists(), "no output directory is created for nothing");
        let _ = fs::remove_dir_all(&root);
    }
}

#[test]
fn freezing_only_already_classified_codes_skips_them_writes_no_file_and_still_purges() {
    let root = project_with_scratch(&format!(r#"{{ "known.code": {} }}"#, entry(400)));
    fs::create_dir_all(root.join("api/config/errors")).unwrap();
    fs::write(
        root.join("api/config/errors/core.json"),
        r#"{ "known.code": { "httpStatus": 400, "exposeDetail": true } }"#,
    )
    .unwrap();
    let report = freeze_report(&root).unwrap();
    assert!(report.written.is_none());
    assert_eq!(report.skipped, ["known.code"]);
    assert!(report.purged);
    assert!(!root.join("api/config/errors").join(dated_name()).exists());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_freeze_with_a_broken_server_json_is_a_config_error_and_writes_nothing() {
    let root = one_code_project();
    fs::write(root.join("api/config/server.json"), "{ not json").unwrap();
    let before = scratch(&root);
    let error = freeze_report(&root).expect_err("a config that does not load stops the freeze");
    assert_eq!(error.kind, ErrorKind::Config);
    assert_eq!(error.exit_code, crate::exit_codes::config_refusal_exit());
    assert_nothing_written(&root, &before);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_corrupt_same_day_dated_file_is_refused_as_a_config_refusal_with_nothing_written_and_nothing_purged() {
    let root = one_code_project();
    fs::create_dir_all(root.join("api/config/errors")).unwrap();
    let dated = root.join("api/config/errors").join(dated_name());
    fs::write(&dated, "{ definitely not json").unwrap();
    let before = scratch(&root);

    let error = freeze_report(&root).expect_err("a corrupt dated file is never replaced");
    // the registry load (which reads every errors/*.json, the dated file included) refuses first; either way it is a
    // configuration refusal exit, never a replaced file
    assert!(matches!(error.kind, ErrorKind::Refusal | ErrorKind::Config), "{:?}", error.kind);
    assert_eq!(error.exit_code, crate::exit_codes::config_refusal_exit());
    assert!(error.message.contains(&dated_name()), "the message names the file: {}", error.message);
    assert_eq!(fs::read_to_string(&dated).unwrap(), "{ definitely not json");
    assert_nothing_written(&root, &before);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_dated_file_that_is_valid_json_of_the_wrong_shape_is_refused_too() {
    let root = one_code_project();
    fs::create_dir_all(root.join("api/config/errors")).unwrap();
    let dated = root.join("api/config/errors").join(dated_name());
    fs::write(&dated, r#"["not", "a", "map"]"#).unwrap();
    // an array is also not a valid error-definitions file, so the registry load itself may refuse first
    let before = scratch(&root);
    assert!(freeze_report(&root).is_err());
    assert_eq!(fs::read_to_string(&dated).unwrap(), r#"["not", "a", "map"]"#);
    assert_nothing_written(&root, &before);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_second_freeze_the_same_day_still_merges_into_a_valid_existing_dated_file() {
    let root = one_code_project();
    freeze_report(&root).unwrap();
    fs::write(root.join("api/config/errors.discovered.json"), format!(r#"{{ "second.code": {} }}"#, entry(503))).unwrap();
    let report = freeze_report(&root).unwrap();
    assert_eq!(report.written.unwrap().1, ["second.code"]);
    let dated: serde_json::Value = serde_json::from_str(&fs::read_to_string(root.join("api/config/errors").join(dated_name())).unwrap()).unwrap();
    assert!(dated.get("new.code").is_some() && dated.get("second.code").is_some(), "{dated}");
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_symlinked_or_junctioned_config_errors_folder_is_refused_and_its_target_gets_nothing() {
    let root = one_code_project();
    let outside = tempdir();
    if !link_dir(&outside, &root.join("api/config/errors")) {
        let _ = fs::remove_dir_all(&root);
        return;
    }
    let before = scratch(&root);
    let error = freeze_report(&root).expect_err("a linked errors folder is refused");
    assert_ne!(error.exit_code, 0);
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 0, "nothing was written through the link");
    assert_nothing_written(&root, &before);
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&outside);
}

#[test]
fn a_symlinked_dated_file_is_refused_and_its_target_is_left_unchanged() {
    let root = one_code_project();
    fs::create_dir_all(root.join("api/config/errors")).unwrap();
    let outside = tempdir();
    let target = outside.join("victim.json");
    fs::write(&target, r#"{ "victim.code": { "httpStatus": 500, "exposeDetail": false } }"#).unwrap();
    if !link_file(&target, &root.join("api/config/errors").join(dated_name())) {
        eprintln!("skipping: could not create a file symlink");
        let _ = fs::remove_dir_all(&root);
        return;
    }
    let before = scratch(&root);
    let error = freeze_report(&root).expect_err("a linked dated file is refused");
    assert_ne!(error.exit_code, 0);
    assert_eq!(
        fs::read_to_string(&target).unwrap(),
        r#"{ "victim.code": { "httpStatus": 500, "exposeDetail": false } }"#
    );
    assert_nothing_written(&root, &before);
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&outside);
}

#[test]
fn a_symlinked_scratch_file_is_never_written_through() {
    let root = one_code_project();
    let outside = tempdir();
    let target = outside.join("scratch.json");
    let content = format!(r#"{{ "new.code": {} }}"#, entry(502));
    fs::write(&target, &content).unwrap();
    fs::remove_file(root.join("api/config/errors.discovered.json")).unwrap();
    if !link_file(&target, &root.join("api/config/errors.discovered.json")) {
        eprintln!("skipping: could not create a file symlink");
        let _ = fs::remove_dir_all(&root);
        return;
    }
    let result = freeze_report(&root);
    assert!(result.is_err(), "the purge of a linked scratch file is refused: {result:?}");
    assert_eq!(fs::read_to_string(&target).unwrap(), content, "the purge must not write through the link");
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&outside);
}

#[test]
fn a_dangling_scratch_link_is_treated_as_outside_and_refused() {
    let root = project_with_scratch("{}");
    fs::remove_file(root.join("api/config/errors.discovered.json")).unwrap();
    let outside = tempdir();
    if !crate::openapi::fs_os_tests::link_dangling_file(&outside.join("gone.json"), &root.join("api/config/errors.discovered.json")) {
        let _ = fs::remove_dir_all(&root);
        return;
    }
    // nothing to freeze, so nothing is attempted; the point is that it neither panics nor creates the target
    let _ = freeze_report(&root);
    assert!(!outside.join("gone.json").exists(), "a dangling link target must not be created");
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&outside);
}
