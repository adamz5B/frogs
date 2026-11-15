//! Acceptance tests for the Phase 3b refactor of `frogs errors freeze`: text output and exit codes must be
//! byte-for-byte what the pre-refactor binary printed, apart from the intended FR23 hardening, which has its own
//! test below. The date in the dated file name is normalised to `<DATE>`.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cli_text_goldens_3b")
}

fn temp_root(label: &str) -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "frogs-freeze-golden-{label}-{}-{}-{n}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn freeze_project() -> PathBuf {
    let root = temp_root("p");
    std::fs::copy(fixture_dir().join("freeze/openapi.yaml"), root.join("openapi.yaml")).unwrap();
    std::fs::create_dir_all(root.join("api/config")).unwrap();
    std::fs::copy(fixture_dir().join("freeze/errors.discovered.json"), root.join("api/config/errors.discovered.json")).unwrap();
    root
}

fn normalize(text: &str, root: &Path) -> String {
    let plain = root.display().to_string();
    let doubled = plain.replace('\\', "\\\\");
    let mut text = text.replace('\r', "");
    // macOS temp dirs sit behind a symlink (/var -> /private/var) and frogs prints the canonical path, so replace that form first.
    if let Ok(canonical) = std::fs::canonicalize(root) {
        let canonical = canonical.display().to_string();
        if canonical != plain {
            text = text.replace(&canonical.replace('\\', "\\\\"), "<ROOT>").replace(&canonical, "<ROOT>");
        }
    }
    let text = text.replace(&doubled, "<ROOT>").replace(&plain, "<ROOT>");
    let text = text.replace("\\\\", "/").replace('\\', "/");
    // discovered-YYYY-MM-DD -> discovered-<DATE>
    let mut out = String::new();
    let mut rest = text.as_str();
    while let Some(at) = rest.find("discovered-") {
        let (head, tail) = rest.split_at(at + "discovered-".len());
        out.push_str(head);
        let is_date = tail.len() >= 10
            && tail.as_bytes()[..10]
                .iter()
                .enumerate()
                .all(|(i, b)| if i == 4 || i == 7 { *b == b'-' } else { b.is_ascii_digit() });
        if is_date {
            out.push_str("<DATE>");
            rest = &tail[10..];
        } else {
            rest = tail;
        }
    }
    out.push_str(rest);
    out
}

fn expected(name: &str, ext: &str) -> String {
    std::fs::read_to_string(fixture_dir().join("expected").join(format!("{name}.{ext}")))
        .unwrap_or_else(|e| panic!("missing golden {name}.{ext}: {e}"))
        .replace("\r\n", "\n")
}

fn freeze(root: &Path) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_frogs"))
        .args(["errors", "freeze"])
        .current_dir(root)
        .env_remove("RUST_LOG")
        .output()
        .expect("the frogs binary should run");
    (
        output.status.code().unwrap(),
        normalize(&String::from_utf8_lossy(&output.stdout), root),
        normalize(&String::from_utf8_lossy(&output.stderr), root),
    )
}

fn assert_golden(result: &(i32, String, String), golden: &str) {
    assert_eq!(result.1, expected(golden, "stdout"), "{golden}: stdout");
    assert_eq!(result.2, expected(golden, "stderr"), "{golden}: stderr");
    assert_eq!(result.0.to_string(), expected(golden, "exitcode").trim(), "{golden}: exit code");
}

#[test]
fn freezing_one_discovered_code_then_freezing_again_prints_exactly_the_pre_refactor_text() {
    let root = freeze_project();
    assert_golden(&freeze(&root), "freeze_one");
    // the scratch file was purged to `{}`: the second run has nothing to freeze
    assert_golden(&freeze(&root), "freeze_empty");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn freeze_refuses_a_corrupt_same_day_file_through_the_binary_writing_nothing_and_purging_nothing() {
    let root = freeze_project();
    let dated = format!("discovered-{}.json", chrono::Utc::now().format("%Y-%m-%d"));
    std::fs::create_dir_all(root.join("api/config/errors")).unwrap();
    std::fs::write(root.join("api/config/errors").join(&dated), "{ corrupt").unwrap();
    let scratch_before = std::fs::read_to_string(root.join("api/config/errors.discovered.json")).unwrap();
    let (code, stdout, stderr) = freeze(&root);
    assert_ne!(code, 0, "{stdout}{stderr}");
    assert!(!stdout.contains("wrote"), "{stdout}");
    assert_eq!(
        std::fs::read_to_string(root.join("api/config/errors").join(&dated)).unwrap(),
        "{ corrupt",
        "the corrupt file is untouched"
    );
    assert_eq!(
        std::fs::read_to_string(root.join("api/config/errors.discovered.json")).unwrap(),
        scratch_before,
        "the scratch file is not purged"
    );
    let _ = std::fs::remove_dir_all(&root);
}
