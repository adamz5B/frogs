//! Acceptance tests for the Phase 3b refactor of `frogs generate`: its text output and exit codes must be
//! byte-for-byte what the pre-refactor binary printed. Fixtures and expected text live under
//! `tests/fixtures/cli_text_goldens_3b/`; the temp-dir root is normalised to `<ROOT>`.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cli_text_goldens_3b")
}

fn temp_root(label: &str) -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "frogs-gen-golden-{label}-{}-{}-{n}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn copy(from: &str, to: &Path) {
    std::fs::create_dir_all(to.parent().unwrap()).unwrap();
    std::fs::copy(fixture_dir().join(from), to).unwrap_or_else(|e| panic!("copy {from}: {e}"));
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
    text.replace("\\\\", "/").replace('\\', "/")
}

fn expected(name: &str, ext: &str) -> String {
    std::fs::read_to_string(fixture_dir().join("expected").join(format!("{name}.{ext}")))
        .unwrap_or_else(|e| panic!("missing golden {name}.{ext}: {e}"))
        .replace("\r\n", "\n")
}

fn generate(root: &Path, golden: &str) {
    let output = Command::new(env!("CARGO_BIN_EXE_frogs"))
        .arg("generate")
        .current_dir(root)
        .env_remove("RUST_LOG")
        .output()
        .expect("the frogs binary should run");
    assert_eq!(
        normalize(&String::from_utf8_lossy(&output.stdout), root),
        expected(golden, "stdout"),
        "{golden}: stdout"
    );
    assert_eq!(
        normalize(&String::from_utf8_lossy(&output.stderr), root),
        expected(golden, "stderr"),
        "{golden}: stderr"
    );
    assert_eq!(output.status.code().unwrap().to_string(), expected(golden, "exitcode").trim(), "{golden}: exit code");
}

#[test]
fn generate_on_a_fresh_project_then_unchanged_then_after_a_spec_change_prints_exactly_the_pre_refactor_text() {
    let root = temp_root("fresh");
    copy("fresh/openapi.step1.yaml", &root.join("openapi.yaml"));
    copy("fresh/index.html", &root.join("index.html"));
    generate(&root, "generate_fresh1");
    generate(&root, "generate_fresh2");
    // the spec loses an operation and gains a response field: one stub migrates, one is orphaned
    copy("fresh/openapi.step3.yaml", &root.join("openapi.yaml"));
    generate(&root, "generate_fresh3");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn generate_with_strict_openapi_and_an_unsafe_path_prints_exactly_the_pre_refactor_text_and_exits_1() {
    let root = temp_root("strict");
    copy("strict/openapi.yaml", &root.join("openapi.yaml"));
    copy("strict/server.json", &root.join("api/config/server.json"));
    generate(&root, "generate_strict");
    let _ = std::fs::remove_dir_all(&root);
}
