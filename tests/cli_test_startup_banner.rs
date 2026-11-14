//! The one acceptance test that has to keep a long-running process alive: `frogs test`'s startup notes (the
//! shadowed-case and no-test-file warnings, the route list, the scenario control-plane line) must be unchanged by the
//! Phase 3a split of `prepare_mock_router`/`build_mock_router`. Kept in its own binary so that spawning and killing a
//! server cannot interfere with the other CLI acceptance tests.

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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

fn strip_ansi(text: &str) -> String {
    let mut out = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            for next in chars.by_ref() {
                if next.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
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

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

#[test]
fn frogs_test_startup_output_is_unchanged_apart_from_line_order_between_the_two_streams() {
    let root = scratch_project("cars_test");
    let port = free_port().to_string();
    let mut child = Command::new(env!("CARGO_BIN_EXE_frogs"))
        .args(["test", "--port", &port])
        .current_dir(&root)
        .env_remove("RUST_LOG")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the frogs binary should run");
    let mut stderr = child.stderr.take().unwrap();
    let stderr_reader = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });
    let mut stdout_lines = Vec::new();
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap() == 0 {
            break;
        }
        let done = line.contains("listening on");
        stdout_lines.push(line);
        if done {
            break;
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    let stderr_text = stderr_reader.join().unwrap();

    let clean = |text: &str| -> Vec<String> {
        let text = strip_ansi(text);
        // `2026-11-13T16:00:14.744910Z  WARN ...` -> `WARN ...`
        let timestamp = |line: &str| -> String {
            match line.split_once("Z ") {
                Some((head, rest)) if head.len() > 10 && head.as_bytes()[4] == b'-' && head.as_bytes()[10] == b'T' => rest.trim_start().to_string(),
                _ => line.to_string(),
            }
        };
        let normalised = normalize(&text, &root)
            .replace(&format!("port={port}"), "port=<PORT>")
            .replace(&format!("127.0.0.1:{port}"), "127.0.0.1:<PORT>");
        let mut lines: Vec<String> = normalised.lines().map(timestamp).collect();
        lines.sort();
        lines
    };
    assert_eq!(clean(&stdout_lines.concat()), clean(&expected("test_cars", "stdout")), "frogs test: stdout lines");
    assert_eq!(
        clean(&stderr_text),
        clean(&expected("test_cars", "stderr")),
        "frogs test: stderr lines (the shadowed-case and no-test-file warnings)"
    );
    let _ = std::fs::remove_dir_all(&root);
}
