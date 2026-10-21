//! `frogs generate` against links under (and above) `datasources/endpoints/`:
//! the write guarantee must hold in every `endpointSymlinks` mode, and a
//! project with no links must behave as before. "Outside" is always a second
//! temp dir, never a folder inside the project.

use super::*;
use crate::openapi::fs_os_tests::{link_dangling_dir, link_dangling_file, link_dir, link_file};
use std::collections::BTreeMap;

struct Fx {
    root: PathBuf,
    outside: PathBuf,
    links: Vec<PathBuf>,
}

fn tempdir(label: &str) -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "frogs-gen-links-{label}-{}-{}-{n}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

impl Fx {
    fn new() -> Fx {
        Fx {
            root: tempdir("root"),
            outside: tempdir("outside"),
            links: Vec::new(),
        }
    }

    fn endpoints(&self) -> PathBuf {
        self.root.join("api/datasources/endpoints")
    }

    fn dir_link(&mut self, target: &Path, link: &Path) -> bool {
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        let ok = link_dir(target, link);
        if ok {
            self.links.push(link.to_path_buf());
        }
        ok
    }

    fn file_link(&mut self, target: &Path, link: &Path) -> bool {
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        let ok = link_file(target, link);
        if ok {
            self.links.push(link.to_path_buf());
        } else {
            eprintln!("skipping: could not create a file symlink");
        }
        ok
    }

    fn dangling_dir(&mut self, target: &Path, link: &Path) -> bool {
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        let ok = link_dangling_dir(target, link);
        if ok {
            self.links.push(link.to_path_buf());
        }
        ok
    }

    fn dangling_file(&mut self, target: &Path, link: &Path) -> bool {
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        let ok = link_dangling_file(target, link);
        if ok {
            self.links.push(link.to_path_buf());
        } else {
            eprintln!("skipping: could not create a dangling file symlink");
        }
        ok
    }

    fn configure(&self, policy: &str, strict: bool) {
        let dir = self.root.join("api/config");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("server.json"), format!(r#"{{ "endpointSymlinks": "{policy}", "strictOpenApi": {strict} }}"#)).unwrap();
    }
}

impl Drop for Fx {
    fn drop(&mut self) {
        for link in &self.links {
            if std::fs::remove_dir(link).is_err() {
                let _ = std::fs::remove_file(link);
            }
        }
        let _ = std::fs::remove_dir_all(&self.root);
        let _ = std::fs::remove_dir_all(&self.outside);
    }
}

fn spec(paths: &[&str]) -> String {
    let mut yaml = String::from("openapi: 3.1.0\ninfo: { title: t, version: 1 }\npaths:\n");
    for (n, path) in paths.iter().enumerate() {
        yaml.push_str(&format!(
            "  '{path}':\n    get:\n      operationId: op{}\n      responses:\n        '200':\n          description: ok\n          content:\n            application/json:\n              schema: {{ type: object, properties: {{ name: {{ type: string }} }} }}\n",
            n + 1
        ));
    }
    yaml
}

fn write_spec(root: &Path, paths: &[&str]) {
    std::fs::write(root.join("openapi.yaml"), spec(paths)).unwrap();
}

/// Every file under `dir`, links reported as `->` markers (never followed).
fn snapshot(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for entry in entries.flatten() {
            let path = entry.path();
            let rel = path.strip_prefix(base).unwrap().to_string_lossy().replace('\\', "/");
            let kind = entry.file_type().unwrap();
            if kind.is_symlink() {
                out.insert(rel, b"<link>".to_vec());
            } else if kind.is_dir() {
                out.insert(format!("{rel}/"), Vec::new());
                walk(base, &path, out);
            } else {
                out.insert(rel, std::fs::read(&path).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(dir, dir, &mut out);
    out
}

const MODES: [&str; 3] = ["contained", "refuse", "follow"];

// ---------------------------------------------------------------- HIGH-1: ancestors and scaffold targets

#[test]
fn an_api_folder_linked_outside_refuses_the_whole_run_in_every_mode_and_writes_nothing_outside() {
    for mode in MODES {
        let mut fx = Fx::new();
        write_spec(&fx.root, &["/cars"]);
        // The mode is only readable from the outside folder here, which is exactly the untrusted-config case.
        std::fs::create_dir_all(fx.outside.join("config")).unwrap();
        std::fs::write(fx.outside.join("config/server.json"), format!(r#"{{ "endpointSymlinks": "{mode}" }}"#)).unwrap();
        let before = snapshot(&fx.outside);
        if !fx.dir_link(&fx.outside.clone(), &fx.root.join("api")) {
            return;
        }
        let outcome = generate_api_inner(&fx.root).unwrap();
        assert!(!outcome.errors.is_empty(), "{mode}: generate must refuse");
        assert_eq!(snapshot(&fx.outside), before, "{mode}: nothing may be written through api/");
    }
}

#[test]
fn a_datasources_folder_linked_outside_refuses_the_whole_run_in_every_mode_and_writes_nothing_anywhere() {
    for mode in MODES {
        let mut fx = Fx::new();
        write_spec(&fx.root, &["/cars"]);
        fx.configure(mode, false);
        let before = snapshot(&fx.outside);
        if !fx.dir_link(&fx.outside.clone(), &fx.root.join("api/datasources")) {
            return;
        }
        let outcome = generate_api_inner(&fx.root).unwrap();
        assert!(!outcome.errors.is_empty(), "{mode}");
        assert_eq!(snapshot(&fx.outside), before, "{mode}");
        assert!(
            !fx.root.join("api/config/errors/core.json").exists(),
            "{mode}: the scaffold must not be partially written"
        );
        assert!(!fx.root.join("api/security").exists(), "{mode}");
    }
}

#[test]
fn a_components_folder_linked_outside_refuses_the_whole_run_in_every_mode_before_any_scaffold() {
    for mode in MODES {
        let mut fx = Fx::new();
        write_spec(&fx.root, &["/cars"]);
        fx.configure(mode, false);
        std::fs::create_dir_all(fx.endpoints()).unwrap();
        let before = snapshot(&fx.outside);
        if !fx.dir_link(&fx.outside.clone(), &fx.root.join("api/datasources/components")) {
            return;
        }
        let outcome = generate_api_inner(&fx.root).unwrap();
        assert!(!outcome.errors.is_empty(), "{mode}");
        assert_eq!(snapshot(&fx.outside), before, "{mode}");
        assert!(!fx.root.join("api/config/errors/core.json").exists(), "{mode}");
        assert!(!fx.endpoints().join("cars").exists(), "{mode}: no endpoint may be written either");
    }
}

#[test]
fn a_dangling_file_link_at_a_scaffold_target_refuses_everything_and_never_creates_the_outside_file() {
    let mut fx = Fx::new();
    write_spec(&fx.root, &["/cars"]);
    let victim = fx.outside.join("created-by-attack.json");
    if !fx.dangling_file(&victim, &fx.root.join("api/config/connections.json")) {
        return;
    }
    let outcome = generate_api_inner(&fx.root).unwrap();
    assert!(!outcome.errors.is_empty());
    assert!(!victim.exists(), "a dangling link must never be written through");
    assert!(!fx.root.join("api/config/server.json").exists(), "no other scaffold file may be written");
    assert!(!fx.root.join("api/security").exists());
    assert!(!fx.endpoints().exists());
}

#[test]
fn a_dangling_directory_link_at_api_security_refuses_everything_and_never_creates_the_outside_folder() {
    let mut fx = Fx::new();
    write_spec(&fx.root, &["/cars"]);
    let gone = fx.outside.join("gone");
    if !fx.dangling_dir(&gone, &fx.root.join("api/security")) {
        return;
    }
    let outcome = generate_api_inner(&fx.root).unwrap();
    assert!(!outcome.errors.is_empty());
    assert!(!gone.exists());
    assert!(!fx.root.join("api/config").exists());
}

#[test]
fn a_dangling_directory_link_at_the_components_folder_refuses_everything() {
    let mut fx = Fx::new();
    write_spec(&fx.root, &["/cars"]);
    let gone = fx.outside.join("gone");
    if !fx.dangling_dir(&gone, &fx.root.join("api/datasources/components")) {
        return;
    }
    let outcome = generate_api_inner(&fx.root).unwrap();
    assert!(!outcome.errors.is_empty());
    assert!(!gone.exists());
    assert!(!fx.root.join("api/config").exists());
}

#[test]
fn a_scaffold_target_that_is_a_live_in_project_file_link_is_refused_and_its_target_unchanged() {
    let mut fx = Fx::new();
    write_spec(&fx.root, &["/cars"]);
    let target = fx.root.join("real-connections.json");
    std::fs::write(&target, b"{\"keep\": true}").unwrap();
    if !fx.file_link(&target, &fx.root.join("api/config/connections.json")) {
        return;
    }
    let outcome = generate_api_inner(&fx.root).unwrap();
    assert!(!outcome.errors.is_empty());
    assert_eq!(std::fs::read(&target).unwrap(), b"{\"keep\": true}");
}

// ---------------------------------------------------------------- HIGH-2: x -> <root> with .git / .frogs

#[test]
fn a_link_to_the_project_root_cannot_make_generate_write_into_dot_git_or_dot_frogs_in_any_mode() {
    for mode in MODES {
        let mut fx = Fx::new();
        write_spec(&fx.root, &["/x/.git/hooks", "/x/.frogs/a"]);
        fx.configure(mode, false);
        std::fs::create_dir_all(fx.root.join(".git/hooks")).unwrap();
        std::fs::write(fx.root.join(".git/HEAD"), b"ref: refs/heads/main").unwrap();
        std::fs::create_dir_all(fx.root.join(".frogs")).unwrap();
        std::fs::write(fx.root.join(".frogs/run.json"), b"{}").unwrap();
        std::fs::create_dir_all(fx.endpoints()).unwrap();
        if !fx.dir_link(&fx.root.clone(), &fx.endpoints().join("x")) {
            return;
        }
        let git_before = snapshot(&fx.root.join(".git"));
        let frogs_before = snapshot(&fx.root.join(".frogs"));
        let outcome = generate_api_inner(&fx.root).unwrap();
        assert!(!outcome.errors.is_empty(), "{mode}");
        assert_eq!(snapshot(&fx.root.join(".git")), git_before, "{mode}: .git must be byte-identical");
        assert_eq!(snapshot(&fx.root.join(".frogs")), frogs_before, "{mode}: .frogs must be byte-identical");
    }
}

#[test]
fn orphaning_and_restoring_through_a_link_to_the_root_never_renames_anything_inside_dot_git() {
    for mode in MODES {
        let mut fx = Fx::new();
        write_spec(&fx.root, &["/x/.git/hooks"]);
        fx.configure(mode, false);
        std::fs::create_dir_all(fx.root.join(".git/hooks")).unwrap();
        // One would be restored by the spec, the other orphaned.
        std::fs::write(fx.root.join(".git/hooks/_endpoint.get.json"), b"{}").unwrap();
        std::fs::write(fx.root.join(".git/hooks/endpoint.post.json"), b"{}").unwrap();
        std::fs::create_dir_all(fx.endpoints()).unwrap();
        if !fx.dir_link(&fx.root.clone(), &fx.endpoints().join("x")) {
            return;
        }
        let before = snapshot(&fx.root.join(".git"));
        let _ = generate_api_inner(&fx.root).unwrap();
        assert_eq!(snapshot(&fx.root.join(".git")), before, "{mode}");
    }
}

// ---------------------------------------------------------------- in-project / outside endpoint links

#[test]
fn an_in_project_directory_link_is_written_through_under_contained_with_no_errors() {
    let mut fx = Fx::new();
    write_spec(&fx.root, &["/cars"]);
    std::fs::create_dir_all(fx.root.join("shared")).unwrap();
    if !fx.dir_link(&fx.root.join("shared"), &fx.endpoints().join("cars")) {
        return;
    }
    let outcome = generate_api_inner(&fx.root).unwrap();
    assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
    assert!(fx.root.join("shared/endpoint.get.json").is_file());
    assert!(fx.root.join("shared/endpoint.get.reference.json").is_file());
}

#[test]
fn an_in_project_directory_link_is_refused_under_refuse_and_its_target_stays_empty() {
    let mut fx = Fx::new();
    write_spec(&fx.root, &["/cars"]);
    fx.configure("refuse", false);
    std::fs::create_dir_all(fx.root.join("shared")).unwrap();
    if !fx.dir_link(&fx.root.join("shared"), &fx.endpoints().join("cars")) {
        return;
    }
    let outcome = generate_api_inner(&fx.root).unwrap();
    assert!(!outcome.errors.is_empty());
    assert_eq!(std::fs::read_dir(fx.root.join("shared")).unwrap().count(), 0);
}

#[test]
fn an_outside_link_fails_only_its_own_operation_in_contained_and_follow_while_other_operations_are_written() {
    for mode in ["contained", "follow"] {
        let mut fx = Fx::new();
        write_spec(&fx.root, &["/cars", "/bars"]);
        fx.configure(mode, false);
        std::fs::create_dir_all(fx.endpoints()).unwrap();
        let before = snapshot(&fx.outside);
        if !fx.dir_link(&fx.outside.clone(), &fx.endpoints().join("cars")) {
            return;
        }
        let outcome = generate_api_inner(&fx.root).unwrap();
        assert!(!outcome.errors.is_empty(), "{mode}: the cars operation must be reported");
        assert_eq!(snapshot(&fx.outside), before, "{mode}: follow mode must still never write outside");
        assert!(
            fx.endpoints().join("bars/endpoint.get.json").is_file(),
            "{mode}: the unrelated operation must still be written"
        );
    }
}

#[test]
fn an_unrelated_outside_link_is_only_a_warning_when_strict_is_off_and_nothing_is_written_outside() {
    let mut fx = Fx::new();
    write_spec(&fx.root, &["/bars"]);
    std::fs::create_dir_all(fx.endpoints()).unwrap();
    std::fs::write(fx.outside.join("endpoint.get.json"), b"{}").unwrap();
    let before = snapshot(&fx.outside);
    if !fx.dir_link(&fx.outside.clone(), &fx.endpoints().join("elsewhere")) {
        return;
    }
    let outcome = generate_api_inner(&fx.root).unwrap();
    assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
    assert!(fx.endpoints().join("bars/endpoint.get.json").is_file());
    assert_eq!(snapshot(&fx.outside), before);
}

#[test]
fn under_strict_an_outside_link_aborts_generate_before_anything_is_written() {
    let mut fx = Fx::new();
    write_spec(&fx.root, &["/bars"]);
    fx.configure("contained", true);
    std::fs::create_dir_all(fx.endpoints()).unwrap();
    let before = snapshot(&fx.outside);
    if !fx.dir_link(&fx.outside.clone(), &fx.endpoints().join("elsewhere")) {
        return;
    }
    let outcome = generate_api_inner(&fx.root).unwrap();
    assert!(outcome.strict_aborted);
    assert!(!outcome.errors.is_empty());
    assert!(!fx.endpoints().join("bars").exists(), "strict must refuse before any endpoint is written");
    assert_eq!(snapshot(&fx.outside), before);
}

// ---------------------------------------------------------------- file links

#[test]
fn a_linked_reference_file_is_an_error_and_its_target_is_never_written() {
    let mut fx = Fx::new();
    write_spec(&fx.root, &["/cars"]);
    let target = fx.root.join("ref.json");
    std::fs::write(&target, b"precious").unwrap();
    if !fx.file_link(&target, &fx.endpoints().join("cars/endpoint.get.reference.json")) {
        return;
    }
    let outcome = generate_api_inner(&fx.root).unwrap();
    assert!(!outcome.errors.is_empty());
    assert_eq!(std::fs::read(&target).unwrap(), b"precious");
}

#[test]
fn a_drifted_linked_stub_is_left_alone_with_no_error_and_its_target_is_unchanged() {
    let mut fx = Fx::new();
    write_spec(&fx.root, &["/cars"]);
    assert!(generate_api_inner(&fx.root).unwrap().errors.is_empty());
    let stub = fx.endpoints().join("cars/endpoint.get.json");
    let moved = fx.root.join("shared-stub.json");
    std::fs::rename(&stub, &moved).unwrap();
    if !fx.file_link(&moved, &stub) {
        std::fs::rename(&moved, &stub).unwrap();
        return;
    }
    let before = std::fs::read(&moved).unwrap();
    // Change the response shape so the endpoint drifts.
    let changed = spec(&["/cars"]).replace("name: { type: string }", "name: { type: string }, extra: { type: integer }");
    std::fs::write(fx.root.join("openapi.yaml"), changed).unwrap();
    let outcome = generate_api_inner(&fx.root).unwrap();
    assert!(outcome.errors.is_empty(), "a drifted linked stub is a warning, not an error: {:?}", outcome.errors);
    assert_eq!(std::fs::read(&moved).unwrap(), before, "never written through a file link");
    assert!(fs_is_link(&stub), "the link itself must still be a link");
    let reference = std::fs::read_to_string(fx.endpoints().join("cars/endpoint.get.reference.json")).unwrap();
    assert!(reference.contains("extra"), "the reference file is regenerated even though the stub is left alone");
}

fn fs_is_link(path: &Path) -> bool {
    std::fs::symlink_metadata(path).map(|m| m.file_type().is_symlink()).unwrap_or(false)
}

// ---------------------------------------------------------------- physical claims

#[test]
fn two_spec_paths_reaching_one_folder_keep_the_link_free_path_in_either_spec_order() {
    for order in [["/cars", "/vehicles"], ["/vehicles", "/cars"]] {
        let mut fx = Fx::new();
        std::fs::create_dir_all(fx.endpoints().join("cars")).unwrap();
        if !fx.dir_link(&fx.endpoints().join("cars"), &fx.endpoints().join("vehicles")) {
            return;
        }
        write_spec(&fx.root, &order);
        let outcome = generate_api_inner(&fx.root).unwrap();
        assert!(!outcome.errors.is_empty(), "{order:?}: the loser must be reported");
        let stub: Value = serde_json::from_str(&std::fs::read_to_string(fx.endpoints().join("cars/endpoint.get.json")).unwrap()).unwrap();
        let expected = if order[0] == "/cars" { "op1" } else { "op2" };
        assert_eq!(stub["operationId"], expected, "{order:?}: the real folder's own operation must win");
    }
}

// ---------------------------------------------------------------- orphan / restore under links

#[test]
fn an_orphan_under_an_in_project_link_is_renamed_through_the_link() {
    let mut fx = Fx::new();
    write_spec(&fx.root, &["/old"]);
    assert!(generate_api_inner(&fx.root).unwrap().errors.is_empty());
    std::fs::rename(fx.endpoints().join("old"), fx.root.join("shared")).unwrap();
    if !fx.dir_link(&fx.root.join("shared"), &fx.endpoints().join("old")) {
        std::fs::rename(fx.root.join("shared"), fx.endpoints().join("old")).unwrap();
        return;
    }
    write_spec(&fx.root, &["/other"]);
    let outcome = generate_api_inner(&fx.root).unwrap();
    assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
    assert!(fx.root.join("shared/_endpoint.get.json").is_file());
    assert!(!fx.root.join("shared/endpoint.get.json").exists());
}

#[test]
fn an_orphan_under_an_outside_link_followed_for_reading_is_refused_and_left_untouched() {
    let mut fx = Fx::new();
    fx.configure("follow", false);
    write_spec(&fx.root, &["/other"]);
    std::fs::write(fx.outside.join("endpoint.get.json"), b"{}").unwrap();
    std::fs::write(fx.outside.join("endpoint.get.reference.json"), b"{}").unwrap();
    std::fs::create_dir_all(fx.endpoints()).unwrap();
    let before = snapshot(&fx.outside);
    if !fx.dir_link(&fx.outside.clone(), &fx.endpoints().join("old")) {
        return;
    }
    let outcome = generate_api_inner(&fx.root).unwrap();
    assert!(!outcome.errors.is_empty(), "the refused orphan rename must be reported");
    assert_eq!(snapshot(&fx.outside), before);
}

#[test]
fn an_orphan_rename_never_overwrites_a_case_variant_destination() {
    let fx = Fx::new();
    write_spec(&fx.root, &["/other"]);
    let dir = fx.endpoints().join("old");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("endpoint.get.json"), b"{\"a\":1}").unwrap();
    std::fs::write(dir.join("_ENDPOINT.get.json"), b"{\"b\":2}").unwrap();
    let _ = generate_api_inner(&fx.root).unwrap();
    // Whatever else happened, neither file's content may have been lost.
    let mut contents: Vec<Vec<u8>> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .filter(|e| e.file_type().unwrap().is_file())
        .map(|e| std::fs::read(e.path()).unwrap())
        .collect();
    contents.sort();
    assert!(contents.contains(&b"{\"a\":1}".to_vec()));
    assert!(contents.contains(&b"{\"b\":2}".to_vec()));
}

// ---------------------------------------------------------------- no-link regression

#[test]
fn a_project_without_links_generates_the_same_files_in_every_mode_and_a_second_run_changes_nothing() {
    let mut results = Vec::new();
    for mode in MODES {
        let fx = Fx::new();
        write_spec(&fx.root, &["/cars", "/cars/{vin}"]);
        fx.configure(mode, false);
        let outcome = generate_api_inner(&fx.root).unwrap();
        assert!(outcome.errors.is_empty(), "{mode}: {:?}", outcome.errors);
        let first = snapshot(&fx.root.join("api/datasources"));
        let outcome = generate_api_inner(&fx.root).unwrap();
        assert!(outcome.errors.is_empty(), "{mode}: {:?}", outcome.errors);
        assert_eq!(snapshot(&fx.root.join("api/datasources")), first, "{mode}: re-running must be a no-op");
        results.push(first);
    }
    assert_eq!(results[0], results[1]);
    assert_eq!(results[0], results[2]);
    assert!(results[0].contains_key("endpoints/cars/endpoint.get.json"));
    assert!(results[0].contains_key("endpoints/cars/{vin}/endpoint.get.json"));
}

#[test]
fn the_scaffolded_server_json_records_the_default_endpoint_symlinks_mode() {
    let fx = Fx::new();
    write_spec(&fx.root, &["/cars"]);
    assert!(generate_api_inner(&fx.root).unwrap().errors.is_empty());
    let text = std::fs::read_to_string(fx.root.join("api/config/server.json")).unwrap();
    let value: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value["endpointSymlinks"], "contained");
}

#[test]
fn write_gate_passes_for_a_plain_project_and_names_the_failing_path_for_a_linked_ancestor() {
    let mut fx = Fx::new();
    let api = fx.root.join("api");
    std::fs::create_dir_all(api.join("datasources")).unwrap();
    assert!(write_gate(&ProjectBoundary::new(&fx.root), &api).is_ok());
    std::fs::remove_dir_all(api.join("datasources")).unwrap();
    if !fx.dir_link(&fx.outside.clone(), &api.join("datasources")) {
        return;
    }
    let err = write_gate(&ProjectBoundary::new(&fx.root), &api).unwrap_err();
    assert!(err.to_string().contains("datasources"), "{err}");
}
