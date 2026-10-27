//! Tests for the static-content deny-list (`deny.rs`) and its enforcement in
//! the static router (`serve.rs`). Fixtures are self-contained temp dirs; the
//! served tests run a real listener and talk raw HTTP to it.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use super::deny::*;
use super::serve::{Located, locate};
use super::{WebServeConfig, router};
use crate::config::ConnectionConfig;
use crate::openapi::fs_os_tests::{link_dir, link_file};
use crate::server::{mount_under, raw_request, spawn_served};

static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// `<tmp>/.frogs-deny-test-.../site`: the project root sits inside a
/// dot-named parent so any rule wrongly applied to components above the root
/// would deny the whole site. Returned canonical.
fn temp_root() -> PathBuf {
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let parent = std::env::temp_dir().join(format!(
        ".frogs-deny-test-{}-{}-{n}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    let root = parent.join("site");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::canonicalize(&root).unwrap()
}

fn list_for(root: &Path, protected: &ProtectedPaths) -> DenyList {
    DenyList::new(root, root, false, protected)
}

fn plain_list(root: &Path) -> DenyList {
    list_for(root, &ProtectedPaths::default())
}

fn connection(database: &str) -> HashMap<String, ConnectionConfig> {
    let mut settings = HashMap::new();
    settings.insert("database".to_string(), serde_json::Value::String(database.to_string()));
    let mut map = HashMap::new();
    map.insert(
        "main".to_string(),
        ConnectionConfig {
            driver: "sqlite".to_string(),
            settings,
        },
    );
    map
}

// ---------------------------------------------------------------- A. unit

#[test]
fn the_lexical_layer_allows_ordinary_site_files_and_near_misses_of_reserved_names() {
    let root = temp_root();
    let list = plain_list(&root);
    for allowed in [
        "index.html",
        "css/style.css",
        "apis/x",
        "api.html",
        "sub/api/x",
        "sub/openapi.yaml",
        "openapi.yaml.bak",
        "./index.html",
        "a//b.css",
    ] {
        assert_eq!(list.request_verdict(allowed), None, "{allowed} must be servable");
    }
}

#[test]
fn the_lexical_layer_denies_every_reserved_or_platform_unsafe_spelling() {
    let root = temp_root();
    let list = plain_list(&root);
    for denied in [
        "api/x",
        "API/x",
        "Api/x",
        "openapi.yaml",
        "OPENAPI.YAML",
        "WebServe.json",
        ".frogs/run.json",
        ".git/config",
        ".env",
        "a/.hidden/x",
        "..",
        "a/../b",
        "_BACKUPS",
        "x/_bac\u{212A}ups/y",
        "ap\u{131}/config",
        "api.",
        "api ",
        "openapi.yaml.",
        "openapi.yaml::$DATA",
        "api:stream",
        "C:x",
        "api\\config\\connections.json",
        "a<b",
        "a|b",
        "a?b",
        "a*b",
        "a\"b",
        "a\u{0}b",
        "a\u{1}b",
        "a\u{7f}b",
        "API~1/config",
        "OPENAP~1.YAM",
        "con.html",
        "NUL",
    ] {
        assert!(list.request_verdict(denied).is_some(), "{denied:?} must be denied");
    }
}

#[test]
fn deny_reasons_distinguish_dot_backups_reserved_root_and_unsafe_segments() {
    let root = temp_root();
    let list = plain_list(&root);
    assert_eq!(list.request_verdict(".env"), Some(DenyReason::DotSegment));
    assert_eq!(list.request_verdict("css/_Backups/x"), Some(DenyReason::Backups));
    assert_eq!(list.request_verdict("API/x"), Some(DenyReason::ReservedRootName));
    assert_eq!(list.request_verdict("a:b"), Some(DenyReason::UnsafeSegment));
}

#[test]
fn reserved_root_names_are_only_reserved_as_the_first_segment_but_backups_and_dots_anywhere() {
    let root = temp_root();
    let list = plain_list(&root);
    assert_eq!(list.request_verdict("docs/api/x.html"), None);
    assert_eq!(list.request_verdict("docs/webserve.json"), None);
    assert!(list.request_verdict("docs/_backups/x.html").is_some());
    assert!(list.request_verdict("docs/.well-known/x").is_some());
}

#[test]
fn a_project_under_a_dot_named_parent_still_serves_ordinary_files() {
    let root = temp_root();
    assert!(root.parent().unwrap().file_name().unwrap().to_string_lossy().starts_with('.'));
    std::fs::write(root.join("index.html"), "ok").unwrap();
    let list = plain_list(&root);
    let canonical = std::fs::canonicalize(root.join("index.html")).unwrap();
    assert_eq!(list.canonical_verdict(&canonical), None);
    assert!(matches!(locate(&root, &root, &list, "index.html"), Located::File(_)));
}

#[test]
fn the_canonical_layer_denies_resolved_paths_under_reserved_names_and_fails_closed_outside_the_root() {
    let root = temp_root();
    let list = plain_list(&root);
    assert_eq!(
        list.canonical_verdict(&root.join("api").join("config").join("x.json")),
        Some(DenyReason::ReservedRootName)
    );
    assert_eq!(list.canonical_verdict(&root.join("OpenAPI.yaml")), Some(DenyReason::ReservedRootName));
    assert_eq!(list.canonical_verdict(&root.join("a").join(".hidden")), Some(DenyReason::DotSegment));
    assert_eq!(list.canonical_verdict(&root.join("a").join("_backups").join("x")), Some(DenyReason::Backups));
    assert_eq!(list.canonical_verdict(&root.join("css").join("style.css")), None);
    let outside = temp_root();
    assert_eq!(list.canonical_verdict(&outside.join("x.txt")), Some(DenyReason::Protected));
}

#[test]
fn the_canonical_layer_applies_dot_rules_only_below_the_root_not_to_the_dot_named_parent() {
    let root = temp_root();
    let list = plain_list(&root);
    assert_eq!(list.canonical_verdict(&root.join("ok.txt")), None);
}

#[test]
fn sqlite_target_recognises_memory_temp_and_plain_forms() {
    assert_eq!(sqlite_target(":memory:"), SqliteTarget::Memory);
    assert_eq!(sqlite_target(""), SqliteTarget::Temp);
    assert_eq!(sqlite_target("file::memory:"), SqliteTarget::Memory);
    assert_eq!(sqlite_target("file:x.db?mode=memory"), SqliteTarget::Path(PathBuf::from("x.db")));
    assert_eq!(sqlite_target("file:x.db?cache=shared&vfs=memdb"), SqliteTarget::Path(PathBuf::from("x.db")));
    assert_eq!(sqlite_target("file:"), SqliteTarget::Temp);
    assert_eq!(sqlite_target("data.db"), SqliteTarget::Path(PathBuf::from("data.db")));
    assert_eq!(sqlite_target("file:data.db?mode=rwc"), SqliteTarget::Path(PathBuf::from("data.db")));
    assert_eq!(sqlite_target("file:data.db#frag"), SqliteTarget::Path(PathBuf::from("data.db")));
}

#[test]
fn sqlite_matches_the_file_prefix_case_sensitively_so_an_uppercase_prefix_is_a_literal_path() {
    assert_eq!(sqlite_target("FILE:x.db?vfs=memdb"), SqliteTarget::Path(PathBuf::from("FILE:x.db?vfs=memdb")));
    assert_eq!(sqlite_target("File:x.db"), SqliteTarget::Path(PathBuf::from("File:x.db")));
}

#[test]
fn sqlite_memory_requires_an_exact_query_pair_never_a_substring() {
    assert_eq!(sqlite_target("file:x.db?xmode=memoryy"), SqliteTarget::Path(PathBuf::from("x.db")));
    assert_eq!(sqlite_target("file:x.db?mode=memory2"), SqliteTarget::Path(PathBuf::from("x.db")));
    assert_eq!(sqlite_target("file:x.db?mode=rwc&xvfs=memdb"), SqliteTarget::Path(PathBuf::from("x.db")));
    assert_eq!(sqlite_target("file:x.db?vfs=memdbx"), SqliteTarget::Path(PathBuf::from("x.db")));
    assert_eq!(sqlite_target("file:x.db?a=b&mode=memory"), SqliteTarget::Path(PathBuf::from("x.db")));
    assert_eq!(sqlite_target("file:data.db?mode=memory&mode=rwc"), SqliteTarget::Path(PathBuf::from("data.db")));
}

#[test]
fn sqlite_uri_paths_are_percent_decoded_and_authority_is_validated() {
    assert_eq!(sqlite_target("file:///abs/da%74a.db"), SqliteTarget::Path(PathBuf::from("/abs/data.db")));
    assert_eq!(sqlite_target("file://localhost/abs/x.db"), SqliteTarget::Path(PathBuf::from("/abs/x.db")));
    assert_eq!(sqlite_target("file://evil/x"), SqliteTarget::Unrecognized);
    assert_eq!(sqlite_target("file:a%00b.db"), SqliteTarget::Unrecognized);
    assert_eq!(sqlite_target("file:%ff%fe.db"), SqliteTarget::Unrecognized);
}

#[cfg(windows)]
#[test]
fn sqlite_windows_drive_letter_uri_loses_its_leading_slash() {
    assert_eq!(sqlite_target("file:///C:/x/y.db"), SqliteTarget::Path(PathBuf::from("C:/x/y.db")));
}

#[cfg(not(windows))]
#[test]
fn sqlite_non_windows_drive_letter_uri_keeps_its_leading_slash() {
    assert_eq!(sqlite_target("file:///C:/x/y.db"), SqliteTarget::Path(PathBuf::from("/C:/x/y.db")));
}

#[test]
fn a_sqlite_database_file_and_every_dash_sibling_are_denied_but_lookalikes_are_not() {
    let root = temp_root();
    let mut protected = ProtectedPaths::default();
    protected.add_sqlite(&connection(&root.join("data.db").to_string_lossy()), &root);
    let list = list_for(&root, &protected);
    for denied in ["data.db", "DATA.DB", "data.db-wal", "data.db-shm", "data.db-journal", "data.db-mj1234", "Data.Db-WAL"] {
        assert_eq!(list.request_verdict(denied), Some(DenyReason::Protected), "{denied}");
    }
    for allowed in ["data.dbx", "data.db.html", "data.html", "sub/data.db"] {
        assert_eq!(list.request_verdict(allowed), None, "{allowed}");
    }
}

#[test]
fn a_relative_sqlite_path_is_also_protected_against_the_project_root() {
    let root = temp_root();
    let mut protected = ProtectedPaths::default();
    protected.add_sqlite(&connection("db/app.sqlite"), &root);
    let list = list_for(&root, &protected);
    assert_eq!(list.request_verdict("db/app.sqlite"), Some(DenyReason::Protected));
    assert_eq!(list.request_verdict("db/app.sqlite-wal"), Some(DenyReason::Protected));
}

#[test]
fn memory_temp_and_non_sqlite_connections_protect_nothing() {
    let root = temp_root();
    let mut protected = ProtectedPaths::default();
    protected.add_sqlite(&connection(":memory:"), &root);
    protected.add_sqlite(&connection(""), &root);
    protected.add_sqlite(&connection("file::memory:"), &root);
    let mut pg = connection("x.db");
    pg.get_mut("main").unwrap().driver = "postgres".to_string();
    protected.add_sqlite(&pg, &root);
    let list = list_for(&root, &protected);
    assert!(list.problems().is_empty());
    assert_eq!(list.request_verdict("x.db"), None);
    assert_eq!(list.request_verdict("data.db"), None);
}

#[test]
fn an_unrecognized_sqlite_uri_is_denied_by_its_literal_spelling_with_a_problem() {
    let root = temp_root();
    let mut protected = ProtectedPaths::default();
    protected.add_sqlite(&connection("file://evil/x.db"), &root);
    let list = list_for(&root, &protected);
    assert_eq!(list.problems().len(), 1, "{:?}", list.problems());
    assert!(list.problems()[0].contains("connections.main.database"));
    assert!(list.problems()[0].contains("could not be resolved; it is denied by its literal spelling only"));
}

#[test]
fn tls_files_are_protected_whatever_the_mode_including_ca_and_every_crl() {
    let root = temp_root();
    let tls: crate::config::TlsConfig = serde_json::from_str(
        r#"{ "mode": "off", "manual": { "certPath": "tls/cert.pem", "keyPath": "tls/key.pem" },
             "clientAuth": { "mode": "required", "caPath": "tls/ca.pem", "crlPaths": ["tls/a.crl", "tls/b.crl"] } }"#,
    )
    .unwrap();
    let mut protected = ProtectedPaths::default();
    protected.add_tls(&tls, &root);
    let list = list_for(&root, &protected);
    for denied in ["tls/cert.pem", "tls/key.pem", "TLS/CA.PEM", "tls/a.crl", "tls/b.crl"] {
        assert_eq!(list.request_verdict(denied), Some(DenyReason::Protected), "{denied}");
    }
    assert_eq!(list.request_verdict("tls/other.txt"), None);
}

#[test]
fn a_protected_directory_denies_itself_and_everything_beneath_it() {
    let root = temp_root();
    let mut protected = ProtectedPaths::default();
    protected.add_dir("logging.directory", &root.join("runtime-logs"));
    let list = list_for(&root, &protected);
    assert_eq!(list.request_verdict("runtime-logs"), Some(DenyReason::Protected));
    assert_eq!(list.request_verdict("RUNTIME-LOGS/frogs.log.2026-10-26"), Some(DenyReason::Protected));
    assert_eq!(list.request_verdict("runtime-logs-other/x"), None);
}

fn expected_in(root: &Path, tail: &[&str]) -> Vec<String> {
    let mut components = fold_components(root);
    components.extend(tail.iter().map(|s| s.to_string()));
    components
}

fn forms_of(placement: Placement) -> Vec<Vec<String>> {
    match placement {
        Placement::Inside(forms) => forms,
        other => panic!("expected Inside, got {other:?}"),
    }
}

#[test]
fn place_treats_a_differently_cased_spelling_of_the_root_as_inside() {
    let root = temp_root();
    let root_folded = fold_components(&root);
    let upper = PathBuf::from(root.to_string_lossy().to_uppercase()).join("logs");
    let forms = forms_of(place(&upper, &root_folded));
    assert!(forms.contains(&expected_in(&root, &["logs"])), "{forms:?}");
}

#[test]
fn place_resolves_dot_dot_segments_regardless_of_whether_the_intermediate_folders_exist() {
    let root = temp_root();
    let root_folded = fold_components(&root);

    let forms = forms_of(place(&root.join("api").join("../logs"), &root_folded));
    assert!(forms.contains(&expected_in(&root, &["logs"])), "{forms:?}");

    let rootname = root.file_name().unwrap().to_string_lossy().to_string();
    let reentry = root.join("api").join("..").join("..").join(&rootname).join("logs");
    let forms = forms_of(place(&reentry, &root_folded));
    assert!(forms.contains(&expected_in(&root, &["logs"])), "{forms:?}");

    let forms = forms_of(place(&root.join("x").join("..").join("y"), &root_folded));
    assert!(forms.contains(&expected_in(&root, &["y"])), "{forms:?}");
}

#[test]
fn place_follows_a_symlinked_root_in_either_direction() {
    let real = temp_root();
    let link_parent = temp_root();
    let link = link_parent.join("via-link");
    if !link_dir(&real, &link) {
        return;
    }
    let canonical_root_folded = fold_components(&std::fs::canonicalize(&link).unwrap());
    let through_link = forms_of(place(&link.join("logs"), &canonical_root_folded));
    assert!(through_link.contains(&expected_in(&real, &["logs"])), "{through_link:?}");
    let through_real = forms_of(place(&real.join("logs"), &canonical_root_folded));
    assert!(through_real.contains(&expected_in(&real, &["logs"])), "{through_real:?}");
}

#[test]
fn a_nonexistent_path_outside_the_root_with_an_existing_ancestor_is_dropped_silently() {
    let root = temp_root();
    let other = temp_root();
    let mut protected = ProtectedPaths::default();
    protected.add_path("tls.manual.keyPath", &root, &other.join("nope").join("key.pem").to_string_lossy());
    let list = list_for(&root, &protected);
    assert!(list.problems().is_empty(), "{:?}", list.problems());
    assert!(list.warnings().is_empty());
    assert_eq!(list.request_verdict("nope/key.pem"), None);
    assert_eq!(list.request_verdict("key.pem"), None);
}

#[cfg(windows)]
#[test]
fn a_path_on_a_nonexistent_drive_is_uncertain_and_reported() {
    let root = temp_root();
    let Some(letter) = ('D'..='Z').rev().find(|l| !Path::new(&format!("{l}:\\")).exists()) else {
        return;
    };
    let bogus = PathBuf::from(format!("{letter}:\\nowhere\\key.pem"));
    assert!(matches!(place(&bogus, &fold_components(&root)), Placement::Uncertain(_)));
    let mut protected = ProtectedPaths::default();
    protected.add_path("tls.manual.keyPath", &root, &bogus.to_string_lossy());
    let list = list_for(&root, &protected);
    assert_eq!(list.problems().len(), 1, "{:?}", list.problems());
    assert!(list.problems()[0].contains("tls.manual.keyPath="));
    assert!(list.problems()[0].contains("could not be resolved"));
}

#[test]
fn an_empty_protected_path_value_is_reported_as_unresolvable() {
    let root = temp_root();
    let mut protected = ProtectedPaths::default();
    protected.add_path("tls.manual.certPath", &root, "");
    let list = list_for(&root, &protected);
    assert_eq!(list.problems().len(), 1, "{:?}", list.problems());
    assert!(list.problems()[0].contains("protected path tls.manual.certPath= could not be resolved; it is denied by its literal spelling only"));
}

#[test]
fn a_root_that_could_not_be_canonicalised_is_a_problem_and_outside_paths_become_uncertain() {
    let root = temp_root();
    let other = temp_root();
    let mut protected = ProtectedPaths::default();
    protected.add_path("tls.manual.keyPath", &root, "tls/key.pem");
    protected.add_path("tls.manual.certPath", &root, &other.join("c.pem").to_string_lossy());
    let list = DenyList::new(&root, &root, true, &protected);
    assert!(
        list.problems().iter().any(|p| p.contains("the project root could not be canonicalised")),
        "{:?}",
        list.problems()
    );
    assert!(
        list.problems()
            .iter()
            .any(|p| p.contains("tls.manual.certPath=") && p.contains("could not be resolved")),
        "{:?}",
        list.problems()
    );
    assert_eq!(list.request_verdict("tls/key.pem"), Some(DenyReason::Protected));
}

#[test]
fn a_protected_path_with_non_ascii_components_is_protected_under_composed_and_decomposed_spellings() {
    let root = temp_root();
    let mut protected = ProtectedPaths::default();
    protected.add_path("tls.manual.keyPath", &root, "s\u{e9}cret/key.pem");
    let list = list_for(&root, &protected);
    assert!(
        list.warnings().is_empty() && list.problems().is_empty(),
        "{:?} {:?}",
        list.warnings(),
        list.problems()
    );
    assert_eq!(list.request_verdict("s\u{e9}cret/key.pem"), Some(DenyReason::Protected));
    assert_eq!(
        list.request_verdict("se\u{301}cret/key.pem"),
        Some(DenyReason::Protected),
        "the decomposed spelling folds to the same name"
    );
    assert_eq!(list.request_verdict("S\u{c9}CRET/key.pem"), Some(DenyReason::Protected));
}

#[test]
fn a_protected_directory_equal_to_the_root_denies_the_whole_site_and_says_so() {
    let root = temp_root();
    let mut protected = ProtectedPaths::default();
    protected.add_dir("logging.directory", &root);
    let list = list_for(&root, &protected);
    assert!(
        list.problems()
            .iter()
            .any(|p| p.contains("is the project root itself; the whole site would be denied")),
        "{:?}",
        list.problems()
    );
    assert_eq!(list.request_verdict("index.html"), Some(DenyReason::Protected));
    assert_eq!(list.request_verdict("css/style.css"), Some(DenyReason::Protected));
}

#[test]
fn a_log_directory_reached_through_dot_dot_that_equals_the_root_is_the_root_itself() {
    let root = temp_root();
    let mut protected = ProtectedPaths::default();
    protected.add_path("logging.directory", &root.join("api"), "..");
    let list = list_for(&root, &protected);
    assert!(list.problems().iter().any(|p| p.contains("the project root itself")), "{:?}", list.problems());
}

#[cfg(windows)]
#[test]
fn fold_components_treats_plain_and_verbatim_drive_prefixes_as_equal() {
    let plain = fold_components(Path::new("C:\\Users\\x"));
    let verbatim = fold_components(Path::new("\\\\?\\C:\\Users\\x"));
    assert_eq!(plain, verbatim);
    assert_eq!(fold_components(Path::new("c:\\USERS\\X")), plain);
}

/// Best effort: skipped when the host has 8.3 short names disabled.
#[cfg(windows)]
#[test]
fn place_matches_a_protected_path_spelled_through_the_roots_8_3_short_name() {
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let long_name = std::env::temp_dir().join(format!("frogs-deny-short-name-test-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&long_name).unwrap();
    let canonical = std::fs::canonicalize(&long_name).unwrap();
    let plain = canonical.to_string_lossy().trim_start_matches("\\\\?\\").to_string();
    use std::os::windows::process::CommandExt;
    let output = std::process::Command::new("cmd")
        .raw_arg(format!("/C for %I in (\"{plain}\") do @echo %~sI"))
        .output();
    let Ok(output) = output else { return };
    let short = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if short.is_empty() || short.eq_ignore_ascii_case(&plain) {
        eprintln!("skipping: 8.3 short names are unavailable");
        return;
    }
    eprintln!("short name resolved as {short:?} for {plain:?}");
    let forms = forms_of(place(&PathBuf::from(&short).join("logs"), &fold_components(&canonical)));
    assert!(forms.contains(&expected_in(&canonical, &["logs"])), "{forms:?}");
}

#[test]
fn page_problems_flags_a_denied_start_page_and_not_found_page_once_each() {
    let root = temp_root();
    std::fs::write(root.join("index.html"), "x").unwrap();
    let config = WebServeConfig {
        allow_dot_paths: Vec::new(),
        start_page: "api/config/connections.json".to_string(),
        port: 8080,
        not_found_page: Some(".frogs/run.json".to_string()),
        tls: Default::default(),
    };
    let (problems, warnings) = page_problems(&root, &config, &ProtectedPaths::default());
    assert_eq!(problems.len(), 2, "{problems:?}");
    assert!(problems[0].starts_with("startPage "), "{problems:?}");
    assert!(problems[1].starts_with("notFoundPage "), "{problems:?}");
    assert!(problems.iter().all(|p| p.contains("is never served")));
    assert!(warnings.is_empty());
}

#[test]
fn page_problems_is_silent_for_servable_pages() {
    let root = temp_root();
    std::fs::write(root.join("index.html"), "x").unwrap();
    std::fs::write(root.join("404.html"), "x").unwrap();
    let config = WebServeConfig {
        allow_dot_paths: Vec::new(),
        start_page: "index.html".to_string(),
        port: 8080,
        not_found_page: Some("404.html".to_string()),
        tls: Default::default(),
    };
    let (problems, warnings) = page_problems(&root, &config, &ProtectedPaths::default());
    assert!(problems.is_empty() && warnings.is_empty(), "{problems:?} {warnings:?}");
}

#[test]
fn page_problems_counts_a_start_page_naming_the_webserve_json_tls_key() {
    let root = temp_root();
    let config = WebServeConfig {
        allow_dot_paths: Vec::new(),
        start_page: "key.pem".to_string(),
        port: 8080,
        not_found_page: None,
        tls: serde_json::from_str(r#"{ "mode": "manual", "manual": { "certPath": "cert.pem", "keyPath": "key.pem" } }"#).unwrap(),
    };
    let (problems, _) = page_problems(&root, &config, &ProtectedPaths::default());
    assert_eq!(problems.len(), 1, "{problems:?}");
}

#[test]
fn lexically_denied_reports_without_touching_the_filesystem() {
    let root = temp_root();
    assert!(lexically_denied(&root, ".hidden.html").is_some());
    assert!(lexically_denied(&root, "openapi.yaml").is_some());
    assert_eq!(lexically_denied(&root, "index.html"), None);
}

// ---------------------------------------------------------------- B. served

const NOT_FOUND_PAGE: &str = "<html>custom not found</html>";

/// Every file carries a unique `SECRET-<n>` marker so any leak is detectable.
fn fixture() -> PathBuf {
    let root = temp_root();
    let files: &[(&str, bool)] = &[
        ("openapi.yaml", true),
        ("webserve.json", true),
        ("api/config/connections.json", true),
        ("api/config/server.json", true),
        ("api/config/secret.txt", true),
        ("api/security/schemes.json", true),
        ("api/datasources/endpoints/ping/endpoint.get.json", true),
        ("api/datasources/endpoints/ping/_backups/endpoint.get.json", true),
        (".frogs/run.json", true),
        (".frogs/service.json", true),
        (".git/config", true),
        (".env", true),
        (".well-known/security.txt", true),
        ("runtime-logs/frogs.log.2026-10-26", true),
        ("tls/server.key", true),
        ("data.db", true),
        ("css/_backups/x.css", true),
        ("sub/openapi.yaml", false),
        ("index.html", false),
        ("css/style.css", false),
        ("pages/index.html", false),
    ];
    for (i, (relative, secret)) in files.iter().enumerate() {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let contents = if *secret { format!("SECRET-{i}") } else { format!("public-{i}") };
        std::fs::write(path, contents).unwrap();
    }
    std::fs::write(root.join("404.html"), NOT_FOUND_PAGE).unwrap();
    root
}

fn protected_for(root: &Path) -> ProtectedPaths {
    let mut protected = ProtectedPaths::default();
    protected.add_path("tls.manual.keyPath", root, "tls/server.key");
    protected.add_dir("logging.directory", &root.join("runtime-logs"));
    protected.add_sqlite(&connection(&root.join("data.db").to_string_lossy()), root);
    protected
}

fn config_for(start_page: &str, not_found: Option<&str>) -> WebServeConfig {
    WebServeConfig {
        allow_dot_paths: Vec::new(),
        start_page: start_page.to_string(),
        port: 8080,
        not_found_page: not_found.map(str::to_string),
        tls: Default::default(),
    }
}

async fn serve_site(root: &Path, api_root: Option<&str>, start_page: &str, not_found: Option<&str>, protected: ProtectedPaths) -> SocketAddr {
    let web = router(root.to_path_buf(), config_for(start_page, not_found), protected);
    let app = match api_root {
        None => web,
        Some(prefix) => mount_under(crate::server::router(), prefix).merge(web),
    };
    spawn_served(app, false).await
}

#[derive(Debug, PartialEq, Eq)]
struct Reply {
    status_line: String,
    content_type: Option<String>,
    content_length: Option<String>,
    etag: Option<String>,
    last_modified: Option<String>,
    body: Vec<u8>,
}

async fn send(addr: SocketAddr, method: &str, target: &str) -> Reply {
    let extra = if method == "POST" { "Content-Length: 0\r\n" } else { "" };
    let request = format!("{method} {target} HTTP/1.1\r\nHost: localhost\r\n{extra}Connection: close\r\n\r\n");
    let (status_line, headers, body, _) = raw_request(addr, request.as_bytes()).await;
    let header = |name: &str| headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone());
    Reply {
        status_line,
        content_type: header("content-type"),
        content_length: header("content-length"),
        etag: header("etag"),
        last_modified: header("last-modified"),
        body,
    }
}

async fn assert_denied_like_missing(addr: SocketAddr, target: &str, missing: &Reply) {
    let reply = send(addr, "GET", target).await;
    assert!(reply.status_line.contains(" 404"), "{target}: {}", reply.status_line);
    assert!(!String::from_utf8_lossy(&reply.body).contains("SECRET-"), "{target} leaked content");
    assert_eq!(&reply, missing, "{target} must be indistinguishable from a missing file");
}

const DENIED_TARGETS: &[&str] = &[
    "/api/config/connections.json",
    "/api/config/server.json",
    "/api/config/secret.txt",
    "/api/security/schemes.json",
    "/api/datasources/endpoints/ping/endpoint.get.json",
    "/api/datasources/endpoints/ping/_backups/endpoint.get.json",
    "/openapi.yaml",
    "/.frogs/run.json",
    "/.frogs/service.json",
    "/webserve.json",
    "/API/config/connections.json",
    "/Api/config/connections.json",
    "/OPENAPI.YAML",
    "/.FROGS/run.json",
    "/%61pi/config/connections.json",
    "/api%2Fconfig%2Fconnections.json",
    "/api%2fconfig/connections.json",
    "/%2Efrogs/run.json",
    "/api%5Cconfig%5Cconnections.json",
    "/openapi.yaml.",
    "/openapi.yaml%20",
    "/api./config/connections.json",
    "/openapi.yaml::$DATA",
    "/openapi.yaml%3A%3A%24DATA",
    "/api:stream",
    "/API~1/config/connections.json",
    "/OPENAP~1.YAM",
    "/ap%C4%B1/config/connections.json",
    "/_bac%E2%84%AAups/x",
    "/css/_backups/x.css",
    "/css/../api/config/connections.json",
    "/.git/config",
    "/.env",
    "/.well-known/security.txt",
    "/runtime-logs/frogs.log.2026-10-26",
    "/tls/server.key",
    "/TLS/SERVER.KEY",
    "/data.db",
    "/DATA.DB",
    "/data.db-wal",
    "/data.db-journal",
];

#[tokio::test]
async fn every_denied_spelling_is_indistinguishable_from_a_missing_file_on_every_listener_shape() {
    for api_root in [None, Some(""), Some("/api")] {
        for not_found in [None, Some("404.html")] {
            let root = fixture();
            let addr = serve_site(&root, api_root, "index.html", not_found, protected_for(&root)).await;
            // Created after the router exists: must still be denied.
            std::fs::write(root.join("data.db-wal"), "SECRET-wal").unwrap();
            std::fs::write(root.join("data.db-journal"), "SECRET-journal").unwrap();

            let missing = send(addr, "GET", "/definitely-missing.html").await;
            assert!(missing.status_line.contains(" 404"), "{missing:?}");
            if not_found.is_some() {
                assert_eq!(missing.body, NOT_FOUND_PAGE.as_bytes());
            } else {
                assert_eq!(missing.body, b"404 Not Found");
            }

            for target in DENIED_TARGETS {
                assert_denied_like_missing(addr, target, &missing).await;
            }
        }
    }
}

#[tokio::test]
async fn head_and_post_on_denied_paths_match_head_and_post_on_missing_ones() {
    let root = fixture();
    let addr = serve_site(&root, None, "index.html", None, protected_for(&root)).await;
    for target in ["/api/config/connections.json", "/openapi.yaml", "/.env", "/tls/server.key"] {
        let denied_head = send(addr, "HEAD", target).await;
        let missing_head = send(addr, "HEAD", "/definitely-missing.html").await;
        assert!(denied_head.status_line.contains(" 404"), "{target}: {}", denied_head.status_line);
        assert_eq!(denied_head, missing_head, "{target}");
        assert!(denied_head.body.is_empty());

        let denied_post = send(addr, "POST", target).await;
        let missing_post = send(addr, "POST", "/definitely-missing.html").await;
        assert!(denied_post.status_line.contains(" 405"), "{target}: {}", denied_post.status_line);
        assert_eq!(denied_post, missing_post, "{target}");
    }
}

#[tokio::test]
async fn ordinary_site_files_are_still_served_and_a_bare_directory_is_still_404() {
    let root = fixture();
    let addr = serve_site(&root, None, "index.html", None, protected_for(&root)).await;
    for target in ["/", "/index.html", "/css/style.css", "/sub/openapi.yaml"] {
        let reply = send(addr, "GET", target).await;
        assert!(reply.status_line.contains(" 200"), "{target}: {}", reply.status_line);
        assert!(String::from_utf8_lossy(&reply.body).starts_with("public-"), "{target}");
    }
    assert!(send(addr, "GET", "/css").await.status_line.contains(" 404"));
}

#[tokio::test]
async fn links_inside_the_site_that_resolve_into_protected_places_are_denied_like_missing_files() {
    let root = fixture();
    let mut links: Vec<(&str, String)> = Vec::new();
    if link_dir(&root.join("api"), &root.join("assets")) {
        links.push(("assets", "/assets/config/connections.json".to_string()));
    }
    if link_dir(&root.join(".frogs"), &root.join("pub")) {
        links.push(("pub", "/pub/run.json".to_string()));
    }
    if link_dir(&root.join("runtime-logs"), &root.join("logview")) {
        links.push(("logview", "/logview/frogs.log.2026-10-26".to_string()));
    }
    if link_file(&root.join("tls").join("server.key"), &root.join("key.txt")) {
        links.push(("key.txt", "/key.txt".to_string()));
    }
    if link_file(&root.join("webserve.json"), &root.join("ws.json")) {
        links.push(("ws.json", "/ws.json".to_string()));
    }
    if links.is_empty() {
        eprintln!("skipping: could not create any link");
        return;
    }
    let addr = serve_site(&root, None, "index.html", None, protected_for(&root)).await;
    let missing = send(addr, "GET", "/definitely-missing.html").await;
    for (name, target) in &links {
        eprintln!("checking link {name}");
        assert_denied_like_missing(addr, target, &missing).await;
    }
}

/// Best effort (meaningful on Windows, where a different-case spelling of a
/// link name resolves): the log directory is configured through a link made
/// before startup, and requested by its real name and link name in other case.
#[tokio::test]
async fn a_log_directory_configured_through_a_link_is_denied_under_every_case_spelling() {
    let root = fixture();
    let link = root.join("logs-link");
    if !link_dir(&root.join("runtime-logs"), &link) {
        eprintln!("skipping: could not create a link");
        return;
    }
    let mut protected = ProtectedPaths::default();
    protected.add_dir("logging.directory", &link);
    let addr = serve_site(&root, None, "index.html", None, protected).await;
    let missing = send(addr, "GET", "/definitely-missing.html").await;
    for target in [
        "/runtime-logs/frogs.log.2026-10-26",
        "/RUNTIME-LOGS/frogs.log.2026-10-26",
        "/Runtime-Logs/FROGS.LOG.2026-10-26",
        "/logs-link/frogs.log.2026-10-26",
        "/LOGS-LINK/frogs.log.2026-10-26",
        "/Logs-Link/Frogs.Log.2026-10-26",
    ] {
        assert_denied_like_missing(addr, target, &missing).await;
    }
}

#[tokio::test]
async fn a_start_page_naming_a_denied_file_makes_the_root_url_an_ordinary_404() {
    let root = fixture();
    let assets_linked = link_dir(&root.join("api"), &root.join("assets"));
    let mut start_pages = vec!["api/config/connections.json", "API/config/connections.json", "pages\\index.html", ".env"];
    if assets_linked {
        start_pages.push("assets/config/connections.json");
    }
    for start_page in start_pages {
        let addr = serve_site(&root, None, start_page, None, protected_for(&root)).await;
        let missing = send(addr, "GET", "/definitely-missing.html").await;
        assert_denied_like_missing(addr, "/", &missing).await;
    }
}

#[tokio::test]
async fn a_denied_not_found_page_falls_back_to_the_generic_404_for_missing_paths() {
    let root = fixture();
    for not_found in [".frogs/run.json", "api/config/secret.txt", "pages\\index.html"] {
        let addr = serve_site(&root, None, "index.html", Some(not_found), protected_for(&root)).await;
        let reply = send(addr, "GET", "/definitely-missing.html").await;
        assert!(reply.status_line.contains(" 404"), "{not_found}: {}", reply.status_line);
        assert_eq!(reply.body, b"404 Not Found", "{not_found}");
        assert_eq!(reply.content_type.as_deref(), Some("text/plain; charset=utf-8"));
        let denied = send(addr, "GET", "/api/config/secret.txt").await;
        assert_eq!(denied, reply, "{not_found}");
    }
}

// ------------------------------------------------- allowDotPaths (.well-known)

fn list_allowing(root: &Path, entries: &[&str]) -> DenyList {
    let mut list = plain_list(root);
    list.set_dot_allow(&entries.iter().map(|e| e.to_string()).collect::<Vec<_>>());
    list
}

#[test]
fn an_allow_entry_exempts_only_its_own_segments_from_the_dot_rule() {
    let root = temp_root();
    let list = list_allowing(&root, &[".well-known/acme-challenge", ".well-known/security.txt"]);
    assert!(list.problems().is_empty(), "{:?}", list.problems());
    for allowed in [
        ".well-known/acme-challenge/token",
        ".well-known/acme-challenge/a/b",
        ".well-known/security.txt",
        ".Well-Known/ACME-CHALLENGE/x",
    ] {
        assert_eq!(list.request_verdict(allowed), None, "{allowed}");
    }
    for denied in [
        ".well-known",
        ".well-known/",
        ".well-known/other",
        ".well-known/acme-challenge/.hidden",
        ".well-known/security.txt/.x",
        ".git/config",
        ".frogs/run.json",
        "x/.well-known/acme-challenge/t",
    ] {
        assert_eq!(list.request_verdict(denied), Some(DenyReason::DotSegment), "{denied}");
    }
}

#[test]
fn without_an_allow_entry_well_known_stays_denied() {
    let root = temp_root();
    let list = plain_list(&root);
    assert_eq!(list.request_verdict(".well-known/security.txt"), Some(DenyReason::DotSegment));
}

#[test]
fn allow_entries_that_could_open_anything_but_well_known_are_reported_and_ignored() {
    let root = temp_root();
    let bad = [
        "",
        ".git",
        ".git/config",
        ".well-known/../.git",
        ".well-known/.secret",
        "docs",
        "..",
        ".well-known//x",
        ".well-known/_backups",
    ];
    let list = list_allowing(&root, &bad);
    assert_eq!(list.problems().len(), bad.len(), "{:?}", list.problems());
    assert!(
        list.problems().iter().all(|p| p.starts_with("allowDotPaths entry ") && p.contains("is ignored")),
        "{:?}",
        list.problems()
    );
    for target in [".git/config", ".well-known/anything", ".well-known/.secret"] {
        assert_eq!(list.request_verdict(target), Some(DenyReason::DotSegment), "{target}");
    }
}

#[test]
fn an_allowed_path_is_still_subject_to_the_protected_path_and_reserved_name_rules() {
    let root = temp_root();
    let mut protected = ProtectedPaths::default();
    protected.add_path("tls.manual.keyPath", &root, ".well-known/acme-challenge/server.key");
    let mut list = list_for(&root, &protected);
    list.set_dot_allow(&[".well-known/acme-challenge".to_string()]);
    assert_eq!(list.request_verdict(".well-known/acme-challenge/server.key"), Some(DenyReason::Protected));
    assert_eq!(list.request_verdict(".well-known/acme-challenge/token"), None);
    assert_eq!(list.request_verdict(".well-known/acme-challenge/_backups/x"), Some(DenyReason::Backups));
}

#[test]
fn the_canonical_layer_applies_the_same_exemption() {
    let root = temp_root();
    let list = list_allowing(&root, &[".well-known/acme-challenge"]);
    assert_eq!(list.canonical_verdict(&root.join(".well-known/acme-challenge/token")), None);
    assert_eq!(list.canonical_verdict(&root.join(".well-known/other")), Some(DenyReason::DotSegment));
    assert_eq!(list.canonical_verdict(&root.join(".well-known/acme-challenge/.x")), Some(DenyReason::DotSegment));
}

#[tokio::test]
async fn a_served_site_answers_an_allowed_well_known_file_and_still_404s_everything_else_dotted() {
    let root = temp_root();
    std::fs::create_dir_all(root.join(".well-known/acme-challenge")).unwrap();
    std::fs::write(root.join("index.html"), "home").unwrap();
    std::fs::write(root.join(".well-known/acme-challenge/token"), "ACME-TOKEN").unwrap();
    std::fs::write(root.join(".well-known/other.txt"), "NOT-ALLOWED").unwrap();
    std::fs::write(root.join(".env"), "SECRET").unwrap();
    let mut config = config_for("index.html", None);
    config.allow_dot_paths = vec![".well-known/acme-challenge".to_string()];
    let addr = spawn_served(router(root.clone(), config, ProtectedPaths::default()), false).await;

    let ok = send(addr, "GET", "/.well-known/acme-challenge/token").await;
    assert!(ok.status_line.contains("200"), "{ok:?}");
    assert_eq!(ok.body, b"ACME-TOKEN");
    let missing = send(addr, "GET", "/no-such-file").await;
    for target in ["/.well-known/other.txt", "/.env", "/.well-known/"] {
        assert_denied_like_missing(addr, target, &missing).await;
    }
}

#[test]
fn allow_dot_paths_round_trips_through_webserve_json_and_is_omitted_when_empty() {
    let config: WebServeConfig = serde_json::from_str(r#"{ "startPage": "i.html", "allowDotPaths": [".well-known/security.txt"] }"#).unwrap();
    assert_eq!(config.allow_dot_paths, vec![".well-known/security.txt".to_string()]);
    assert!(serde_json::to_string(&config).unwrap().contains("allowDotPaths"));
    let plain: WebServeConfig = serde_json::from_str(r#"{ "startPage": "i.html" }"#).unwrap();
    assert!(plain.allow_dot_paths.is_empty());
    assert!(!serde_json::to_string(&plain).unwrap().contains("allowDotPaths"));
}

#[test]
fn page_problems_reports_a_bad_allow_entry() {
    let root = temp_root();
    std::fs::write(root.join("index.html"), "x").unwrap();
    let mut config = config_for("index.html", None);
    config.allow_dot_paths = vec![".git".to_string()];
    let (problems, _) = page_problems(&root, &config, &ProtectedPaths::default());
    assert_eq!(problems.len(), 1, "{problems:?}");
}

// ------------------------------------------ hard links and aliases

#[tokio::test]
async fn a_hard_link_to_a_protected_file_is_denied_like_a_missing_file() {
    let root = temp_root();
    std::fs::create_dir_all(root.join("tls")).unwrap();
    std::fs::write(root.join("index.html"), "home").unwrap();
    std::fs::write(root.join("tls/server.key"), "PRIVATE-KEY").unwrap();
    std::fs::hard_link(root.join("tls/server.key"), root.join("innocent.txt")).unwrap();
    std::fs::write(root.join("plain.txt"), "fine").unwrap();
    let mut protected = ProtectedPaths::default();
    protected.add_path("tls.manual.keyPath", &root, "tls/server.key");
    let addr = spawn_served(router(root.clone(), config_for("index.html", None), protected), false).await;

    let missing = send(addr, "GET", "/no-such-file").await;
    assert_denied_like_missing(addr, "/tls/server.key", &missing).await;
    assert_denied_like_missing(addr, "/innocent.txt", &missing).await;
    let fine = send(addr, "GET", "/plain.txt").await;
    assert!(fine.status_line.contains("200"), "{fine:?}");
}

#[test]
fn a_hard_link_to_a_protected_sqlite_sidecar_is_denied_too() {
    let root = temp_root();
    std::fs::write(root.join("data.db"), "x").unwrap();
    std::fs::write(root.join("data.db-wal"), "wal").unwrap();
    std::fs::hard_link(root.join("data.db-wal"), root.join("copy.txt")).unwrap();
    let mut protected = ProtectedPaths::default();
    protected.add_sqlite(&connection(&root.join("data.db").to_string_lossy()), &root);
    let list = list_for(&root, &protected);
    assert_eq!(list.identity_verdict(&root.join("copy.txt"), &root), Some(DenyReason::Protected));
    assert_eq!(list.identity_verdict(&root.join("data.db-wal"), &root), Some(DenyReason::Protected));
    std::fs::write(root.join("other.txt"), "x").unwrap();
    assert_eq!(list.identity_verdict(&root.join("other.txt"), &root), None);
}
