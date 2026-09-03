use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use serde_json::Value;

use crate::config::Config;
use crate::endpoint::{EndpointFile, MockOutcome, resolve_for_test};
use crate::project::require_project_root;
use crate::security::VerifierCache;

/// Discovers every `endpoint.<method>.test.json` file under
/// `datasources/endpoints/` and runs its cases through `resolve_for_test` —
/// the same security-check/source-resolution/response-building/error-
/// envelope logic a real request goes through, per source either run for
/// real or substituted per the case's own `mocks`. Prints pass/fail per
/// case and exits non-zero if anything failed or a file couldn't be read.
pub async fn run(cwd: &Path) -> io::Result<()> {
    let root = require_project_root(cwd);
    let api_root = crate::project::api_base(&root);
    let config = Config::load_or_exit(&api_root);

    let drivers = match crate::sql::connect_all(&config.connections).await {
        Ok(drivers) => drivers,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(1);
        }
    };

    let sql_root = api_root.join("datasources/sql");
    let http_root = api_root.join("datasources/http");
    let endpoints_root = api_root.join("datasources/endpoints");
    let discovered_errors_path = api_root.join("config/errors.discovered.json");
    let http_client = reqwest::Client::new();
    let verifier_cache = VerifierCache::new();
    // A plain `Mutex`, not `Arc`-wrapped — `run()` itself is the only
    // caller of `resolve_for_test` here (unlike `build_router`'s per-route
    // `Arc<RouteState>`, nothing else needs to share ownership of this).
    let discovered_errors = Mutex::new(config.discovered_errors);

    let test_files = discover_test_files(&endpoints_root);
    if test_files.is_empty() {
        println!("no *.test.json files found under datasources/endpoints/");
        return Ok(());
    }

    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut errored = 0usize;

    for (display_path, method, test_file_path, endpoint_file_path) in test_files {
        let endpoint = match read_endpoint_file(&endpoint_file_path) {
            Ok(endpoint) => endpoint,
            Err(message) => {
                eprintln!("error: {message}");
                errored += 1;
                continue;
            }
        };

        let test_file = match crate::testing::load(&test_file_path) {
            Ok(file) => file,
            Err(e) => {
                eprintln!("error: {}: {e}", test_file_path.display());
                errored += 1;
                continue;
            }
        };

        println!("{} {display_path}", method.to_uppercase());
        // Fresh per file, never shared across files or reused across runs —
        // this is what `{{memory.X}}` scoping to "this file's cases, run in
        // order" actually means in practice.
        let mut memory = crate::testing::Memory::new();
        for case in &test_file.cases {
            let path_params = memory.substitute_string_map(&case.request.path);
            let query_params = memory.substitute_string_map(&case.request.query);
            let header_values = memory.substitute_string_map(&case.request.headers);
            let headers = build_headers(&header_values);
            let body = case.request.body.as_ref().map(|b| memory.substitute(b)).unwrap_or(Value::Null);
            let mocks: HashMap<String, MockOutcome> = case
                .mocks
                .iter()
                .map(|(name, outcome)| {
                    let substituted = match outcome {
                        MockOutcome::Success(v) => MockOutcome::Success(memory.substitute(v)),
                        MockOutcome::Fail(code) => MockOutcome::Fail(code.clone()),
                    };
                    (name.clone(), substituted)
                })
                .collect();

            // A distinct, recognizable value per run rather than a real
            // correlation ID — there's no HTTP middleware generating one
            // here, and a case asserting on `context.transactionId` cares
            // that *some* stable value flows through, not what it is.
            let (status, response_body) = resolve_for_test(
                &endpoint,
                &config.security,
                &config.services,
                &drivers,
                &sql_root,
                &http_root,
                &http_client,
                &config.errors,
                &discovered_errors,
                &discovered_errors_path,
                config.server.debug_mode,
                &verifier_cache,
                &headers,
                &path_params,
                &query_params,
                &body,
                "frogs-test-run",
                &mocks,
            )
            .await;

            let expect_body = case.expect.body.as_ref().map(|b| memory.substitute(b));
            let expect = crate::testing::Expectation {
                status: case.expect.status,
                body: expect_body,
            };
            let mismatches = crate::testing::evaluate(&expect, status, &response_body);
            if mismatches.is_empty() {
                println!("  \u{2713} {}", case.name);
                passed += 1;
            } else {
                println!("  \u{2717} {}", case.name);
                for mismatch in &mismatches {
                    println!("      {}: expected {}, got {}", mismatch.path, mismatch.expected, mismatch.actual);
                }
                failed += 1;
            }

            if !case.save.is_empty() {
                memory.save(&case.save, status, &response_body);
            }
        }
    }

    println!();
    if errored > 0 {
        println!("{passed} passed, {failed} failed, {errored} errored");
    } else {
        println!("{passed} passed, {failed} failed");
    }

    if failed > 0 || errored > 0 {
        std::process::exit(1);
    }
    Ok(())
}

/// `frogs test record <path> <method>` — runs one real request against
/// real infrastructure (no mocks, no security check either — see
/// `endpoint::record_sources`) and appends what actually happened as a new
/// case in the sibling `.test.json` file, creating it if it doesn't exist
/// yet. Per the design doc: this generates the `mocks` (and a starting
/// `expect`, computed from the real response), not the assertions — a
/// human still needs to review the recorded case, trim its `expect` down
/// to what actually matters, and give it a meaningful name.
pub async fn record(cwd: &Path, path: &str, method: &str) -> io::Result<()> {
    let root = require_project_root(cwd);
    let api_root = crate::project::api_base(&root);
    let config = Config::load_or_exit(&api_root);

    let drivers = match crate::sql::connect_all(&config.connections).await {
        Ok(drivers) => drivers,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(1);
        }
    };

    let sql_root = api_root.join("datasources/sql");
    let http_root = api_root.join("datasources/http");
    let endpoints_root = api_root.join("datasources/endpoints");
    let http_client = reqwest::Client::new();

    let method = method.to_lowercase();
    let (request_path, query_params) = split_path_and_query(path);

    let Some((endpoint_file_path, path_params)) = find_endpoint_file(&endpoints_root, &request_path, &method) else {
        eprintln!("error: no endpoint.{method}.json found matching {request_path}");
        std::process::exit(1);
    };

    let endpoint = match read_endpoint_file(&endpoint_file_path) {
        Ok(endpoint) => endpoint,
        Err(message) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
    };

    let (status, response_body, resolved) = match crate::endpoint::record_sources(
        &endpoint,
        &config.services,
        &drivers,
        &sql_root,
        &http_root,
        &http_client,
        &path_params,
        &query_params,
        &Value::Null,
        "frogs-test-record",
    )
    .await
    {
        Ok(result) => result,
        Err((source_name, code, message)) => {
            eprintln!("error: recording failed: source '{source_name}' failed ({code}): {message}");
            eprintln!("nothing was recorded — a non-optional source failing means there's no real response to capture");
            std::process::exit(1);
        }
    };

    let mut mocks = HashMap::new();
    for (name, value) in &resolved {
        match value {
            Some(v) => {
                mocks.insert(name.clone(), MockOutcome::Success(v.clone()));
            }
            None => {
                eprintln!(
                    "warning: source '{name}' failed during recording — it's optional, so the request itself still \
                     succeeded, but no mock was captured for it; add one by hand (e.g. \"{name}\": {{\"fail\": \
                     \"<code>\"}}) if this case should exercise that path"
                );
            }
        }
    }

    let test_file_path = endpoint_file_path.with_file_name(format!("endpoint.{method}.test.json"));
    let mut test_file = match crate::testing::load(&test_file_path) {
        Ok(file) => file,
        Err(crate::testing::TestLoadError::Io(e)) if e.kind() == io::ErrorKind::NotFound => crate::testing::TestFile { cases: Vec::new() },
        Err(e) => {
            eprintln!("error: {}: {e}", test_file_path.display());
            std::process::exit(1);
        }
    };

    test_file.cases.push(crate::testing::TestCase {
        name: format!("recorded {}", chrono::Utc::now().to_rfc3339()),
        request: crate::testing::TestRequest {
            path: path_params,
            query: query_params,
            headers: HashMap::new(),
            body: None,
        },
        mocks,
        expect: crate::testing::Expectation {
            status: Some(status),
            body: Some(response_body),
        },
        save: HashMap::new(),
    });

    if let Err(e) = crate::testing::save_to(&test_file_path, &test_file) {
        eprintln!("error: failed to write {}: {e}", test_file_path.display());
        std::process::exit(1);
    }

    println!("recorded 1 new case into {}", test_file_path.display());
    println!("review its name and expect block (and add any mocks noted above) before relying on it");
    Ok(())
}

/// Splits a CLI-supplied path into its path and query parts, e.g.
/// `/cars?maker=Honda` -> (`/cars`, {"maker": "Honda"}). Deliberately plain
/// splitting, no percent-decoding — a CLI argument typed at a real
/// terminal is already in its literal form, unlike a URL a browser or HTTP
/// client would encode.
fn split_path_and_query(path: &str) -> (String, HashMap<String, String>) {
    let Some((request_path, query_string)) = path.split_once('?') else {
        return (path.to_string(), HashMap::new());
    };
    let query_params = query_string
        .split('&')
        .filter(|pair| !pair.is_empty())
        .filter_map(|pair| pair.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    (request_path.to_string(), query_params)
}

/// Finds the `endpoint.<method>.json` file whose route template (e.g.
/// `/cars/{vin}`) matches `concrete_path` (e.g. `/cars/1HGCM82633A004352`),
/// returning it alongside the path parameters the match extracted. Doesn't
/// reuse `endpoint::build_router`'s axum-facing route matching — nothing
/// here ever registers a real route, so a plain segment-by-segment compare
/// against the same `{name}`-braced folder names `display_path` already
/// reads is simpler than pulling axum's matcher in for this one purpose.
fn find_endpoint_file(endpoints_root: &Path, concrete_path: &str, method: &str) -> Option<(PathBuf, HashMap<String, String>)> {
    let mut routes = Vec::new();
    collect_routes(endpoints_root, endpoints_root, method, &mut routes);

    let concrete_segments: Vec<&str> = concrete_path.trim_matches('/').split('/').filter(|s| !s.is_empty()).collect();
    for (template, endpoint_file) in &routes {
        let template_segments: Vec<&str> = template.trim_matches('/').split('/').filter(|s| !s.is_empty()).collect();
        if template_segments.len() != concrete_segments.len() {
            continue;
        }

        let mut params = HashMap::new();
        let mut matched = true;
        for (t, c) in template_segments.iter().zip(concrete_segments.iter()) {
            match t.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
                Some(name) => {
                    params.insert(name.to_string(), c.to_string());
                }
                None if t == c => {}
                None => {
                    matched = false;
                    break;
                }
            }
        }

        if matched {
            return Some((endpoint_file.clone(), params));
        }
    }
    None
}

fn collect_routes(root: &Path, dir: &Path, method: &str, out: &mut Vec<(String, PathBuf)>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    let target_name = format!("endpoint.{method}.json");
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().and_then(|n| n.to_str()) == Some("_backups") {
                continue;
            }
            collect_routes(root, &path, method, out);
        } else if path.file_name().and_then(|n| n.to_str()) == Some(target_name.as_str()) {
            out.push((display_path(root, &path), path.clone()));
        }
    }
}

fn read_endpoint_file(path: &Path) -> Result<EndpointFile, String> {
    let contents = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&contents).map_err(|e| format!("{}: invalid JSON: {e}", path.display()))
}

/// A header whose name or value doesn't parse as valid HTTP (rare, but
/// possible in a hand-authored `.test.json`) is silently skipped rather
/// than failing the whole run — the case itself will fail its own
/// assertions soon enough if that header actually mattered, with a much
/// clearer signal (a mismatch, not a crash) than a parse-time error would.
fn build_headers(headers: &HashMap<String, String>) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        if let (Ok(header_name), Ok(header_value)) = (HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_str(value)) {
            map.insert(header_name, header_value);
        }
    }
    map
}

fn discover_test_files(root: &Path) -> Vec<(String, String, PathBuf, PathBuf)> {
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, String, PathBuf, PathBuf)>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // `_backups/` holds history, not live config — never a test file.
            if path.file_name().and_then(|n| n.to_str()) == Some("_backups") {
                continue;
            }
            walk(root, &path, out);
        } else if let Some(method) = test_file_method(&path) {
            let display_path = display_path(root, &path);
            // Sibling to the test file, same folder — the file the design
            // doc's "config lives next to what it configures" pattern says
            // this test file is testing.
            let endpoint_file = path.parent().expect("a file always has a parent").join(format!("endpoint.{method}.json"));
            out.push((display_path, method.to_string(), path.clone(), endpoint_file));
        }
    }
}

/// The HTTP method an `endpoint.<method>.test.json` file tests, or `None`
/// for anything else in the tree (the stub/reference files themselves,
/// `_backups/` contents, non-endpoint files).
fn test_file_method(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    let method = name.strip_prefix("endpoint.")?.strip_suffix(".test.json")?;
    Some(method.to_string())
}

/// Converts a folder path under `datasources/endpoints/` into a readable
/// display path for test output, e.g. `.../cars/{vin}/endpoint.get.test.json`
/// -> `/cars/{vin}` — deliberately keeping OpenAPI's own `{name}` braces
/// (unlike `endpoint::url_path_for`'s axum `:name` translation), since
/// nothing here ever registers a real axum route.
fn display_path(root: &Path, file_path: &Path) -> String {
    let dir = file_path.parent().expect("a file always has a parent");
    let relative = dir.strip_prefix(root).unwrap_or(dir);
    let segments: Vec<String> = relative.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
    if segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segments.join("/"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Same `endpoints/` shape `examples/cars-demo` has (`/cars` GET+POST,
    /// `/cars/{vin}` GET with its one `.test.json` sibling) — built fresh
    /// per test rather than read from `examples/`, since `discover_test_files`
    /// and `find_endpoint_file` are purely filename/path-driven and never
    /// parse a file's contents.
    struct EndpointsFixture {
        root: PathBuf,
    }

    impl EndpointsFixture {
        fn path(&self) -> &Path {
            &self.root
        }
    }

    impl Drop for EndpointsFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn sample_endpoints_root() -> EndpointsFixture {
        let root = std::env::temp_dir().join(format!(
            "frogs-commands-test-endpoints-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(root.join("cars/{vin}")).unwrap();
        std::fs::write(root.join("cars/endpoint.get.json"), "{}").unwrap();
        std::fs::write(root.join("cars/endpoint.post.json"), "{}").unwrap();
        std::fs::write(root.join("cars/{vin}/endpoint.get.json"), "{}").unwrap();
        std::fs::write(root.join("cars/{vin}/endpoint.get.test.json"), "{}").unwrap();
        EndpointsFixture { root }
    }

    #[test]
    fn test_file_method_recognizes_a_test_file() {
        let path = Path::new("/proj/datasources/endpoints/cars/endpoint.get.test.json");
        assert_eq!(test_file_method(path), Some("get".to_string()));
    }

    #[test]
    fn test_file_method_ignores_the_stub_and_reference_siblings() {
        assert_eq!(test_file_method(Path::new("/proj/datasources/endpoints/cars/endpoint.get.json")), None);
        assert_eq!(test_file_method(Path::new("/proj/datasources/endpoints/cars/endpoint.get.reference.json")), None);
    }

    #[test]
    fn display_path_keeps_openapi_style_braces() {
        let root = Path::new("/proj/datasources/endpoints");
        let file = root.join("cars").join("{vin}").join("endpoint.get.test.json");
        assert_eq!(display_path(root, &file), "/cars/{vin}");
    }

    #[test]
    fn display_path_maps_the_root_to_a_single_slash() {
        let root = Path::new("/proj/datasources/endpoints");
        let file = root.join("endpoint.get.test.json");
        assert_eq!(display_path(root, &file), "/");
    }

    #[test]
    fn discovers_test_files_and_their_sibling_endpoint_file() {
        let fixture = sample_endpoints_root();
        let found = discover_test_files(fixture.path());
        assert_eq!(found.len(), 1, "the fixture has exactly one .test.json file");
        let (display_path, method, test_file_path, endpoint_file_path) = &found[0];
        assert_eq!(display_path, "/cars/{vin}");
        assert_eq!(method, "get");
        assert!(test_file_path.ends_with("endpoint.get.test.json"));
        assert!(endpoint_file_path.ends_with("endpoint.get.json"));
    }

    #[test]
    fn split_path_and_query_with_no_query_string() {
        let (path, query) = split_path_and_query("/cars/1HGCM82633A004352");
        assert_eq!(path, "/cars/1HGCM82633A004352");
        assert!(query.is_empty());
    }

    #[test]
    fn split_path_and_query_parses_multiple_params() {
        let (path, query) = split_path_and_query("/cars?maker=Honda&model=Accord");
        assert_eq!(path, "/cars");
        assert_eq!(query.get("maker"), Some(&"Honda".to_string()));
        assert_eq!(query.get("model"), Some(&"Accord".to_string()));
    }

    #[test]
    fn find_endpoint_file_matches_a_concrete_path_against_a_braced_template() {
        let fixture = sample_endpoints_root();
        let (file, params) = find_endpoint_file(fixture.path(), "/cars/1HGCM82633A004352", "get").expect("should match the /cars/{vin} template");
        assert!(file.ends_with("endpoint.get.json"));
        assert_eq!(params.get("vin"), Some(&"1HGCM82633A004352".to_string()));
    }

    #[test]
    fn find_endpoint_file_matches_a_flat_path_with_no_params() {
        let fixture = sample_endpoints_root();
        let (file, params) = find_endpoint_file(fixture.path(), "/cars", "get").expect("should match the /cars template");
        assert!(file.ends_with("cars/endpoint.get.json"));
        assert!(params.is_empty());
    }

    #[test]
    fn find_endpoint_file_returns_none_for_an_unknown_path() {
        let fixture = sample_endpoints_root();
        assert!(find_endpoint_file(fixture.path(), "/does/not/exist", "get").is_none());
    }

    #[test]
    fn find_endpoint_file_returns_none_for_the_wrong_segment_count() {
        let fixture = sample_endpoints_root();
        assert!(find_endpoint_file(fixture.path(), "/cars/extra/segment", "get").is_none());
    }

    #[test]
    fn find_endpoint_file_respects_the_method() {
        let fixture = sample_endpoints_root();
        // The fixture has no DELETE endpoint at all.
        assert!(find_endpoint_file(fixture.path(), "/cars/1HGCM82633A004352", "delete").is_none());
    }
}
