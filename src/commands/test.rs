use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Router;
use serde_json::Value;

use crate::config::{Config, ServerConfig};
use crate::endpoint::mock::{NO_MATCHING_CASE, RouteKey, SOURCE_NOT_MOCKED, UNKNOWN_SCENARIO};
use crate::endpoint::{EndpointFile, MockOutcome, SourceDef, nested_many_parent};
use crate::errors::ErrorDefinition;
use crate::project::{MANIFEST_FILE, require_project_root};
use crate::server::service;
use crate::testing::{LoadedTestFile, MockSession, ReportConfig, ReportFormat};

/// The bare `frogs test` command line, already parsed by clap.
#[derive(Debug, Clone)]
pub struct TestServerOptions {
    /// Overrides `config/server.json`'s `port` for this process only.
    pub port: Option<u16>,
    pub bind: IpAddr,
    pub scenario: Option<String>,
    pub report: ReportFormat,
    pub report_file: Option<PathBuf>,
}

/// `frogs test` — boots the project's API as a mock server and serves
/// until stopped: every route `build_router` registers resolves its
/// sources from the sibling `*.test.json` files' `mocks` (matched back to
/// a case per request, see `testing::select`), never from a real database
/// or upstream HTTP service. `sql::connect_all` is never called. Writes
/// nothing into the project except `.frogs/run.json` (so `frogs stop`
/// works and `frogs run` can't double-bind) and the `--report-file` the
/// user chose. Exits 1 after shutdown if any request failed its `expect`,
/// matched no case, or hit an unmocked required source.
pub async fn run(cwd: &Path, opts: TestServerOptions) -> io::Result<()> {
    let root = require_project_root(cwd);
    if !root.join(MANIFEST_FILE).is_file() {
        eprintln!("error: no {MANIFEST_FILE} at {} — frogs test serves the API role only", root.display());
        std::process::exit(1);
    }

    // Never dispatches through `service::read_record`/`run_registered` the
    // way `frogs run` does — a mock server always serves in-process. A
    // registered service that's actually up would fight this process over
    // the pidfile, so that one case is refused outright.
    if let Some(record) = service::read_record(&root)? {
        match service::is_running(&record) {
            Ok(true) => {
                eprintln!(
                    "error: this project is registered as service {} and it is currently running — run `frogs stop` first, \
                     or unregister it, before serving mocks from the same project",
                    record.name
                );
                std::process::exit(1);
            }
            Ok(false) => println!(
                "note: this project is registered as service {} — `frogs stop` targets that service, so stop this mock server with Ctrl+C",
                record.name
            ),
            Err(e) => println!(
                "note: this project is registered as service {} (could not check whether it's running: {e}) — `frogs stop` targets \
                 that service, so stop this mock server with Ctrl+C",
                record.name
            ),
        }
    }

    let (router, session, server_config) = build_mock_router(&root, &opts).await?;

    if root.join("webserve.json").is_file() {
        println!("note: webserve.json found — frogs test serves the API role only, static content is not served");
    }
    if !opts.bind.is_loopback() {
        println!(
            "warning: binding {} — /_frogs/scenario is unauthenticated and will be reachable from the network",
            opts.bind
        );
    }

    crate::commands::run::refuse_if_already_running(&root)?;

    let port = opts.port.unwrap_or(server_config.port);
    tracing::info!(port, tls_mode = ?server_config.tls.mode, scenario = ?opts.scenario, "frogs test starting");
    let api_dir = crate::project::api_base(&root);
    let result = crate::commands::run::serve(&root, router, opts.bind, port, &server_config.tls, &api_dir, shutdown_signal()).await;

    let summary = session.finish();
    println!("{}", crate::testing::report::render_summary_line(&summary));
    if let Some(path) = &opts.report_file {
        println!("report written to {}", path.display());
    }
    result?;
    if summary.has_problems() {
        std::process::exit(1);
    }
    Ok(())
}

/// Ctrl+C everywhere, plus SIGTERM on Unix — the signal a supervisor or
/// CI runner actually sends, so the report still gets finalized then.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("registering a SIGTERM handler should succeed");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Everything `run` does before binding a port, returned rather than
/// served so a test can drive the router itself: loads config, every
/// `*.test.json` file (a malformed one is exit 1), prints corpus warnings,
/// resolves `--scenario`, and assembles the real API router with the
/// session installed as every route's `MockProvider` plus the
/// `/_frogs/scenario` control plane merged at the absolute root.
pub(crate) async fn build_mock_router(root: &Path, opts: &TestServerOptions) -> io::Result<(Router, Arc<MockSession>, ServerConfig)> {
    let api_root = crate::project::api_base(root);
    let mut config = Config::load_or_exit(&api_root);
    let endpoints_root = api_root.join("datasources/endpoints");

    // Harness-owned codes classify like any other — a project that
    // deliberately defines one of them in `config/errors/` keeps its own.
    for (code, http_status) in [(SOURCE_NOT_MOCKED, 501), (NO_MATCHING_CASE, 404), (UNKNOWN_SCENARIO, 400)] {
        config.errors.insert_if_absent(
            code,
            ErrorDefinition {
                http_status,
                expose_detail: true,
            },
        );
    }

    let mut files = Vec::new();
    for (display_path, method, test_file_path, endpoint_file_path) in discover_test_files(&endpoints_root) {
        let file = match crate::testing::load(&test_file_path) {
            Ok(file) => file,
            Err(e) => {
                eprintln!("error: {}: {e}", test_file_path.display());
                std::process::exit(1);
            }
        };
        let endpoint = match read_endpoint_file(&endpoint_file_path) {
            Ok(endpoint) => Some(endpoint),
            Err(message) => {
                if endpoint_file_path.is_file() {
                    eprintln!("warning: {message}");
                }
                None
            }
        };
        files.push(LoadedTestFile {
            route: RouteKey { method, path: display_path },
            path: test_file_path,
            file,
            endpoint,
        });
    }

    let mut routable = HashMap::new();
    for (url_path, method, file_path) in crate::endpoint::discover_endpoint_files(&endpoints_root) {
        if let Ok(endpoint) = read_endpoint_file(&file_path) {
            routable.insert(
                RouteKey {
                    method,
                    path: crate::endpoint::mock::openapi_style_path(&url_path),
                },
                endpoint,
            );
        }
    }
    for loaded in &files {
        tracing::info!(
            "{} {} <- {} ({} case(s))",
            loaded.route.method.to_uppercase(),
            loaded.route.path,
            loaded.path.display(),
            loaded.file.cases.len()
        );
    }
    for warning in crate::testing::validate::validate_corpus(&files, &routable) {
        eprintln!("warning: {warning}");
    }
    println!(
        "loaded {} test file(s) with {} case(s) — {} route(s) discovered",
        files.len(),
        files.iter().map(|f| f.file.cases.len()).sum::<usize>(),
        routable.len()
    );

    let session = match MockSession::new(
        files,
        opts.scenario.clone(),
        ReportConfig {
            format: opts.report,
            file: opts.report_file.clone(),
        },
    ) {
        Ok(session) => session,
        Err(message) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
    };
    if !session.known_scenarios().is_empty() {
        println!("scenarios: {}", session.known_scenarios().join(", "));
    }
    if let Some(flag) = session.scenario_flag() {
        println!("active scenario (--scenario): {flag}");
    }

    let provider: Arc<dyn crate::endpoint::mock::MockProvider> = session.clone();
    let (router, server_config) = crate::commands::run::assemble_api_router(root, config, Arc::new(HashMap::new()), Some(provider)).await?;
    // Merged last, at the absolute root: outside `apiRoot`, outside every
    // optional middleware layer (correlation, metrics, rate limiting, CORS)
    // — merging never retroactively shares layers, which is exactly what
    // keeps this route un-CORS'd.
    let router = router.merge(crate::testing::control_plane::router(session.clone()));
    println!("scenario control plane: GET/POST/DELETE /_frogs/scenario");

    Ok((router, session, server_config))
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

    // A nested-many source never gets a top-level `resolved` entry of its
    // own (see `endpoint::resolve::resolve_nested_many`), so the loop above
    // never produces a mock for one — its recorded value instead lives
    // embedded in its bracket parent's own first row, already merged there
    // by the real, unmocked recording run just above.
    for (name, source) in &endpoint.sources {
        let (allow_nested_many, parameters) = match source {
            SourceDef::Sql {
                allow_nested_many, parameters, ..
            } => (*allow_nested_many, parameters),
            SourceDef::Http {
                allow_nested_many, parameters, ..
            } => (*allow_nested_many, parameters),
        };
        if !allow_nested_many {
            continue;
        }
        let Ok(parent_name) = nested_many_parent(parameters) else {
            continue;
        };
        let Some(Some(Value::Array(rows))) = resolved.get(parent_name) else {
            continue;
        };
        if let Some(value) = rows.first().and_then(|row| row.get(name)) {
            mocks.insert(name.clone(), MockOutcome::Success(value.clone()));
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
        scenario: None,
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
/// display path, e.g. `.../cars/{vin}/endpoint.get.test.json` ->
/// `/cars/{vin}` — deliberately keeping OpenAPI's own `{name}` braces
/// (unlike `endpoint::url_path_for`'s axum `:name` translation); this is
/// the form `RouteKey::path` carries and the report names routes by.
pub(crate) fn display_path(root: &Path, file_path: &Path) -> String {
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

    /// A minimal but complete scratch project (`frogs run`'s own
    /// `scratch_api_project` precedent, `src/commands/run.rs`) — everything
    /// `Config::load_or_exit`/`connect_all`/`record` need present, so
    /// `record` runs its real assembly path end to end rather than hitting
    /// `process::exit` on a config problem this test doesn't care about.
    struct RecordFixture {
        root: PathBuf,
    }

    impl Drop for RecordFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    /// `cars` is a `cardinality: "many"` HTTP source with two rows
    /// (`vin: "AAA"`/`"BBB"`), and `pricing` is its nested-many dependent —
    /// each row's own `vin` becomes the `?vin=` query the fake pricing
    /// server distinguishes on, so row 0 (`AAA`) and row 1 (`BBB`) get
    /// distinguishably different recorded amounts.
    async fn record_fixture() -> RecordFixture {
        use axum::extract::Query;
        use axum::routing::get;
        use axum::{Json, Router};

        let app = Router::new()
            .route("/cars", get(|| async { Json(serde_json::json!([{ "vin": "AAA" }, { "vin": "BBB" }])) }))
            .route(
                "/pricing",
                get(|Query(params): Query<HashMap<String, String>>| async move {
                    let amount = if params.get("vin").map(String::as_str) == Some("AAA") { 111 } else { 222 };
                    Json(serde_json::json!({ "amount": amount }))
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let root = std::env::temp_dir().join(format!(
            "frogs-commands-test-record-nested-many-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let api_dir = root.join("api");
        std::fs::create_dir_all(api_dir.join("config/errors")).unwrap();
        std::fs::create_dir_all(api_dir.join("security")).unwrap();
        std::fs::create_dir_all(api_dir.join("datasources/http")).unwrap();
        std::fs::create_dir_all(api_dir.join("datasources/endpoints/cars")).unwrap();
        std::fs::write(root.join("openapi.yaml"), "openapi: 3.0.3\ninfo: { title: t, version: '1' }\npaths: {}\n").unwrap();
        std::fs::write(api_dir.join("config/server.json"), r#"{ "features": { "requestValidation": false } }"#).unwrap();
        std::fs::write(api_dir.join("config/errors/core.json"), "{}").unwrap();
        std::fs::write(api_dir.join("config/connections.json"), "{}").unwrap();
        std::fs::write(api_dir.join("security/schemes.json"), "{}").unwrap();
        std::fs::write(
            api_dir.join("datasources/http/cars.json"),
            format!(r#"{{ "method": "GET", "url": "http://{addr}/cars" }}"#),
        )
        .unwrap();
        std::fs::write(
            api_dir.join("datasources/http/pricing.json"),
            format!(r#"{{ "method": "GET", "url": "http://{addr}/pricing?vin={{{{vin}}}}" }}"#),
        )
        .unwrap();
        std::fs::write(
            api_dir.join("datasources/endpoints/cars/endpoint.get.json"),
            r#"{
                "operationId": "listCars",
                "sources": {
                    "cars": { "type": "http", "request": "cars.json", "cardinality": "many" },
                    "pricing": {
                        "type": "http", "request": "pricing.json",
                        "allowNestedMany": true, "maxConcurrency": 2, "maxRows": 10,
                        "parameters": [{ "name": "vin", "from": "sources.cars[].vin" }]
                    }
                },
                "response": { "type": "array", "source": "sources.cars", "items": { "vin": "vin" } }
            }"#,
        )
        .unwrap();

        RecordFixture { root }
    }

    /// `frogs test record`'s new post-loop pass (Point 6's nested-many
    /// extension): a nested-many source never gets its own top-level
    /// `resolved` entry (see `endpoint::resolve::resolve_nested_many`), so
    /// without this pass its recorded mocks would simply never mention it.
    /// This proves the captured mock is exactly the *first* row's own
    /// merged value, not the whole array or some other row's.
    #[tokio::test]
    async fn record_captures_a_nested_many_sources_own_first_row_result_as_its_mock() {
        let fixture = record_fixture().await;

        record(&fixture.root, "/cars", "get")
            .await
            .expect("record should succeed against the real fake infrastructure");

        let test_file_path = fixture.root.join("api/datasources/endpoints/cars/endpoint.get.test.json");
        let test_file = crate::testing::load(&test_file_path).expect("record should have written a loadable test file");
        assert_eq!(test_file.cases.len(), 1);
        let case = &test_file.cases[0];

        assert_eq!(
            case.mocks.get("pricing"),
            Some(&MockOutcome::Success(serde_json::json!({ "amount": 111 }))),
            "the recorded mock for the nested-many source must be exactly row 0's (vin AAA's) own merged result, not row 1's or the whole array"
        );

        // Sanity check: `cars` itself *did* get an ordinary top-level mock
        // (it's a real, resolved source, just not a nested-many one), and
        // its own recorded array still has the merge embedded per row —
        // proving this is reading the same real resolution the nested-many
        // pass also reads from, not a separately mocked value.
        let Some(MockOutcome::Success(cars_mock)) = case.mocks.get("cars") else {
            panic!("expected an ordinary Success mock for 'cars'");
        };
        assert_eq!(cars_mock[0]["pricing"]["amount"], 111);
        assert_eq!(cars_mock[1]["pricing"]["amount"], 222);
    }

    /// `frogs test record` must keep writing exactly the file shape it did
    /// before scenarios existed — a freshly recorded (untagged) case must
    /// not gain a `scenario` key, or every recorded corpus would churn.
    #[tokio::test]
    async fn record_writes_no_scenario_key_for_a_freshly_recorded_case() {
        let fixture = record_fixture().await;
        record(&fixture.root, "/cars", "get").await.expect("record should succeed");
        let raw = std::fs::read_to_string(fixture.root.join("api/datasources/endpoints/cars/endpoint.get.test.json")).unwrap();
        assert!(!raw.contains("scenario"), "an untagged recorded case must serialize without any scenario key:\n{raw}");
    }

    // ----------------------------------------------------------------------
    // `frogs test` as a mock server, driven through `build_mock_router`
    // (everything `run` does short of binding the configured port).
    // ----------------------------------------------------------------------

    /// A real HTTP server every "real infrastructure" reference in the
    /// fixture points at — every hit is counted, and the whole point of the
    /// tests below is that the count stays at zero.
    struct FakeUpstream {
        addr: std::net::SocketAddr,
        hits: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl FakeUpstream {
        fn hits(&self) -> usize {
            self.hits.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    async fn fake_upstream() -> FakeUpstream {
        use axum::extract::State;
        use axum::{Json, Router};

        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let app = Router::new()
            .fallback(|State(hits): State<Arc<std::sync::atomic::AtomicUsize>>| async move {
                hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Json(serde_json::json!({ "maker": "REAL-UPSTREAM", "active": true, "vin": "REAL" }))
            })
            .with_state(hits.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        FakeUpstream { addr, hits }
    }

    struct MockProject {
        root: PathBuf,
        upstream: FakeUpstream,
    }

    impl Drop for MockProject {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    /// A complete scratch API project whose every source and verifier
    /// points at real-but-must-never-be-touched infrastructure: HTTP
    /// sources and the verifier at `fake_upstream`, and a sqlite connection
    /// at a path that cannot be opened.
    ///
    /// Routes:
    /// - `GET /cars/{vin}` — `car` (required HTTP) + `pricing` (optional
    ///   HTTP), with a test file covering happy/unmocked/scenario cases.
    /// - `POST /cars` — `create` (HTTP), one case that `save`s the vin.
    /// - `GET /secret` — `security: apiKeyAuth` (HTTP verifier), no sources.
    /// - `GET /untested` — an HTTP source, no test file.
    /// - `GET /sqlcar` — a SQL source on the unreachable connection, no test file.
    /// - `GET /ping` — no sources, no security, no test file.
    async fn mock_project() -> MockProject {
        let upstream = fake_upstream().await;
        let addr = upstream.addr;
        let root = std::env::temp_dir().join(format!(
            "frogs-commands-test-mock-server-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let api = root.join("api");
        for dir in [
            "config/errors",
            "security/verifiers",
            "datasources/http",
            "datasources/sql/db",
            "datasources/endpoints/cars/{vin}",
            "datasources/endpoints/secret",
            "datasources/endpoints/untested",
            "datasources/endpoints/sqlcar",
            "datasources/endpoints/ping",
        ] {
            std::fs::create_dir_all(api.join(dir)).unwrap();
        }
        std::fs::write(root.join("openapi.yaml"), "openapi: 3.0.3\ninfo: { title: t, version: '1' }\npaths: {}\n").unwrap();
        std::fs::write(api.join("config/server.json"), r#"{ "features": { "requestValidation": false } }"#).unwrap();
        std::fs::write(
            api.join("config/errors/core.json"),
            r#"{
                "auth.invalid_credentials": { "httpStatus": 401, "exposeDetail": true },
                "auth.verifier_unavailable": { "httpStatus": 500, "exposeDetail": false }
            }"#,
        )
        .unwrap();
        let unreachable_db = root.join("does-not-exist").join("db.sqlite").display().to_string().replace('\\', "/");
        std::fs::write(
            api.join("config/connections.json"),
            format!(r#"{{ "db": {{ "driver": "sqlite", "database": "{unreachable_db}" }} }}"#),
        )
        .unwrap();
        std::fs::write(api.join("security/schemes.json"), r#"{ "apiKeyAuth": { "verifier": "apiKeyVerifier.json" } }"#).unwrap();
        std::fs::write(
            api.join("security/verifiers/apiKeyVerifier.json"),
            r#"{ "type": "http", "request": "verify.json", "parameters": [{ "name": "key", "from": "header.X-Api-Key" }], "validIf": "response.active = true" }"#,
        )
        .unwrap();
        std::fs::write(
            api.join("datasources/http/upstream.json"),
            format!(r#"{{ "method": "GET", "url": "http://{addr}/car" }}"#),
        )
        .unwrap();
        std::fs::write(
            api.join("datasources/http/verify.json"),
            format!(r#"{{ "method": "GET", "url": "http://{addr}/verify?key={{{{key}}}}" }}"#),
        )
        .unwrap();
        std::fs::write(api.join("datasources/sql/db/car.sql"), "SELECT 'REAL' AS maker;").unwrap();

        let endpoints = api.join("datasources/endpoints");
        std::fs::write(
            endpoints.join("cars/{vin}/endpoint.get.json"),
            r#"{
                "operationId": "getCar",
                "sources": {
                    "car": { "type": "http", "request": "upstream.json" },
                    "pricing": { "type": "http", "request": "upstream.json", "optional": true }
                },
                "response": { "maker": "sources.car.maker", "price": "sources.pricing.amount" }
            }"#,
        )
        .unwrap();
        std::fs::write(
            endpoints.join("cars/{vin}/endpoint.get.test.json"),
            r#"{ "cases": [
                {
                    "name": "happy path",
                    "request": { "path": { "vin": "AAA" } },
                    "mocks": { "car": { "maker": "Honda" }, "pricing": { "amount": 1 } },
                    "expect": { "status": 200, "body": { "maker": "Honda", "price": 1 } }
                },
                {
                    "name": "pricing unmocked",
                    "request": { "path": { "vin": "BBB" } },
                    "mocks": { "car": { "maker": "Honda" } },
                    "expect": { "status": 200, "body": { "maker": "Honda" } }
                },
                {
                    "name": "car unmocked",
                    "request": { "path": { "vin": "CCC" } },
                    "mocks": { "pricing": { "amount": 1 } },
                    "expect": { "status": 200 }
                },
                {
                    "name": "pricing down",
                    "scenario": "pricing-down",
                    "request": { "path": { "vin": "AAA" } },
                    "mocks": { "car": { "maker": "Scenario" }, "pricing": { "fail": "datasource.http.timeout" } },
                    "expect": { "status": 200, "body": { "maker": "Scenario", "price": null } }
                },
                {
                    "name": "db down",
                    "scenario": "db-down",
                    "request": { "path": { "vin": "AAA" } },
                    "mocks": { "car": { "fail": "datasource.sql.connection_failed" } },
                    "expect": { "status": 500 }
                },
                {
                    "name": "read back created",
                    "request": { "path": { "vin": "{{memory.vin}}" } },
                    "mocks": { "car": { "maker": "FromMemory" }, "pricing": { "amount": 2 } },
                    "expect": { "status": 200, "body": { "maker": "FromMemory" } }
                }
            ] }"#,
        )
        .unwrap();
        std::fs::write(
            endpoints.join("cars/endpoint.post.json"),
            r#"{
                "operationId": "createCar",
                "successStatus": 201,
                "sources": { "create": { "type": "http", "request": "upstream.json" } },
                "response": { "vin": "sources.create.vin" }
            }"#,
        )
        .unwrap();
        std::fs::write(
            endpoints.join("cars/endpoint.post.test.json"),
            r#"{ "cases": [
                {
                    "name": "create",
                    "request": { "body": { "maker": "Honda" } },
                    "mocks": { "create": { "vin": "NEW123" } },
                    "expect": { "status": 201 },
                    "save": { "vin": "response.body.vin" }
                }
            ] }"#,
        )
        .unwrap();
        std::fs::write(
            endpoints.join("secret/endpoint.get.json"),
            r#"{ "operationId": "getSecret", "security": "apiKeyAuth", "sources": {}, "response": {} }"#,
        )
        .unwrap();
        std::fs::write(
            endpoints.join("secret/endpoint.get.test.json"),
            r#"{ "cases": [
                { "name": "verifier not mocked", "request": { "headers": { "X-Api-Key": "unmocked" } }, "expect": { "status": 200 } },
                { "name": "verifier mocked", "request": { "headers": { "X-Api-Key": "mocked" } }, "mocks": { "verifier": { "active": true } }, "expect": { "status": 200 } }
            ] }"#,
        )
        .unwrap();
        std::fs::write(
            endpoints.join("untested/endpoint.get.json"),
            r#"{ "operationId": "untested", "sources": { "car": { "type": "http", "request": "upstream.json" } }, "response": { "maker": "sources.car.maker" } }"#,
        )
        .unwrap();
        std::fs::write(
            endpoints.join("sqlcar/endpoint.get.json"),
            r#"{ "operationId": "sqlcar", "sources": { "car": { "type": "sql", "connection": "db", "script": "car.sql" } }, "response": { "maker": "sources.car.maker" } }"#,
        )
        .unwrap();
        std::fs::write(
            endpoints.join("ping/endpoint.get.json"),
            r#"{ "operationId": "ping", "sources": {}, "response": {} }"#,
        )
        .unwrap();

        MockProject { root, upstream }
    }

    fn default_opts() -> TestServerOptions {
        TestServerOptions {
            port: None,
            bind: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            scenario: None,
            report: ReportFormat::Text,
            report_file: None,
        }
    }

    /// Boots the mock router on an ephemeral loopback port and hands back
    /// the base URL plus the session, so a test can both hit routes and
    /// read the verdicts the session recorded.
    async fn serve_mock(project: &MockProject, opts: TestServerOptions) -> (String, Arc<MockSession>) {
        let (router, session, _) = build_mock_router(&project.root, &opts)
            .await
            .expect("the mock router must build without touching any infrastructure");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (format!("http://{addr}"), session)
    }

    async fn get_json(client: &reqwest::Client, url: &str) -> (u16, Value) {
        let response = client.get(url).send().await.unwrap();
        let status = response.status().as_u16();
        (status, response.json().await.unwrap_or(Value::Null))
    }

    #[tokio::test]
    async fn the_mock_router_builds_without_connecting_even_though_the_configured_connection_is_unreachable() {
        let project = mock_project().await;

        // First prove the fixture's connection genuinely can't be opened —
        // otherwise "built without connecting" would be a hollow claim.
        let config = Config::load_or_exit(&crate::project::api_base(&project.root));
        assert!(
            crate::sql::connect_all(&config.connections).await.is_err(),
            "the fixture's sqlite path is inside a nonexistent directory and must be unopenable"
        );

        let (router, session, _) = build_mock_router(&project.root, &default_opts())
            .await
            .expect("frogs test must never call connect_all, so an unreachable connection can't stop it");
        drop(router);
        assert_eq!(session.known_scenarios(), ["db-down", "pricing-down"]);
        assert_eq!(project.upstream.hits(), 0);
    }

    #[tokio::test]
    async fn an_unmocked_required_source_returns_501_source_not_mocked_and_never_contacts_the_upstream() {
        let project = mock_project().await;
        let (base, session) = serve_mock(&project, default_opts()).await;
        let client = reqwest::Client::new();

        let (status, body) = get_json(&client, &format!("{base}/cars/CCC")).await;

        assert_eq!(status, 501, "{body}");
        assert_eq!(body["name"], SOURCE_NOT_MOCKED);
        let detail = body["detail"].as_str().unwrap_or_default();
        assert!(detail.contains("source(s) not mocked: car"), "{detail}");
        assert!(detail.contains("matched case \"car unmocked\" in /cars/{vin}/endpoint.get.test.json"), "{detail}");
        assert!(
            !detail.contains(&project.root.display().to_string()),
            "a served detail must never leak an absolute path: {detail}"
        );
        assert_eq!(project.upstream.hits(), 0, "the real upstream must never be dialed for an unmocked source");
        assert_eq!(session.summary().not_mocked, 1);
    }

    #[tokio::test]
    async fn a_route_with_sources_but_no_test_file_returns_501_without_dialing_out() {
        let project = mock_project().await;
        let (base, session) = serve_mock(&project, default_opts()).await;
        let client = reqwest::Client::new();

        let (status, body) = get_json(&client, &format!("{base}/untested")).await;
        assert_eq!(status, 501, "{body}");
        assert_eq!(body["name"], SOURCE_NOT_MOCKED);
        assert!(
            body["detail"].as_str().unwrap_or_default().contains("no .test.json file exists for this route"),
            "{body}"
        );

        let (status, body) = get_json(&client, &format!("{base}/sqlcar")).await;
        assert_eq!(
            status, 501,
            "a SQL source on the unreachable connection must fail the same way, never try the driver: {body}"
        );
        assert_eq!(body["name"], SOURCE_NOT_MOCKED);

        assert_eq!(project.upstream.hits(), 0);
        assert_eq!(session.summary().not_mocked, 2);
    }

    #[tokio::test]
    async fn a_route_with_no_sources_no_security_and_no_test_file_serves_normally() {
        let project = mock_project().await;
        let (base, session) = serve_mock(&project, default_opts()).await;
        let client = reqwest::Client::new();

        let (status, body) = get_json(&client, &format!("{base}/ping")).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body, serde_json::json!({}));
        let summary = session.summary();
        assert_eq!(summary.served, 1);
        assert!(!summary.has_problems());
    }

    #[tokio::test]
    async fn a_fully_mocked_case_is_served_through_the_real_response_mapping_and_passes_its_expect() {
        let project = mock_project().await;
        let (base, session) = serve_mock(&project, default_opts()).await;
        let client = reqwest::Client::new();

        let (status, body) = get_json(&client, &format!("{base}/cars/AAA")).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body, serde_json::json!({ "maker": "Honda", "price": 1 }));
        assert_eq!(project.upstream.hits(), 0);
        let summary = session.summary();
        assert_eq!(summary.passed, 1);
        assert!(!summary.has_problems());
    }

    #[tokio::test]
    async fn an_unmocked_verifier_on_a_secured_route_returns_501_and_never_reaches_the_real_verifier() {
        let project = mock_project().await;
        let (base, session) = serve_mock(&project, default_opts()).await;
        let client = reqwest::Client::new();

        let response = client.get(format!("{base}/secret")).header("X-Api-Key", "unmocked").send().await.unwrap();
        let status = response.status().as_u16();
        let body: Value = response.json().await.unwrap();
        assert_eq!(status, 501, "{body}");
        assert_eq!(body["name"], SOURCE_NOT_MOCKED);
        assert!(body["detail"].as_str().unwrap_or_default().contains("source(s) not mocked: verifier"), "{body}");
        assert_eq!(project.upstream.hits(), 0, "security::verify must never run its real HTTP verifier under frogs test");

        let response = client.get(format!("{base}/secret")).header("X-Api-Key", "mocked").send().await.unwrap();
        assert_eq!(response.status(), 200, "a mocked verifier satisfying validIf authorizes the request");
        assert_eq!(project.upstream.hits(), 0);

        let summary = session.summary();
        assert_eq!((summary.not_mocked, summary.passed), (1, 1));
    }

    #[tokio::test]
    async fn an_unmocked_optional_source_degrades_to_null_and_the_case_still_passes() {
        let project = mock_project().await;
        let (base, session) = serve_mock(&project, default_opts()).await;
        let client = reqwest::Client::new();

        let (status, body) = get_json(&client, &format!("{base}/cars/BBB")).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body, serde_json::json!({ "maker": "Honda", "price": null }));
        assert_eq!(project.upstream.hits(), 0, "an optional source is degraded, never actually attempted");
        let summary = session.summary();
        assert_eq!(summary.passed, 1);
        assert!(!summary.has_problems(), "an optional unmocked source is reported but is not a problem");
    }

    #[tokio::test]
    async fn a_request_no_case_matches_returns_404_no_matching_case() {
        let project = mock_project().await;
        let (base, session) = serve_mock(&project, default_opts()).await;
        let client = reqwest::Client::new();

        let (status, body) = get_json(&client, &format!("{base}/cars/ZZZ")).await;
        assert_eq!(status, 404, "{body}");
        assert_eq!(body["name"], NO_MATCHING_CASE);
        assert!(body["detail"].as_str().unwrap_or_default().contains("GET /cars/{vin}"), "{body}");
        assert_eq!(project.upstream.hits(), 0);
        assert_eq!(session.summary().unmatched, 1);
    }

    #[tokio::test]
    async fn the_scenario_header_selects_a_tagged_case_for_that_one_request_only() {
        let project = mock_project().await;
        let (base, _) = serve_mock(&project, default_opts()).await;
        let client = reqwest::Client::new();

        let response = client
            .get(format!("{base}/cars/AAA"))
            .header("X-Frogs-Scenario", "pricing-down")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body: Value = response.json().await.unwrap();
        assert_eq!(
            body,
            serde_json::json!({ "maker": "Scenario", "price": null }),
            "the tagged case's mocks, with the mocked pricing failure degraded"
        );

        let (_, body) = get_json(&client, &format!("{base}/cars/AAA")).await;
        assert_eq!(body["maker"], "Honda", "the header is per-request — the next request is back on the baseline");
        assert_eq!(project.upstream.hits(), 0);
    }

    #[tokio::test]
    async fn an_unknown_scenario_header_is_a_400_unknown_scenario() {
        let project = mock_project().await;
        let (base, session) = serve_mock(&project, default_opts()).await;
        let client = reqwest::Client::new();

        let response = client.get(format!("{base}/cars/AAA")).header("X-Frogs-Scenario", "made-up").send().await.unwrap();
        assert_eq!(response.status(), 400);
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["name"], UNKNOWN_SCENARIO);
        assert!(
            body["detail"].as_str().unwrap_or_default().contains("known scenarios: db-down, pricing-down"),
            "{body}"
        );
        assert_eq!(session.summary().unmatched, 1);
    }

    #[tokio::test]
    async fn the_control_plane_reports_sets_and_clears_the_process_wide_scenario() {
        let project = mock_project().await;
        let (base, _) = serve_mock(&project, default_opts()).await;
        let client = reqwest::Client::new();
        let control = format!("{base}/_frogs/scenario");

        let (status, body) = get_json(&client, &control).await;
        assert_eq!(status, 200);
        assert_eq!(
            body,
            serde_json::json!({ "scenario": null, "source": "baseline", "known": ["db-down", "pricing-down"] })
        );

        let response = client.post(&control).json(&serde_json::json!({ "name": "pricing-down" })).send().await.unwrap();
        assert_eq!(response.status(), 200);
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["scenario"], "pricing-down");
        assert_eq!(body["source"], "control-plane");

        let (_, body) = get_json(&client, &format!("{base}/cars/AAA")).await;
        assert_eq!(body["maker"], "Scenario", "every subsequent request sees the override without any per-request change");

        let response = client.post(&control).json(&serde_json::json!({ "name": null })).send().await.unwrap();
        assert_eq!(response.status(), 200);
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["source"], "baseline", "{{\"name\": null}} clears the override");
        let (_, body) = get_json(&client, &format!("{base}/cars/AAA")).await;
        assert_eq!(body["maker"], "Honda");

        client.post(&control).json(&serde_json::json!({ "name": "pricing-down" })).send().await.unwrap();
        let response = client.delete(&control).send().await.unwrap();
        assert_eq!(response.status(), 200);
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["source"], "baseline", "DELETE clears the override too");
        let (_, body) = get_json(&client, &format!("{base}/cars/AAA")).await;
        assert_eq!(body["maker"], "Honda");
    }

    #[tokio::test]
    async fn the_control_plane_refuses_an_unknown_name_and_a_non_json_body() {
        let project = mock_project().await;
        let (base, _) = serve_mock(&project, default_opts()).await;
        let client = reqwest::Client::new();
        let control = format!("{base}/_frogs/scenario");

        let response = client.post(&control).json(&serde_json::json!({ "name": "made-up" })).send().await.unwrap();
        assert_eq!(response.status(), 400);
        let body: Value = response.json().await.unwrap();
        assert!(body["error"].as_str().unwrap_or_default().contains("unknown scenario 'made-up'"), "{body}");
        let (_, body) = get_json(&client, &control).await;
        assert_eq!(body["source"], "baseline", "a refused name must not have changed anything");

        let response = client
            .post(&control)
            .header("content-type", "text/plain")
            .body(r#"{ "name": "pricing-down" }"#)
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            415,
            "a non-JSON content type is refused outright — this is what keeps a cross-origin form post from flipping the scenario"
        );
        let (_, body) = get_json(&client, &control).await;
        assert_eq!(body["source"], "baseline");
    }

    #[tokio::test]
    async fn scenario_precedence_is_header_over_control_plane_over_flag_over_baseline() {
        let project = mock_project().await;
        let opts = TestServerOptions {
            scenario: Some("pricing-down".to_string()),
            ..default_opts()
        };
        let (base, _) = serve_mock(&project, opts).await;
        let client = reqwest::Client::new();
        let control = format!("{base}/_frogs/scenario");

        let (_, body) = get_json(&client, &control).await;
        assert_eq!(body["scenario"], "pricing-down");
        assert_eq!(body["source"], "flag");
        let (_, body) = get_json(&client, &format!("{base}/cars/AAA")).await;
        assert_eq!(body["maker"], "Scenario", "the --scenario flag is the default for every request");

        client.post(&control).json(&serde_json::json!({ "name": "db-down" })).send().await.unwrap();
        let (status, body) = get_json(&client, &format!("{base}/cars/AAA")).await;
        assert_eq!(status, 500, "the control plane beats the flag — db-down's mocked failure now serves: {body}");
        assert_eq!(body["name"], "datasource.sql.connection_failed");

        let response = client
            .get(format!("{base}/cars/AAA"))
            .header("X-Frogs-Scenario", "pricing-down")
            .send()
            .await
            .unwrap();
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["maker"], "Scenario", "the header beats the control plane");

        client.delete(&control).send().await.unwrap();
        let (_, body) = get_json(&client, &control).await;
        assert_eq!(body["source"], "flag", "clearing the override falls back to the flag, not the baseline");
    }

    #[tokio::test]
    async fn a_value_saved_by_a_post_case_matches_a_later_get_through_a_memory_placeholder() {
        let project = mock_project().await;
        let (base, session) = serve_mock(&project, default_opts()).await;
        let client = reqwest::Client::new();

        let (status, _) = get_json(&client, &format!("{base}/cars/NEW123")).await;
        assert_eq!(status, 404, "before anything is saved the {{{{memory.vin}}}} case can't match");

        let response = client
            .post(format!("{base}/cars"))
            .json(&serde_json::json!({ "maker": "Honda" }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 201);
        let body: Value = response.json().await.unwrap();
        assert_eq!(body, serde_json::json!({ "vin": "NEW123" }));

        let (status, body) = get_json(&client, &format!("{base}/cars/NEW123")).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["maker"], "FromMemory", "the GET on another route matched via the vin the POST case saved");

        assert_eq!(project.upstream.hits(), 0);
        let summary = session.summary();
        assert_eq!((summary.unmatched, summary.passed), (1, 2));
    }

    #[tokio::test]
    async fn a_json_report_file_records_every_request_with_its_scenario_once_the_session_finishes() {
        let project = mock_project().await;
        let report_path = project.root.join("report.json");
        let opts = TestServerOptions {
            report: ReportFormat::Json,
            report_file: Some(report_path.clone()),
            ..default_opts()
        };
        let (base, session) = serve_mock(&project, opts).await;
        let client = reqwest::Client::new();

        get_json(&client, &format!("{base}/cars/AAA")).await;
        client
            .get(format!("{base}/cars/AAA"))
            .header("X-Frogs-Scenario", "pricing-down")
            .send()
            .await
            .unwrap();
        get_json(&client, &format!("{base}/cars/CCC")).await;

        let summary = session.finish();
        assert_eq!(summary.requests, 3);
        assert!(summary.has_problems(), "the unmocked required source must flip the exit-code rule");

        let report: Value = serde_json::from_str(&std::fs::read_to_string(&report_path).unwrap()).expect("the report file must be valid JSON");
        assert_eq!(report["summary"]["requests"], 3);
        assert_eq!(report["summary"]["passed"], 2);
        assert_eq!(report["summary"]["notMocked"], 1);
        assert_eq!(report["entries"][0]["scenario"], Value::Null);
        assert_eq!(report["entries"][1]["scenario"], "pricing-down");
        assert_eq!(report["entries"][1]["scenarioSource"], "header");
        assert_eq!(report["entries"][1]["case"], "pricing down");
        assert_eq!(report["entries"][2]["verdict"], "notMocked");
        assert_eq!(report["entries"][2]["unmocked"][0]["name"], "car");

        let leftovers: Vec<String> = std::fs::read_dir(&project.root)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    /// The harness codes are inserted into the loaded registry at startup
    /// specifically so they classify like any other code — under
    /// `debugMode` (the only mode that writes the discovery scratch file)
    /// a 501/404/400 from the harness must not create
    /// `config/errors.discovered.json`.
    #[tokio::test]
    async fn harness_error_codes_never_land_in_the_discovered_errors_scratch_file_even_under_debug_mode() {
        let project = mock_project().await;
        let api = crate::project::api_base(&project.root);
        std::fs::write(api.join("config/server.json"), r#"{ "debugMode": true, "features": { "requestValidation": false } }"#).unwrap();
        let (base, _) = serve_mock(&project, default_opts()).await;
        let client = reqwest::Client::new();

        let (status, _) = get_json(&client, &format!("{base}/cars/CCC")).await;
        assert_eq!(status, 501);
        let (status, _) = get_json(&client, &format!("{base}/cars/ZZZ")).await;
        assert_eq!(status, 404);
        let response = client.get(format!("{base}/cars/AAA")).header("X-Frogs-Scenario", "made-up").send().await.unwrap();
        assert_eq!(response.status(), 400);

        assert!(
            !api.join("config/errors.discovered.json").is_file(),
            "test.source_not_mocked / test.no_matching_case / test.unknown_scenario are registry entries, not discoveries"
        );
    }

    /// A project that classifies a harness code itself keeps its own
    /// definition end to end — the served status is the project's, not the
    /// harness default.
    #[tokio::test]
    async fn a_project_defined_harness_code_wins_over_the_harness_default_when_served() {
        let project = mock_project().await;
        let api = crate::project::api_base(&project.root);
        std::fs::write(
            api.join("config/errors/harness.json"),
            r#"{ "test.no_matching_case": { "httpStatus": 422, "exposeDetail": false } }"#,
        )
        .unwrap();
        let (base, _) = serve_mock(&project, default_opts()).await;
        let client = reqwest::Client::new();

        let (status, body) = get_json(&client, &format!("{base}/cars/ZZZ")).await;
        assert_eq!(status, 422, "{body}");
        assert_eq!(body["name"], NO_MATCHING_CASE);
        assert!(body.get("detail").is_none(), "the project said exposeDetail: false, so no detail: {body}");
    }
}
