//! Startup refusals for route-table problems and the spec -> file security
//! checks (`frogs run`, the `register` precheck): they happen before any
//! connection, bind or pidfile, whatever `strictOpenApi` says.

use super::*;

const SPEC_HEAD: &str = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\ncomponents:\n  securitySchemes:\n    a: { type: apiKey, in: header, name: ka }\npaths:\n";
const SECURED_ADMIN: &str = "  /cars/admin:\n    get:\n      operationId: admin\n      security: [ { a: [] } ]\n      responses: { '200': { description: ok } }\n  /cars/{id}:\n    get:\n      operationId: byId\n      responses: { '200': { description: ok } }\n";

fn tempdir() -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "frogs-run-routes-{}-{}-{n}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct Fx {
    root: PathBuf,
}

impl Fx {
    /// `server_json` is the whole `config/server.json`; `paths` is appended to the spec header.
    fn new(server_json: &str, paths: &str) -> Fx {
        let root = tempdir();
        let api = root.join("api");
        for dir in ["config/errors", "security", "datasources/endpoints"] {
            std::fs::create_dir_all(api.join(dir)).unwrap();
        }
        std::fs::write(root.join("openapi.yaml"), format!("{SPEC_HEAD}{paths}")).unwrap();
        std::fs::write(api.join("config/server.json"), server_json).unwrap();
        std::fs::write(api.join("config/errors/core.json"), "{}").unwrap();
        // A driver that does not exist: reaching `connect_all` would surface a connection error instead of the refusal under test.
        std::fs::write(api.join("config/connections.json"), r#"{ "main": { "driver": "nosuchdriver", "url": "nowhere" } }"#).unwrap();
        std::fs::write(api.join("security/schemes.json"), "{}").unwrap();
        Fx { root }
    }

    fn endpoint(&self, folder: &str, token: &str, security: Option<&str>) {
        let dir = self.root.join("api/datasources/endpoints").join(folder);
        std::fs::create_dir_all(&dir).unwrap();
        let body = match security {
            Some(s) => format!(r#"{{ "operationId": "x", "security": "{s}", "sources": {{}}, "response": {{}} }}"#),
            None => r#"{ "operationId": "x", "sources": {}, "response": {} }"#.to_string(),
        };
        std::fs::write(dir.join(format!("endpoint.{token}.json")), body).unwrap();
    }

    fn server(&self) -> ServerConfig {
        Config::load(&self.root.join("api")).unwrap().server
    }

    fn tree(&self) -> Arc<EndpointTree> {
        startup_endpoint_tree(&self.root, &self.server()).unwrap()
    }

    fn startup(&self, hint: &str) -> io::Result<(Option<Arc<crate::openapi::OpenApiDocument>>, StartupSecurityReport)> {
        load_openapi_for_startup_reported(&self.root, &self.server(), hint, &self.tree())
    }
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

const QUIET: &str = r#"{ "features": { "requestValidation": false, "metrics": false, "readyzCheck": false } }"#;
const NO_PATHS: &str = "  /unused:
    get:
      operationId: unused
      responses: { '200': { description: ok } }
";

// ------------------------------------------------------------------- T1.15 / T1.16

#[test]
fn check_route_table_refuses_a_folder_on_a_builtin_path_with_the_counted_message_and_the_hint() {
    let fx = Fx::new(QUIET, NO_PATHS);
    fx.endpoint("healthz", "get", None);
    let err = check_route_table(&fx.server(), &fx.tree(), RootExtras::default(), " HINT-TEXT")
        .map(|_| ())
        .expect_err("must refuse");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    let text = err.to_string();
    assert!(
        text.starts_with("1 route problem(s)") && text.contains("refusing to start; run frogs validate HINT-TEXT"),
        "{text}"
    );
}

#[tokio::test]
async fn assemble_api_router_refuses_a_builtin_collision_with_an_error_instead_of_panicking() {
    let fx = Fx::new(QUIET, NO_PATHS);
    fx.endpoint("healthz", "get", None);
    let config = Config::load(&fx.root.join("api")).unwrap();
    let result = assemble_api_router(&fx.root, config, Arc::new(HashMap::new()), None, None, fx.tree()).await;
    let err = result.map(|_| ()).expect_err("must refuse");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn a_route_conflict_is_refused_before_connections_are_opened_and_before_any_pidfile() {
    let fx = Fx::new(QUIET, NO_PATHS);
    fx.endpoint("x/{a}", "get", None);
    fx.endpoint("x/{b}", "get", None);
    let err = build_api_router(&fx.root, false).await.map(|_| ()).expect_err("must refuse");
    assert!(err.to_string().contains("route problem(s)"), "{err}");
    assert!(
        !err.to_string().to_lowercase().contains("nosuchdriver"),
        "the route refusal must win over the connection error: {err}"
    );
    assert!(!fx.root.join(".frogs/run.json").exists());
}

#[tokio::test]
async fn a_root_endpoint_collides_with_the_web_root_unless_api_root_moves_the_api_off_the_root() {
    let fx = Fx::new(QUIET, NO_PATHS);
    fx.endpoint("", "get", None);
    let both = build_api_router(&fx.root, true).await.map(|_| ()).expect_err("web role: `/` collides");
    assert!(both.to_string().contains("route problem(s)"), "{both}");
    let err_text = both.to_string();
    assert!(!err_text.to_lowercase().contains("nosuchdriver"), "{err_text}");
    // API-only: no web `/` to collide with, so the refusal is not about routes (it reaches the bad connection instead).
    let fx = Fx::new(r#"{ "features": { "requestValidation": false }, "apiRoot": "/api" }"#, NO_PATHS);
    fx.endpoint("", "get", None);
    assert!(check_route_table(&fx.server(), &fx.tree(), RootExtras { web: true, control_plane: false }, "").is_ok());
}

#[test]
fn the_service_precheck_refuses_a_route_problem_with_the_restart_loop_hint_and_passes_a_clean_project() {
    let fx = Fx::new(QUIET, NO_PATHS);
    fx.endpoint("x/{a}", "get", None);
    fx.endpoint("x/{b}", "get", None);
    let err = precheck_security_for_service(&fx.root).expect_err("must refuse");
    let text = err.to_string();
    assert!(text.contains("route problem(s)") && text.contains("restarts every 5 s"), "{text}");
}

#[test]
fn the_service_precheck_counts_a_web_root_collision_only_when_webserve_json_exists() {
    let fx = Fx::new(QUIET, NO_PATHS);
    fx.endpoint("", "get", None);
    let without = precheck_security_for_service(&fx.root);
    assert!(without.is_ok(), "{without:?}");
    std::fs::write(fx.root.join("webserve.json"), "{}").unwrap();
    let err = precheck_security_for_service(&fx.root).expect_err("the web root now collides");
    assert!(err.to_string().contains("route problem(s)"), "{err}");
}

#[test]
fn a_partial_template_folder_only_warns_normally_and_refuses_under_strict() {
    let fx = Fx::new(QUIET, NO_PATHS);
    fx.endpoint("p/{id}.json", "get", None);
    assert!(check_route_table(&fx.server(), &fx.tree(), RootExtras::default(), "").is_ok());
    let strict = Fx::new(r#"{ "strictOpenApi": true, "features": { "requestValidation": false } }"#, NO_PATHS);
    strict.endpoint("p/{id}.json", "get", None);
    let err = check_route_table(&strict.server(), &strict.tree(), RootExtras::default(), "")
        .map(|_| ())
        .expect_err("strict refuses");
    assert!(err.to_string().contains("route problem(s)"), "{err}");
}

#[test]
fn an_invalid_api_root_in_server_json_is_refused_not_a_panic() {
    let fx = Fx::new(r#"{ "apiRoot": "a:b", "features": { "requestValidation": false } }"#, NO_PATHS);
    fx.endpoint("x", "get", None);
    let err = check_route_table(&fx.server(), &fx.tree(), RootExtras::default(), "")
        .map(|_| ())
        .expect_err("must refuse");
    assert!(err.to_string().contains("route problem(s)"), "{err}");
}

// ------------------------------------------------------------------- T2.1

#[test]
fn a_shadowed_secured_operation_refuses_startup_with_strict_request_validation_and_docs_all_off() {
    let fx = Fx::new(QUIET, SECURED_ADMIN);
    fx.endpoint("cars/{id}", "get", None);
    let err = fx.startup(" HINT-TEXT").map(|_| ()).expect_err("must refuse");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    let text = err.to_string();
    assert!(
        text.contains("would be answered by a route that does not enforce their security") && text.contains("HINT-TEXT"),
        "{text}"
    );
}

#[test]
fn the_service_precheck_refuses_a_shadowed_secured_operation_with_the_hint() {
    let fx = Fx::new(QUIET, SECURED_ADMIN);
    fx.endpoint("cars/{id}", "get", None);
    let err = precheck_security_for_service(&fx.root).expect_err("must refuse");
    assert!(err.to_string().contains("restarts every 5 s"), "{err}");
}

#[test]
fn a_shadow_whose_serving_file_declares_the_scheme_starts_normally() {
    let fx = Fx::new(QUIET, SECURED_ADMIN);
    fx.endpoint("cars/{id}", "get", Some("a"));
    fx.endpoint("cars/admin", "get", Some("a"));
    assert!(fx.startup("").is_ok());
}

#[test]
fn the_spec_is_returned_only_when_something_needs_it_even_though_the_checks_always_run() {
    let fx = Fx::new(QUIET, NO_PATHS);
    let (doc, _) = fx.startup("").unwrap();
    assert!(doc.is_none(), "N9: nothing asked for the document");
    let needed = Fx::new("{}", NO_PATHS);
    let (doc, _) = needed.startup("").unwrap();
    assert!(doc.is_some(), "requestValidation is on by default");
}

// ------------------------------------------------------------------- T2.12 / FR-9

#[test]
fn a_document_default_secured_healthz_is_a_logged_warning_in_the_report_and_startup_succeeds() {
    let spec = "  /healthz:\n    get:\n      operationId: h\n      responses: { '200': { description: ok } }\n";
    let top_security = format!("{SPEC_HEAD}{spec}").replace("components:", "security: [ { a: [] } ]\ncomponents:");
    let fx = Fx::new(QUIET, spec);
    std::fs::write(fx.root.join("openapi.yaml"), top_security).unwrap();
    let (_, report) = fx.startup("").expect("an inherited default on /healthz is only a warning");
    assert_eq!(report.builtin_warnings.len(), 1, "{:?}", report.builtin_warnings);
    assert!(report.builtin_warnings[0].contains("security: []"));
}

#[test]
fn an_operation_level_secured_metrics_operation_refuses_startup_when_metrics_is_on() {
    let spec = "  /metrics:\n    get:\n      operationId: m\n      security: [ { a: [] } ]\n      responses: { '200': { description: ok } }\n";
    let on = Fx::new(r#"{ "features": { "requestValidation": false, "metrics": true } }"#, spec);
    let err = on.startup("").map(|_| ()).expect_err("must refuse");
    assert!(err.to_string().contains("would be answered by a route that does not enforce their security"), "{err}");
    let off = Fx::new(QUIET, spec);
    assert!(off.startup("").is_ok(), "metrics off: no built-in route to answer it");
}

// ------------------------------------------------------------------- T3.1 / T3.9

#[test]
fn an_unmatched_file_is_only_a_warning_normally_and_a_refusal_under_strict() {
    let spec = "  /other:\n    get:\n      operationId: o\n      responses: { '200': { description: ok } }\n";
    let lax = Fx::new(QUIET, spec);
    lax.endpoint("stray", "get", None);
    let (_, report) = lax.startup("").unwrap();
    assert_eq!(report.unmatched.len(), 1);

    let strict = Fx::new(r#"{ "strictOpenApi": true, "features": { "requestValidation": false } }"#, spec);
    strict.endpoint("stray", "get", None);
    strict.endpoint("other", "get", None);
    let err = strict.startup(" HINT-TEXT").map(|_| ()).expect_err("strict refuses an unmatched file");
    let text = err.to_string();
    assert!(
        text.contains("match no openapi.yaml operation") && text.contains("strictOpenApi") && text.contains("HINT-TEXT"),
        "{text}"
    );
}

#[tokio::test]
async fn the_strict_unmatched_refusal_happens_before_connections_are_opened_and_before_any_pidfile() {
    let strict = Fx::new(r#"{ "strictOpenApi": true, "features": { "requestValidation": false } }"#, NO_PATHS);
    strict.endpoint("stray", "get", None);
    let err = build_api_router(&strict.root, false).await.map(|_| ()).expect_err("must refuse");
    assert!(err.to_string().contains("match no openapi.yaml operation"), "{err}");
    assert!(!err.to_string().to_lowercase().contains("nosuchdriver"));
    assert!(!strict.root.join(".frogs/run.json").exists());
}

#[test]
fn an_unconditional_stale_variant_refusal_does_not_depend_on_strict() {
    let spec =
        "  /x:\n    additionalOperations:\n      purge:\n        operationId: p\n        security: [ { a: [] } ]\n        responses: { '200': { description: ok } }\n";
    let fx = Fx::new(r#"{ "caseSensitiveMethods": true, "features": { "requestValidation": false } }"#, spec);
    fx.endpoint("x", "PURGE", None);
    let err = fx.startup("").map(|_| ()).expect_err("must refuse");
    assert!(err.to_string().contains("another method spelling"), "{err}");
}

#[test]
fn an_unconditional_template_instance_refusal_does_not_depend_on_strict() {
    let spec = "  /cars/{id}:\n    get:\n      operationId: byId\n      security: [ { a: [] } ]\n      responses: { '200': { description: ok } }\n";
    let fx = Fx::new(QUIET, spec);
    fx.endpoint("cars/new", "get", None);
    let err = fx.startup("").map(|_| ()).expect_err("must refuse");
    assert!(err.to_string().contains("instances of a secured openapi.yaml path template"), "{err}");
}

// ------------------------------------------------------------------- same template, different parameter names

const ITEM_ID_AND_ID: &str = "  /items/{itemId}:\n    get:\n      operationId: byItemId\n      security: [ { a: [] } ]\n      responses: { '200': { description: ok } }\n  /items/{id}:\n    get:\n      operationId: byId\n      responses: { '200': { description: ok } }\n";

#[test]
fn a_secured_template_declared_twice_with_different_parameter_names_refuses_startup_even_when_not_strict() {
    let fx = Fx::new(QUIET, ITEM_ID_AND_ID);
    fx.endpoint("items/{id}", "get", None);
    let err = fx.startup("").map(|_| ()).expect_err("must refuse");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    let text = err.to_string();
    assert!(text.contains("would be answered by a route that does not enforce their security"), "{text}");
}

#[test]
fn the_same_twice_declared_template_layout_starts_when_the_serving_file_declares_the_scheme() {
    let fx = Fx::new(QUIET, ITEM_ID_AND_ID);
    fx.endpoint("items/{id}", "get", Some("a"));
    assert!(fx.startup("").is_ok());
}
