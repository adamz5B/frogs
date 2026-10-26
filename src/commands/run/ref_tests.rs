//! Startup behaviour for `$ref` resolution failures: unresolved parameter refs refuse only when
//! request validation is actually on and a routed file exists, strict refuses every new issue
//! kind, and all of it happens before connections, bind or pidfile.

use super::*;

const SPEC_HEAD: &str = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\ncomponents:\n  securitySchemes:\n    a: { type: apiKey, in: header, name: ka }\npaths:\n";
const UNRESOLVED_PARAM: &str =
    "  /x:\n    get:\n      operationId: getX\n      parameters:\n        - $ref: '#/components/parameters/Gone'\n      responses: { '200': { description: ok } }\n";

fn tempdir() -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "frogs-run-refs-{}-{}-{n}",
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
    fn new(server_json: &str, paths: &str) -> Fx {
        let root = tempdir();
        let api = root.join("api");
        for dir in ["config/errors", "security", "datasources/endpoints"] {
            std::fs::create_dir_all(api.join(dir)).unwrap();
        }
        std::fs::write(root.join("openapi.yaml"), format!("{SPEC_HEAD}{paths}")).unwrap();
        std::fs::write(api.join("config/server.json"), server_json).unwrap();
        std::fs::write(api.join("config/errors/core.json"), "{}").unwrap();
        std::fs::write(api.join("config/connections.json"), r#"{ "main": { "driver": "nosuchdriver", "url": "nowhere" } }"#).unwrap();
        std::fs::write(api.join("security/schemes.json"), "{}").unwrap();
        Fx { root }
    }

    fn endpoint(&self, folder: &str, token: &str) {
        let dir = self.root.join("api/datasources/endpoints").join(folder);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("endpoint.{token}.json")), r#"{ "operationId": "x", "sources": {}, "response": {} }"#).unwrap();
    }

    fn startup(&self) -> io::Result<(Option<Arc<crate::openapi::OpenApiDocument>>, StartupSecurityReport)> {
        let server = Config::load(&self.root.join("api")).unwrap().server;
        let tree = startup_endpoint_tree(&self.root, &server).unwrap();
        load_openapi_for_startup_reported(&self.root, &server, " HINT-TEXT", &tree, crate::endpoint::route_plan::RootExtras::default())
    }
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

const VALIDATION_ON: &str = r#"{ "features": { "requestValidation": true, "metrics": false, "readyzCheck": false } }"#;
const VALIDATION_OFF: &str = r#"{ "features": { "requestValidation": false, "metrics": false, "readyzCheck": false } }"#;

#[test]
fn with_request_validation_on_a_routed_file_and_an_unresolved_parameter_ref_refuse_startup() {
    let fx = Fx::new(VALIDATION_ON, UNRESOLVED_PARAM);
    fx.endpoint("x", "get");
    let err = fx.startup().map(|_| ()).expect_err("must refuse");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    let text = err.to_string();
    assert!(text.contains("parameter $ref frogs could not resolve") && text.contains("HINT-TEXT"), "{text}");
}

#[test]
fn with_request_validation_off_the_same_project_starts_and_the_issue_stays_a_load_issue() {
    let fx = Fx::new(VALIDATION_OFF, UNRESOLVED_PARAM);
    fx.endpoint("x", "get");
    let (doc, _report) = fx.startup().expect("starts");
    assert!(doc.is_none(), "the spec is only handed over when something needs it");
}

#[test]
fn an_unresolved_parameter_ref_without_a_routed_file_does_not_refuse() {
    let fx = Fx::new(VALIDATION_ON, UNRESOLVED_PARAM);
    fx.startup().expect("no file for the operation: nothing to validate wrongly");
}

#[test]
fn an_unresolved_parameter_ref_on_a_different_route_than_the_file_does_not_refuse() {
    let fx = Fx::new(
        VALIDATION_ON,
        &format!("{UNRESOLVED_PARAM}  /y:\n    get:\n      operationId: getY\n      responses: {{ '200': {{ description: ok }} }}\n"),
    );
    fx.endpoint("y", "get");
    fx.startup().expect("only /x is incomplete");
}

#[test]
fn docs_ui_alone_does_not_trigger_the_parameter_ref_refusal() {
    let fx = Fx::new(r#"{ "features": { "requestValidation": false }, "docsUi": { "enabled": true } }"#, UNRESOLVED_PARAM);
    fx.endpoint("x", "get");
    fx.startup().expect("docs only: not refused (strict would refuse via the issue)");
}

#[test]
fn the_parameter_ref_refusal_happens_before_connections_are_opened_and_before_any_pidfile() {
    let fx = Fx::new(VALIDATION_ON, UNRESOLVED_PARAM);
    fx.endpoint("x", "get");
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let err = rt.block_on(build_api_router(&fx.root, false)).map(|_| ()).expect_err("must refuse");
    assert!(err.to_string().contains("parameter $ref frogs could not resolve"), "{err}");
    assert!(!err.to_string().to_lowercase().contains("nosuchdriver"));
    assert!(!fx.root.join(".frogs/run.json").exists());
}

#[test]
fn strict_mode_refuses_each_new_unresolved_kind_and_the_sibling_warning() {
    let cases = [
        (
            "parameter",
            "  /x:\n    get:\n      operationId: g\n      parameters: [ { $ref: '#/components/parameters/Gone' } ]\n      responses: { '200': { description: ok } }\n",
        ),
        (
            "request body",
            "  /x:\n    post:\n      operationId: g\n      requestBody: { $ref: '#/components/requestBodies/Gone' }\n      responses: { '200': { description: ok } }\n",
        ),
        (
            "response",
            "  /x:\n    get:\n      operationId: g\n      responses: { '200': { $ref: '#/components/responses/Gone' } }\n",
        ),
        ("path item", "  /x:\n    $ref: '#/components/pathItems/Gone'\n"),
        (
            "sibling",
            "  /x:\n    get:\n      operationId: g\n      parameters: [ { $ref: '#/components/parameters/P', required: true } ]\n      responses: { '200': { description: ok } }\n",
        ),
    ];
    for (label, paths) in cases {
        let spec = format!("{SPEC_HEAD}{paths}").replace("components:\n", "components:\n  parameters:\n    P: { name: p, in: query }\n");
        let fx = Fx::new(r#"{ "strictOpenApi": true, "features": { "requestValidation": false } }"#, paths);
        std::fs::write(fx.root.join("openapi.yaml"), spec).unwrap();
        let err = fx.startup().map(|_| ()).expect_err(label);
        assert!(err.to_string().contains("strictOpenApi"), "{label}: {err}");
        let lax = Fx::new(VALIDATION_OFF, paths);
        std::fs::write(
            lax.root.join("openapi.yaml"),
            format!("{SPEC_HEAD}{paths}").replace("components:\n", "components:\n  parameters:\n    P: { name: p, in: query }\n"),
        )
        .unwrap();
        lax.startup().unwrap_or_else(|e| panic!("{label} must only warn when not strict: {e}"));
    }
}

#[test]
fn the_unresolved_parameter_list_names_at_most_five_refs_then_an_ellipsis_and_escapes_control_characters() {
    let refs: Vec<String> = (0..7).map(|i| format!("#/components/parameters/P{i}")).collect();
    let shown = crate::endpoint::unresolved_parameter_ref_list(&refs);
    assert!(shown.contains("P4") && !shown.contains("P5") && shown.ends_with('…'), "{shown}");
    let hostile = crate::endpoint::unresolved_parameter_ref_list(&["a\u{1b}[31m\nb".to_string()]);
    assert!(!hostile.chars().any(|c| c.is_control()), "{hostile:?}");
    assert_eq!(
        crate::endpoint::unresolved_parameter_ref_list(&refs[..2]),
        "#/components/parameters/P0, #/components/parameters/P1"
    );
}
