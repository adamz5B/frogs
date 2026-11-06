//! `frogs validate` counts route-table and spec -> file security findings as problems.

use super::*;
use std::fs;

const HEAD: &str = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\ncomponents:\n  securitySchemes:\n    a: { type: apiKey, in: header, name: ka }\npaths:\n";
const OTHER: &str = "  /other:\n    get:\n      operationId: other\n      responses: { '200': { description: ok } }\n";

fn tempdir() -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "frogs-validate-routes-{}-{}-{n}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

struct Fx {
    root: PathBuf,
}

impl Fx {
    fn new(server_json: &str, paths: &str) -> Fx {
        let root = tempdir();
        fs::create_dir_all(root.join("api/config")).unwrap();
        fs::create_dir_all(root.join("api/datasources/endpoints")).unwrap();
        fs::write(root.join("api/config/server.json"), server_json).unwrap();
        fs::write(root.join(MANIFEST_FILE), format!("{HEAD}{paths}")).unwrap();
        Fx { root }
    }

    fn endpoint(&self, folder: &str, token: &str, security: Option<&str>) {
        let dir = self.root.join("api/datasources/endpoints").join(folder);
        fs::create_dir_all(&dir).unwrap();
        let body = match security {
            Some(s) => format!(r#"{{ "operationId": "x", "security": "{s}", "sources": {{}}, "response": {{}} }}"#),
            None => r#"{ "operationId": "x", "sources": {}, "response": {} }"#.to_string(),
        };
        fs::write(dir.join(format!("endpoint.{token}.json")), body).unwrap();
    }
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

const LAX: &str = r#"{ "features": { "metrics": false, "readyzCheck": false } }"#;
const STRICT: &str = r#"{ "strictOpenApi": true, "features": { "metrics": false, "readyzCheck": false } }"#;

#[tokio::test]
async fn a_project_with_no_route_problems_reports_none() {
    let fx = Fx::new(LAX, OTHER);
    fx.endpoint("other", "get", None);
    assert_eq!(validate_api(&fx.root).await, 0);
}

#[tokio::test]
async fn a_parameter_name_conflict_between_folders_is_a_problem() {
    let fx = Fx::new(LAX, OTHER);
    fx.endpoint("other", "get", None);
    fx.endpoint("x/{a}", "get", None);
    fx.endpoint("x/{b}", "get", None);
    assert!(validate_api(&fx.root).await >= 1);
}

#[tokio::test]
async fn a_folder_on_the_healthz_builtin_is_a_problem() {
    let fx = Fx::new(LAX, OTHER);
    fx.endpoint("other", "get", None);
    fx.endpoint("healthz", "get", None);
    assert!(validate_api(&fx.root).await >= 1);
}

#[tokio::test]
async fn a_partial_template_folder_is_a_problem_only_under_strict() {
    let lax = Fx::new(LAX, OTHER);
    lax.endpoint("other", "get", None);
    lax.endpoint("p/{id}.json", "get", None);
    let lax_problems = validate_api(&lax.root).await;
    let strict = Fx::new(STRICT, OTHER);
    strict.endpoint("other", "get", None);
    strict.endpoint("p/{id}.json", "get", None);
    let strict_problems = validate_api(&strict.root).await;
    assert!(strict_problems > lax_problems, "lax {lax_problems}, strict {strict_problems}");
}

#[tokio::test]
async fn a_shadowed_secured_operation_is_a_problem_even_without_strict_and_the_same_layout_without_security_is_clean() {
    let paths = "  /cars/admin:\n    get:\n      operationId: admin\n      security: [ { a: [] } ]\n      responses: { '200': { description: ok } }\n  /cars/{id}:\n    get:\n      operationId: byId\n      responses: { '200': { description: ok } }\n";
    let shadowed = Fx::new(LAX, paths);
    shadowed.endpoint("cars/{id}", "get", None);
    let before = validate_api(&shadowed.root).await;
    assert!(before >= 1);
    let open_paths = paths.replace("      security: [ { a: [] } ]\n", "");
    let open_spec = Fx::new(LAX, &open_paths);
    open_spec.endpoint("cars/{id}", "get", None);
    assert_eq!(
        validate_api(&open_spec.root).await,
        0,
        "the same layout with no security in the spec has nothing to shadow"
    );
}

#[tokio::test]
async fn an_unmatched_file_is_a_problem_only_under_strict() {
    let lax = Fx::new(LAX, OTHER);
    lax.endpoint("other", "get", None);
    lax.endpoint("stray", "get", None);
    let strict = Fx::new(STRICT, OTHER);
    strict.endpoint("other", "get", None);
    strict.endpoint("stray", "get", None);
    assert_eq!(validate_api(&lax.root).await, 0);
    assert!(validate_api(&strict.root).await >= 1);
}
