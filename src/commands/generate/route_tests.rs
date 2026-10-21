//! `frogs generate`: spec paths the route table can't carry, hand-made folder
//! conflicts and the spec -> file security findings all end up in the outcome's
//! errors (exit 1), and nothing unsafe is ever created from spec text.

use super::*;

fn tempdir() -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "frogs-gen-routes-{}-{}-{n}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct Fx {
    root: PathBuf,
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

const HEAD: &str = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\ncomponents:\n  securitySchemes:\n    a: { type: apiKey, in: header, name: ka }\npaths:\n";

fn op(path: &str, method: &str, id: &str, secured: bool) -> String {
    let security = if secured { "      security: [ { a: [] } ]\n" } else { "" };
    format!("  '{path}':\n    {method}:\n      operationId: {id}\n{security}      responses: {{ '200': {{ description: ok }} }}\n")
}

fn fx(server_json: Option<&str>, paths: &str) -> Fx {
    let root = tempdir();
    std::fs::write(root.join("openapi.yaml"), format!("{HEAD}{paths}")).unwrap();
    if let Some(json) = server_json {
        std::fs::create_dir_all(root.join("api/config")).unwrap();
        std::fs::write(root.join("api/config/server.json"), json).unwrap();
    }
    Fx { root }
}

fn endpoints(fx: &Fx) -> PathBuf {
    fx.root.join("api/datasources/endpoints")
}

fn put_endpoint(fx: &Fx, folder: &str, token: &str, security: Option<&str>) {
    let dir = endpoints(fx).join(folder);
    std::fs::create_dir_all(&dir).unwrap();
    let body = match security {
        Some(s) => format!(r#"{{ "operationId": "x", "security": "{s}", "sources": {{}}, "response": {{}} }}"#),
        None => r#"{ "operationId": "x", "sources": {}, "response": {} }"#.to_string(),
    };
    std::fs::write(dir.join(format!("endpoint.{token}.json")), body).unwrap();
}

#[test]
fn a_colon_path_in_the_spec_is_skipped_creates_no_folder_and_makes_generate_fail() {
    let fx = fx(None, &(op("/a:b", "get", "colon", false) + &op("/ok", "get", "ok", false)));
    let outcome = generate_api_inner(&fx.root).unwrap();
    assert!(!outcome.errors.is_empty(), "a skipped path is an error (exit 1)");
    assert!(outcome.errors.iter().any(|e| e.contains("a:b")), "{:?}", outcome.errors);
    let created: Vec<String> = std::fs::read_dir(endpoints(&fx))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(created.contains(&"ok".to_string()), "{created:?}");
    assert!(
        created.iter().all(|n| !n.contains(':')),
        "no folder may be created from the skipped path: {created:?}"
    );
}

#[test]
fn strict_generate_refuses_a_partial_template_path_before_writing_any_endpoint_folder() {
    let fx = fx(Some(r#"{ "strictOpenApi": true }"#), &op("/x/{id}.json", "get", "partial", false));
    let outcome = generate_api_inner(&fx.root).unwrap();
    assert!(outcome.strict_aborted, "{:?}", outcome.errors);
    assert!(!endpoints(&fx).join("x").exists());
}

#[test]
fn a_partial_template_path_without_strict_is_generated_with_only_a_warning() {
    let fx = fx(None, &op("/x/{id}.json", "get", "partial", false));
    let outcome = generate_api_inner(&fx.root).unwrap();
    assert!(!outcome.strict_aborted);
    assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
}

#[test]
fn a_hand_made_parameter_name_conflict_between_folders_is_a_generate_error() {
    let fx = fx(None, &op("/other", "get", "other", false));
    put_endpoint(&fx, "x/{a}", "get", None);
    put_endpoint(&fx, "x/{b}", "get", None);
    let outcome = generate_api_inner(&fx.root).unwrap();
    assert!(outcome.errors.iter().any(|e| e.contains("different parameter names")), "{:?}", outcome.errors);
}

#[test]
fn a_folder_on_a_builtin_route_is_a_generate_error() {
    let fx = fx(None, &op("/other", "get", "other", false));
    put_endpoint(&fx, "healthz", "get", None);
    let outcome = generate_api_inner(&fx.root).unwrap();
    assert!(outcome.errors.iter().any(|e| e.contains("built-in /healthz")), "{:?}", outcome.errors);
}

#[test]
fn a_folder_on_the_scenario_control_plane_is_reported_as_a_frogs_test_refusal() {
    let fx = fx(None, &op("/other", "get", "other", false));
    put_endpoint(&fx, "_frogs/scenario", "get", None);
    let outcome = generate_api_inner(&fx.root).unwrap();
    assert!(outcome.errors.iter().any(|e| e.contains("frogs test would refuse to start")), "{:?}", outcome.errors);
}

#[test]
fn a_secured_skipped_path_whose_open_parameter_route_would_answer_it_is_a_generate_error() {
    let fx = fx(None, &(op("/v1/{id}:cancel", "post", "cancel", true) + &op("/v1/{id}", "post", "make", false)));
    put_endpoint(&fx, "v1/{id}", "post", None);
    let outcome = generate_api_inner(&fx.root).unwrap();
    assert!(
        outcome
            .errors
            .iter()
            .any(|e| e.contains("openapi.yaml requires security") && e.contains("v1/{id}:cancel")),
        "{:?}",
        outcome.errors
    );
}

#[test]
fn a_clean_project_still_generates_without_route_or_security_errors() {
    let fx = fx(None, &(op("/cars/{id}", "get", "byId", true) + &op("/cars", "get", "list", false)));
    let outcome = generate_api_inner(&fx.root).unwrap();
    assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
}
