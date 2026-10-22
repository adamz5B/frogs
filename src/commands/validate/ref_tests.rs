//! `frogs validate` reports an unresolved parameter `$ref` on a routed endpoint file as a problem.

use super::*;
use std::fs;

fn project(spec: &str, with_file: bool) -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "frogs-validate-refs-{}-{}-{n}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir_all(root.join("api/config")).unwrap();
    fs::create_dir_all(root.join("api/datasources/endpoints/x")).unwrap();
    fs::write(root.join("api/config/server.json"), "{}").unwrap();
    fs::write(root.join(MANIFEST_FILE), spec).unwrap();
    if with_file {
        fs::write(
            root.join("api/datasources/endpoints/x/endpoint.get.json"),
            r#"{ "operationId": "getX", "sources": {}, "response": {} }"#,
        )
        .unwrap();
    }
    root
}

fn spec(parameters_component: &str, reference: &str) -> String {
    format!(
        "openapi: 3.2.0\ninfo: {{ title: t, version: '1' }}\ncomponents:\n  parameters:\n{parameters_component}paths:\n  /x:\n    get:\n      operationId: getX\n      parameters:\n        - $ref: '{reference}'\n      responses: {{ '200': {{ description: ok }} }}\n"
    )
}

#[tokio::test]
async fn an_unresolved_parameter_ref_on_a_routed_file_is_a_validate_problem() {
    let root = project(&spec("    P: { name: p, in: query }\n", "#/components/parameters/Typo"), true);
    assert!(validate_api(&root).await >= 1);
    let _ = fs::remove_dir_all(&root);
}

#[tokio::test]
async fn a_resolved_parameter_ref_is_clean() {
    let root = project(&spec("    P: { name: p, in: query }\n", "#/components/parameters/P"), true);
    assert_eq!(validate_api(&root).await, 0);
    let _ = fs::remove_dir_all(&root);
}

#[tokio::test]
async fn an_unresolved_parameter_ref_with_no_endpoint_file_adds_no_route_finding() {
    let with_file = project(&spec("    P: { name: p, in: query }\n", "#/components/parameters/Typo"), true);
    let without = project(&spec("    P: { name: p, in: query }\n", "#/components/parameters/Typo"), false);
    let (a, b) = (validate_api(&with_file).await, validate_api(&without).await);
    assert!(a > b, "with file {a}, without {b}");
    let _ = fs::remove_dir_all(&with_file);
    let _ = fs::remove_dir_all(&without);
}

#[tokio::test]
async fn an_unresolved_path_item_ref_with_a_file_at_that_path_is_a_validate_problem() {
    let root = project(
        "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths:\n  /x:\n    $ref: '#/components/pathItems/Gone'\n",
        true,
    );
    assert!(validate_api(&root).await >= 1);
    let _ = fs::remove_dir_all(&root);
}
