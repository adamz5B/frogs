//! `frogs test` / `frogs test record` against links under `datasources/endpoints/`.

use super::*;
use crate::config::EndpointSymlinks;
use crate::openapi::endpoint_tree::tree_for_tests_with;
use crate::openapi::fs_os_tests::link_dir;

const STUB: &str = r#"{ "operationId": "findCar", "sources": {}, "response": {} }"#;
const TEST_FILE: &str = r#"{ "cases": [ { "name": "happy", "request": {}, "mocks": {}, "expect": { "status": 200 } } ] }"#;
const SECRET: &str = "TOPSECRET-123";

fn tempdir(label: &str) -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "frogs-test-links-{label}-{}-{}-{n}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct Fx {
    root: PathBuf,
    outside: PathBuf,
    links: Vec<PathBuf>,
}

impl Fx {
    fn new(server_json: &str) -> Fx {
        let root = tempdir("root");
        let outside = tempdir("outside");
        let api = root.join("api");
        for dir in ["config/errors", "security", "datasources/endpoints"] {
            std::fs::create_dir_all(api.join(dir)).unwrap();
        }
        std::fs::write(root.join("openapi.yaml"), "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths: {}\n").unwrap();
        std::fs::write(api.join("config/server.json"), server_json).unwrap();
        std::fs::write(api.join("config/errors/core.json"), "{}").unwrap();
        std::fs::write(api.join("config/connections.json"), "{}").unwrap();
        std::fs::write(api.join("security/schemes.json"), "{}").unwrap();
        Fx {
            root,
            outside,
            links: Vec::new(),
        }
    }

    fn endpoints(&self) -> PathBuf {
        self.root.join("api/datasources/endpoints")
    }

    fn put(&self, path: &Path, contents: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    fn link(&mut self, target: &Path, link: &Path) -> bool {
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        let ok = link_dir(target, link);
        if ok {
            self.links.push(link.to_path_buf());
        }
        ok
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

fn opts() -> TestServerOptions {
    TestServerOptions {
        port: None,
        bind: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        scenario: None,
        report: ReportFormat::Text,
        report_file: None,
    }
}

#[test]
fn a_test_file_under_an_in_project_directory_link_is_discovered_under_its_logical_route() {
    let mut fx = Fx::new("{}");
    fx.put(&fx.root.join("shared/endpoint.get.json"), STUB);
    fx.put(&fx.root.join("shared/endpoint.get.test.json"), TEST_FILE);
    if !fx.link(&fx.root.join("shared"), &fx.endpoints().join("cars")) {
        return;
    }
    for policy in [EndpointSymlinks::Contained, EndpointSymlinks::Follow] {
        let tree = tree_for_tests_with(&fx.root, &fx.endpoints(), policy);
        let (files, findings) = discover_test_files(&tree, MethodCase::Default);
        assert!(findings.is_empty(), "{policy:?}: {findings:?}");
        assert_eq!(files.len(), 1, "{policy:?}");
        assert_eq!(files[0].0, "/cars");
        assert!(files[0].3.is_some(), "the sibling stub is found through the link too");
    }
}

#[test]
fn a_test_file_under_an_outside_link_is_not_discovered_and_carries_a_strict_finding_unless_follow() {
    let mut fx = Fx::new("{}");
    fx.put(&fx.outside.join("endpoint.get.test.json"), TEST_FILE);
    if !fx.link(&fx.outside.clone(), &fx.endpoints().join("ext")) {
        return;
    }
    let tree = tree_for_tests_with(&fx.root, &fx.endpoints(), EndpointSymlinks::Contained);
    let (files, findings) = discover_test_files(&tree, MethodCase::Default);
    assert!(files.is_empty());
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(findings[0].strict_error);

    let tree = tree_for_tests_with(&fx.root, &fx.endpoints(), EndpointSymlinks::Follow);
    let (files, findings) = discover_test_files(&tree, MethodCase::Default);
    assert_eq!(files.len(), 1);
    assert!(findings.is_empty());
}

#[test]
fn a_test_file_under_a_refused_link_is_never_discovered() {
    let mut fx = Fx::new("{}");
    fx.put(&fx.root.join("shared/endpoint.get.test.json"), TEST_FILE);
    if !fx.link(&fx.root.join("shared"), &fx.endpoints().join("cars")) {
        return;
    }
    let tree = tree_for_tests_with(&fx.root, &fx.endpoints(), EndpointSymlinks::Refuse);
    let (files, findings) = discover_test_files(&tree, MethodCase::Default);
    assert!(files.is_empty());
    assert!(findings.iter().all(|f| f.strict_error));
}

async fn serve_mock(root: &Path) -> std::net::SocketAddr {
    let (router, _session, server_config) = build_mock_router(root, &opts()).await.expect("mock router builds");
    crate::server::spawn_served(router, server_config.case_sensitive_methods()).await
}

#[tokio::test]
async fn the_mock_server_serves_a_route_whose_stub_and_test_file_live_behind_an_in_project_link() {
    let mut fx = Fx::new(r#"{ "features": { "requestValidation": false } }"#);
    fx.put(&fx.root.join("shared/endpoint.get.json"), STUB);
    fx.put(&fx.root.join("shared/endpoint.get.test.json"), TEST_FILE);
    if !fx.link(&fx.root.join("shared"), &fx.endpoints().join("cars")) {
        return;
    }
    let addr = serve_mock(&fx.root).await;
    let response = reqwest::get(format!("http://{addr}/cars")).await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.json::<Value>().await.unwrap(), serde_json::json!({}));
}

#[tokio::test]
async fn the_mock_server_does_not_serve_a_route_behind_an_outside_link_under_contained() {
    let mut fx = Fx::new(r#"{ "features": { "requestValidation": false } }"#);
    fx.put(&fx.outside.join("endpoint.get.json"), STUB);
    fx.put(&fx.outside.join("endpoint.get.test.json"), TEST_FILE);
    if !fx.link(&fx.outside.clone(), &fx.endpoints().join("cars")) {
        return;
    }
    let addr = serve_mock(&fx.root).await;
    assert_eq!(reqwest::get(format!("http://{addr}/cars")).await.unwrap().status(), 404);
}

#[tokio::test]
async fn the_mock_server_refuses_to_start_under_strict_when_an_outside_link_exists() {
    let mut fx = Fx::new(r#"{ "strictOpenApi": true, "features": { "requestValidation": false } }"#);
    fx.put(&fx.outside.join("endpoint.get.json"), STUB);
    if !fx.link(&fx.outside.clone(), &fx.endpoints().join("cars")) {
        return;
    }
    let err = build_mock_router(&fx.root, &opts()).await.err().expect("strict + outside link must refuse");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn a_linked_endpoint_or_test_file_failure_is_redacted_on_every_frogs_test_load_path() {
    let mut fx = Fx::new("{}");
    fx.put(
        &fx.root.join("shared/endpoint.get.json"),
        r#"{ "operationId": "x", "sources": "TOPSECRET-123", "response": {} }"#,
    );
    fx.put(&fx.root.join("shared/endpoint.get.test.json"), r#"{ "cases": "TOPSECRET-123" }"#);
    if !fx.link(&fx.root.join("shared"), &fx.endpoints().join("cars")) {
        return;
    }
    let endpoint = fx.endpoints().join("cars/endpoint.get.json");
    let message = read_endpoint_file(&endpoint, true).unwrap_err();
    assert!(!message.contains(SECRET), "{message}");
    assert!(message.contains("line 1"), "{message}");

    let test_file = fx.endpoints().join("cars/endpoint.get.test.json");
    let err = crate::testing::load_redacted(&test_file).unwrap_err().to_string();
    assert!(!err.contains(SECRET), "{err}");
    assert!(err.contains("line"), "{err}");
    // The premise: the unredacted loader would have quoted it.
    let leaked = crate::testing::load(&test_file).unwrap_err().to_string();
    assert!(leaked.contains(SECRET), "premise of this test: {leaked}");
}

#[tokio::test]
async fn record_writes_the_new_case_through_an_in_project_link_to_the_real_folder() {
    let mut fx = Fx::new("{}");
    fx.put(&fx.root.join("shared/endpoint.get.json"), STUB);
    if !fx.link(&fx.root.join("shared"), &fx.endpoints().join("cars")) {
        return;
    }
    record(&fx.root, "/cars", "get").await.unwrap();
    let written = std::fs::read_to_string(fx.root.join("shared/endpoint.get.test.json")).unwrap();
    assert!(written.contains("recorded"), "{written}");
}
