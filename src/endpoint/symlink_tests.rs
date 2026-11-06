//! What the router, `validate` and the docs summary do with links under
//! `datasources/endpoints/`, per `endpointSymlinks` mode, and that nothing read
//! through a link ever echoes that file's content.

use std::collections::HashMap;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use super::*;
use crate::config::EndpointSymlinks;
use crate::openapi::endpoint_tree::{EndpointTree, tree_for_tests_with};
use crate::openapi::fs_os_tests::link_dir;

const SECRET: &str = "TOPSECRET-123";
const OK_ENDPOINT: &str = r#"{ "operationId": "x", "sources": {}, "response": { "ok": "literal" } }"#;
/// Parses as JSON but not as an endpoint file: serde's own message for this quotes the string.
const LEAKY_ENDPOINT: &str = r#"{ "operationId": "x", "sources": "TOPSECRET-123", "response": {} }"#;

fn tempdir(label: &str) -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "frogs-endpoint-links-{label}-{}-{}-{n}",
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
    fn new() -> Fx {
        let root = tempdir("root");
        let outside = tempdir("outside");
        let api = root.join("api");
        std::fs::create_dir_all(api.join("datasources/endpoints")).unwrap();
        std::fs::create_dir_all(api.join("config/errors")).unwrap();
        std::fs::create_dir_all(api.join("security/verifiers")).unwrap();
        std::fs::write(api.join("config/errors/core.json"), "{}").unwrap();
        std::fs::write(api.join("security/schemes.json"), "{}").unwrap();
        Fx {
            root,
            outside,
            links: Vec::new(),
        }
    }

    fn api(&self) -> PathBuf {
        self.root.join("api")
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

    fn tree(&self, policy: EndpointSymlinks) -> EndpointTree {
        tree_for_tests_with(&self.root, &self.endpoints(), policy)
    }

    fn router(&self, policy: EndpointSymlinks) -> axum::Router {
        let api = self.api();
        build_router(
            &api,
            &self.tree(policy),
            Arc::new(HashMap::new()),
            &HashMap::new(),
            Arc::new(ErrorRegistry::load(&api.join("config/errors")).unwrap()),
            Arc::new(SecurityConfig::load(&api.join("security")).unwrap()),
            Arc::new(HashMap::new()),
            Arc::new(Mutex::new(DiscoveredErrors::default())),
            false,
            None,
            None,
            NonZeroU64::new(5_000).unwrap(),
            false,
            MethodCase::Default,
        )
    }

    async fn serve(&self, policy: EndpointSymlinks) -> String {
        format!("http://{}", crate::server::spawn_served(self.router(policy), false).await)
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

async fn status(base: &str, path: &str) -> u16 {
    reqwest::get(format!("{base}{path}")).await.unwrap().status().as_u16()
}

#[tokio::test]
async fn an_in_project_directory_link_is_served_and_an_outside_one_is_a_404_under_contained() {
    let mut fx = Fx::new();
    fx.put(&fx.endpoints().join("real/endpoint.get.json"), OK_ENDPOINT);
    fx.put(&fx.root.join("shared/ping/endpoint.get.json"), OK_ENDPOINT);
    fx.put(&fx.outside.join("ping/endpoint.get.json"), OK_ENDPOINT);
    if !fx.link(&fx.root.join("shared"), &fx.endpoints().join("v2")) || !fx.link(&fx.outside.clone(), &fx.endpoints().join("ext")) {
        return;
    }
    let base = fx.serve(EndpointSymlinks::Contained).await;
    assert_eq!(status(&base, "/real").await, 200);
    assert_eq!(status(&base, "/v2/ping").await, 200);
    assert_eq!(status(&base, "/ext/ping").await, 404);
}

#[tokio::test]
async fn an_outside_directory_link_is_served_under_follow() {
    let mut fx = Fx::new();
    fx.put(&fx.outside.join("ping/endpoint.get.json"), OK_ENDPOINT);
    if !fx.link(&fx.outside.clone(), &fx.endpoints().join("ext")) {
        return;
    }
    let base = fx.serve(EndpointSymlinks::Follow).await;
    assert_eq!(status(&base, "/ext/ping").await, 200);
}

#[tokio::test]
async fn every_link_is_a_404_under_refuse_even_when_it_points_inside_the_project() {
    let mut fx = Fx::new();
    fx.put(&fx.endpoints().join("real/endpoint.get.json"), OK_ENDPOINT);
    fx.put(&fx.root.join("shared/ping/endpoint.get.json"), OK_ENDPOINT);
    if !fx.link(&fx.root.join("shared"), &fx.endpoints().join("v2")) {
        return;
    }
    let base = fx.serve(EndpointSymlinks::Refuse).await;
    assert_eq!(status(&base, "/real").await, 200);
    assert_eq!(status(&base, "/v2/ping").await, 404);
}

#[tokio::test]
async fn a_cycle_back_to_the_endpoints_folder_does_not_hang_or_double_register_routes() {
    let mut fx = Fx::new();
    fx.put(&fx.endpoints().join("real/endpoint.get.json"), OK_ENDPOINT);
    if !fx.link(&fx.endpoints(), &fx.endpoints().join("a")) {
        return;
    }
    let base = fx.serve(EndpointSymlinks::Contained).await;
    assert_eq!(status(&base, "/real").await, 200);
    assert_eq!(status(&base, "/a/real").await, 404, "the cycle must not be walked");
}

// ---------------------------------------------------------------- redaction (plan item 6)

#[derive(Clone, Default)]
struct LogBuf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuf {
    type Writer = LogBuf;
    fn make_writer(&'a self) -> LogBuf {
        self.clone()
    }
}

fn leaky_fixture() -> Option<(Fx, PathBuf)> {
    let mut fx = Fx::new();
    fx.put(&fx.root.join("shared/endpoint.get.json"), LEAKY_ENDPOINT);
    let link = fx.endpoints().join("v2");
    if !fx.link(&fx.root.join("shared"), &link) {
        return None;
    }
    Some((fx, link))
}

#[test]
fn the_premise_a_non_linked_file_parse_error_does_quote_content_while_a_linked_one_never_does() {
    let plain = parse_endpoint_json(LEAKY_ENDPOINT, false).unwrap_err();
    assert!(plain.contains(SECRET), "premise of the redaction tests: serde quotes the value ({plain})");
    let linked = parse_endpoint_json(LEAKY_ENDPOINT, true).unwrap_err();
    assert!(!linked.contains(SECRET), "{linked}");
    assert!(linked.contains("line 1") && linked.contains("column"), "{linked}");
}

#[test]
fn a_linked_endpoint_files_parse_failure_never_reaches_validate_problems_with_its_content() {
    let Some((fx, _link)) = leaky_fixture() else { return };
    let tree = fx.tree(EndpointSymlinks::Contained);
    let (count, problems) = validate_endpoint_files(&tree, &SecurityConfig::default(), &HashMap::new(), false, MethodCase::Default);
    assert_eq!(count, 1);
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(!problems[0].contains(SECRET), "{}", problems[0]);
    assert!(problems[0].contains("line 1"), "{}", problems[0]);
}

#[test]
fn a_linked_endpoint_files_parse_failure_never_reaches_the_router_logs_with_its_content() {
    let Some((fx, _link)) = leaky_fixture() else { return };
    let buf = LogBuf::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buf.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        let _ = fx.router(EndpointSymlinks::Contained);
    });
    let logged = String::from_utf8_lossy(&buf.0.lock().unwrap()).into_owned();
    assert!(logged.contains("skipping"), "the route must be skipped with a log line: {logged}");
    assert!(!logged.contains(SECRET), "{logged}");
}

#[test]
fn the_docs_summary_and_stream_key_scan_over_a_linked_unparseable_file_stay_silent_and_do_not_echo_it() {
    let Some((fx, _link)) = leaky_fixture() else { return };
    let tree = fx.tree(EndpointSymlinks::Contained);
    let summaries = docs_summary::endpoint_summaries(&tree, MethodCase::Default);
    assert!(summaries.is_empty());
    assert!(!format!("{summaries:?}").contains(SECRET));
    assert!(reserved_stream_key_files(&tree, MethodCase::Default).is_empty());
}

#[test]
fn a_linked_file_that_is_not_json_at_all_is_reported_by_position_and_category_only() {
    let mut fx = Fx::new();
    fx.put(&fx.root.join("shared/endpoint.get.json"), "{\n  \"operationId\": TOPSECRET-123\n}");
    if !fx.link(&fx.root.join("shared"), &fx.endpoints().join("v2")) {
        return;
    }
    let tree = fx.tree(EndpointSymlinks::Contained);
    let (_, problems) = validate_endpoint_files(&tree, &SecurityConfig::default(), &HashMap::new(), false, MethodCase::Default);
    assert_eq!(problems.len(), 1);
    assert!(!problems[0].contains(SECRET), "{}", problems[0]);
    assert!(problems[0].contains("line 2"), "{}", problems[0]);
}

// ---------------------------------------------------------------- cross-consumer consistency (plan item 4)

#[tokio::test]
async fn every_endpoint_walker_sees_the_same_routes_under_each_policy() {
    let mut fx = Fx::new();
    fx.put(&fx.endpoints().join("things/endpoint.get.json"), OK_ENDPOINT);
    fx.put(&fx.root.join("shared/a/endpoint.get.json"), OK_ENDPOINT);
    // Wrong-case stub under the in-project link: never routed, but reported wherever the link is followed.
    fx.put(&fx.root.join("shared/b/endpoint.GET.json"), OK_ENDPOINT);
    fx.put(&fx.outside.join("endpoint.get.json"), OK_ENDPOINT);
    if !fx.link(&fx.root.join("shared"), &fx.endpoints().join("inlink")) || !fx.link(&fx.outside.clone(), &fx.endpoints().join("outlink")) {
        return;
    }
    let cases: [(EndpointSymlinks, Vec<&str>, usize); 3] = [
        (EndpointSymlinks::Contained, vec!["/inlink/a", "/things"], 1),
        (EndpointSymlinks::Refuse, vec!["/things"], 0),
        (EndpointSymlinks::Follow, vec!["/inlink/a", "/outlink", "/things"], 1),
    ];
    for (policy, expected, wrong_case_findings) in cases {
        let tree = fx.tree(policy);
        let mut discovered: Vec<String> = discover_endpoint_files(&tree, MethodCase::Default).into_iter().map(|(url, _, _)| url).collect();
        discovered.sort();
        assert_eq!(discovered, expected, "{policy:?}: discover_endpoint_files");

        let mut summarised: Vec<String> = docs_summary::endpoint_summaries(&tree, MethodCase::Default)
            .iter()
            .map(|v| v["path"].as_str().unwrap().to_string())
            .collect();
        summarised.sort();
        assert_eq!(summarised, expected, "{policy:?}: endpoint_summaries");

        let (count, problems) = validate_endpoint_files(&tree, &SecurityConfig::default(), &HashMap::new(), false, MethodCase::Default);
        assert_eq!(count, expected.len(), "{policy:?}: validate_endpoint_files");
        assert!(problems.is_empty(), "{policy:?}: {problems:?}");

        assert_eq!(
            method_file_findings(&tree, MethodCase::Default).len(),
            wrong_case_findings,
            "{policy:?}: method_file_findings"
        );

        let base = fx.serve(policy).await;
        for url in ["/things", "/inlink/a", "/outlink"] {
            let want = if expected.contains(&url) { 200 } else { 404 };
            assert_eq!(status(&base, url).await, want, "{policy:?}: GET {url}");
        }
    }
}
