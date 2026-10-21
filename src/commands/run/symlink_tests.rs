//! Startup behaviour of `frogs run` (and the `register` precheck) for links
//! under `datasources/endpoints/`.

use super::*;
use crate::config::EndpointSymlinks;
use crate::openapi::fs_os_tests::link_dir;
use std::sync::Mutex;

const OK_ENDPOINT: &str = r#"{ "operationId": "x", "sources": {}, "response": {} }"#;
const CLEAN_SPEC: &str = "openapi: 3.1.0\ninfo: { title: t, version: '1' }\npaths: {}\n";

fn tempdir(label: &str) -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "frogs-run-links-{label}-{}-{}-{n}",
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
        std::fs::write(root.join("openapi.yaml"), CLEAN_SPEC).unwrap();
        std::fs::write(api.join("config/server.json"), server_json).unwrap();
        std::fs::write(api.join("config/errors/core.json"), "{}").unwrap();
        // A driver that does not exist: reaching `connect_all` would surface a connection error instead of the refusal under test.
        std::fs::write(api.join("config/connections.json"), r#"{ "main": { "driver": "nosuchdriver", "url": "nowhere" } }"#).unwrap();
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

fn server(json: &str) -> ServerConfig {
    serde_json::from_str(json).unwrap()
}

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

fn capture_logs<T>(f: impl FnOnce() -> T) -> (T, String) {
    let buf = LogBuf::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buf.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .finish();
    let value = tracing::subscriber::with_default(subscriber, f);
    let text = String::from_utf8_lossy(&buf.0.lock().unwrap()).into_owned();
    (value, text)
}

#[test]
fn follow_mode_logs_the_startup_warning_and_other_modes_do_not() {
    let fx = Fx::new("{}");
    for (policy, warns) in [("follow", true), ("contained", false), ("refuse", false)] {
        let json = format!(r#"{{ "endpointSymlinks": "{policy}" }}"#);
        let (_, logs) = capture_logs(|| scan_endpoint_tree(&fx.root, &server(&json)));
        assert_eq!(logs.contains("endpointSymlinks is \"follow\""), warns, "{policy}: {logs}");
        if warns {
            assert!(logs.contains("writes are still confined"), "{logs}");
        }
    }
}

#[test]
fn an_escaping_link_is_logged_with_its_target_the_mode_and_the_fix_when_not_strict() {
    let mut fx = Fx::new("{}");
    fx.put(&fx.outside.join("endpoint.get.json"), OK_ENDPOINT);
    if !fx.link(&fx.outside.clone(), &fx.endpoints().join("ext")) {
        return;
    }
    let (result, logs) = capture_logs(|| startup_endpoint_tree(&fx.root, &ServerConfig::default()));
    let tree = result.expect("non-strict startup continues");
    assert!(tree.files().is_empty());
    assert!(logs.contains("ext"), "{logs}");
    assert!(logs.contains("follow"), "the fix must be named: {logs}");
    assert!(logs.contains("contained"), "the mode must be named: {logs}");
}

#[test]
fn strict_refuses_startup_when_any_link_finding_exists() {
    let mut fx = Fx::new("{}");
    if !fx.link(&fx.outside.clone(), &fx.endpoints().join("ext")) {
        return;
    }
    let err = startup_endpoint_tree(&fx.root, &server(r#"{ "strictOpenApi": true }"#)).expect_err("strict + finding must refuse");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("link"), "{err}");
    // Not strict: the same finding is a warning.
    assert!(startup_endpoint_tree(&fx.root, &server("{}")).is_ok());
}

#[tokio::test]
async fn a_strict_link_refusal_happens_before_connections_are_opened_and_before_any_pidfile() {
    let mut fx = Fx::new(r#"{ "strictOpenApi": true, "features": { "requestValidation": false } }"#);
    if !fx.link(&fx.outside.clone(), &fx.endpoints().join("ext")) {
        return;
    }
    let err = build_api_router(&fx.root, false).await.expect_err("must refuse");
    assert!(
        err.to_string().contains("link(s)"),
        "the link refusal must win over the nosuchdriver connection error: {err}"
    );
    assert!(!err.to_string().to_lowercase().contains("nosuchdriver"));
    assert!(!fx.root.join(".frogs/run.json").exists());
}

#[test]
fn the_service_precheck_refuses_a_project_with_an_escaping_link_under_strict_but_not_otherwise() {
    let mut fx = Fx::new(r#"{ "strictOpenApi": true }"#);
    if !fx.link(&fx.outside.clone(), &fx.endpoints().join("ext")) {
        return;
    }
    let err = precheck_security_for_service(&fx.root).expect_err("strict precheck must refuse");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);

    std::fs::write(fx.root.join("api/config/server.json"), "{}").unwrap();
    assert!(precheck_security_for_service(&fx.root).is_ok(), "non-strict only warns");
}

#[test]
fn the_service_precheck_passes_a_link_free_project_under_strict() {
    let fx = Fx::new(r#"{ "strictOpenApi": true }"#);
    fx.put(&fx.endpoints().join("real/endpoint.get.json"), OK_ENDPOINT);
    std::fs::write(
        fx.root.join("openapi.yaml"),
        "openapi: 3.1.0\ninfo: { title: t, version: '1' }\npaths:\n  /real:\n    get:\n      operationId: getReal\n      responses: { '200': { description: ok } }\n",
    )
    .unwrap();
    assert!(precheck_security_for_service(&fx.root).is_ok());
}

#[test]
fn report_tree_findings_counts_every_strict_finding_in_the_refusal() {
    let mut fx = Fx::new("{}");
    if !fx.link(&fx.outside.clone(), &fx.endpoints().join("one")) {
        return;
    }
    let outside2 = tempdir("outside2");
    let linked_second = fx.link(&outside2, &fx.endpoints().join("two"));
    let tree = scan_endpoint_tree(&fx.root, &ServerConfig::default());
    let err = report_tree_findings(&tree, true).unwrap_err();
    let expected = if linked_second { "2 link(s)" } else { "1 link(s)" };
    assert!(err.to_string().contains(expected), "{err}");
    assert!(report_tree_findings(&tree, false).is_ok());
    let _ = std::fs::remove_dir_all(&outside2);
}

#[test]
fn the_config_line_option_endpoint_symlinks_resolves_from_server_json() {
    assert_eq!(server("{}").endpoint_symlinks(), EndpointSymlinks::Contained);
    assert_eq!(server(r#"{ "endpointSymlinks": "refuse" }"#).endpoint_symlinks(), EndpointSymlinks::Refuse);
    let fx = Fx::new(r#"{ "endpointSymlinks": "follow" }"#);
    let config = Config::load_or_exit(&crate::project::api_base(&fx.root));
    assert_eq!(config.server.endpoint_symlinks(), EndpointSymlinks::Follow);
    assert_eq!(link_context(&fx.root, &config.server).policy, EndpointSymlinks::Follow);
}
