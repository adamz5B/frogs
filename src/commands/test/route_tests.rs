//! `frogs test` builds the same route table as `frogs run` plus the
//! `/_frogs/scenario` control plane, and refuses the same problems.

use super::*;

const STUB: &str = r#"{ "operationId": "x", "sources": {}, "response": {} }"#;

fn tempdir() -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "frogs-test-routes-{}-{}-{n}",
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
    fn new(server_json: &str) -> Fx {
        let root = tempdir();
        let api = root.join("api");
        for dir in ["config/errors", "security", "datasources/endpoints"] {
            std::fs::create_dir_all(api.join(dir)).unwrap();
        }
        std::fs::write(root.join("openapi.yaml"), "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths: {}\n").unwrap();
        std::fs::write(api.join("config/server.json"), server_json).unwrap();
        std::fs::write(api.join("config/errors/core.json"), "{}").unwrap();
        std::fs::write(api.join("config/connections.json"), "{}").unwrap();
        std::fs::write(api.join("security/schemes.json"), "{}").unwrap();
        Fx { root }
    }

    fn endpoint(&self, folder: &str) {
        let dir = self.root.join("api/datasources/endpoints").join(folder);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("endpoint.get.json"), STUB).unwrap();
    }
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
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

const QUIET: &str = r#"{ "features": { "requestValidation": false, "metrics": false, "readyzCheck": false } }"#;

#[tokio::test]
async fn an_endpoint_folder_on_the_scenario_control_plane_is_refused_at_an_unprefixed_api_root() {
    let fx = Fx::new(QUIET);
    fx.endpoint("_frogs/scenario");
    let err = build_mock_router(&fx.root, &opts()).await.map(|_| ()).expect_err("must refuse");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("route problem(s)"), "{err}");
}

#[tokio::test]
async fn the_same_folder_is_fine_when_api_root_moves_the_api_off_the_control_plane() {
    let fx = Fx::new(r#"{ "apiRoot": "/api", "features": { "requestValidation": false, "metrics": false, "readyzCheck": false } }"#);
    fx.endpoint("_frogs/scenario");
    assert!(build_mock_router(&fx.root, &opts()).await.is_ok());
}

#[tokio::test]
async fn a_parameter_name_conflict_is_refused_by_frogs_test_before_anything_is_served() {
    let fx = Fx::new(QUIET);
    fx.endpoint("x/{a}");
    fx.endpoint("x/{b}");
    let err = build_mock_router(&fx.root, &opts()).await.map(|_| ()).expect_err("must refuse");
    assert!(err.to_string().contains("route problem(s)"), "{err}");
    assert!(!fx.root.join(".frogs/run.json").exists());
}
