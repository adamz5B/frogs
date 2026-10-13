//! Real-handshake mTLS tests: a genuine `serve` instance on an ephemeral port,
//! real rustls clients (reqwest and raw tokio-rustls), certificates generated
//! in memory by `server::test_pki`. Nothing here touches `examples/`.

use super::*;
use crate::security::ClientCertIdentity;
use crate::server::test_pki::*;
use axum::extract::Extension;
use axum::routing::get;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const REQUIRED: &str = r#"{ "mode": "required", "caPath": "client-ca.pem" }"#;
const OPTIONAL: &str = r#"{ "mode": "optional", "caPath": "client-ca.pem" }"#;
const MTLS_ORDERS: &str = r#"{ "type": "mtls", "validIf": "cert.san.dns = orders.internal.example.com" }"#;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

struct Harness {
    root: std::path::PathBuf,
    api_dir: std::path::PathBuf,
    pki: Pki,
    port: u16,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<io::Result<()>>>,
}

impl Harness {
    fn new() -> Harness {
        ensure_crypto_provider();
        let root = temp_dir("run");
        let api_dir = root.join("api");
        std::fs::create_dir_all(&api_dir).unwrap();
        let pki = Pki::new();
        write_basic_tls_files(&api_dir, &pki);
        Harness {
            root,
            api_dir,
            pki,
            port: free_port(),
            stop: None,
            task: None,
        }
    }

    fn tls(&self, client_auth: &str) -> TlsConfig {
        tls_config(Some(client_auth))
    }

    fn write(&self, name: &str, contents: &str) {
        std::fs::write(self.api_dir.join(name), contents).unwrap();
    }

    fn leaf(&self, spec: &LeafSpec) -> Leaf {
        build_leaf(&self.pki.client_ca, spec)
    }

    async fn start(&mut self, router: Router, tls: TlsConfig) {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        self.stop = Some(tx);
        let (root, api_dir, port) = (self.root.clone(), self.api_dir.clone(), self.port);
        self.task = Some(tokio::spawn(async move {
            serve(&root, router, IpAddr::V4(Ipv4Addr::LOCALHOST), port, &tls, &api_dir, async {
                let _ = rx.await;
            })
            .await
        }));
        for _ in 0..100 {
            if self.task.as_ref().unwrap().is_finished() {
                let result = self.task.take().unwrap().await;
                panic!("serve ended before listening: {result:?}");
            }
            if TcpStream::connect(("127.0.0.1", self.port)).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("server never started listening");
    }

    async fn start_echo(&mut self, client_auth: &str) {
        let tls = self.tls(client_auth);
        self.start(echo_router(), tls).await;
    }

    fn client(&self, identity_pem: Option<&str>) -> reqwest::Client {
        let mut builder = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(self.pki.server_ca.pem().as_bytes()).unwrap())
            .resolve("localhost", SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.port))
            .timeout(Duration::from_secs(10));
        if let Some(pem) = identity_pem {
            builder = builder.identity(reqwest::Identity::from_pem(pem.as_bytes()).unwrap());
        }
        builder.build().unwrap()
    }

    async fn get(&self, client: &reqwest::Client, path: &str) -> Result<(u16, String), reqwest::Error> {
        let response = client.get(format!("https://localhost:{}{path}", self.port)).send().await?;
        let status = response.status().as_u16();
        Ok((status, response.text().await?))
    }

    async fn get_as(&self, spec: Option<&LeafSpec>, path: &str) -> Result<(u16, String), reqwest::Error> {
        let pem = spec.map(|s| self.leaf(s).identity_pem());
        self.get(&self.client(pem.as_deref()), path).await
    }

    async fn echo_as(&self, spec: Option<&LeafSpec>) -> Result<(u16, String), reqwest::Error> {
        self.get_as(spec, "/echo").await
    }

    /// Everything `serve` leaves behind when it refuses to start.
    fn assert_nothing_was_left_behind(&self) {
        assert!(
            pidfile::read(&self.root).unwrap().is_none(),
            "a startup error must happen before the pidfile is written"
        );
        assert!(
            std::net::TcpListener::bind(("127.0.0.1", self.port)).is_ok(),
            "a startup error must happen before the port is bound"
        );
    }

    async fn serve_expecting_error(&self, tls: &TlsConfig) -> io::Error {
        let result = serve(
            &self.root,
            echo_router(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            self.port,
            tls,
            &self.api_dir,
            std::future::pending::<()>(),
        )
        .await;
        let err = result.expect_err("serve must refuse to start");
        self.assert_nothing_was_left_behind();
        err
    }
}

fn echo_router() -> Router {
    Router::new()
        .route(
            "/echo",
            get(|id: Option<Extension<Arc<ClientCertIdentity>>>| async move {
                match id {
                    Some(Extension(id)) => axum::Json(id.to_json()),
                    None => axum::Json(serde_json::json!({ "anonymous": true })),
                }
            }),
        )
        .route("/healthz", get(|| async { "ok" }))
}

fn json(body: &str) -> serde_json::Value {
    serde_json::from_str(body).unwrap_or_else(|e| panic!("{body}: {e}"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------
// required / optional basics
// ---------------------------------------------------------------------

#[tokio::test]
async fn required_mode_serves_a_valid_client_and_the_echo_route_shows_its_identity() {
    let mut h = Harness::new();
    h.start_echo(REQUIRED).await;
    let leaf = h.leaf(&LeafSpec::valid());
    let client = h.client(Some(&leaf.identity_pem()));
    let (status, body) = h.get(&client, "/echo").await.unwrap();
    assert_eq!(status, 200);
    let body = json(&body);
    let expected_fp = hex(ring::digest::digest(&ring::digest::SHA256, &leaf.der()).as_ref());
    assert_eq!(body["fingerprint"], expected_fp);
    assert_eq!(body["cn"], "client.example.com");
    assert_eq!(
        body["san"]["dns"],
        serde_json::json!(["a.svc.example", "b.svc.example", "orders.internal.example.com"])
    );
    assert_eq!(body["san"]["uri"], serde_json::json!(["spiffe://example.org/ns/a", "spiffe://example.org/ns/orders"]));
    assert_eq!(body["san"]["email"], serde_json::json!(["first@example.com", "Alice@Example.com"]));
    assert_eq!(body["issuer"], "CN=frogs test client root");
}

#[tokio::test]
async fn required_mode_rejects_a_client_with_no_certificate() {
    let mut h = Harness::new();
    h.start_echo(REQUIRED).await;
    assert!(h.echo_as(None).await.is_err(), "no certificate must fail the handshake under required");
}

#[tokio::test]
async fn required_mode_rejects_certificates_it_should_not_trust() {
    let mut h = Harness::new();
    h.start_echo(REQUIRED).await;

    let wrong_ca = build_leaf(&h.pki.wrong_ca, &LeafSpec::valid());
    assert!(
        h.get(&h.client(Some(&wrong_ca.identity_pem())), "/echo").await.is_err(),
        "a certificate from an unrelated CA"
    );

    for (what, spec) in [
        ("expired", LeafSpec::expired()),
        ("not yet valid", LeafSpec::not_yet_valid()),
        ("serverAuth-only EKU", LeafSpec::server_auth_only()),
        ("no EKU (default requires clientAuth)", LeafSpec::no_eku()),
    ] {
        assert!(h.echo_as(Some(&spec)).await.is_err(), "{what} must fail the handshake");
    }
    // The server is still healthy for a good client afterwards.
    assert_eq!(h.echo_as(Some(&LeafSpec::valid())).await.unwrap().0, 200);
}

#[tokio::test]
async fn disabling_the_eku_requirement_accepts_a_no_eku_leaf_but_still_rejects_a_server_auth_only_one() {
    let mut h = Harness::new();
    h.start_echo(r#"{ "mode": "required", "caPath": "client-ca.pem", "requireClientAuthEku": false }"#)
        .await;
    assert_eq!(h.echo_as(Some(&LeafSpec::no_eku())).await.unwrap().0, 200);
    assert!(
        h.echo_as(Some(&LeafSpec::server_auth_only())).await.is_err(),
        "an EKU that is present without clientAuth stays rejected"
    );
}

#[tokio::test]
async fn certificates_with_oversized_or_hostile_names_fail_the_handshake() {
    let mut h = Harness::new();
    h.start_echo(REQUIRED).await;
    assert!(h.echo_as(Some(&LeafSpec::with_dns_count(65))).await.is_err(), "65 SANs");
    assert_eq!(
        h.echo_as(Some(&LeafSpec::with_dns_count(64))).await.unwrap().0,
        200,
        "64 SANs is the limit, not a failure"
    );
    assert!(
        h.echo_as(Some(&LeafSpec {
            dns: vec!["a".repeat(2048)],
            ..LeafSpec::valid()
        }))
        .await
        .is_err(),
        "a 2 KiB SAN"
    );
    assert!(
        h.echo_as(Some(&LeafSpec {
            cn: vec!["evil\u{1}cn".into()],
            ..LeafSpec::valid()
        }))
        .await
        .is_err(),
        "a control character in the CN"
    );
}

#[tokio::test]
async fn optional_mode_admits_a_client_with_no_certificate_as_anonymous() {
    let mut h = Harness::new();
    h.start_echo(OPTIONAL).await;
    let (status, body) = h.echo_as(None).await.unwrap();
    assert_eq!(status, 200);
    assert_eq!(json(&body), serde_json::json!({ "anonymous": true }));
    assert_eq!(h.get_as(None, "/healthz").await.unwrap().0, 200);
}

#[tokio::test]
async fn optional_mode_attaches_the_identity_when_a_valid_certificate_is_presented() {
    let mut h = Harness::new();
    h.start_echo(OPTIONAL).await;
    let (status, body) = h.echo_as(Some(&LeafSpec::valid())).await.unwrap();
    assert_eq!(status, 200);
    assert_eq!(json(&body)["cn"], "client.example.com");
}

#[tokio::test]
async fn optional_mode_still_fully_validates_a_presented_certificate() {
    let mut h = Harness::new();
    h.start_echo(OPTIONAL).await;
    let wrong_ca = build_leaf(&h.pki.wrong_ca, &LeafSpec::valid());
    assert!(
        h.get(&h.client(Some(&wrong_ca.identity_pem())), "/echo").await.is_err(),
        "optional must not mean unchecked"
    );
    assert!(h.echo_as(Some(&LeafSpec::expired())).await.is_err());
    assert!(h.echo_as(Some(&LeafSpec::server_auth_only())).await.is_err());
}

#[tokio::test]
async fn a_crlf_converted_ca_bundle_still_loads_and_authenticates() {
    let mut h = Harness::new();
    h.write("client-ca.pem", &h.pki.client_ca.pem().replace('\n', "\r\n"));
    h.start_echo(REQUIRED).await;
    assert_eq!(h.echo_as(Some(&LeafSpec::valid())).await.unwrap().0, 200);
}

// ---------------------------------------------------------------------
// revocation
// ---------------------------------------------------------------------

#[tokio::test]
async fn a_certificate_listed_in_a_loaded_crl_is_rejected() {
    let mut h = Harness::new();
    let revoked = h.leaf(&LeafSpec::valid());
    let fine = h.leaf(&LeafSpec::valid());
    h.write("a.crl", &h.pki.client_ca.fresh_crl_pem(std::slice::from_ref(&revoked.serial)));
    h.start_echo(r#"{ "mode": "required", "caPath": "client-ca.pem", "crlPaths": ["a.crl"] }"#).await;

    assert!(h.get(&h.client(Some(&revoked.identity_pem())), "/echo").await.is_err());
    assert_eq!(h.get(&h.client(Some(&fine.identity_pem())), "/echo").await.unwrap().0, 200);
}

#[tokio::test]
async fn a_revoked_certificate_is_rejected_in_optional_mode_too() {
    let mut h = Harness::new();
    let revoked = h.leaf(&LeafSpec::valid());
    h.write("a.crl", &h.pki.client_ca.fresh_crl_pem(std::slice::from_ref(&revoked.serial)));
    h.start_echo(r#"{ "mode": "optional", "caPath": "client-ca.pem", "crlPaths": ["a.crl"], "crlPolicy": "bestEffort" }"#)
        .await;
    assert!(h.get(&h.client(Some(&revoked.identity_pem())), "/echo").await.is_err());
    assert_eq!(h.echo_as(None).await.unwrap().0, 200);
}

#[tokio::test]
async fn an_issuer_with_no_loaded_crl_is_rejected_under_fail_closed() {
    let mut h = Harness::new();
    h.write("other.crl", &h.pki.wrong_ca.fresh_crl_pem(&[]));
    h.start_echo(r#"{ "mode": "required", "caPath": "client-ca.pem", "crlPaths": ["other.crl"] }"#).await;
    assert!(h.echo_as(Some(&LeafSpec::valid())).await.is_err());
}

#[tokio::test]
async fn an_issuer_with_no_loaded_crl_is_accepted_under_best_effort() {
    let mut h = Harness::new();
    h.write("other.crl", &h.pki.wrong_ca.fresh_crl_pem(&[]));
    h.start_echo(r#"{ "mode": "required", "caPath": "client-ca.pem", "crlPaths": ["other.crl"], "crlPolicy": "bestEffort" }"#)
        .await;
    assert_eq!(h.echo_as(Some(&LeafSpec::valid())).await.unwrap().0, 200);
}

#[tokio::test]
async fn an_expired_crl_rejects_everyone_under_fail_closed() {
    let mut h = Harness::new();
    h.write("old.crl", &h.pki.client_ca.crl_pem(&[], now_unix() - 10 * DAY, now_unix() - DAY));
    h.start_echo(r#"{ "mode": "required", "caPath": "client-ca.pem", "crlPaths": ["old.crl"] }"#).await;
    assert!(h.echo_as(Some(&LeafSpec::valid())).await.is_err());
}

#[tokio::test]
async fn an_expired_crl_is_tolerated_under_best_effort() {
    let mut h = Harness::new();
    h.write("old.crl", &h.pki.client_ca.crl_pem(&[], now_unix() - 10 * DAY, now_unix() - DAY));
    h.start_echo(r#"{ "mode": "required", "caPath": "client-ca.pem", "crlPaths": ["old.crl"], "crlPolicy": "bestEffort" }"#)
        .await;
    assert_eq!(h.echo_as(Some(&LeafSpec::valid())).await.unwrap().0, 200);
}

#[tokio::test]
async fn a_root_intermediate_leaf_chain_is_accepted_without_crls() {
    let mut h = Harness::new();
    let root = Ca::root("chain root");
    let inter = root.intermediate("chain intermediate");
    h.write("client-ca.pem", &root.pem());
    h.start_echo(REQUIRED).await;
    let leaf = build_leaf(&inter, &LeafSpec::valid());
    let (status, body) = h.get(&h.client(Some(&leaf.identity_pem_with_chain(&[&inter]))), "/echo").await.unwrap();
    assert_eq!(status, 200);
    assert_eq!(json(&body)["issuer"], "CN=chain intermediate");
}

#[tokio::test]
async fn a_chain_is_accepted_with_crls_from_both_issuers() {
    let mut h = Harness::new();
    let root = Ca::root("chain root");
    let inter = root.intermediate("chain intermediate");
    h.write("client-ca.pem", &root.pem());
    h.write("root.crl", &root.fresh_crl_pem(&[]));
    h.write("inter.crl", &inter.fresh_crl_pem(&[]));
    h.start_echo(r#"{ "mode": "required", "caPath": "client-ca.pem", "crlPaths": ["root.crl", "inter.crl"] }"#)
        .await;
    let leaf = build_leaf(&inter, &LeafSpec::valid());
    assert_eq!(h.get(&h.client(Some(&leaf.identity_pem_with_chain(&[&inter]))), "/echo").await.unwrap().0, 200);
}

#[tokio::test]
async fn without_any_crl_paths_revocation_is_not_checked_and_the_server_says_so() {
    let logs = LogBuffer::default();
    let _guard = logs.install(tracing::Level::WARN);
    let mut h = Harness::new();
    let revoked = h.leaf(&LeafSpec::valid());
    // A CRL that would revoke this certificate exists on disk but is not configured.
    h.write("unloaded.crl", &h.pki.client_ca.fresh_crl_pem(std::slice::from_ref(&revoked.serial)));
    h.start_echo(REQUIRED).await;

    assert_eq!(
        h.get(&h.client(Some(&revoked.identity_pem())), "/echo").await.unwrap().0,
        200,
        "an unloaded CRL has no effect"
    );
    assert!(
        logs.text().contains("revocation is NOT checked"),
        "the startup warning is the only protection against assuming otherwise: {}",
        logs.text()
    );
}

// ---------------------------------------------------------------------
// startup configuration errors: before bind, before the pidfile
// ---------------------------------------------------------------------

#[tokio::test]
async fn a_crl_policy_with_empty_crl_paths_is_a_startup_error() {
    let h = Harness::new();
    let err = h
        .serve_expecting_error(&h.tls(r#"{ "mode": "required", "caPath": "client-ca.pem", "crlPolicy": "failClosed" }"#))
        .await;
    assert!(err.to_string().contains("crlPolicy"), "{err}");
}

#[tokio::test]
async fn client_auth_fields_alongside_mode_off_are_startup_errors_naming_the_field() {
    let h = Harness::new();
    for (field, block) in [
        ("caPath", r#"{ "mode": "off", "caPath": "client-ca.pem" }"#),
        ("crlPaths", r#"{ "mode": "off", "crlPaths": ["a.crl"] }"#),
        ("crlPolicy", r#"{ "mode": "off", "crlPolicy": "bestEffort" }"#),
        ("requireClientAuthEku", r#"{ "mode": "off", "requireClientAuthEku": true }"#),
    ] {
        let err = h.serve_expecting_error(&h.tls(block)).await;
        assert!(err.to_string().contains(field), "{field}: {err}");
    }
}

#[tokio::test]
async fn client_auth_over_plain_http_is_a_startup_error() {
    let h = Harness::new();
    let tls: TlsConfig = serde_json::from_str(r#"{ "mode": "off", "clientAuth": { "mode": "required", "caPath": "client-ca.pem" } }"#).unwrap();
    let err = h.serve_expecting_error(&tls).await;
    assert!(err.to_string().contains("manual"), "{err}");
}

#[tokio::test]
async fn a_missing_empty_or_garbage_ca_file_is_a_startup_error_naming_the_file() {
    let h = Harness::new();
    let err = h.serve_expecting_error(&h.tls(r#"{ "mode": "required", "caPath": "nope-ca.pem" }"#)).await;
    assert!(err.to_string().contains("nope-ca.pem"), "{err}");

    h.write("empty-ca.pem", "");
    let err = h.serve_expecting_error(&h.tls(r#"{ "mode": "required", "caPath": "empty-ca.pem" }"#)).await;
    assert!(err.to_string().contains("empty-ca.pem"), "{err}");

    h.write("garbage-ca.pem", "definitely not PEM");
    let err = h.serve_expecting_error(&h.tls(r#"{ "mode": "required", "caPath": "garbage-ca.pem" }"#)).await;
    assert!(err.to_string().contains("garbage-ca.pem"), "{err}");
}

#[tokio::test]
async fn a_missing_ca_path_when_client_auth_is_on_is_a_startup_error() {
    let h = Harness::new();
    let err = h.serve_expecting_error(&h.tls(r#"{ "mode": "optional" }"#)).await;
    assert!(err.to_string().contains("caPath"), "{err}");
}

#[tokio::test]
async fn an_unparseable_or_missing_crl_is_a_startup_error_naming_the_file() {
    let h = Harness::new();
    h.write("broken.crl", "garbage bytes");
    let err = h
        .serve_expecting_error(&h.tls(r#"{ "mode": "required", "caPath": "client-ca.pem", "crlPaths": ["broken.crl"] }"#))
        .await;
    assert!(err.to_string().contains("broken.crl"), "{err}");

    let err = h
        .serve_expecting_error(&h.tls(r#"{ "mode": "required", "caPath": "client-ca.pem", "crlPaths": ["absent.crl"] }"#))
        .await;
    assert!(err.to_string().contains("absent.crl"), "{err}");
}

// ---------------------------------------------------------------------
// raw-connection behaviour: resumption, keep-alive expiry, handshake timeout
// ---------------------------------------------------------------------

fn raw_config(h: &Harness, identity: Option<&Leaf>) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(h.pki.server_ca.cert.der().to_vec())).unwrap();
    let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
    let mut config = match identity {
        Some(leaf) => builder
            .with_client_auth_cert(
                vec![CertificateDer::from(leaf.der())],
                PrivateKeyDer::from_pem_slice(leaf.key_pem().as_bytes()).unwrap(),
            )
            .unwrap(),
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

async fn raw_connect(h: &Harness, config: &Arc<rustls::ClientConfig>) -> tokio_rustls::client::TlsStream<TcpStream> {
    let tcp = TcpStream::connect(("127.0.0.1", h.port)).await.unwrap();
    tokio_rustls::TlsConnector::from(config.clone())
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap()
}

/// One keep-alive HTTP/1.1 GET over an already-established TLS stream.
async fn raw_get(stream: &mut tokio_rustls::client::TlsStream<TcpStream>, path: &str) -> (u16, String) {
    stream.write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    loop {
        let mut chunk = [0u8; 4096];
        let n = match tokio::time::timeout(Duration::from_secs(10), stream.read(&mut chunk)).await {
            Ok(Ok(n)) => n,
            Ok(Err(_)) => 0,
            Err(_) => panic!("timed out reading the response"),
        };
        buf.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&buf).to_string();
        if let Some(split) = text.find("\r\n\r\n") {
            let head = text[..split].to_ascii_lowercase();
            let length: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .map(|v| v.trim().parse().unwrap())
                .unwrap_or(0);
            if buf.len() >= split + 4 + length {
                let status: u16 = head.split_whitespace().nth(1).unwrap().parse().unwrap();
                return (status, text[split + 4..split + 4 + length].to_string());
            }
        }
        if n == 0 {
            panic!("connection ended before a full response: {text:?}");
        }
    }
}

#[tokio::test]
async fn sessions_are_never_resumed_when_client_auth_is_on_and_identity_is_present_every_time() {
    let mut h = Harness::new();
    h.start_echo(REQUIRED).await;
    let leaf = h.leaf(&LeafSpec::valid());
    let config = raw_config(&h, Some(&leaf));
    let fingerprint = hex(ring::digest::digest(&ring::digest::SHA256, &leaf.der()).as_ref());

    for round in 0..3 {
        let mut conn = raw_connect(&h, &config).await;
        let kind = conn.get_ref().1.handshake_kind();
        assert_eq!(kind, Some(rustls::HandshakeKind::Full), "round {round}: a client-auth listener must never resume");
        let (status, body) = raw_get(&mut conn, "/echo").await;
        assert_eq!(status, 200);
        assert_eq!(json(&body)["fingerprint"], fingerprint, "round {round}: identity must be present on every connection");
    }
}

#[tokio::test]
async fn the_control_listener_without_client_auth_does_still_resume_sessions() {
    let mut h = Harness::new();
    let tls = tls_config(None);
    h.start(echo_router(), tls).await;
    let config = raw_config(&h, None);

    let mut first = raw_connect(&h, &config).await;
    assert_eq!(first.get_ref().1.handshake_kind(), Some(rustls::HandshakeKind::Full));
    // Reading the response is also what lets the client process the server's session tickets.
    assert_eq!(raw_get(&mut first, "/healthz").await.0, 200);
    drop(first);

    let second = raw_connect(&h, &config).await;
    assert_eq!(
        second.get_ref().1.handshake_kind(),
        Some(rustls::HandshakeKind::Resumed),
        "without clientAuth rustls's default resumption must be untouched"
    );
}

/// An API-role project served over TLS with the full endpoint pipeline.
fn write_api_project(h: &Harness, client_auth: &str, verifier_json: &str, extra_server: serde_json::Value) {
    let api = &h.api_dir;
    for dir in ["config/errors", "security/verifiers", "datasources/endpoints/protected", "datasources/endpoints/open"] {
        std::fs::create_dir_all(api.join(dir)).unwrap();
    }
    std::fs::write(
        h.root.join("openapi.yaml"),
        "openapi: 3.1.0\ninfo: { title: t, version: '1' }\n\
         paths:\n  /protected:\n    get:\n      operationId: getProtected\n      security: [{ certAuth: [] }]\n      responses: { '200': { description: ok } }\n  \
         /open:\n    get:\n      operationId: getOpen\n      responses: { '200': { description: ok } }\n\
         components:\n  securitySchemes:\n    certAuth: { type: mutualTLS }\n",
    )
    .unwrap();
    let mut server = serde_json::json!({
        "port": h.port,
        "features": { "requestCorrelation": false, "requestValidation": false, "readyzCheck": false, "metrics": false },
        "tls": { "mode": "manual", "manual": { "certPath": "cert.pem", "keyPath": "key.pem" }, "clientAuth": serde_json::from_str::<serde_json::Value>(client_auth).unwrap() },
    });
    for (k, v) in extra_server.as_object().cloned().unwrap_or_default() {
        server[k] = v;
    }
    std::fs::write(api.join("config/server.json"), server.to_string()).unwrap();
    // Deliberately WITHOUT the client-cert codes: the runtime defaults must supply them.
    std::fs::write(
        api.join("config/errors/core.json"),
        r#"{ "auth.invalid_credentials": { "httpStatus": 401, "exposeDetail": true }, "auth.verifier_unavailable": { "httpStatus": 500, "exposeDetail": false } }"#,
    )
    .unwrap();
    std::fs::write(api.join("config/connections.json"), "{}").unwrap();
    std::fs::write(api.join("security/schemes.json"), r#"{ "certAuth": { "verifier": "cert.json" } }"#).unwrap();
    std::fs::write(api.join("security/verifiers/cert.json"), verifier_json).unwrap();
    std::fs::write(
        api.join("datasources/endpoints/protected/endpoint.get.json"),
        r#"{ "operationId": "getProtected", "security": "certAuth", "sources": {}, "response": {} }"#,
    )
    .unwrap();
    std::fs::write(
        api.join("datasources/endpoints/open/endpoint.get.json"),
        r#"{ "operationId": "getOpen", "sources": {}, "response": {} }"#,
    )
    .unwrap();
}

async fn start_api(h: &mut Harness) {
    let (router, server_config) = build_api_router(&h.root).await.expect("scratch project should build");
    h.start(router, server_config.tls).await;
}

#[tokio::test]
async fn in_connection_expiry_is_enforced_on_a_kept_alive_connection() {
    let mut h = Harness::new();
    write_api_project(&h, OPTIONAL, MTLS_ORDERS, serde_json::json!({}));
    start_api(&mut h).await;
    let leaf = h.leaf(&LeafSpec::short_lived(3));
    let config = raw_config(&h, Some(&leaf));
    let mut conn = raw_connect(&h, &config).await;

    let (status, body) = raw_get(&mut conn, "/protected").await;
    assert_eq!(status, 200, "{body}");

    tokio::time::sleep(Duration::from_millis(4_200)).await;

    let (status, body) = raw_get(&mut conn, "/protected").await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(
        json(&body)["name"],
        "auth.client_cert_expired",
        "the same connection outlived its certificate: {body}"
    );
}

#[tokio::test]
async fn a_silent_tcp_client_is_dropped_by_the_handshake_timeout_while_others_are_served() {
    let mut h = Harness::new();
    h.start_echo(REQUIRED).await;
    let mut silent = TcpStream::connect(("127.0.0.1", h.port)).await.unwrap();
    let started = std::time::Instant::now();

    // Meanwhile a legitimate client is served normally.
    assert_eq!(h.echo_as(Some(&LeafSpec::valid())).await.unwrap().0, 200);

    let mut buf = [0u8; 16];
    let closed = tokio::time::timeout(crate::server::tls::TLS_HANDSHAKE_TIMEOUT + Duration::from_secs(4), silent.read(&mut buf)).await;
    match closed {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!("unexpected {n} bytes from a server we never spoke to"),
        Err(_) => panic!("the silent connection was still open {:?} after connecting", started.elapsed()),
    }
    assert!(started.elapsed() < crate::server::tls::TLS_HANDSHAKE_TIMEOUT + Duration::from_secs(4));
}

// ---------------------------------------------------------------------
// the full endpoint pipeline over real mTLS
// ---------------------------------------------------------------------

#[tokio::test]
async fn an_mtls_route_is_401_client_cert_missing_for_an_anonymous_client_while_other_routes_stay_open() {
    let mut h = Harness::new();
    write_api_project(&h, OPTIONAL, MTLS_ORDERS, serde_json::json!({}));
    start_api(&mut h).await;
    let client = h.client(None);

    let (status, body) = h.get(&client, "/protected").await.unwrap();
    assert_eq!(status, 401, "{body}");
    assert_eq!(json(&body)["name"], "auth.client_cert_missing");

    assert_eq!(h.get(&client, "/healthz").await.unwrap().0, 200);
    assert_eq!(h.get(&client, "/open").await.unwrap().0, 200, "a route with no security stays anonymous");
}

#[tokio::test]
async fn an_mtls_verifier_authorizes_the_third_dns_san_and_refuses_a_different_one() {
    let mut h = Harness::new();
    write_api_project(&h, OPTIONAL, MTLS_ORDERS, serde_json::json!({}));
    start_api(&mut h).await;
    assert_eq!(h.get_as(Some(&LeafSpec::valid()), "/protected").await.unwrap().0, 200);

    let other = LeafSpec {
        dns: vec!["a.svc.example".into(), "b.svc.example".into()],
        ..LeafSpec::valid()
    };
    let (status, body) = h.get_as(Some(&other), "/protected").await.unwrap();
    assert_eq!(status, 401, "{body}");
    assert_eq!(json(&body)["name"], "auth.invalid_credentials");
}

#[tokio::test]
async fn required_mode_with_an_mtls_route_serves_a_matching_client() {
    let mut h = Harness::new();
    write_api_project(&h, REQUIRED, MTLS_ORDERS, serde_json::json!({}));
    start_api(&mut h).await;
    assert_eq!(h.get_as(Some(&LeafSpec::valid()), "/protected").await.unwrap().0, 200);
    assert!(h.get_as(None, "/protected").await.is_err(), "required: no certificate never reaches the route at all");
}

#[tokio::test]
async fn a_cert_route_is_refused_at_startup_when_client_auth_is_off() {
    let mut h = Harness::new();
    let tls_off = serde_json::json!({ "tls": { "mode": "manual", "manual": { "certPath": "cert.pem", "keyPath": "key.pem" } } });
    write_api_project(&h, r#"{ "mode": "off" }"#, MTLS_ORDERS, tls_off);
    start_api(&mut h).await;
    let client = h.client(None);
    assert_eq!(
        h.get(&client, "/protected").await.unwrap().0,
        404,
        "no way to ever obtain a certificate: the route must not exist"
    );
    assert_eq!(h.get(&client, "/open").await.unwrap().0, 200);
}

#[tokio::test]
async fn the_docs_ui_localhost_gate_still_sees_the_peer_address_under_tls_and_client_auth() {
    let mut h = Harness::new();
    write_api_project(&h, OPTIONAL, MTLS_ORDERS, serde_json::json!({ "docsUi": { "mode": "localhost" } }));
    start_api(&mut h).await;
    let client = h.client(None);
    let (status, _) = h.get(&client, "/docs").await.unwrap();
    assert_eq!(
        status, 200,
        "ConnectInfo must still reach the gate through the client-cert acceptor (a missing one fails closed with 403)"
    );
}

#[tokio::test]
async fn the_docs_operations_json_flags_a_client_certificate_requirement() {
    let mut h = Harness::new();
    write_api_project(&h, OPTIONAL, MTLS_ORDERS, serde_json::json!({ "docsUi": { "mode": "public" } }));
    start_api(&mut h).await;
    let (status, body) = h.get(&h.client(None), "/docs/operations.json").await.unwrap();
    assert_eq!(status, 200);
    let body = json(&body);
    let operations = body["operations"].as_array().expect("operations array");
    let protected = operations.iter().find(|o| o["path"] == "/protected").unwrap_or_else(|| panic!("{body}"));
    assert_eq!(protected["security"]["clientCert"], true, "{protected}");
    let open = operations.iter().find(|o| o["path"] == "/open").unwrap();
    assert!(open["security"].is_null(), "{open}");
}

#[tokio::test]
async fn the_client_cert_error_codes_are_classified_even_though_the_projects_core_json_lacks_them() {
    // core.json in `write_api_project` defines neither code; a 401 (not the
    // unclassified-error 500) proves the runtime defaults were inserted.
    let mut h = Harness::new();
    write_api_project(&h, OPTIONAL, MTLS_ORDERS, serde_json::json!({}));
    start_api(&mut h).await;
    let (status, body) = h.get(&h.client(None), "/protected").await.unwrap();
    assert_eq!(status, 401);
    assert!(json(&body)["detail"].is_string(), "exposeDetail defaults to true for the new codes: {body}");
}

#[tokio::test]
async fn required_mode_with_probes_enabled_warns_at_startup_and_optional_does_not() {
    for (mode, expect_warning) in [(REQUIRED, true), (OPTIONAL, false)] {
        let logs = LogBuffer::default();
        let _guard = logs.install(tracing::Level::WARN);
        let h = Harness::new();
        write_api_project(
            &h,
            mode,
            MTLS_ORDERS,
            serde_json::json!({ "features": { "requestCorrelation": false, "requestValidation": false, "readyzCheck": true, "metrics": false } }),
        );
        let _ = build_api_router(&h.root).await.unwrap();
        let warned = logs.text().contains("load-balancer probes");
        assert_eq!(warned, expect_warning, "{mode}: {}", logs.text());
    }
}

// ---------------------------------------------------------------------
// logging hygiene
// ---------------------------------------------------------------------

#[tokio::test]
async fn info_logs_never_contain_names_or_pem_for_success_rejected_handshakes_or_failed_verification() {
    let logs = LogBuffer::default();
    let _guard = logs.install(tracing::Level::INFO);
    let mut h = Harness::new();
    write_api_project(&h, OPTIONAL, MTLS_ORDERS, serde_json::json!({}));
    start_api(&mut h).await;

    let canary = LeafSpec {
        cn: vec!["leak-canary-cn".into()],
        dns: vec!["leak-canary.example".into(), "orders.internal.example.com".into()],
        email: vec!["leak-canary@example.com".into()],
        ..LeafSpec::valid()
    };
    let ok_leaf = h.leaf(&canary);
    let fingerprint = hex(ring::digest::digest(&ring::digest::SHA256, &ok_leaf.der()).as_ref());
    // success
    assert_eq!(h.get(&h.client(Some(&ok_leaf.identity_pem())), "/protected").await.unwrap().0, 200);
    // rejected handshake (wrong CA, same canary names)
    let rogue = build_leaf(&h.pki.wrong_ca, &canary);
    assert!(h.get(&h.client(Some(&rogue.identity_pem())), "/protected").await.is_err());
    // failed verification (valid chain, SAN does not match)
    let mismatch = LeafSpec {
        cn: vec!["leak-canary-cn".into()],
        dns: vec!["leak-canary.example".into()],
        ..LeafSpec::valid()
    };
    assert_eq!(h.get_as(Some(&mismatch), "/protected").await.unwrap().0, 401);

    let text = logs.text();
    for forbidden in ["leak-canary", "BEGIN CERTIFICATE", "BEGIN PRIVATE KEY", "frogs test client root", &fingerprint] {
        assert!(!text.contains(forbidden), "INFO output leaked {forbidden:?}:\n{text}");
    }
}

// ---------------------------------------------------------------------
// isolation and spoofing over real connections
// ---------------------------------------------------------------------

#[tokio::test]
async fn interleaved_keep_alive_connections_each_keep_their_own_identity() {
    let mut h = Harness::new();
    h.start_echo(OPTIONAL).await;
    let (a, b) = (h.leaf(&LeafSpec::valid()), h.leaf(&LeafSpec::valid()));
    let fp = |leaf: &Leaf| hex(ring::digest::digest(&ring::digest::SHA256, &leaf.der()).as_ref());
    let (config_a, config_b, config_anon) = (raw_config(&h, Some(&a)), raw_config(&h, Some(&b)), raw_config(&h, None));
    let mut conn_a = raw_connect(&h, &config_a).await;
    let mut conn_b = raw_connect(&h, &config_b).await;
    let mut conn_anon = raw_connect(&h, &config_anon).await;

    for round in 0..3 {
        let (_, body_a) = raw_get(&mut conn_a, "/echo").await;
        let (_, body_anon) = raw_get(&mut conn_anon, "/echo").await;
        let (_, body_b) = raw_get(&mut conn_b, "/echo").await;
        assert_eq!(json(&body_a)["fingerprint"], fp(&a), "round {round}");
        assert_eq!(json(&body_b)["fingerprint"], fp(&b), "round {round}");
        assert_eq!(
            json(&body_anon),
            serde_json::json!({ "anonymous": true }),
            "round {round}: an anonymous connection must never inherit a neighbour's identity"
        );
    }
}

#[tokio::test]
async fn spoofed_certificate_headers_over_tls_without_a_certificate_yield_no_identity() {
    let mut h = Harness::new();
    write_api_project(&h, OPTIONAL, MTLS_ORDERS, serde_json::json!({}));
    start_api(&mut h).await;
    let client = h.client(None);
    let spoof = |path: &str| {
        client
            .get(format!("https://localhost:{}{path}", h.port))
            .header(
                "X-Forwarded-Client-Cert",
                "Hash=abcd;Subject=\"CN=client.example.com\";URI=spiffe://example.org/ns/orders;DNS=orders.internal.example.com",
            )
            .header("X-SSL-Client-Fingerprint", "ab".repeat(32))
            .header("X-SSL-Client-CN", "client.example.com")
            .header("cert.san.dns", "orders.internal.example.com")
            .send()
    };
    let response = spoof("/protected").await.unwrap();
    assert_eq!(response.status(), 401);
    assert_eq!(response.json::<serde_json::Value>().await.unwrap()["name"], "auth.client_cert_missing");
}

#[tokio::test]
async fn spoofed_headers_do_not_override_a_real_but_non_matching_certificate() {
    let mut h = Harness::new();
    write_api_project(&h, OPTIONAL, MTLS_ORDERS, serde_json::json!({}));
    start_api(&mut h).await;
    let other = h.leaf(&LeafSpec {
        dns: vec!["unrelated.example".into()],
        ..LeafSpec::valid()
    });
    let client = h.client(Some(&other.identity_pem()));
    let response = client
        .get(format!("https://localhost:{}/protected", h.port))
        .header("X-Forwarded-Client-Cert", "DNS=orders.internal.example.com")
        .header("cert.san.dns", "orders.internal.example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    assert_eq!(response.json::<serde_json::Value>().await.unwrap()["name"], "auth.invalid_credentials");
}

#[tokio::test]
async fn spoofed_headers_over_plain_http_never_create_an_identity_in_the_echo_route() {
    // A plain-HTTP (clientAuth-less) listener: no acceptor strips anything,
    // so the only defence is that nothing ever reads a header into an identity.
    let router = echo_router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let response = reqwest::Client::new()
        .get(format!("http://{addr}/echo"))
        .header("X-Forwarded-Client-Cert", "Subject=CN=evil")
        .header("X-SSL-Client-Fingerprint", "ab".repeat(32))
        .header("cert.san.dns", "orders.internal.example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(response.json::<serde_json::Value>().await.unwrap(), serde_json::json!({ "anonymous": true }));
}
