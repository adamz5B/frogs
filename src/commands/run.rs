use std::io;
use std::path::Path;

use axum::Router;

use crate::config::{Config, ManualTlsConfig, ServerConfig, TlsConfig, TlsMode};
use crate::project::{MANIFEST_FILE, require_project_root};
use crate::server::pidfile;
use crate::webserve::WebServeConfig;

pub async fn run(cwd: &Path) -> io::Result<()> {
    let root = require_project_root(cwd);

    if let Some(existing) = pidfile::read(&root)? {
        if pidfile::is_alive(existing.pid) {
            eprintln!(
                "error: a server is already running for this project (pid {}, port {}) — \
                 run `frogs stop` first",
                existing.pid, existing.port
            );
            std::process::exit(1);
        }
        // Stale from a previous run that didn't get to clean up after
        // itself (e.g. killed rather than stopped via `frogs stop`).
        pidfile::remove(&root)?;
    }

    // `openapi.yaml`/`webserve.json`'s presence (not `.html` files or
    // `api/`'s own contents) is what `run` keys its mode off of — the same
    // two markers `generate` itself resolves a role from, and both are
    // present together whenever `generate` produced both sides (see
    // `commands::generate::run`'s `(true, true)` branch).
    let has_api = root.join(MANIFEST_FILE).is_file();
    let has_web = root.join("webserve.json").is_file();

    match (has_api, has_web) {
        (false, false) => {
            eprintln!("error: no {MANIFEST_FILE} or webserve.json found at {} — run `frogs generate` first", root.display());
            std::process::exit(1);
        }
        (true, false) => run_api(&root).await,
        (false, true) => run_web(&root).await,
        (true, true) => run_both(&root).await,
    }
}

async fn run_api(root: &Path) -> io::Result<()> {
    println!("project root: {}", root.display());
    let (router, server_config) = build_api_router(root).await?;

    println!(
        "serving GET/POST/PUT/PATCH/DELETE endpoints discovered under datasources/endpoints/ (see log output \
         above) plus {}",
        operational_routes_display(&server_config).join(", ")
    );

    let api_dir = crate::project::api_base(root);
    serve(root, router, server_config.port, &server_config.tls, &api_dir).await
}

/// `/healthz` (always) plus `/readyz`/`/metrics` (only when their feature
/// is on), each already prefixed with `apiRoot` — the same list `run_api`
/// and `run_both` both print at startup, so a project running both roles
/// doesn't get a less informative status line than an API-only one.
fn operational_routes_display(server_config: &ServerConfig) -> Vec<String> {
    let api_root_display = crate::server::normalize_api_root(&server_config.api_root).unwrap_or_default();
    let mut routes = vec![format!("{api_root_display}/healthz")];
    if server_config.features.readyz_check {
        routes.push(format!("{api_root_display}/readyz"));
    }
    if server_config.features.metrics {
        routes.push(format!("{api_root_display}/metrics"));
    }
    routes
}

async fn run_web(root: &Path) -> io::Result<()> {
    println!("project root: {}", root.display());
    let (router, config) = build_web_router(root);

    println!(
        "serving static content — startPage: {}, port: {}{}",
        config.start_page,
        config.port,
        config.not_found_page.as_ref().map(|p| format!(", notFoundPage: {p}")).unwrap_or_default()
    );

    // No `api/` subfolder in a web-only project — `certPath`/`keyPath`
    // resolve relative to the project root itself, right alongside
    // `webserve.json`.
    serve(root, router, config.port, &config.tls, root).await
}

async fn run_both(root: &Path) -> io::Result<()> {
    println!("project root: {}", root.display());
    let (api_router, server_config) = build_api_router(root).await?;
    let (web_router, web_config) = build_web_router(root);

    let api_root_display = crate::server::normalize_api_root(&server_config.api_root).unwrap_or_else(|| "unprefixed".to_string());
    println!(
        "serving both an API ({api_root_display}) and static content (startPage: {}) from one process",
        web_config.start_page
    );
    println!("API operational routes: {}", operational_routes_display(&server_config).join(", "));
    if web_config.port != server_config.port {
        // Only one process, only one listener — `config/server.json`'s port
        // is authoritative whenever both roles run together (see Point 1's
        // design discussion); `webserve.json`'s own `port` still matters for
        // a standalone web-only project, just not this one.
        println!(
            "note: webserve.json's own port ({}) is ignored while serving both roles — config/server.json's \
             port ({}) is authoritative",
            web_config.port, server_config.port
        );
    }
    if web_config.tls.mode != TlsMode::Off {
        // Same authority split as `port` just above, for the same reason —
        // one listener, one TLS configuration.
        println!(
            "note: webserve.json's own tls settings are ignored while serving both roles — config/server.json's \
             tls settings are authoritative"
        );
    }

    // `Router::merge` combines the two as siblings: the API side's specific
    // routes (already nested under `apiRoot`, already middleware-wrapped)
    // take priority over the static side's `/*path` catch-all at matchit's
    // routing level, and the static side stays exactly as un-middlewared as
    // it is standalone — merging doesn't retroactively share layers between
    // the two (see `server::apply_middleware`'s own doc comment).
    let router = api_router.merge(web_router);

    // `config/server.json`'s `tls` is authoritative here too — same
    // single-listener reasoning as the port-authority note above.
    let api_dir = crate::project::api_base(root);
    serve(root, router, server_config.port, &server_config.tls, &api_dir).await
}

/// Loads config, connects every SQL driver, and builds the fully-nested,
/// middleware-wrapped API router — the piece `run_api` and `run_both` both
/// need, extracted so serving both roles from one process doesn't mean
/// duplicating SQL connection handling or router composition.
async fn build_api_router(root: &Path) -> io::Result<(Router, ServerConfig)> {
    let api_dir = crate::project::api_base(root);
    let config = Config::load_or_exit(&api_dir);
    println!(
        "loaded config — debugMode={}, {} connection(s), {} error code(s)",
        config.server.debug_mode,
        config.connections.len(),
        config.errors.len()
    );

    // A log line, not a blocker — the server starts normally either way.
    // Exists so an accumulating pile of unclassified errors (see
    // `endpoint::record_discovered_error`) doesn't go unnoticed
    // indefinitely; this only ever fires in projects that run with
    // `debugMode` on, since that's the only way the scratch file grows.
    let discovered_count = config.discovered_errors.len();
    if should_warn_about_discovered_errors(discovered_count, config.server.discovered_errors_warn_threshold) {
        tracing::warn!(
            "config/errors.discovered.json has {discovered_count} entries (threshold: {}). Consider running \
             `frogs errors freeze` to snapshot these into config/errors/, or review and hand-classify them \
             individually.",
            config.server.discovered_errors_warn_threshold
        );
    }

    let drivers = match crate::sql::connect_all(&config.connections).await {
        Ok(drivers) => drivers,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(1);
        }
    };
    println!("connected {} SQL data source(s)", drivers.len());
    let drivers = std::sync::Arc::new(drivers);

    let debug_mode = config.server.debug_mode;
    let errors = std::sync::Arc::new(config.errors);
    let security = std::sync::Arc::new(config.security);
    let services = std::sync::Arc::new(config.services);
    let discovered_errors = std::sync::Arc::new(std::sync::Mutex::new(config.discovered_errors));

    // Only loaded (and only consulted) when `features.requestValidation` is
    // on — a load failure degrades to "no route gets validation" with a
    // warning, the same graceful-degradation posture `build_router` itself
    // uses for a route whose operation can't be matched, rather than
    // refusing to start the server over a request-validation-only concern.
    let openapi_document = if config.server.features.request_validation {
        match crate::openapi::load(&root.join(crate::project::MANIFEST_FILE)) {
            Ok(doc) => Some(doc),
            Err(e) => {
                tracing::warn!("failed to load {}: {e} — request validation is disabled for this run", crate::project::MANIFEST_FILE);
                None
            }
        }
    } else {
        None
    };
    let endpoint_router = crate::endpoint::build_router(
        &api_dir,
        drivers.clone(),
        errors,
        security,
        services,
        discovered_errors,
        debug_mode,
        openapi_document.as_ref(),
    );
    let mut router = crate::server::router().merge(endpoint_router);

    // Each is a separate, independently-stated router merged in only when
    // its feature is on — see `server::readyz_router`/`metrics_router`'s
    // own doc comments for why this shape, rather than baking both into
    // `server::router()` unconditionally.
    if config.server.features.readyz_check {
        router = router.merge(crate::server::readyz_router(drivers));
    }
    let metrics = config.server.features.metrics.then(|| std::sync::Arc::new(crate::server::Metrics::new()));
    if let Some(metrics) = &metrics {
        router = router.merge(crate::server::metrics_router(metrics.clone()));
    }

    let router = crate::server::mount_under(router, &config.server.api_root);
    // Applied last, after every route is registered (nesting under
    // apiRoot included) — see `server::apply_middleware`'s doc comment for
    // why this ordering matters; `apply_metrics`/`apply_rate_limit` have the
    // same requirement, for the same reason.
    let router = if config.server.features.request_correlation {
        crate::server::apply_middleware(router)
    } else {
        router
    };
    let router = match metrics {
        Some(metrics) => crate::server::apply_metrics(router, metrics),
        None => router,
    };
    let router = if config.server.features.rate_limiting {
        let limiter = std::sync::Arc::new(crate::server::RateLimiter::new(
            config.server.rate_limit.requests_per_second,
            config.server.rate_limit.burst,
        ));
        crate::server::apply_rate_limit(router, limiter)
    } else {
        router
    };
    // Outermost of all the optional middleware layers — see
    // `server::apply_cors`'s doc comment for why it has to wrap the others,
    // not just come after them in registration order.
    let router = if config.server.features.cors {
        if config.server.cors.allowed_origins.is_empty() {
            tracing::warn!("features.cors is enabled but cors.allowedOrigins is empty — no origin will receive CORS headers");
        }
        crate::server::apply_cors(router, &config.server.cors.allowed_origins)
    } else {
        router
    };

    Ok((router, config.server))
}

/// Loads `webserve.json` and builds the static-content router — the piece
/// `run_web` and `run_both` both need. Exits the process on a malformed
/// config, same posture as `build_api_router` does for a broken
/// `config/server.json`.
fn build_web_router(root: &Path) -> (Router, WebServeConfig) {
    let config = match crate::webserve::load(&root.join("webserve.json")) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(1);
        }
    };
    let router = crate::webserve::router(root.to_path_buf(), config.clone());
    (router, config)
}

/// Binds `port`, writes the PID file, serves `router` until Ctrl+C or an
/// external `frogs stop`, then cleans the PID file up — the tail end every
/// run mode (`run_api`/`run_web`/`run_both`) shares once its own router is
/// built, regardless of which role(s) that router serves. `tls` selects
/// plain HTTP (`TlsMode::Off`, unchanged behavior) or HTTPS via a
/// user-supplied cert/key pair (`TlsMode::Manual`) — see
/// `docs/frogs-https-development.md`. `tls_base` is where `tls.manual`'s
/// `certPath`/`keyPath` resolve relative to — `api_base(root)` for
/// `run_api`/`run_both` (matching where `config/server.json` itself, and
/// every other path it reads, already resolve from), or `root` itself for
/// `run_web` (no `api/` subfolder exists in a web-only project).
///
/// No graceful in-flight-request draining — a deliberate scope decision,
/// not an oversight: frogs holds no state of its own across a request (the
/// real data lives in Postgres/downstream APIs, or on disk for static
/// content), so the only risk a hard kill carries is a caller not finding
/// out whether their in-flight write's response made it back — which a
/// clean shutdown signal wouldn't fully eliminate either, since the write
/// can already have committed upstream before the signal arrives. Ctrl+C
/// and an external `frogs stop` both just end the process; the `select!`
/// in both `serve_http`/`serve_https` below only makes sure
/// `.frogs/run.json` doesn't linger after the terminal (Ctrl+C) case
/// specifically, since `frogs stop` already removes it itself after
/// terminating the process externally.
async fn serve(root: &Path, router: Router, port: u16, tls: &TlsConfig, tls_base: &Path) -> io::Result<()> {
    match tls.mode {
        TlsMode::Off => serve_http(root, router, port).await,
        TlsMode::Manual => {
            let manual = tls
                .manual
                .as_ref()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "tls.mode is \"manual\" but tls.manual (certPath/keyPath) is missing"))?;
            serve_https(root, router, port, manual, tls_base).await
        }
    }
}

async fn serve_http(root: &Path, router: Router, port: u16) -> io::Result<()> {
    let addr = format!("0.0.0.0:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    pidfile::write(
        root,
        &pidfile::RunInfo {
            pid: std::process::id(),
            port,
            started_at: chrono::Utc::now(),
        },
    )?;

    println!("listening on http://{addr} (Ctrl+C to stop, or `frogs stop` from another terminal)");

    let result = tokio::select! {
        result = axum::serve(listener, router) => result,
        _ = tokio::signal::ctrl_c() => {
            println!("received Ctrl+C, shutting down");
            Ok(())
        }
    };

    pidfile::remove(root)?;
    result
}

/// `manual.certPath`/`keyPath` resolve relative to `tls_base` — see
/// `serve`'s own doc comment for which base each caller passes and why.
async fn serve_https(root: &Path, router: Router, port: u16, manual: &ManualTlsConfig, tls_base: &Path) -> io::Result<()> {
    let addr_str = format!("0.0.0.0:{port}");
    let addr: std::net::SocketAddr = addr_str
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid port {port}: {e}")))?;

    let cert_path = tls_base.join(&manual.cert_path);
    let key_path = tls_base.join(&manual.key_path);
    let rustls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert_path, &key_path).await.map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("failed to load TLS cert/key ({}, {}): {e}", cert_path.display(), key_path.display()),
        )
    })?;

    // A `std::net::TcpListener` (not tokio's), bound synchronously here so a
    // port-already-in-use failure surfaces as an immediate `?` — same
    // fail-before-writing-the-pidfile ordering `serve_http` gets for free
    // from `tokio::net::TcpListener::bind`'s own early `?`. Must be put in
    // non-blocking mode explicitly before tokio adopts it: on Unix, tokio
    // asserts this itself (and panics in debug builds if it's missed), but
    // that check is a silent no-op on Windows (it can't query the flag),
    // so skipping this here would still register a *blocking* socket with
    // the async reactor — its `accept()` calls then block the whole
    // executor thread instead of yielding, which on the single-threaded
    // runtime `#[tokio::test]` defaults to is a real, observed deadlock:
    // the server's own accept loop starves every other task on that same
    // thread, including a test's own client request waiting on it.
    let listener = std::net::TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    let server = axum_server::from_tcp_rustls(listener, rustls_config)?;

    pidfile::write(
        root,
        &pidfile::RunInfo {
            pid: std::process::id(),
            port,
            started_at: chrono::Utc::now(),
        },
    )?;

    println!("listening on https://{addr_str} (Ctrl+C to stop, or `frogs stop` from another terminal)");

    let result = tokio::select! {
        result = server.serve(router.into_make_service()) => result,
        _ = tokio::signal::ctrl_c() => {
            println!("received Ctrl+C, shutting down");
            Ok(())
        }
    };

    pidfile::remove(root)?;
    result
}

/// `>=`, not `>` — a project whose threshold is exactly met is exactly the
/// point the design doc means by "grown enough to be worth dealing with,"
/// not one entry later.
fn should_warn_about_discovered_errors(count: usize, threshold: u32) -> bool {
    count as u32 >= threshold
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn does_not_warn_below_the_threshold() {
        assert!(!should_warn_about_discovered_errors(19, 20));
    }

    #[test]
    fn warns_exactly_at_the_threshold() {
        assert!(should_warn_about_discovered_errors(20, 20));
    }

    #[test]
    fn warns_above_the_threshold() {
        assert!(should_warn_about_discovered_errors(24, 20));
    }

    #[test]
    fn a_zero_threshold_always_warns_even_with_nothing_discovered_yet() {
        // An edge case worth pinning down explicitly: a project that sets
        // the threshold to 0 is asking to be told about every single
        // discovered error, including having zero of them — not a
        // never-warn setting.
        assert!(should_warn_about_discovered_errors(0, 0));
    }

    fn temp_project() -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "frogs-run-tls-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    /// `main()`'s own `install_default()` call never runs under `cargo
    /// test` (the test binary has no `main` of its own) — each test that
    /// actually performs a TLS handshake needs the same install itself.
    /// `Once`-guarded since installing twice in one test binary would
    /// otherwise error on the second call.
    fn ensure_crypto_provider() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    /// An OS-assigned free port, released immediately so `serve` (which
    /// takes a fixed `port: u16`, not "any free port") can bind it for
    /// real — the same small, standard bind-then-drop trick used to hand a
    /// synchronous port number to an API that doesn't accept one directly.
    fn free_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    }

    /// `tls.mode: "manual"` with no `tls.manual` block at all — a config
    /// mistake that must fail loudly before ever binding a port, not panic
    /// or silently fall back to plain HTTP.
    #[tokio::test]
    async fn manual_mode_with_no_manual_config_is_a_clear_error() {
        let root = temp_project();
        let tls = TlsConfig {
            mode: TlsMode::Manual,
            manual: None,
        };
        let router = Router::new();

        let err = serve(&root, router, free_port(), &tls, &root)
            .await
            .expect_err("tls.mode: manual with no tls.manual block must fail, not silently serve plain HTTP");
        assert!(err.to_string().contains("tls.manual"));

        // Nothing should have been bound or written for a config error this
        // early.
        assert!(pidfile::read(&root).unwrap().is_none());
    }

    /// A `certPath`/`keyPath` that doesn't actually resolve to a real file —
    /// must fail with a clear message naming both paths, not panic or hang
    /// waiting on a listener that never gets bound.
    #[tokio::test]
    async fn a_missing_cert_file_is_a_clear_error() {
        ensure_crypto_provider();
        let root = temp_project();
        let tls = TlsConfig {
            mode: TlsMode::Manual,
            manual: Some(ManualTlsConfig {
                cert_path: "does-not-exist-cert.pem".to_string(),
                key_path: "does-not-exist-key.pem".to_string(),
            }),
        };
        let router = Router::new();

        let err = serve(&root, router, free_port(), &tls, &root)
            .await
            .expect_err("a nonexistent cert file must fail to load, not panic or hang");
        assert!(err.to_string().contains("does-not-exist-cert.pem"));
        assert!(err.to_string().contains("does-not-exist-key.pem"));

        assert!(pidfile::read(&root).unwrap().is_none());
    }

    /// Real end-to-end proof of the whole manual-TLS path: a genuine
    /// self-signed cert (via `rcgen`, matching this project's own
    /// `docs/frogs-https-development.md` testing guidance — no committed
    /// cert fixtures, no external tool needed), the real `serve` function
    /// loading it exactly the way `run_api`/`run_both` do (from PEM files
    /// on disk, via `config/server.json`'s `tls.manual`), and a real
    /// `reqwest` client that only trusts *this* generated cert's own root —
    /// proving actual TLS validation succeeds, not just "any cert accepted."
    #[tokio::test]
    async fn a_real_https_request_succeeds_against_a_manually_configured_cert() {
        ensure_crypto_provider();
        let root = temp_project();
        // `serve`'s `tls_base` for `run_api`/`run_both` is `api_base(root)`
        // (`<root>/api`) — see `serve`'s own doc comment — so the cert has
        // to actually live there for this test to exercise the real path.
        let api_dir = root.join("api");
        std::fs::create_dir_all(&api_dir).unwrap();
        let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_pem = key.cert.pem();
        std::fs::write(api_dir.join("cert.pem"), &cert_pem).unwrap();
        std::fs::write(api_dir.join("key.pem"), key.key_pair.serialize_pem()).unwrap();

        let tls = TlsConfig {
            mode: TlsMode::Manual,
            manual: Some(ManualTlsConfig {
                cert_path: "cert.pem".to_string(),
                key_path: "key.pem".to_string(),
            }),
        };
        let port = free_port();
        let router = Router::new().route("/hello", axum::routing::get(|| async { "hi" }));

        let spawned_root = root.clone();
        let spawned_api_dir = api_dir.clone();
        tokio::spawn(async move {
            let _ = serve(&spawned_root, router, port, &tls, &spawned_api_dir).await;
        });
        // Brief wait for the spawned task to actually bind the listener
        // before the client below tries to connect to it.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let trusted_root = reqwest::Certificate::from_pem(cert_pem.as_bytes()).unwrap();
        let client = reqwest::Client::builder().add_root_certificate(trusted_root).build().unwrap();

        let response = client
            .get(format!("https://localhost:{port}/hello"))
            .send()
            .await
            .expect("a real HTTPS request against a cert this client actually trusts should succeed");
        assert_eq!(response.status(), 200);
        assert_eq!(response.text().await.unwrap(), "hi");
    }

    /// The exact inverse of the test above: a client that does *not* trust
    /// the self-signed cert's root must have its request rejected — proof
    /// this is real certificate validation, not a server that happens to
    /// accept any TLS connection regardless of trust.
    #[tokio::test]
    async fn a_client_that_does_not_trust_the_cert_is_rejected() {
        ensure_crypto_provider();
        let root = temp_project();
        let api_dir = root.join("api");
        std::fs::create_dir_all(&api_dir).unwrap();
        let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        std::fs::write(api_dir.join("cert.pem"), key.cert.pem()).unwrap();
        std::fs::write(api_dir.join("key.pem"), key.key_pair.serialize_pem()).unwrap();

        let tls = TlsConfig {
            mode: TlsMode::Manual,
            manual: Some(ManualTlsConfig {
                cert_path: "cert.pem".to_string(),
                key_path: "key.pem".to_string(),
            }),
        };
        let port = free_port();
        let router = Router::new().route("/hello", axum::routing::get(|| async { "hi" }));

        let spawned_root = root.clone();
        let spawned_api_dir = api_dir.clone();
        tokio::spawn(async move {
            let _ = serve(&spawned_root, router, port, &tls, &spawned_api_dir).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // The default client trusts the normal public CA roots, not this
        // one-off self-signed cert.
        let client = reqwest::Client::new();
        let result = client.get(format!("https://localhost:{port}/hello")).send().await;
        assert!(result.is_err(), "a client with no reason to trust this self-signed cert must reject the connection");
    }

    /// The web-only counterpart to the two tests above: `run_web` (no
    /// `api/` at all) resolving `webserve.json`'s own `tls.manual` — proof
    /// that a purely static-content project really does get real HTTPS,
    /// with `certPath`/`keyPath` resolving against the project root
    /// (there's no `api/` subfolder to nest them under here), not
    /// `api_base(root)` the way `run_api`/`run_both` do.
    #[tokio::test]
    async fn run_web_serves_real_https_from_its_own_webserve_json_tls_config() {
        ensure_crypto_provider();
        let root = temp_project();
        std::fs::write(root.join("index.html"), "hello from static content").unwrap();

        let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_pem = key.cert.pem();
        std::fs::write(root.join("cert.pem"), &cert_pem).unwrap();
        std::fs::write(root.join("key.pem"), key.key_pair.serialize_pem()).unwrap();

        let port = free_port();
        std::fs::write(
            root.join("webserve.json"),
            format!(
                r#"{{
                    "startPage": "index.html",
                    "port": {port},
                    "tls": {{
                        "mode": "manual",
                        "manual": {{ "certPath": "cert.pem", "keyPath": "key.pem" }}
                    }}
                }}"#
            ),
        )
        .unwrap();

        let spawned_root = root.clone();
        tokio::spawn(async move {
            let _ = run_web(&spawned_root).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let trusted_root = reqwest::Certificate::from_pem(cert_pem.as_bytes()).unwrap();
        let client = reqwest::Client::builder().add_root_certificate(trusted_root).build().unwrap();

        let response = client
            .get(format!("https://localhost:{port}/"))
            .send()
            .await
            .expect("a real HTTPS request against run_web's own tls config should succeed");
        assert_eq!(response.status(), 200);
        assert_eq!(response.text().await.unwrap(), "hello from static content");
    }

    /// A minimal but complete API-role scratch project — every file
    /// `Config::load_or_exit`/`connect_all` need present (even if empty),
    /// so `build_api_router` runs its real assembly path end to end without
    /// hitting either function's own `process::exit` on a genuine config
    /// problem. `requestValidation` is off so this test isn't also
    /// exercising that unrelated feature.
    fn scratch_api_project(request_correlation: bool) -> std::path::PathBuf {
        let root = temp_project();
        let api_dir = root.join("api");
        std::fs::create_dir_all(api_dir.join("config/errors")).unwrap();
        std::fs::create_dir_all(api_dir.join("security")).unwrap();
        std::fs::create_dir_all(api_dir.join("datasources/endpoints")).unwrap();
        std::fs::write(root.join("openapi.yaml"), "openapi: 3.0.3\ninfo: { title: t, version: '1' }\npaths: {}\n").unwrap();
        std::fs::write(
            api_dir.join("config/server.json"),
            format!(r#"{{ "features": {{ "requestCorrelation": {request_correlation}, "requestValidation": false }} }}"#),
        )
        .unwrap();
        std::fs::write(api_dir.join("config/errors/core.json"), "{}").unwrap();
        std::fs::write(api_dir.join("config/connections.json"), "{}").unwrap();
        std::fs::write(api_dir.join("security/schemes.json"), "{}").unwrap();
        root
    }

    /// The gap this section closes: `features.requestCorrelation` used to
    /// have zero effect (the middleware ran unconditionally regardless of
    /// this setting) — proven both ways through the real `build_api_router`
    /// assembly, not just `server::apply_middleware`'s own isolated tests.
    #[tokio::test]
    async fn request_correlation_true_adds_the_x_request_id_header() {
        let root = scratch_api_project(true);
        let (router, _) = build_api_router(&root).await.expect("a minimal but complete scratch project should build cleanly");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let response = reqwest::get(format!("http://{addr}/healthz")).await.unwrap();
        assert!(response.headers().contains_key("x-request-id"), "requestCorrelation: true must add X-Request-Id");
    }

    #[tokio::test]
    async fn request_correlation_false_omits_the_x_request_id_header() {
        let root = scratch_api_project(false);
        let (router, _) = build_api_router(&root).await.expect("a minimal but complete scratch project should build cleanly");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let response = reqwest::get(format!("http://{addr}/healthz")).await.unwrap();
        assert!(
            !response.headers().contains_key("x-request-id"),
            "requestCorrelation: false must actually disable X-Request-Id, not just be a documented-but-inert toggle"
        );
    }

    /// Same shape as `scratch_api_project`, but for `features.cors` — a
    /// separate helper rather than growing that one's signature further,
    /// since only these two tests need a configurable origin allowlist.
    fn scratch_api_project_with_cors(allowed_origins: &str) -> std::path::PathBuf {
        let root = temp_project();
        let api_dir = root.join("api");
        std::fs::create_dir_all(api_dir.join("config/errors")).unwrap();
        std::fs::create_dir_all(api_dir.join("security")).unwrap();
        std::fs::create_dir_all(api_dir.join("datasources/endpoints")).unwrap();
        std::fs::write(root.join("openapi.yaml"), "openapi: 3.0.3\ninfo: { title: t, version: '1' }\npaths: {}\n").unwrap();
        std::fs::write(
            api_dir.join("config/server.json"),
            format!(r#"{{ "features": {{ "cors": true, "requestValidation": false }}, "cors": {{ "allowedOrigins": {allowed_origins} }} }}"#),
        )
        .unwrap();
        std::fs::write(api_dir.join("config/errors/core.json"), "{}").unwrap();
        std::fs::write(api_dir.join("config/connections.json"), "{}").unwrap();
        std::fs::write(api_dir.join("security/schemes.json"), "{}").unwrap();
        root
    }

    /// The same "prove the feature flag actually gates something, through
    /// the real `build_api_router` assembly" discipline as the
    /// `requestCorrelation` tests above — `server::apply_cors`'s own tests
    /// already cover the middleware in isolation; this proves `frogs run`
    /// actually wires `config/server.json`'s `cors` block into it.
    #[tokio::test]
    async fn cors_end_to_end_echoes_an_allowed_origin_and_omits_others() {
        let root = scratch_api_project_with_cors(r#"["https://allowed.example"]"#);
        let (router, _) = build_api_router(&root).await.expect("a minimal but complete scratch project should build cleanly");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let client = reqwest::Client::new();
        let allowed = client
            .get(format!("http://{addr}/healthz"))
            .header("origin", "https://allowed.example")
            .send()
            .await
            .unwrap();
        assert_eq!(allowed.headers().get("access-control-allow-origin").unwrap(), "https://allowed.example");

        let other = client
            .get(format!("http://{addr}/healthz"))
            .header("origin", "https://other.example")
            .send()
            .await
            .unwrap();
        assert!(other.headers().get("access-control-allow-origin").is_none());
    }
}
