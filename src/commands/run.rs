use std::io;
use std::path::Path;

use axum::Router;

use crate::config::{Config, ServerConfig};
use crate::project::{require_project_root, MANIFEST_FILE};
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
            eprintln!(
                "error: no {MANIFEST_FILE} or webserve.json found at {} — run `frogs generate` first",
                root.display()
            );
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

    serve(root, router, server_config.port).await
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

    serve(root, router, config.port).await
}

async fn run_both(root: &Path) -> io::Result<()> {
    println!("project root: {}", root.display());
    let (api_router, server_config) = build_api_router(root).await?;
    let (web_router, web_config) = build_web_router(root);

    let api_root_display = crate::server::normalize_api_root(&server_config.api_root).unwrap_or_else(|| "unprefixed".to_string());
    println!("serving both an API ({api_root_display}) and static content (startPage: {}) from one process", web_config.start_page);
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

    // `Router::merge` combines the two as siblings: the API side's specific
    // routes (already nested under `apiRoot`, already middleware-wrapped)
    // take priority over the static side's `/*path` catch-all at matchit's
    // routing level, and the static side stays exactly as un-middlewared as
    // it is standalone — merging doesn't retroactively share layers between
    // the two (see `server::apply_middleware`'s own doc comment).
    let router = api_router.merge(web_router);

    serve(root, router, server_config.port).await
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
    let discovered_errors = std::sync::Arc::new(std::sync::Mutex::new(config.discovered_errors));
    let endpoint_router =
        crate::endpoint::build_router(&api_dir, drivers.clone(), errors, security, discovered_errors, debug_mode);
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
    // why this ordering matters; `apply_metrics` has the same requirement,
    // for the same reason.
    let router = crate::server::apply_middleware(router);
    let router = match metrics {
        Some(metrics) => crate::server::apply_metrics(router, metrics),
        None => router,
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
/// built, regardless of which role(s) that router serves.
///
/// No graceful in-flight-request draining — a deliberate scope decision,
/// not an oversight: frogs holds no state of its own across a request (the
/// real data lives in Postgres/downstream APIs, or on disk for static
/// content), so the only risk a hard kill carries is a caller not finding
/// out whether their in-flight write's response made it back — which a
/// clean shutdown signal wouldn't fully eliminate either, since the write
/// can already have committed upstream before the signal arrives. Ctrl+C
/// and an external `frogs stop` both just end the process; the `select!`
/// below only makes sure `.frogs/run.json` doesn't linger after the
/// terminal (Ctrl+C) case specifically, since `frogs stop` already removes
/// it itself after terminating the process externally.
async fn serve(root: &Path, router: Router, port: u16) -> io::Result<()> {
    let addr = format!("0.0.0.0:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    pidfile::write(root, &pidfile::RunInfo { pid: std::process::id(), port, started_at: chrono::Utc::now() })?;

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
}
