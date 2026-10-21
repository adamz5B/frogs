use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Router;

use crate::config::{Config, ServerConfig, TlsConfig, TlsMode};
use crate::endpoint::mock::MockProvider;
use crate::endpoint::route_plan::{RootExtras, RouteContext, RoutePlan};
use crate::openapi::endpoint_tree::{EndpointTree, LinkContext};
use crate::openapi::method_token::MethodCase;
use crate::project::{MANIFEST_FILE, require_project_root};
use crate::server::pidfile;
use crate::server::service::{self, RunDecision, ServiceRecord};
use crate::sql::SqlDriver;
use crate::webserve::WebServeConfig;

/// `service_managed` is the hidden, internal-only flag baked into every
/// registered service definition's own command line (`run
/// --service-managed`) — it exists purely to stop the OS-supervised process
/// from recursively delegating back to `run_registered` below. `restart` is
/// the normal public flag that only has an effect for a registered project.
pub async fn run(cwd: &Path, service_managed: bool, restart: bool) -> io::Result<()> {
    let root = require_project_root(cwd);

    if !service_managed {
        if let Some(record) = service::read_record(&root)? {
            // A registered project's `frogs run` never binds a port itself
            // (see `run_registered`'s own doc comment) — same stdout-only
            // posture `generate`/`stop` already have, not the persistent
            // file subscriber `run_direct_with_shutdown` installs.
            crate::server::logging::install_bootstrap_subscriber();
            return run_registered(&root, &record, restart).await;
        }
        if restart {
            println!("note: --restart has no effect — this project is not registered as a service");
        }
    }

    run_direct(&root).await
}

/// The default, Ctrl+C-based shutdown signal every unregistered project's
/// `frogs run` (and every existing test of this module) uses —
/// `run_direct_with_shutdown` accepts any future so a registered Windows
/// Service (see `server::service_host::run_service`) can instead pass one
/// tied to the SCM's own Stop/Shutdown control events.
pub async fn run_direct(root: &Path) -> io::Result<()> {
    run_direct_with_shutdown(root, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
}

/// The registered-project path: revalidate the record unconditionally,
/// then decide whether to start, report, or restart the OS-managed service
/// — never binds a port itself, in any outcome, since the real server
/// always runs as the separately-supervised `--service-managed` process.
async fn run_registered(root: &Path, record: &ServiceRecord, restart_requested: bool) -> io::Result<()> {
    if let Err(e) = service::revalidate(record, root) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
    if let Err(e) = precheck_security_for_service(root) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }

    let running = service::is_running(record)?;
    match service::decide_run_action(running, restart_requested) {
        RunDecision::Start => {
            service::start_registered(record, root)?;
            println!("service {} was not running — started via {}", record.name, service::backend_label(record.backend));
        }
        RunDecision::AlreadyRunningReportOnly => {
            service::report_status_only(record, root)?;
            println!(
                "service {} is already running via {} — run `frogs run --restart` to restart it",
                record.name,
                service::backend_label(record.backend)
            );
        }
        RunDecision::Restart => {
            service::restart_registered(record, root)?;
            println!(
                "service {} was already running — restarted via {} (--restart)",
                record.name,
                service::backend_label(record.backend)
            );
        }
    }
    Ok(())
}

/// Today's exact `frogs run` behavior — pidfile check, role detection,
/// router build/serve — reached both by an unregistered project (via
/// `run_direct`, below) and by every OS-supervised process, on any
/// platform (`--service-managed` on Linux/macOS, `service_host::run_service`
/// on Windows), which must always land here directly rather than ever
/// routing back through `run_registered`. `shutdown` is awaited instead of
/// a hardcoded `tokio::signal::ctrl_c()` so a supervised process can tie
/// its own shutdown to whatever signal its supervisor actually uses,
/// without duplicating this function's own pidfile/role-detection logic.
pub async fn run_direct_with_shutdown(root: &Path, shutdown: impl std::future::Future<Output = ()> + Send + 'static) -> io::Result<()> {
    // `openapi.yaml`/`webserve.json`'s presence (not `.html` files or
    // `api/`'s own contents) is what `run` keys its mode off of — the same
    // two markers `generate` itself resolves a role from, and both are
    // present together whenever `generate` produced both sides (see
    // `commands::generate::run`'s `(true, true)` branch). Hoisted to the top
    // of this function (ahead of the pidfile check below) because the
    // persistent-logging subscriber needs `has_api` to resolve the right log
    // directory before anything else in this function runs — see
    // `docs/frogs-persistent-logging.md`'s note on this ordering tradeoff
    // (the log directory/file now gets created before the "already running"
    // pidfile check, accepted rather than restructured).
    let has_api = root.join(MANIFEST_FILE).is_file();
    let has_web = root.join("webserve.json").is_file();

    // Bound for the rest of this function's body — `LoggingHandles`'s
    // `Drop` flushes buffered file writes, so it must not go out of scope
    // (and drop) before `serve` actually returns.
    let (log_dir, log_level) = crate::server::logging::resolve_log_directory(root, has_api);
    let _logging_handles = crate::server::logging::install_run_subscriber(&log_dir, log_level);

    refuse_if_already_running(root)?;

    match (has_api, has_web) {
        (false, false) => {
            eprintln!("error: no {MANIFEST_FILE} or webserve.json found at {} — run `frogs generate` first", root.display());
            std::process::exit(1);
        }
        (true, false) => run_api(root, shutdown).await,
        (false, true) => run_web(root, shutdown).await,
        (true, true) => run_both(root, shutdown).await,
    }
}

/// The "already running" pidfile check every server-binding command
/// (`frogs run`, `frogs test`) makes before touching a port: exits the
/// process if `.frogs/run.json` names a live PID, cleans up a stale one.
pub(crate) fn refuse_if_already_running(root: &Path) -> io::Result<()> {
    if let Some(existing) = pidfile::read(root)? {
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
        pidfile::remove(root)?;
    }
    Ok(())
}

async fn run_api(root: &Path, shutdown: impl std::future::Future<Output = ()> + Send + 'static) -> io::Result<()> {
    println!("project root: {}", root.display());
    let (router, server_config) = build_api_router(root, false).await?;

    println!(
        "serving GET/POST/PUT/PATCH/DELETE/QUERY endpoints discovered under datasources/endpoints/ (see log output \
         above) plus {}",
        operational_routes_display(&server_config).join(", ")
    );
    tracing::info!(roles = "api", port = server_config.port, tls_mode = ?server_config.tls.mode, "frogs run starting");

    let api_dir = crate::project::api_base(root);
    serve(
        root,
        router,
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        server_config.port,
        &server_config.tls,
        &api_dir,
        server_config.case_sensitive_methods(),
        shutdown,
    )
    .await
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
    if server_config.docs_ui.mode != crate::config::DocsUiMode::Off {
        routes.push(format!("{api_root_display}/{}", crate::server::normalize_docs_ui_path(&server_config.docs_ui.path)));
    }
    routes
}

async fn run_web(root: &Path, shutdown: impl std::future::Future<Output = ()> + Send + 'static) -> io::Result<()> {
    println!("project root: {}", root.display());
    let (router, config) = build_web_router(root);

    println!(
        "serving static content — startPage: {}, port: {}{}",
        config.start_page,
        config.port,
        config.not_found_page.as_ref().map(|p| format!(", notFoundPage: {p}")).unwrap_or_default()
    );
    tracing::info!(roles = "web", port = config.port, tls_mode = ?config.tls.mode, "frogs run starting");

    // No `api/` subfolder in a web-only project — `certPath`/`keyPath`
    // resolve relative to the project root itself, right alongside
    // `webserve.json`.
    serve(root, router, IpAddr::V4(Ipv4Addr::UNSPECIFIED), config.port, &config.tls, root, true, shutdown).await
}

async fn run_both(root: &Path, shutdown: impl std::future::Future<Output = ()> + Send + 'static) -> io::Result<()> {
    println!("project root: {}", root.display());
    let (api_router, server_config) = build_api_router(root, true).await?;
    let (web_router, web_config) = build_web_router(root);

    let api_root_display = crate::server::normalize_api_root(&server_config.api_root).unwrap_or_else(|| "unprefixed".to_string());
    println!(
        "serving both an API ({api_root_display}) and static content (startPage: {}) from one process",
        web_config.start_page
    );
    println!("API operational routes: {}", operational_routes_display(&server_config).join(", "));
    tracing::info!(roles = "api+web", port = server_config.port, tls_mode = ?server_config.tls.mode, "frogs run starting");
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
    if web_config.tls.mode != TlsMode::Off || web_config.tls.client_auth.is_some() {
        // Same authority split as `port` just above, for the same reason —
        // one listener, one TLS configuration.
        println!(
            "note: webserve.json's own tls settings (clientAuth included) are ignored while serving both roles — config/server.json's \
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
    // single-listener reasoning as the port-authority note above. Likewise
    // `caseSensitiveMethods`: same authority rule as `port`/`tls`, so it also
    // decides method matching for the static routes.
    let api_dir = crate::project::api_base(root);
    serve(
        root,
        router,
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        server_config.port,
        &server_config.tls,
        &api_dir,
        server_config.case_sensitive_methods(),
        shutdown,
    )
    .await
}

/// Loads config, connects every SQL driver, and builds the fully-nested,
/// middleware-wrapped API router — the piece `run_api` and `run_both` both
/// need, extracted so serving both roles from one process doesn't mean
/// duplicating SQL connection handling or router composition.
async fn build_api_router(root: &Path, web_role: bool) -> io::Result<(Router, ServerConfig)> {
    let api_dir = crate::project::api_base(root);
    let config = Config::load_or_exit(&api_dir);
    println!(
        "loaded config — debugMode={}, {} connection(s), {} error code(s), strictOpenApi={}, caseSensitiveMethods={}, endpointSymlinks={}",
        config.server.debug_mode,
        config.connections.len(),
        config.errors.len(),
        config.server.strict_open_api(),
        config.server.case_sensitive_methods(),
        config.server.endpoint_symlinks().as_str()
    );
    announce_method_case(&config.server);

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

    // Before any connection is opened: a strict refusal must not have
    // touched real infrastructure, let alone bound a port or written a pidfile.
    let endpoint_tree = startup_endpoint_tree(root, &config.server)?;
    check_route_table(
        &config.server,
        &endpoint_tree,
        RootExtras {
            web: web_role,
            control_plane: false,
        },
        "",
    )?;
    let openapi_document = load_openapi_for_startup(root, &config.server, &endpoint_tree)?;

    let drivers = match crate::sql::connect_all(&config.connections).await {
        Ok(drivers) => drivers,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(1);
        }
    };
    println!("connected {} SQL data source(s)", drivers.len());

    assemble_api_router(root, config, Arc::new(drivers), None, openapi_document, endpoint_tree).await
}

#[cfg(test)]
fn tree_of(root: &Path) -> EndpointTree {
    scan_endpoint_tree(root, &ServerConfig::default())
}

pub(crate) fn link_context(root: &Path, server: &ServerConfig) -> LinkContext {
    LinkContext::new(root, server.endpoint_symlinks())
}

/// One scan of `api/datasources/endpoints/` under the configured link policy;
/// every walker in a command shares the result. Says so when the policy lets
/// endpoint files be read from outside the project.
pub(crate) fn scan_endpoint_tree(root: &Path, server: &ServerConfig) -> EndpointTree {
    if server.endpoint_symlinks() == crate::config::EndpointSymlinks::Follow {
        tracing::warn!("endpointSymlinks is \"follow\" — endpoint files may be read from outside the project (writes are still confined to it)");
    }
    EndpointTree::scan(&link_context(root, server), &crate::project::api_base(root).join("datasources/endpoints"))
}

/// Logs every link the scan refused to follow; under `strictOpenApi` each one
/// is an error and startup is refused.
pub(crate) fn report_tree_findings(tree: &EndpointTree, strict: bool) -> io::Result<()> {
    let mut strict_findings = 0usize;
    for (finding, message) in tree.findings().iter().zip(tree.link_messages()) {
        if strict && finding.strict {
            strict_findings += 1;
            eprintln!("error: {message}");
            tracing::error!("{message}");
        } else {
            tracing::warn!("{message}");
        }
    }
    if strict_findings > 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{strict_findings} link(s) under datasources/endpoints were not followed and \"strictOpenApi\" is true — refusing to start"),
        ));
    }
    Ok(())
}

pub(crate) fn startup_endpoint_tree(root: &Path, server: &ServerConfig) -> io::Result<Arc<EndpointTree>> {
    let tree = scan_endpoint_tree(root, server);
    report_tree_findings(&tree, server.strict_open_api())?;
    Ok(Arc::new(tree))
}

const METHOD_CASE_MISSING_NOTICE: &str = "HTTP method names are matched case-insensitively (default; caseSensitiveMethods is not set in config/server.json) — a proxy/WAF rule blocking an exact method like DELETE can be bypassed with 'delete'; set caseSensitiveMethods: true for RFC 9110 exact matching";
const METHOD_CASE_EXPLICIT_FALSE_NOTICE: &str =
    "HTTP method names are matched case-insensitively (caseSensitiveMethods: false in config/server.json); set caseSensitiveMethods: true for RFC 9110 exact matching";

/// What to tell the operator about method-name matching, and at what level:
/// a warning when the key was never set, info when it was explicitly false,
/// nothing under exact matching. Not a spec issue, so never fatal under strict.
pub(crate) fn method_case_notice(server: &ServerConfig) -> Option<(tracing::Level, String)> {
    if server.case_sensitive_methods() {
        None
    } else if server.case_sensitive_methods_explicit() {
        Some((tracing::Level::INFO, METHOD_CASE_EXPLICIT_FALSE_NOTICE.to_string()))
    } else {
        Some((tracing::Level::WARN, METHOD_CASE_MISSING_NOTICE.to_string()))
    }
}

pub(crate) fn announce_method_case(server: &ServerConfig) {
    if let Some((level, message)) = method_case_notice(server) {
        if level == tracing::Level::WARN {
            tracing::warn!("{message}");
        } else {
            tracing::info!("{message}");
        }
        println!("{message}");
    }
}

/// What the startup security check found beyond a refusal, returned so a
/// caller (or a test) can see exactly what was warned about.
#[derive(Debug, Default)]
pub(crate) struct StartupSecurityReport {
    /// Built-in routes (`/healthz`, `/readyz`) answering a secured operation whose
    /// security is only the document-wide default: logged, not refused.
    pub builtin_warnings: Vec<String>,
    /// Why `openapi.yaml` couldn't be loaded (strict off), so endpoint
    /// security was not checked at all.
    pub not_loaded: Option<String>,
    /// `Severity::Error` load issues (strict off) — operations the loader
    /// dropped, whose routes therefore weren't checked.
    pub dropped_issues: usize,
    pub unmatched: Vec<PathBuf>,
}

/// Builds the route table the server is about to register (endpoint files, the API
/// built-ins and any root-level extras) without building a router, logs warnings, and
/// refuses on anything axum would panic on or misroute. Runs before any connection,
/// bind or pidfile.
pub(crate) fn check_route_table(server: &ServerConfig, tree: &EndpointTree, extras: RootExtras, refusal_hint: &str) -> io::Result<RoutePlan> {
    check_route_table_logging(server, tree, extras, refusal_hint, true)
}

fn check_route_table_logging(server: &ServerConfig, tree: &EndpointTree, extras: RootExtras, refusal_hint: &str, log_warnings: bool) -> io::Result<RoutePlan> {
    let mode = MethodCase::from_case_sensitive(server.case_sensitive_methods());
    let plan = RoutePlan::build(tree, mode, &RouteContext::for_server(server).with_extras(extras));
    let strict = server.strict_open_api();
    if log_warnings {
        for warning in plan.warnings(strict) {
            tracing::warn!("{}", warning.message());
        }
    }
    let refusals = plan.refusals(strict);
    if refusals.is_empty() {
        return Ok(plan);
    }
    for problem in &refusals {
        eprintln!("error: {}", problem.message());
        tracing::error!("{}", problem.message());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "{} route problem(s) under datasources/endpoints or config/server.json — refusing to start; run frogs validate{refusal_hint}",
            refusals.len()
        ),
    ))
}

fn refuse_class(items: Vec<String>, summary: impl FnOnce(usize) -> String) -> io::Result<()> {
    if items.is_empty() {
        return Ok(());
    }
    for message in &items {
        eprintln!("error: {message}");
        tracing::error!("{message}");
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, summary(items.len())))
}

pub(crate) const REGISTERED_SERVICE_SECURITY_HINT: &str = " — a registered service that hits this on start exits with failure and restarts every 5 s under --restart-policy on-failure; fix the files, or register with --restart-policy never";

/// Loads `openapi.yaml` and checks every endpoint file's `security` against
/// it (always, for an API project — the refusal is not tied to
/// `strictOpenApi`). The loaded document is handed back only when something
/// else needs it — request validation, the docs UI, or `strictOpenApi`
/// itself — and every issue it found is logged. A load failure degrades to
/// `None` with a warning, except under strict where it (and any
/// strict-class issue) refuses to start.
pub(crate) fn load_openapi_for_startup(root: &Path, server: &ServerConfig, tree: &EndpointTree) -> io::Result<Option<Arc<crate::openapi::OpenApiDocument>>> {
    load_openapi_for_startup_reported(root, server, "", tree).map(|(doc, _)| doc)
}

pub(crate) fn load_openapi_for_startup_reported(
    root: &Path,
    server: &ServerConfig,
    refusal_hint: &str,
    tree: &EndpointTree,
) -> io::Result<(Option<Arc<crate::openapi::OpenApiDocument>>, StartupSecurityReport)> {
    let strict = server.strict_open_api();
    let spec_needed = strict || server.features.request_validation || server.docs_ui.mode != crate::config::DocsUiMode::Off;
    let mut report = StartupSecurityReport::default();
    match crate::openapi::load(&root.join(crate::project::MANIFEST_FILE), server.openapi_load_options()) {
        Ok(doc) => {
            if spec_needed {
                let mut strict_findings = 0usize;
                for issue in &doc.issues {
                    let is_strict = strict && issue.kind.is_strict_error();
                    if is_strict {
                        strict_findings += 1;
                        eprintln!("error: {}", issue.message);
                        tracing::error!("{}", issue.message);
                    } else {
                        tracing::warn!("{}", issue.message);
                    }
                }
                if strict_findings > 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "{strict_findings} {} issue(s) found and \"strictOpenApi\" is true — refusing to start",
                            crate::project::MANIFEST_FILE
                        ),
                    ));
                }
                if strict {
                    let stream_files = crate::endpoint::reserved_stream_key_files(tree, doc.method_case);
                    if !stream_files.is_empty() {
                        for file in &stream_files {
                            let message = format!(
                                "{}: \"stream\" is reserved for streaming responses, which this frogs version does not implement",
                                file.display()
                            );
                            eprintln!("error: {message}");
                            tracing::error!("{message}");
                        }
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "{} endpoint file(s) use the reserved \"stream\" key and \"strictOpenApi\" is true — refusing to start",
                                stream_files.len()
                            ),
                        ));
                    }
                }
            }

            if !strict {
                report.dropped_issues = doc.issues.iter().filter(|i| i.severity == crate::openapi::Severity::Error).count();
                if report.dropped_issues > 0 {
                    tracing::warn!(
                        "{} openapi.yaml issue(s) dropped or skipped part of the spec; the skipped and dropped operations are still checked for routing shadows, but endpoint security for them is only compared to the spec leniently",
                        report.dropped_issues
                    );
                }
            }
            let mode = MethodCase::from_case_sensitive(server.case_sensitive_methods());
            let plan = RoutePlan::build(tree, mode, &RouteContext::for_server(server));
            let check = crate::endpoint::security_check_with_routes(tree, &doc, &plan);
            for message in &check.builtin_warnings {
                tracing::warn!("{message}");
            }
            report.builtin_warnings = check.builtin_warnings.clone();
            for file in &check.unmatched {
                tracing::warn!("{}", crate::endpoint::unmatched_security_message(file));
            }
            report.unmatched = check.unmatched.clone();

            refuse_class(check.ambiguous.iter().map(|f| f.message()).collect(), |n| {
                format!(
                    "{n} endpoint file(s) belong to a method openapi.yaml declares ambiguously (keys differing only in case) — refusing to start; fix openapi.yaml, then run frogs validate{refusal_hint}"
                )
            })?;
            refuse_class(check.mismatches.iter().map(|m| m.message()).collect(), |n| {
                format!(
                    "{n} endpoint file(s) don't apply the security openapi.yaml declares — refusing to start; set each file's \"security\" to one of the acceptable schemes shown (or change openapi.yaml), then run frogs validate{refusal_hint}"
                )
            })?;
            refuse_class(check.stale_variants.iter().map(|v| v.message()).collect(), |n| {
                format!(
                    "{n} endpoint file(s) stand in for a secured openapi.yaml operation under another method spelling without its security — refusing to start; then run frogs validate{refusal_hint}"
                )
            })?;
            refuse_class(check.template_instances.iter().map(|v| v.message()).collect(), |n| {
                format!(
                    "{n} endpoint file(s) are instances of a secured openapi.yaml path template without its security — refusing to start; then run frogs validate{refusal_hint}"
                )
            })?;
            let shadow_messages: Vec<String> = check
                .shadowed
                .iter()
                .map(|v| v.message())
                .chain(check.unverifiable.iter().map(|v| v.message()))
                .chain(check.builtin_refusals.iter().map(|v| v.message()))
                .collect();
            refuse_class(shadow_messages, |n| {
                format!(
                    "{n} secured openapi.yaml operation(s) would be answered by a route that does not enforce their security — refusing to start; then run frogs validate{refusal_hint}"
                )
            })?;
            if strict && !check.unmatched.is_empty() {
                for file in &check.unmatched {
                    let message = crate::endpoint::unmatched_security_message(file);
                    eprintln!("error: {message}");
                    tracing::error!("{message}");
                }
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "{} endpoint file(s) match no openapi.yaml operation and \"strictOpenApi\" is true — refusing to start{refusal_hint}",
                        check.unmatched.len()
                    ),
                ));
            }
            Ok((spec_needed.then(|| Arc::new(doc)), report))
        }
        Err(e) if strict => {
            eprintln!("error: failed to load {}: {e}", crate::project::MANIFEST_FILE);
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to load {}: {e} (\"strictOpenApi\" is true)", crate::project::MANIFEST_FILE),
            ))
        }
        Err(e) => {
            if spec_needed {
                tracing::warn!(
                    "failed to load {}: {e} — request validation is disabled and docs UI's operation list is empty for this run",
                    crate::project::MANIFEST_FILE
                );
            }
            tracing::warn!("could not load openapi.yaml ({e}) — endpoint security was not checked against it for this run");
            report.not_loaded = Some(e.to_string());
            Ok((None, report))
        }
    }
}

/// The same check `frogs run` does at startup, for `frogs register` and a
/// registered `frogs run` — a service whose project would be refused on
/// start must not get installed or (re)started. Web-only projects have
/// nothing to check.
pub(crate) fn precheck_security_for_service(root: &Path) -> io::Result<()> {
    if !root.join(crate::project::MANIFEST_FILE).is_file() {
        return Ok(());
    }
    let config = Config::load(&crate::project::api_base(root)).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let tree = startup_endpoint_tree(root, &config.server)?;
    check_route_table(
        &config.server,
        &tree,
        RootExtras {
            web: root.join("webserve.json").is_file(),
            control_plane: false,
        },
        REGISTERED_SERVICE_SECURITY_HINT,
    )?;
    load_openapi_for_startup_reported(root, &config.server, REGISTERED_SERVICE_SECURITY_HINT, &tree).map(|_| ())
}

/// Composes the fully-nested, middleware-wrapped API router from an
/// already-loaded `Config` and already-connected drivers — the half of
/// `build_api_router` that doesn't touch real infrastructure, so `frogs
/// test` can reuse every bit of route/middleware composition with an empty
/// driver map and a `MockProvider` installed, while `frogs run` passes
/// `None` and is otherwise unchanged.
pub(crate) async fn assemble_api_router(
    root: &Path,
    config: Config,
    drivers: Arc<HashMap<String, Box<dyn SqlDriver>>>,
    mock_provider: Option<Arc<dyn MockProvider>>,
    openapi_document: Option<Arc<crate::openapi::OpenApiDocument>>,
    endpoint_tree: Arc<EndpointTree>,
) -> io::Result<(Router, ServerConfig)> {
    let api_dir = crate::project::api_base(root);
    let debug_mode = config.server.debug_mode;
    let method_case = MethodCase::from_case_sensitive(config.server.case_sensitive_methods());
    if let Some(doc) = &openapi_document
        && doc.method_case != method_case
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "openapi.yaml was loaded under a different caseSensitiveMethods setting than the router is being built with — refusing to start",
        ));
    }
    // The client-certificate codes ship as runtime defaults (rather than
    // only in a freshly generated `config/errors/core.json`, which is
    // write-once) so a project generated before mTLS existed classifies
    // them correctly too; a project that defines either keeps its own.
    let mut errors = config.errors;
    for code in ["auth.client_cert_missing", "auth.client_cert_expired"] {
        errors.insert_if_absent(
            code,
            crate::errors::ErrorDefinition {
                http_status: 401,
                expose_detail: true,
            },
        );
    }
    errors.insert_if_absent(
        "endpoint.unavailable",
        crate::errors::ErrorDefinition {
            http_status: 503,
            expose_detail: false,
        },
    );
    let errors = std::sync::Arc::new(errors);
    check_route_table_logging(&config.server, &endpoint_tree, RootExtras::default(), "", false)?;
    let client_identity_available = mock_provider.is_some() || config.server.tls.client_identity_enabled();
    if config
        .server
        .tls
        .client_auth
        .as_ref()
        .is_some_and(|c| c.mode == crate::config::ClientAuthMode::Required)
        && (config.server.features.readyz_check || config.server.features.metrics || config.server.docs_ui.mode != crate::config::DocsUiMode::Off)
    {
        tracing::warn!(
            "tls.clientAuth.mode is \"required\" while readyz/metrics/docsUi is enabled — load-balancer probes and browsers without a client certificate              can't even connect to those; use \"optional\" and let routes decide"
        );
    }
    let security = std::sync::Arc::new(config.security);
    let services = std::sync::Arc::new(config.services);
    let discovered_errors = std::sync::Arc::new(std::sync::Mutex::new(config.discovered_errors));

    let endpoint_router = crate::endpoint::build_router(
        &api_dir,
        &endpoint_tree,
        drivers.clone(),
        &config.connections,
        errors,
        security.clone(),
        services,
        discovered_errors,
        debug_mode,
        openapi_document.as_deref(),
        mock_provider,
        config.server.effective_source_call_timeout_ms(),
        client_identity_available,
        method_case,
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
    if config.server.docs_ui.mode != crate::config::DocsUiMode::Off {
        let endpoint_summaries = crate::endpoint::endpoint_summaries(&endpoint_tree, method_case);
        router = router.merge(crate::server::docs_ui_router(
            config.server.docs_ui.mode,
            &config.server.docs_ui.path,
            openapi_document.clone(),
            security,
            endpoint_summaries,
        ));
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

/// Binds `port`, writes the PID file, serves `router` until `shutdown`
/// resolves or an external `frogs stop` kills the process, then cleans the
/// PID file up — the tail end every run mode (`run_api`/`run_web`/
/// `run_both`) shares once its own router is built, regardless of which
/// role(s) that router serves. `shutdown` is Ctrl+C for an unregistered
/// project (`run_direct`'s own default) or the SCM's Stop/Shutdown control
/// events for a registered Windows Service (`server::service_host`) —
/// `serve`/`serve_http`/`serve_https` don't care which, they just await
/// whatever future the caller hands them. `tls` selects plain HTTP
/// (`TlsMode::Off`, unchanged behavior) or HTTPS via a user-supplied
/// cert/key pair (`TlsMode::Manual`) — see `docs/frogs-https-development.md`.
/// `tls_base` is where `tls.manual`'s `certPath`/`keyPath` resolve relative
/// to — `api_base(root)` for `run_api`/`run_both` (matching where
/// `config/server.json` itself, and every other path it reads, already
/// resolve from), or `root` itself for `run_web` (no `api/` subfolder
/// exists in a web-only project).
///
/// No graceful in-flight-request draining — a deliberate scope decision,
/// not an oversight: frogs holds no state of its own across a request (the
/// real data lives in Postgres/downstream APIs, or on disk for static
/// content), so the only risk a hard kill carries is a caller not finding
/// out whether their in-flight write's response made it back — which a
/// clean shutdown signal wouldn't fully eliminate either, since the write
/// can already have committed upstream before the signal arrives.
/// `shutdown` resolving and an external `frogs stop` both just end the
/// process; the `select!` in both `serve_http`/`serve_https` below only
/// makes sure `.frogs/run.json` doesn't linger after the former case
/// specifically, since `frogs stop` already removes it itself after
/// terminating the process externally. `bind` is the interface to listen
/// on — every `frogs run` caller passes the unspecified address (all
/// interfaces); `frogs test` defaults to loopback.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve(
    root: &Path,
    router: Router,
    bind: IpAddr,
    port: u16,
    tls: &TlsConfig,
    tls_base: &Path,
    case_sensitive_methods: bool,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    // Structure first (a `clientAuth` block over plain HTTP is an error, not
    // an ignored setting), before anything is bound or written.
    tls.validate_structure().map_err(|m| io::Error::new(io::ErrorKind::InvalidInput, m))?;
    match tls.mode {
        TlsMode::Off => serve_http(root, router, bind, port, case_sensitive_methods, shutdown).await,
        TlsMode::Manual => serve_https(root, router, bind, port, tls, tls_base, case_sensitive_methods, shutdown).await,
    }
}

async fn serve_http(
    root: &Path,
    router: Router,
    bind: IpAddr,
    port: u16,
    case_sensitive_methods: bool,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    let addr = SocketAddr::new(bind, port);
    let listener = tokio::net::TcpListener::bind(addr).await?;

    pidfile::write(
        root,
        &pidfile::RunInfo {
            pid: std::process::id(),
            port,
            started_at: chrono::Utc::now(),
        },
    )?;

    println!("listening on http://{addr} (Ctrl+C to stop, or `frogs stop` from another terminal)");

    // `with_connect_info` (not the plain `into_make_service`) so
    // `docs_ui_localhost_gate` can see the real TCP peer when `docsUi.mode`
    // is `localhost` — harmless overhead for every other route, which
    // simply never looks at `ConnectInfo`.
    let result = tokio::select! {
        result = axum::serve(listener, crate::server::served_service(router, case_sensitive_methods)) => result,
        _ = shutdown => {
            println!("shutting down");
            Ok(())
        }
    };

    pidfile::remove(root)?;
    result
}

/// `manual.certPath`/`keyPath` (and `clientAuth`'s `caPath`/`crlPaths`)
/// resolve relative to `tls_base` — see `serve`'s own doc comment for which
/// base each caller passes and why. The whole `ServerConfig` (every file
/// read, every parse) is built before the port is bound or the pidfile is
/// written, so any misconfiguration fails the process cleanly first.
#[allow(clippy::too_many_arguments)]
async fn serve_https(
    root: &Path,
    router: Router,
    bind: IpAddr,
    port: u16,
    tls: &TlsConfig,
    tls_base: &Path,
    case_sensitive_methods: bool,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    let addr = SocketAddr::new(bind, port);

    let built = crate::server::tls::build_server_config(tls, tls_base)?;
    for warning in &built.warnings {
        tracing::warn!("{warning}");
    }
    let client_auth = tls.client_auth.as_ref().filter(|c| c.mode != crate::config::ClientAuthMode::Off);
    if let Some(client_auth) = client_auth {
        crate::server::tls::warn_about_crl_freshness(&built.crl_next_updates, client_auth.effective_crl_policy() == crate::config::CrlPolicy::FailClosed);
    }
    let rustls_config = axum_server::tls_rustls::RustlsConfig::from_config(built.config.clone());
    let acceptor = crate::server::tls::ClientCertAcceptor::new(
        axum_server::tls_rustls::RustlsAcceptor::new(rustls_config).handshake_timeout(crate::server::tls::TLS_HANDSHAKE_TIMEOUT),
    );

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
    let server = axum_server::from_tcp(listener)?.acceptor(acceptor);
    let crl_watch = client_auth.and_then(|_| crate::server::tls::spawn_crl_expiry_watch(&built.crl_next_updates));

    pidfile::write(
        root,
        &pidfile::RunInfo {
            pid: std::process::id(),
            port,
            started_at: chrono::Utc::now(),
        },
    )?;

    println!("listening on https://{addr} (Ctrl+C to stop, or `frogs stop` from another terminal)");

    // Same `with_connect_info` reasoning as `serve_http` — axum-server's
    // TLS acceptor supports the identical `MakeService` shape.
    let result = tokio::select! {
        result = server.serve(crate::server::served_service(router, case_sensitive_methods)) => result,
        _ = shutdown => {
            println!("shutting down");
            Ok(())
        }
    };

    if let Some(watch) = crl_watch {
        watch.abort();
    }
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
    use crate::config::ManualTlsConfig;

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

    /// The same default shutdown future `run_direct` itself builds for an
    /// unregistered project — every test below that calls `serve`/`run_web`
    /// directly (bypassing `run_direct`) needs to supply one explicitly now
    /// that the signature takes it as a parameter, with no behavior change
    /// versus the hardcoded `tokio::signal::ctrl_c()` these tests exercised
    /// before.
    async fn ctrl_c_shutdown() {
        let _ = tokio::signal::ctrl_c().await;
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
            client_auth: None,
        };
        let router = Router::new();

        let err = serve(&root, router, IpAddr::V4(Ipv4Addr::UNSPECIFIED), free_port(), &tls, &root, false, ctrl_c_shutdown())
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
            client_auth: None,
        };
        let router = Router::new();

        let err = serve(&root, router, IpAddr::V4(Ipv4Addr::UNSPECIFIED), free_port(), &tls, &root, false, ctrl_c_shutdown())
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
            client_auth: None,
        };
        let port = free_port();
        let router = Router::new().route("/hello", axum::routing::get(|| async { "hi" }));

        let spawned_root = root.clone();
        let spawned_api_dir = api_dir.clone();
        tokio::spawn(async move {
            let _ = serve(
                &spawned_root,
                router,
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                port,
                &tls,
                &spawned_api_dir,
                false,
                ctrl_c_shutdown(),
            )
            .await;
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
            client_auth: None,
        };
        let port = free_port();
        let router = Router::new().route("/hello", axum::routing::get(|| async { "hi" }));

        let spawned_root = root.clone();
        let spawned_api_dir = api_dir.clone();
        tokio::spawn(async move {
            let _ = serve(
                &spawned_root,
                router,
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                port,
                &tls,
                &spawned_api_dir,
                false,
                ctrl_c_shutdown(),
            )
            .await;
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
            let _ = run_web(&spawned_root, ctrl_c_shutdown()).await;
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
        let (router, _) = build_api_router(&root, false)
            .await
            .expect("a minimal but complete scratch project should build cleanly");

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
        let (router, _) = build_api_router(&root, false)
            .await
            .expect("a minimal but complete scratch project should build cleanly");

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

    /// Same shape as `scratch_api_project`, but pinned to a caller-supplied
    /// port (via `config/server.json`'s own `port` field) rather than the
    /// default 8080 — needed by any test that calls `run_direct_with_shutdown`
    /// (or `run_api`) directly, since those actually bind the real listener
    /// rather than a test-owned ephemeral one.
    fn scratch_api_project_with_port(port: u16) -> std::path::PathBuf {
        let root = temp_project();
        let api_dir = root.join("api");
        std::fs::create_dir_all(api_dir.join("config/errors")).unwrap();
        std::fs::create_dir_all(api_dir.join("security")).unwrap();
        std::fs::create_dir_all(api_dir.join("datasources/endpoints")).unwrap();
        std::fs::write(root.join("openapi.yaml"), "openapi: 3.0.3\ninfo: { title: t, version: '1' }\npaths: {}\n").unwrap();
        std::fs::write(
            api_dir.join("config/server.json"),
            format!(r#"{{ "features": {{ "requestCorrelation": false, "requestValidation": false }}, "port": {port} }}"#),
        )
        .unwrap();
        std::fs::write(api_dir.join("config/errors/core.json"), "{}").unwrap();
        std::fs::write(api_dir.join("config/connections.json"), "{}").unwrap();
        std::fs::write(api_dir.join("security/schemes.json"), "{}").unwrap();
        root
    }

    /// `run_direct_with_shutdown` hoisted `has_api`/`has_web` detection —
    /// and the persistent-logging subscriber install that depends on it —
    /// above the pidfile check (see that function's own doc comment on the
    /// reordering). This pins down that the reordering didn't quietly break
    /// the stale-pidfile cleanup that already lived there: a leftover
    /// `.frogs/run.json` pointing at a PID that cannot possibly be alive
    /// must still be treated as stale and removed, not mistaken for a real
    /// "already running" server — which would otherwise `eprintln!` and
    /// `std::process::exit(1)`, killing this very test process.
    #[tokio::test]
    async fn run_direct_with_shutdown_still_cleans_up_a_stale_pidfile_now_that_logging_install_runs_first() {
        let port = free_port();
        let root = scratch_api_project_with_port(port);

        pidfile::write(
            &root,
            &pidfile::RunInfo {
                pid: u32::MAX, // guaranteed to never be a real, alive process (see pidfile::tests::is_alive_is_false_for_a_pid_that_cannot_exist)
                port,
                started_at: chrono::Utc::now(),
            },
        )
        .unwrap();

        run_direct_with_shutdown(&root, async {})
            .await
            .expect("a minimal but complete scratch project with only a stale pidfile should still run cleanly");

        assert!(
            pidfile::read(&root).unwrap().is_none(),
            "the stale pidfile should have been recognized as stale and removed, not mistaken for a live server"
        );
        assert!(
            root.join("api/runtime-logs").is_dir(),
            "the persistent-logging directory should still be created, even with its install now running before the pidfile check"
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
        let (router, _) = build_api_router(&root, false)
            .await
            .expect("a minimal but complete scratch project should build cleanly");

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

    /// Same shape as `scratch_api_project`, for `docsUi.mode`.
    fn scratch_api_project_with_docs_ui(mode: &str) -> std::path::PathBuf {
        let root = temp_project();
        let api_dir = root.join("api");
        std::fs::create_dir_all(api_dir.join("config/errors")).unwrap();
        std::fs::create_dir_all(api_dir.join("security")).unwrap();
        std::fs::create_dir_all(api_dir.join("datasources/endpoints")).unwrap();
        std::fs::write(root.join("openapi.yaml"), "openapi: 3.0.3\ninfo: { title: t, version: '1' }\npaths: {}\n").unwrap();
        std::fs::write(
            api_dir.join("config/server.json"),
            format!(r#"{{ "features": {{ "requestValidation": false }}, "docsUi": {{ "mode": "{mode}" }} }}"#),
        )
        .unwrap();
        std::fs::write(api_dir.join("config/errors/core.json"), "{}").unwrap();
        std::fs::write(api_dir.join("config/connections.json"), "{}").unwrap();
        std::fs::write(api_dir.join("security/schemes.json"), "{}").unwrap();
        root
    }

    /// Proves `docsUi.mode: "off"` behaves like `readyzCheck`/`metrics` off
    /// — the route isn't merely hidden, it's never registered at all.
    #[tokio::test]
    async fn docs_ui_off_never_registers_the_route() {
        let root = scratch_api_project_with_docs_ui("off");
        let (router, _) = build_api_router(&root, false)
            .await
            .expect("a minimal but complete scratch project should build cleanly");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let response = reqwest::get(format!("http://{addr}/docs")).await.unwrap();
        assert_eq!(response.status(), 404);
    }

    /// End-to-end through the real `serve_http` wiring, connect-info
    /// included — `server::docs_ui_localhost_gate`'s own tests already cover
    /// the gate logic in isolation; this proves `frogs run` actually gets a
    /// real peer address to it, not just that the gate function works when
    /// handed one directly.
    #[tokio::test]
    async fn docs_ui_localhost_mode_is_reachable_through_the_real_serve_http_connect_info_wiring() {
        let root = scratch_api_project_with_docs_ui("localhost");
        let (router, _) = build_api_router(&root, false)
            .await
            .expect("a minimal but complete scratch project should build cleanly");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .await
                .unwrap();
        });

        let response = reqwest::get(format!("http://{addr}/docs")).await.unwrap();
        assert_eq!(
            response.status(),
            200,
            "a real loopback request through serve_http's own connect-info wiring must be admitted"
        );
    }

    /// Proves `docsUi.path` is actually wired end-to-end — the default
    /// `"docs"` path is what every other docs-UI test in this module
    /// exercises implicitly; this is the one that proves a custom value
    /// actually changes the mounted route, through the real
    /// `build_api_router` assembly.
    #[tokio::test]
    async fn docs_ui_custom_path_is_wired_through_build_api_router() {
        let root = temp_project();
        let api_dir = root.join("api");
        std::fs::create_dir_all(api_dir.join("config/errors")).unwrap();
        std::fs::create_dir_all(api_dir.join("security")).unwrap();
        std::fs::create_dir_all(api_dir.join("datasources/endpoints")).unwrap();
        std::fs::write(root.join("openapi.yaml"), "openapi: 3.0.3\ninfo: { title: t, version: '1' }\npaths: {}\n").unwrap();
        std::fs::write(
            api_dir.join("config/server.json"),
            r#"{ "features": { "requestValidation": false }, "docsUi": { "mode": "public", "path": "internal-docs" } }"#,
        )
        .unwrap();
        std::fs::write(api_dir.join("config/errors/core.json"), "{}").unwrap();
        std::fs::write(api_dir.join("config/connections.json"), "{}").unwrap();
        std::fs::write(api_dir.join("security/schemes.json"), "{}").unwrap();

        let (router, _) = build_api_router(&root, false)
            .await
            .expect("a minimal but complete scratch project should build cleanly");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let custom = reqwest::get(format!("http://{addr}/internal-docs")).await.unwrap();
        assert_eq!(custom.status(), 200);
        let default = reqwest::get(format!("http://{addr}/docs")).await.unwrap();
        assert_eq!(default.status(), 404, "the default 'docs' path must not also be live once a custom one is configured");
    }

    /// Proves a real endpoint file on disk actually reaches
    /// `/docs/endpoints.json` through `build_api_router`'s own wiring —
    /// `endpoint::docs_summary`'s own tests already cover the sanitization
    /// logic in isolation; this is the "does `frogs run` actually call it"
    /// check.
    #[tokio::test]
    async fn docs_ui_endpoints_json_reflects_a_real_endpoint_file_on_disk() {
        let root = temp_project();
        let api_dir = root.join("api");
        std::fs::create_dir_all(api_dir.join("config/errors")).unwrap();
        std::fs::create_dir_all(api_dir.join("security")).unwrap();
        std::fs::create_dir_all(api_dir.join("datasources/endpoints/ping")).unwrap();
        std::fs::write(root.join("openapi.yaml"), "openapi: 3.0.3\ninfo: { title: t, version: '1' }\npaths: {}\n").unwrap();
        std::fs::write(
            api_dir.join("config/server.json"),
            r#"{ "features": { "requestValidation": false }, "docsUi": { "mode": "public" } }"#,
        )
        .unwrap();
        std::fs::write(api_dir.join("config/errors/core.json"), "{}").unwrap();
        std::fs::write(api_dir.join("config/connections.json"), "{}").unwrap();
        std::fs::write(api_dir.join("security/schemes.json"), "{}").unwrap();
        std::fs::write(
            api_dir.join("datasources/endpoints/ping/endpoint.get.json"),
            r#"{ "operationId": "ping", "sources": {}, "response": {} }"#,
        )
        .unwrap();

        let (router, _) = build_api_router(&root, false)
            .await
            .expect("a minimal but complete scratch project should build cleanly");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let body: serde_json::Value = reqwest::get(format!("http://{addr}/docs/endpoints.json")).await.unwrap().json().await.unwrap();
        assert_eq!(body["endpoints"][0]["operationId"], "ping");
        assert_eq!(body["endpoints"][0]["path"], "/ping");
    }

    /// The design doc's hard requirement for the scenario control plane:
    /// it must be *structurally absent* from the router `frogs run` builds
    /// — not disabled, not gated — and the `X-Frogs-Scenario` header must
    /// be inert there. Proven through the real `build_api_router` against a
    /// project that even has a `.test.json` file with mocks sitting next to
    /// its endpoint: under `frogs run` the real upstream is what answers.
    #[tokio::test]
    async fn the_scenario_control_plane_and_header_do_not_exist_under_frogs_run() {
        use axum::extract::State;
        use axum::{Json, Router};

        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let upstream = Router::new()
            .fallback(|State(hits): State<Arc<std::sync::atomic::AtomicUsize>>| async move {
                hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Json(serde_json::json!({ "maker": "REAL" }))
            })
            .with_state(hits.clone());
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(upstream_listener, upstream).await.unwrap();
        });

        let root = temp_project();
        let api_dir = root.join("api");
        std::fs::create_dir_all(api_dir.join("config/errors")).unwrap();
        std::fs::create_dir_all(api_dir.join("security")).unwrap();
        std::fs::create_dir_all(api_dir.join("datasources/http")).unwrap();
        std::fs::create_dir_all(api_dir.join("datasources/endpoints/cars")).unwrap();
        std::fs::write(root.join("openapi.yaml"), "openapi: 3.0.3\ninfo: { title: t, version: '1' }\npaths: {}\n").unwrap();
        std::fs::write(api_dir.join("config/server.json"), r#"{ "features": { "requestValidation": false } }"#).unwrap();
        std::fs::write(api_dir.join("config/errors/core.json"), "{}").unwrap();
        std::fs::write(api_dir.join("config/connections.json"), "{}").unwrap();
        std::fs::write(api_dir.join("security/schemes.json"), "{}").unwrap();
        std::fs::write(
            api_dir.join("datasources/http/upstream.json"),
            format!(r#"{{ "method": "GET", "url": "http://{upstream_addr}/cars" }}"#),
        )
        .unwrap();
        std::fs::write(
            api_dir.join("datasources/endpoints/cars/endpoint.get.json"),
            r#"{ "operationId": "listCars", "sources": { "car": { "type": "http", "request": "upstream.json" } }, "response": { "maker": "sources.car.maker" } }"#,
        )
        .unwrap();
        std::fs::write(
            api_dir.join("datasources/endpoints/cars/endpoint.get.test.json"),
            r#"{ "cases": [
                { "name": "baseline", "mocks": { "car": { "maker": "MOCKED" } }, "expect": {} },
                { "name": "tagged", "scenario": "pricing-down", "mocks": { "car": { "maker": "MOCKED-SCENARIO" } }, "expect": {} }
            ] }"#,
        )
        .unwrap();

        let (router, _) = build_api_router(&root, false)
            .await
            .expect("a minimal but complete scratch project should build cleanly");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let client = reqwest::Client::new();

        for (method, label) in [(reqwest::Method::GET, "GET"), (reqwest::Method::POST, "POST"), (reqwest::Method::DELETE, "DELETE")] {
            let response = client
                .request(method, format!("http://{addr}/_frogs/scenario"))
                .json(&serde_json::json!({ "name": "pricing-down" }))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 404, "{label} /_frogs/scenario must not exist under frogs run");
        }

        let response = client
            .get(format!("http://{addr}/cars"))
            .header("X-Frogs-Scenario", "pricing-down")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(
            body["maker"], "REAL",
            "under frogs run the real upstream answers, the .test.json mocks and the header are ignored"
        );
        assert_eq!(
            hits.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "frogs run really did dial the upstream — no mock provider is installed"
        );

        let response = client
            .get(format!("http://{addr}/cars"))
            .header("X-Frogs-Scenario", "no-such-scenario")
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            200,
            "an unknown scenario name is not even inspected under frogs run, let alone rejected"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod mtls_tests;

#[cfg(test)]
mod strict_open_api_startup_tests {
    use super::*;

    fn temp_project() -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "frogs-run-m1-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    /// Same shape as the other scratch projects in this file, but with a
    /// caller-supplied spec and `server.json`.
    fn scratch(server_json: &str, spec: Option<&str>) -> std::path::PathBuf {
        let root = temp_project();
        let api_dir = root.join("api");
        std::fs::create_dir_all(api_dir.join("config/errors")).unwrap();
        std::fs::create_dir_all(api_dir.join("security")).unwrap();
        std::fs::create_dir_all(api_dir.join("datasources/endpoints")).unwrap();
        if let Some(spec) = spec {
            std::fs::write(root.join("openapi.yaml"), spec).unwrap();
        }
        std::fs::write(api_dir.join("config/server.json"), server_json).unwrap();
        std::fs::write(api_dir.join("config/errors/core.json"), "{}").unwrap();
        std::fs::write(api_dir.join("config/connections.json"), "{}").unwrap();
        std::fs::write(api_dir.join("security/schemes.json"), "{}").unwrap();
        root
    }

    fn server(json: &str) -> ServerConfig {
        serde_json::from_str(json).unwrap()
    }

    const CLEAN: &str =
        "openapi: 3.1.0\ninfo: { title: t, version: '1' }\npaths:\n  /ping:\n    get:\n      operationId: ping\n      responses:\n        '200': { description: ok }\n";
    const UNSAFE: &str =
        "openapi: 3.1.0\ninfo: { title: t, version: '1' }\npaths:\n  /x/..:\n    get:\n      operationId: bad\n      responses:\n        '200': { description: ok }\n";
    const OFF: &str = r#"{ "features": { "requestValidation": false } }"#;
    const STRICT_OFF_FEATURES: &str = r#"{ "strictOpenApi": true, "features": { "requestValidation": false } }"#;

    #[test]
    fn strict_loads_the_spec_even_when_request_validation_and_docs_ui_are_off() {
        let root = scratch(STRICT_OFF_FEATURES, Some(CLEAN));
        let doc = load_openapi_for_startup(&root, &server(STRICT_OFF_FEATURES), &tree_of(&root)).unwrap();
        assert_eq!(doc.expect("strict must load the document").operations.len(), 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn non_strict_with_nothing_needing_the_spec_does_not_load_it() {
        let root = scratch(OFF, Some(UNSAFE));
        assert!(load_openapi_for_startup(&root, &server(OFF), &tree_of(&root)).unwrap().is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn non_strict_with_issues_still_starts_and_hands_back_the_document() {
        let root = scratch(r#"{ "features": { "requestValidation": true } }"#, Some(UNSAFE));
        let doc = load_openapi_for_startup(&root, &server(r#"{ "features": { "requestValidation": true } }"#), &tree_of(&root))
            .unwrap()
            .expect("loaded");
        assert!(doc.operations.is_empty());
        assert!(!doc.issues.is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn non_strict_with_a_missing_spec_degrades_to_none() {
        let json = r#"{ "features": { "requestValidation": true } }"#;
        let root = scratch(json, None);
        assert!(load_openapi_for_startup(&root, &server(json), &tree_of(&root)).unwrap().is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn strict_with_a_missing_spec_is_a_refusal() {
        let root = scratch(STRICT_OFF_FEATURES, None);
        let err = load_openapi_for_startup(&root, &server(STRICT_OFF_FEATURES), &tree_of(&root)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn strict_with_an_unsafe_path_is_a_refusal_naming_the_issue_count() {
        let root = scratch(STRICT_OFF_FEATURES, Some(UNSAFE));
        let err = load_openapi_for_startup(&root, &server(STRICT_OFF_FEATURES), &tree_of(&root)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("1 openapi.yaml issue(s)"), "{err}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn strict_treats_a_missing_version_as_a_refusal_but_not_served_operations_as_fine() {
        let no_version = "info: { title: t, version: '1' }\npaths: {}\n";
        let root = scratch(STRICT_OFF_FEATURES, Some(no_version));
        assert!(load_openapi_for_startup(&root, &server(STRICT_OFF_FEATURES), &tree_of(&root)).is_err());

        let not_served = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths:\n  /s:\n    additionalOperations:\n      PURGE:\n        operationId: q\n        responses: { '200': { description: ok } }\n";
        std::fs::write(root.join("openapi.yaml"), not_served).unwrap();
        assert!(load_openapi_for_startup(&root, &server(STRICT_OFF_FEATURES), &tree_of(&root)).unwrap().is_some());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_strict_refusal_happens_before_any_port_or_pidfile_is_touched() {
        let root = scratch(STRICT_OFF_FEATURES, Some(UNSAFE));
        let err = build_api_router(&root, false).await.expect_err("strict + unsafe path must refuse");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(!root.join(".frogs/run.json").exists());
        assert!(pidfile::read(&root).unwrap().is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_strict_refusal_happens_before_connections_are_opened() {
        let root = scratch(STRICT_OFF_FEATURES, Some(UNSAFE));
        std::fs::write(
            root.join("api/config/connections.json"),
            r#"{ "main": { "driver": "nosuchdriver", "url": "nowhere" } }"#,
        )
        .unwrap();
        let err = build_api_router(&root, false).await.expect_err("must refuse");
        assert!(err.to_string().contains("openapi.yaml"), "the spec refusal must win over the connection error: {err}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_strict_project_with_a_clean_spec_builds_normally() {
        let root = scratch(STRICT_OFF_FEATURES, Some(CLEAN));
        assert!(build_api_router(&root, false).await.is_ok());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `/Cars` and `/cars` are ambiguous (generate sets both aside), but
    /// `run` routes from disk and request validation must still apply, by
    /// exact bytes, via `find_operation`'s fallback.
    fn ambiguous_project(server_json: &str) -> std::path::PathBuf {
        let spec = "openapi: 3.1.0\ninfo: { title: t, version: '1' }\npaths:\n  /Cars:\n    get:\n      operationId: upper\n      parameters:\n        - { name: q, in: query, required: true, schema: { type: string } }\n      responses:\n        '200': { description: ok }\n  /cars:\n    get:\n      operationId: lower\n      parameters:\n        - { name: q, in: query, required: true, schema: { type: string } }\n      responses:\n        '200': { description: ok }\n";
        let root = scratch(server_json, Some(spec));
        let dir = root.join("api/datasources/endpoints/cars");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("endpoint.get.json"), r#"{ "operationId": "lower", "sources": {}, "response": {} }"#).unwrap();
        std::fs::write(
            root.join("api/config/errors/core.json"),
            r#"{ "validation.missing_parameter": { "httpStatus": 400, "exposeDetail": true } }"#,
        )
        .unwrap();
        root
    }

    #[tokio::test]
    async fn ambiguous_paths_still_get_request_validation_when_not_strict() {
        let root = ambiguous_project(r#"{ "features": { "requestValidation": true } }"#);
        let (router, _) = build_api_router(&root, false).await.expect("non-strict must start");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let missing = reqwest::get(format!("http://{addr}/cars")).await.unwrap();
        assert_eq!(missing.status(), 400, "a missing required query parameter must be rejected, not fail open");
        let ok = reqwest::get(format!("http://{addr}/cars?q=1")).await.unwrap();
        assert_eq!(ok.status(), 200);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn ambiguous_paths_are_a_refusal_when_strict() {
        let root = ambiguous_project(r#"{ "strictOpenApi": true }"#);
        assert!(build_api_router(&root, false).await.is_err());
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod m2_strict_startup_tests {
    use super::*;

    fn scratch(server_json: &str, spec: &str) -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "frogs-run-m2-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let api_dir = root.join("api");
        std::fs::create_dir_all(api_dir.join("config")).unwrap();
        std::fs::create_dir_all(api_dir.join("datasources/endpoints/things")).unwrap();
        std::fs::write(root.join("openapi.yaml"), spec).unwrap();
        std::fs::write(api_dir.join("config/server.json"), server_json).unwrap();
        root
    }

    fn write_endpoint(root: &std::path::Path, json: &str) {
        std::fs::write(root.join("api/datasources/endpoints/things/endpoint.get.json"), json).unwrap();
    }

    fn server(json: &str) -> ServerConfig {
        serde_json::from_str(json).unwrap()
    }

    const STRICT: &str = r#"{ "strictOpenApi": true }"#;
    const LAX: &str = r#"{ "strictOpenApi": false, "features": { "requestValidation": true } }"#;
    const CLEAN: &str = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths:\n  /things:\n    get:\n      operationId: getThings\n      responses:\n        '200': { description: ok }\n";
    const STREAM_FILE: &str = r#"{ "operationId": "getThings", "stream": null, "sources": {}, "response": {} }"#;
    const NESTED_STREAM_ONLY: &str = r#"{ "operationId": "getThings", "sources": {}, "response": { "stream": "sources.a.b" } }"#;

    #[test]
    fn strict_with_a_top_level_stream_key_refuses_to_start_naming_the_reserved_key() {
        let root = scratch(STRICT, CLEAN);
        write_endpoint(&root, STREAM_FILE);
        let err = load_openapi_for_startup(&root, &server(STRICT), &tree_of(&root)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let message = err.to_string();
        assert!(message.contains("1 endpoint file(s) use the reserved \"stream\" key"), "{message}");
        assert!(message.contains("refusing to start"), "{message}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn non_strict_with_a_stream_key_still_starts() {
        let root = scratch(LAX, CLEAN);
        write_endpoint(&root, STREAM_FILE);
        assert!(load_openapi_for_startup(&root, &server(LAX), &tree_of(&root)).unwrap().is_some());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn strict_with_only_a_nested_stream_key_is_fine() {
        let root = scratch(STRICT, CLEAN);
        write_endpoint(&root, NESTED_STREAM_ONLY);
        assert!(load_openapi_for_startup(&root, &server(STRICT), &tree_of(&root)).unwrap().is_some());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn strict_with_only_w2_w3_w4_findings_starts_normally() {
        let spec = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths:\n  /things:\n    get:\n      operationId: getThings\n      security: [ { old: [] } ]\n      responses:\n        '200':\n          description: ok\n          content:\n            text/event-stream: {}\n  /u:\n    post:\n      operationId: u\n      requestBody:\n        content:\n          multipart/form-data: { schema: { type: object } }\n      responses:\n        '200': { description: ok }\ncomponents:\n  securitySchemes:\n    old: { type: apiKey, in: header, name: k, deprecated: true }\n";
        let root = scratch(STRICT, spec);
        let doc = load_openapi_for_startup(&root, &server(STRICT), &tree_of(&root)).unwrap().expect("loaded");
        assert!(doc.issues.len() >= 3);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn strict_with_an_unresolved_default_mapping_refuses_to_start_with_the_unchanged_message() {
        let spec = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths: {}\ncomponents:\n  schemas:\n    V: { oneOf: [ { type: string } ], discriminator: { propertyName: k, defaultMapping: Nope } }\n";
        let root = scratch(STRICT, spec);
        let err = load_openapi_for_startup(&root, &server(STRICT), &tree_of(&root)).unwrap_err();
        assert_eq!(err.to_string(), "1 openapi.yaml issue(s) found and \"strictOpenApi\" is true — refusing to start");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn strict_with_a_broken_media_type_ref_refuses_to_start() {
        let spec = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths:\n  /a:\n    get:\n      operationId: a\n      responses:\n        '200':\n          description: ok\n          content:\n            application/json: { $ref: '#/components/mediaTypes/Missing' }\n";
        let root = scratch(STRICT, spec);
        assert!(load_openapi_for_startup(&root, &server(STRICT), &tree_of(&root)).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod m2_7_startup_security_tests {
    use super::*;

    fn scratch(server_json: &str, spec: Option<&str>, endpoint: Option<&str>) -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "frogs-run-m27-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let api_dir = root.join("api");
        std::fs::create_dir_all(api_dir.join("config/errors")).unwrap();
        std::fs::create_dir_all(api_dir.join("security")).unwrap();
        std::fs::create_dir_all(api_dir.join("datasources/endpoints/things")).unwrap();
        if let Some(spec) = spec {
            std::fs::write(root.join("openapi.yaml"), spec).unwrap();
        }
        if let Some(endpoint) = endpoint {
            std::fs::write(api_dir.join("datasources/endpoints/things/endpoint.get.json"), endpoint).unwrap();
        }
        std::fs::write(api_dir.join("config/server.json"), server_json).unwrap();
        std::fs::write(api_dir.join("config/errors/core.json"), "{}").unwrap();
        std::fs::write(api_dir.join("config/connections.json"), "{}").unwrap();
        std::fs::write(api_dir.join("security/schemes.json"), "{}").unwrap();
        root
    }

    fn server(json: &str) -> ServerConfig {
        serde_json::from_str(json).unwrap()
    }

    const DEFAULT: &str = "{}";
    const FEATURES_OFF: &str = r#"{ "features": { "requestValidation": false } }"#;
    const STRICT: &str = r#"{ "strictOpenApi": true }"#;

    const SECURED_SPEC: &str = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\ncomponents:\n  securitySchemes:\n    apiKeyAuth: { type: apiKey, in: header, name: k }\npaths:\n  /things:\n    get:\n      operationId: getThings\n      security: [ { apiKeyAuth: [] } ]\n      responses:\n        '200': { description: ok }\n";
    const OPEN_SPEC: &str = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths:\n  /things:\n    get:\n      operationId: getThings\n      responses:\n        '200': { description: ok }\n";
    const UNPROTECTED: &str = r#"{ "operationId": "getThings", "sources": {}, "response": {} }"#;
    const PROTECTED: &str = r#"{ "operationId": "getThings", "security": "apiKeyAuth", "sources": {}, "response": {} }"#;

    #[test]
    fn a_mismatch_is_refused_even_with_strict_off_and_every_spec_consuming_feature_off() {
        let root = scratch(FEATURES_OFF, Some(SECURED_SPEC), Some(UNPROTECTED));
        let err = load_openapi_for_startup(&root, &server(FEATURES_OFF), &tree_of(&root)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let message = err.to_string();
        assert!(
            message.starts_with("1 endpoint file(s) don't apply the security openapi.yaml declares — refusing to start;"),
            "{message}"
        );
        assert!(message.ends_with("then run frogs validate"), "no registered-service hint on a plain run: {message}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_mismatch_is_refused_under_strict_too() {
        let root = scratch(STRICT, Some(SECURED_SPEC), Some(UNPROTECTED));
        let err = load_openapi_for_startup(&root, &server(STRICT), &tree_of(&root)).unwrap_err();
        assert!(err.to_string().contains("don't apply the security"), "{err}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_registered_service_refusal_carries_the_restart_policy_hint() {
        let root = scratch(FEATURES_OFF, Some(SECURED_SPEC), Some(UNPROTECTED));
        let err = precheck_security_for_service(&root).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("don't apply the security"), "{message}");
        assert!(message.contains("--restart-policy never"), "{message}");
        assert!(message.contains("restarts every 5 s under --restart-policy on-failure"), "{message}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_clean_project_with_the_spec_features_off_loads_nothing_into_memory() {
        let root = scratch(FEATURES_OFF, Some(SECURED_SPEC), Some(PROTECTED));
        let (doc, report) = load_openapi_for_startup_reported(&root, &server(FEATURES_OFF), "", &tree_of(&root)).unwrap();
        assert!(doc.is_none(), "the document must not leak into request validation / docs when those are off");
        assert!(report.unmatched.is_empty() && report.not_loaded.is_none() && report.dropped_issues == 0);
        assert!(load_openapi_for_startup(&root, &server(FEATURES_OFF), &tree_of(&root)).unwrap().is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_clean_project_with_default_config_hands_back_the_document() {
        let root = scratch(DEFAULT, Some(SECURED_SPEC), Some(PROTECTED));
        assert!(load_openapi_for_startup(&root, &server(DEFAULT), &tree_of(&root)).unwrap().is_some());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_file_with_no_matching_operation_is_reported_unmatched_and_startup_proceeds() {
        let root = scratch(DEFAULT, Some(OPEN_SPEC), Some(UNPROTECTED));
        std::fs::create_dir_all(root.join("api/datasources/endpoints/ghost")).unwrap();
        std::fs::write(root.join("api/datasources/endpoints/ghost/endpoint.get.json"), UNPROTECTED).unwrap();
        let (doc, report) = load_openapi_for_startup_reported(&root, &server(DEFAULT), "", &tree_of(&root)).unwrap();
        assert!(doc.is_some());
        assert_eq!(report.unmatched.len(), 1);
        assert!(report.unmatched[0].to_string_lossy().contains("ghost"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_unsafe_path_spec_with_strict_off_reports_the_dropped_operations_summary() {
        let spec = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths:\n  /x/..:\n    get:\n      operationId: bad\n      responses:\n        '200': { description: ok }\n";
        let root = scratch(FEATURES_OFF, Some(spec), Some(UNPROTECTED));
        let (_, report) = load_openapi_for_startup_reported(&root, &server(FEATURES_OFF), "", &tree_of(&root)).unwrap();
        assert!(report.dropped_issues >= 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_missing_or_unparseable_spec_with_strict_off_starts_with_a_not_checked_report() {
        let missing = scratch(FEATURES_OFF, None, Some(UNPROTECTED));
        let (doc, report) = load_openapi_for_startup_reported(&missing, &server(FEATURES_OFF), "", &tree_of(&missing)).unwrap();
        assert!(doc.is_none());
        assert!(report.not_loaded.is_some());

        let broken = scratch(FEATURES_OFF, Some("openapi: [unterminated"), Some(UNPROTECTED));
        let (doc, report) = load_openapi_for_startup_reported(&broken, &server(FEATURES_OFF), "", &tree_of(&broken)).unwrap();
        assert!(doc.is_none());
        assert!(report.not_loaded.is_some());
        let _ = std::fs::remove_dir_all(&missing);
        let _ = std::fs::remove_dir_all(&broken);
    }

    #[test]
    fn a_missing_spec_under_strict_is_still_refused() {
        let root = scratch(STRICT, None, Some(UNPROTECTED));
        assert!(load_openapi_for_startup(&root, &server(STRICT), &tree_of(&root)).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_service_precheck_only_warns_on_load_failure_and_unmatched_files() {
        let missing = scratch(FEATURES_OFF, None, Some(UNPROTECTED));
        assert!(precheck_security_for_service(&missing).is_ok());
        let unmatched = scratch(FEATURES_OFF, Some(OPEN_SPEC), None);
        std::fs::create_dir_all(unmatched.join("api/datasources/endpoints/ghost")).unwrap();
        std::fs::write(unmatched.join("api/datasources/endpoints/ghost/endpoint.get.json"), UNPROTECTED).unwrap();
        assert!(precheck_security_for_service(&unmatched).is_ok());
        let ok = scratch(FEATURES_OFF, Some(SECURED_SPEC), Some(PROTECTED));
        assert!(precheck_security_for_service(&ok).is_ok());
        let _ = std::fs::remove_dir_all(&missing);
        let _ = std::fs::remove_dir_all(&unmatched);
        let _ = std::fs::remove_dir_all(&ok);
    }

    #[test]
    fn a_web_only_project_without_a_spec_passes_the_service_precheck() {
        let root = std::env::temp_dir().join(format!(
            "frogs-run-m27-web-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("index.html"), "<html></html>").unwrap();
        assert!(precheck_security_for_service(&root).is_ok());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_mismatch_check_reads_the_api_subfolder_not_the_project_root() {
        // A same-shaped tree at the project root (not under api/) must be ignored.
        let root = scratch(FEATURES_OFF, Some(SECURED_SPEC), Some(PROTECTED));
        std::fs::create_dir_all(root.join("datasources/endpoints/things")).unwrap();
        std::fs::write(root.join("datasources/endpoints/things/endpoint.get.json"), UNPROTECTED).unwrap();
        assert!(load_openapi_for_startup(&root, &server(FEATURES_OFF), &tree_of(&root)).is_ok());
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod m3_method_case_tests {
    use super::*;

    fn temp_project() -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "frogs-run-m3-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn server(json: &str) -> ServerConfig {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn a_missing_key_warns_with_the_bypass_wording_and_matching_is_case_insensitive() {
        let config = server("{}");
        assert!(!config.case_sensitive_methods());
        assert!(!config.case_sensitive_methods_explicit());
        let (level, message) = method_case_notice(&config).expect("a notice");
        assert_eq!(level, tracing::Level::WARN);
        assert!(message.contains("caseSensitiveMethods is not set") && message.contains("bypass"), "{message}");
    }

    #[test]
    fn an_explicit_false_is_an_info_notice_with_the_documented_text() {
        let config = server(r#"{ "caseSensitiveMethods": false }"#);
        assert!(config.case_sensitive_methods_explicit());
        let (level, message) = method_case_notice(&config).expect("a notice");
        assert_eq!(level, tracing::Level::INFO);
        assert_eq!(
            message,
            "HTTP method names are matched case-insensitively (caseSensitiveMethods: false in config/server.json); set caseSensitiveMethods: true for RFC 9110 exact matching"
        );
    }

    #[test]
    fn an_explicit_true_has_no_notice_and_reaches_the_load_options() {
        let config = server(r#"{ "caseSensitiveMethods": true }"#);
        assert!(method_case_notice(&config).is_none());
        assert!(config.openapi_load_options().case_sensitive_methods);
        assert!(!server("{}").openapi_load_options().case_sensitive_methods);
    }

    #[test]
    fn the_default_server_config_writes_the_key_as_false_and_an_absent_key_is_not_serialized() {
        let written = serde_json::to_value(ServerConfig::default()).unwrap();
        assert_eq!(written["caseSensitiveMethods"], false);
        let unset = serde_json::to_value(server("{}")).unwrap();
        assert!(unset.get("caseSensitiveMethods").is_none(), "{unset}");
    }

    const QUERY_ON_31: &str =
        "openapi: 3.1.0\ninfo: { title: t, version: '1' }\npaths:\n  /q:\n    query:\n      operationId: q\n      responses:\n        '200': { description: ok }\n";

    fn scratch(server_json: &str, spec: &str) -> std::path::PathBuf {
        let root = temp_project();
        let api_dir = root.join("api");
        std::fs::create_dir_all(api_dir.join("config/errors")).unwrap();
        std::fs::create_dir_all(api_dir.join("security")).unwrap();
        std::fs::create_dir_all(api_dir.join("datasources/endpoints")).unwrap();
        std::fs::write(root.join("openapi.yaml"), spec).unwrap();
        std::fs::write(api_dir.join("config/server.json"), server_json).unwrap();
        std::fs::write(api_dir.join("config/errors/core.json"), "{}").unwrap();
        std::fs::write(api_dir.join("config/connections.json"), "{}").unwrap();
        std::fs::write(api_dir.join("security/schemes.json"), "{}").unwrap();
        root
    }

    #[test]
    fn strict_refuses_to_start_a_3_1_spec_that_uses_query_but_non_strict_starts() {
        let strict = r#"{ "strictOpenApi": true, "features": { "requestValidation": false } }"#;
        let root = scratch(strict, QUERY_ON_31);
        let err = load_openapi_for_startup(&root, &server(strict), &tree_of(&root)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            load_openapi_for_startup(&root, &server(r#"{ "features": { "requestValidation": true } }"#), &tree_of(&root))
                .unwrap()
                .is_some()
        );

        std::fs::write(root.join("openapi.yaml"), QUERY_ON_31.replace("3.1.0", "3.2.0")).unwrap();
        assert!(load_openapi_for_startup(&root, &server(strict), &tree_of(&root)).unwrap().is_some());
        let _ = std::fs::remove_dir_all(&root);
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    }

    async fn both_roles_get_status(case_sensitive_json: &str) -> u16 {
        let port = free_port();
        let root = scratch(
            &format!(r#"{{ "features": {{ "requestCorrelation": false, "requestValidation": false }}, "port": {port}{case_sensitive_json} }}"#),
            "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths: {}\n",
        );
        std::fs::write(root.join("index.html"), "<html>hello</html>").unwrap();
        std::fs::write(root.join("webserve.json"), r#"{ "startPage": "index.html" }"#).unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let run_root = root.clone();
        let task = tokio::spawn(async move {
            run_direct_with_shutdown(&run_root, async {
                let _ = rx.await;
            })
            .await
        });
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let mut up = false;
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                up = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(up, "the both-roles server never started listening");
        let (line, _, _, _) = crate::server::raw_request(addr, b"get /index.html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await;
        let _ = tx.send(());
        let _ = task.await;
        let _ = std::fs::remove_dir_all(&root);
        line.split(' ').nth(1).unwrap().parse().unwrap()
    }

    #[tokio::test]
    async fn a_both_roles_project_serves_a_lowercase_get_static_asset_when_matching_is_case_insensitive() {
        assert_eq!(both_roles_get_status(r#", "caseSensitiveMethods": false"#).await, 200);
    }

    #[tokio::test]
    async fn a_both_roles_project_applies_case_sensitive_methods_to_its_static_routes_too() {
        assert_eq!(both_roles_get_status(r#", "caseSensitiveMethods": true"#).await, 405);
    }
}

#[cfg(test)]
mod m4_run_tests {
    use super::*;

    fn temp_project() -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "frogs-run-m4-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn server(json: &str) -> ServerConfig {
        serde_json::from_str(json).unwrap()
    }

    const DUPLICATE_KEYS: &str = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths:\n  /x:\n    additionalOperations:\n      purge:\n        operationId: a\n        responses: { '200': { description: ok } }\n      PURGE:\n        operationId: b\n        responses: { '200': { description: ok } }\n";
    const SINGLE_PURGE: &str = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths:\n  /x:\n    additionalOperations:\n      PURGE:\n        operationId: a\n        responses: { '200': { description: ok } }\n";
    const STUB: &str = r#"{ "operationId": "a", "sources": {}, "response": {} }"#;

    fn project(spec: &str, server_json: &str, files: &[&str]) -> std::path::PathBuf {
        let root = temp_project();
        let api = root.join("api");
        for dir in ["config/errors", "security", "datasources/endpoints/x"] {
            std::fs::create_dir_all(api.join(dir)).unwrap();
        }
        std::fs::write(root.join("openapi.yaml"), spec).unwrap();
        std::fs::write(api.join("config/server.json"), server_json).unwrap();
        std::fs::write(api.join("config/errors/core.json"), "{}").unwrap();
        std::fs::write(api.join("config/connections.json"), "{}").unwrap();
        std::fs::write(api.join("security/schemes.json"), "{}").unwrap();
        for file in files {
            std::fs::write(api.join("datasources/endpoints/x").join(file), STUB).unwrap();
        }
        root
    }

    #[test]
    fn an_endpoint_file_for_a_method_declared_by_case_only_duplicate_keys_refuses_startup_with_strict_off() {
        let root = project(DUPLICATE_KEYS, "{}", &["endpoint.PURGE.json"]);
        let err = load_openapi_for_startup(&root, &server("{}"), &tree_of(&root)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("declares ambiguously"), "{err}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_same_ambiguous_file_refuses_startup_with_strict_on_too() {
        let root = project(DUPLICATE_KEYS, r#"{ "strictOpenApi": true }"#, &["endpoint.PURGE.json"]);
        let err = load_openapi_for_startup(&root, &server(r#"{ "strictOpenApi": true }"#), &tree_of(&root)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn case_only_duplicate_keys_with_no_endpoint_file_do_not_stop_startup_when_strict_is_off() {
        let root = project(DUPLICATE_KEYS, "{}", &[]);
        assert!(load_openapi_for_startup(&root, &server("{}"), &tree_of(&root)).is_ok());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_registered_service_precheck_refuses_an_ambiguous_method_file_too() {
        let root = project(DUPLICATE_KEYS, "{}", &["endpoint.PURGE.json"]);
        let err = precheck_security_for_service(&root).unwrap_err();
        assert!(err.to_string().contains("declares ambiguously"), "{err}");
        let ok = project(SINGLE_PURGE, "{}", &["endpoint.PURGE.json"]);
        assert!(precheck_security_for_service(&ok).is_ok());
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&ok);
    }

    #[test]
    fn strict_startup_refuses_every_m4_issue_kind_and_a_clean_spec_starts() {
        let strict = r#"{ "strictOpenApi": true }"#;
        let bad_key = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths:\n  /x:\n    additionalOperations:\n      OPTIONS:\n        operationId: a\n        responses: { '200': { description: ok } }\n";
        let root = project(bad_key, strict, &[]);
        assert!(load_openapi_for_startup(&root, &server(strict), &tree_of(&root)).is_err(), "S3 under strict");
        assert!(
            load_openapi_for_startup(&root, &server("{}"), &tree_of(&root)).is_ok(),
            "S3 without strict only warns"
        );
        let _ = std::fs::remove_dir_all(&root);

        let fixed_variant = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths:\n  /x:\n    additionalOperations:\n      get:\n        operationId: a\n        responses: { '200': { description: ok } }\n";
        let root = project(fixed_variant, strict, &[]);
        assert!(load_openapi_for_startup(&root, &server(strict), &tree_of(&root)).is_err(), "S4 under strict");
        let _ = std::fs::remove_dir_all(&root);

        // W1 (case-distinct method, exact mode) never refuses, even under strict.
        let exact_strict = r#"{ "strictOpenApi": true, "caseSensitiveMethods": true }"#;
        let root = project(&fixed_variant.replace("get:", "purge:"), exact_strict, &[]);
        assert!(
            load_openapi_for_startup(&root, &server(exact_strict), &tree_of(&root)).is_ok(),
            "W1 is not a strict error"
        );
        let _ = std::fs::remove_dir_all(&root);

        let root = project(SINGLE_PURGE, strict, &["endpoint.PURGE.json"]);
        assert!(load_openapi_for_startup(&root, &server(strict), &tree_of(&root)).is_ok());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn assemble_api_router_refuses_a_document_loaded_under_the_other_case_setting() {
        for (server_json, load_case_sensitive) in [(r#"{ "caseSensitiveMethods": true }"#, false), (r#"{ "caseSensitiveMethods": false }"#, true)] {
            let root = project(SINGLE_PURGE, server_json, &[]);
            let api = root.join("api");
            let config = Config::load(&api).unwrap();
            let doc = crate::openapi::load(
                &root.join("openapi.yaml"),
                crate::openapi::LoadOptions {
                    case_sensitive_methods: load_case_sensitive,
                },
            )
            .unwrap();
            let err = assemble_api_router(&root, config, Arc::new(HashMap::new()), None, Some(Arc::new(doc)), Arc::new(tree_of(&root)))
                .await
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert!(err.to_string().contains("different caseSensitiveMethods"), "{err}");
            let _ = std::fs::remove_dir_all(&root);
        }
    }

    #[tokio::test]
    async fn assemble_api_router_accepts_a_document_loaded_under_the_same_setting_and_serves_the_extension_route() {
        for (server_json, case_sensitive, token, request) in [
            (
                r#"{ "caseSensitiveMethods": false, "features": { "requestValidation": false } }"#,
                false,
                "PURGE",
                "purge",
            ),
            (
                r#"{ "caseSensitiveMethods": true, "features": { "requestValidation": false } }"#,
                true,
                "PURGE",
                "PURGE",
            ),
        ] {
            let root = project(SINGLE_PURGE, server_json, &[]);
            std::fs::write(root.join("api/datasources/endpoints/x").join(format!("endpoint.{token}.json")), STUB).unwrap();
            let config = Config::load(&root.join("api")).unwrap();
            let doc = crate::openapi::load(
                &root.join("openapi.yaml"),
                crate::openapi::LoadOptions {
                    case_sensitive_methods: case_sensitive,
                },
            )
            .unwrap();
            let (router, server_config) = assemble_api_router(&root, config, Arc::new(HashMap::new()), None, Some(Arc::new(doc)), Arc::new(tree_of(&root)))
                .await
                .expect("matching settings assemble");
            let addr = crate::server::spawn_served(router, server_config.case_sensitive_methods()).await;
            let resp = reqwest::Client::new()
                .request(reqwest::Method::from_bytes(request.as_bytes()).unwrap(), format!("http://{addr}/x"))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 200, "{server_json} {request}");
            let _ = std::fs::remove_dir_all(&root);
        }
    }
}

#[cfg(test)]
mod symlink_tests;

#[cfg(test)]
mod route_tests;
