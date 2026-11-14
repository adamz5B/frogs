use std::io;
use std::path::{Path, PathBuf};

use crate::commands::report::{CommandError, Lines, ReportLine};
use crate::config::{ClientAuthMode, Config, CrlPolicy, TlsConfig, TlsMode};
use crate::project::{MANIFEST_FILE, api_base, require_project_root};
use crate::server::tls::{CRL_EXPIRY_WARNING_DAYS, CrlStatus, build_server_config, crl_freshness};

/// What a dry run may touch beyond reading files. `check_connections` is whether SQL connections are really opened
/// (which can create an absent SQLite database file).
#[derive(Debug, Clone, Copy)]
pub(crate) struct ValidateOptions {
    pub check_connections: bool,
}

/// A finished dry run: every line in print order, plus the error that stopped it early, if any.
pub(crate) struct ValidateReport {
    pub lines: Vec<ReportLine>,
    pub fatal: Option<CommandError>,
    pub connections_checked: bool,
}

impl ValidateReport {
    pub(crate) fn problems(&self) -> usize {
        self.lines.iter().filter(|line| line.problem).count()
    }
}

/// A read-only dry run of everything `frogs run` would otherwise only
/// surface as a side effect of actually starting: config loading, every
/// configured SQL connection, and every endpoint file — packaged as an
/// explicit command (design doc: "much of this logic already exists from
/// Phase 1–2's startup checks... mostly packaging it as an explicit dry-run
/// mode") instead of only being discoverable by running the real server.
/// Never binds a port, writes a PID file, or touches `.frogs/` — safe to
/// run repeatedly, e.g. as a pre-deploy CI check.
///
/// Uses the same `(has_api, has_web)` role detection as `commands::run`,
/// so it validates whichever side(s) of the project actually exist.
pub async fn run(cwd: &Path) -> io::Result<()> {
    let root = require_project_root(cwd);
    let report = validate_report(&root, ValidateOptions { check_connections: true }).await;
    for line in &report.lines {
        println!("{}", line.render());
    }
    if let Some(fatal) = &report.fatal {
        eprintln!("error: {}", fatal.message);
        std::process::exit(fatal.exit_code);
    }

    let problems = report.problems();
    if problems == 0 {
        println!("frogs validate: OK, no problems found");
        Ok(())
    } else {
        eprintln!("frogs validate: {problems} problem(s) found");
        std::process::exit(1);
    }
}

/// `frogs validate --json`: exactly one JSON document on stdout, the same exit codes as the plain form.
pub async fn run_json(cwd: &Path) -> io::Result<()> {
    let root = require_project_root(cwd);
    let report = validate_report(&root, ValidateOptions { check_connections: true }).await;
    let (document, exit_code) = json_document(&report);
    println!("{document}");
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

fn json_document(report: &ValidateReport) -> (serde_json::Value, i32) {
    if let Some(fatal) = &report.fatal {
        return (
            serde_json::json!({ "schemaVersion": 1, "ok": false, "fatal": { "message": fatal.message } }),
            fatal.exit_code,
        );
    }
    let problems = report.problems();
    let document = serde_json::json!({
        "schemaVersion": 1,
        "ok": problems == 0,
        "problemCount": problems,
        "findings": findings_json(&report.lines, |text| text.to_string()),
        "connections": if report.connections_checked { "checked" } else { "skipped" },
    });
    (document, i32::from(problems != 0))
}

/// The findings (everything that isn't a plain status line) as JSON; `scrub` is applied to every free-text string.
pub(crate) fn findings_json(lines: &[ReportLine], scrub: impl Fn(&str) -> String) -> Vec<serde_json::Value> {
    lines
        .iter()
        .filter(|line| line.severity != crate::commands::report::Severity::Info)
        .map(|line| {
            let mut finding = serde_json::json!({
                "severity": line.severity.as_str(),
                "problem": line.problem,
                "section": line.section,
                "message": scrub(&line.message),
            });
            if let Some(file) = &line.file {
                finding["file"] = serde_json::Value::String(scrub(file));
            }
            finding
        })
        .collect()
}

/// The whole dry run as data; never prints and never exits.
pub(crate) async fn validate_report(root: &Path, opts: ValidateOptions) -> ValidateReport {
    let mut lines = Lines::default();
    let fatal = validate_all(root, opts, &mut lines).await.err();
    ValidateReport {
        lines: lines.0,
        fatal,
        connections_checked: opts.check_connections,
    }
}

async fn validate_all(root: &Path, opts: ValidateOptions, out: &mut Lines) -> Result<(), CommandError> {
    let has_api = root.join(MANIFEST_FILE).is_file();
    let has_web = root.join("webserve.json").is_file();

    if !has_api && !has_web {
        return Err(CommandError::precondition(format!(
            "no {MANIFEST_FILE} or webserve.json found at {} — run `frogs generate` first",
            root.display()
        )));
    }

    if has_api {
        validate_api_lines(root, opts, out).await?;
    }
    if has_web {
        validate_web_lines(root, out);
    }
    Ok(())
}

/// One section printed the way a standalone run does, returning its problem count — what the sibling test modules assert on.
#[cfg(test)]
async fn validate_api(root: &Path) -> usize {
    let mut lines = Lines::default();
    let result = validate_api_lines(root, ValidateOptions { check_connections: true }, &mut lines).await;
    for line in &lines.0 {
        println!("{}", line.render());
    }
    if let Err(fatal) = result {
        eprintln!("error: {}", fatal.message);
        std::process::exit(fatal.exit_code);
    }
    lines.problems()
}

#[cfg(test)]
fn validate_tls(label: &str, tls: &TlsConfig, tls_base: &Path) -> usize {
    let mut lines = Lines::default();
    validate_tls_lines(&mut lines, label, tls, tls_base);
    lines.problems()
}

#[cfg(test)]
fn report_spec_issues(doc: &crate::openapi::OpenApiDocument, strict: bool) -> usize {
    let mut lines = Lines::default();
    report_spec_issues_lines(&mut lines, doc, strict);
    lines.problems()
}

#[cfg(test)]
fn validate_web(root: &Path) -> usize {
    let mut lines = Lines::default();
    validate_web_lines(root, &mut lines);
    for line in &lines.0 {
        println!("{}", line.render());
    }
    lines.problems()
}

async fn validate_api_lines(root: &Path, opts: ValidateOptions, out: &mut Lines) -> Result<(), CommandError> {
    let api_dir = api_base(root);
    out.plain("project", format!("API project at {}", api_dir.display()));

    // A genuine config problem ends the run with a clear message — same
    // posture as every other command; there's nothing left worth checking
    // (SQL connections, endpoint files) if the config that describes them
    // didn't even load.
    let config = Config::load(&api_dir).map_err(|err| CommandError::config_load(&api_dir, err))?;
    out.info(
        "config",
        format!(
            "config: OK ({} connection(s), {} error code(s), {} security scheme(s), strictOpenApi={}, endpointSymlinks={})",
            config.connections.len(),
            config.errors.len(),
            config.security.schemes.len(),
            config.server.strict_open_api(),
            config.server.endpoint_symlinks().as_str()
        ),
    );

    // Same read-only check generate makes before it writes anything: every
    // folder and file it would create must resolve inside the project.
    let boundary = crate::openapi::endpoint_tree::ProjectBoundary::new(root);
    if let Err(e) = crate::commands::generate::write_gate(&boundary, &api_dir) {
        out.error("config", e.to_string());
    }
    let ctx = crate::commands::run::link_context(root, &config.server);
    let endpoint_tree = crate::commands::run::scan_endpoint_tree(root, &config.server);
    let links = crate::commands::generate::link_report(&endpoint_tree);
    for message in &links.errors {
        out.error("endpoints", message.as_str());
    }
    for message in &links.warnings {
        if config.server.strict_open_api() {
            out.error("endpoints", message.as_str());
        } else {
            out.warning("endpoints", message.as_str());
        }
    }

    match crate::commands::run::method_case_notice(&config.server) {
        None => out.info("config", "method case: exact (caseSensitiveMethods: true)"),
        Some((tracing::Level::WARN, message)) => {
            out.info("config", "method case: case-insensitive (default)");
            out.warning("config", message);
        }
        Some((_, _)) => out.info("config", "method case: case-insensitive (caseSensitiveMethods: false)"),
    }

    // `frogs run` clamps this at startup rather than refusing to start (see
    // `ServerConfig::effective_source_call_timeout_ms`) — reported here so
    // it's visible without a live run.
    if config.server.source_call_timeout_ms.get() > crate::config::MAX_SOURCE_CALL_TIMEOUT_MS {
        out.failure(
            "config",
            format!(
                "server.json: sourceCallTimeoutMs {} exceeds the hard ceiling of {} — it will be clamped at startup",
                config.server.source_call_timeout_ms.get(),
                crate::config::MAX_SOURCE_CALL_TIMEOUT_MS
            ),
        );
    }

    if let Some(requested) = config.server.verifier_cache_max_entries
        && !(crate::config::MIN_VERIFIER_CACHE_MAX_ENTRIES..=crate::config::MAX_VERIFIER_CACHE_MAX_ENTRIES).contains(&requested)
    {
        out.warning(
            "config",
            format!(
                "server.json: verifierCacheMaxEntries {requested} is outside {}..={} — it will be clamped at startup",
                crate::config::MIN_VERIFIER_CACHE_MAX_ENTRIES,
                crate::config::MAX_VERIFIER_CACHE_MAX_ENTRIES
            ),
        );
    }

    validate_tls_lines(out, "config/server.json", &config.server.tls, &api_dir);
    if config.server.tls.client_auth.as_ref().is_some_and(|c| c.mode == ClientAuthMode::Required)
        && (config.server.features.readyz_check || config.server.features.metrics || config.server.docs_ui.mode != crate::config::DocsUiMode::Off)
    {
        out.warning(
            "tls",
            "tls.clientAuth.mode is \"required\" while readyz/metrics/docsUi is enabled — load-balancer probes and browsers without a client certificate \
             can't even connect to those; use \"optional\" and let routes decide",
        );
    }

    let strict_routes = config.server.strict_open_api();
    let route_mode = crate::openapi::method_token::MethodCase::from_case_sensitive(config.server.case_sensitive_methods());
    let route_ctx = crate::endpoint::route_plan::RouteContext::for_server(&config.server).with_extras(crate::endpoint::route_plan::RootExtras {
        web: root.join("webserve.json").is_file(),
        control_plane: false,
    });
    let route_plan = crate::endpoint::route_plan::RoutePlan::build(&endpoint_tree, route_mode, &route_ctx);
    let route_refusals = route_plan.refusals(strict_routes);
    out.info(
        "routes",
        format!("routes: {} registered, {} problem(s)", route_plan.routes.len(), route_refusals.len()),
    );
    for problem in &route_refusals {
        out.bullet_problem("routes", problem.message());
    }
    for problem in route_plan.warnings(strict_routes) {
        out.warning("routes", problem.message());
    }

    match crate::openapi::load(&root.join(MANIFEST_FILE), config.server.openapi_load_options()) {
        Ok(doc) => {
            out.info("openapi", format!("{MANIFEST_FILE}: OK ({} operation(s))", doc.operations.len()));
            report_spec_issues_lines(out, &doc, config.server.strict_open_api());
            let plan = crate::commands::generate::plan_endpoint_files(&api_dir, &doc, &endpoint_tree, &ctx);
            for error in &plan.errors {
                out.error("openapi", error.message.as_str());
            }
            for item in &plan.archive {
                out.warning(
                    "openapi",
                    format!(
                        "{}: orphaned {} will be moved into _backups/ by frogs generate (never deleted) — {}",
                        item.dir.display(),
                        crate::openapi::untrusted(&item.name),
                        item.reason
                    ),
                );
            }
            for message in &plan.wrong_mode {
                out.error("openapi", message.as_str());
            }
            for message in &plan.invalid_tokens {
                if config.server.strict_open_api() {
                    out.error("openapi", message.as_str());
                } else {
                    out.warning("openapi", message.as_str());
                }
            }
            let security = crate::endpoint::security_check_with_routes(&endpoint_tree, &doc, &route_plan, &config.security);
            let mut security_errors: Vec<String> = Vec::new();
            security_errors.extend(security.mismatches.iter().map(|m| m.message()));
            security_errors.extend(security.ambiguous.iter().map(|m| m.message()));
            security_errors.extend(security.stale_variants.iter().map(|m| m.message()));
            security_errors.extend(security.template_instances.iter().map(|m| m.message()));
            security_errors.extend(security.shadowed.iter().map(|m| m.message()));
            security_errors.extend(security.unverifiable.iter().map(|m| m.message()));
            security_errors.extend(security.builtin_refusals.iter().map(|m| m.message()));
            security_errors.extend(security.scope_mismatches.iter().cloned());
            security_errors.extend(crate::endpoint::unresolved_parameter_routes(&endpoint_tree, &doc));
            for message in &security_errors {
                out.error("security", message.as_str());
            }
            for message in security.builtin_warnings.iter().chain(&security.scope_warnings) {
                out.warning("security", message.as_str());
            }
            for stricter in &security.stricter {
                out.warning("security", stricter.message());
            }
            for file in &security.unmatched {
                let message = crate::endpoint::unmatched_security_message(file);
                if config.server.strict_open_api() {
                    out.error("security", format!("{message} (\"strictOpenApi\" is true)"));
                } else {
                    out.warning("security", message);
                }
            }
            for op in &doc.operations {
                let Some(scheme) = &op.security else { continue };
                if doc.security_scheme_types.get(scheme).map(String::as_str) != Some("mutualTLS") {
                    continue;
                }
                if let Some(verifier) = config.security.verifiers.get(scheme)
                    && !verifier.requires_client_cert()
                {
                    out.failure(
                        "security",
                        format!(
                            "{MANIFEST_FILE}: {} {} uses the mutualTLS scheme '{scheme}', but its verifier never looks at the client certificate \
                             (use an mtls verifier or a cert.* parameter)",
                            op.http_method, op.path
                        ),
                    );
                }
            }
        }
        Err(e) => {
            out.failure("openapi", format!("{MANIFEST_FILE}: FAILED — {e}"));
        }
    }

    if config.connections.is_empty() {
        out.info("connections", "SQL connections: none configured");
    } else if opts.check_connections {
        for (name, result) in crate::sql::try_connect_each(&config.connections).await {
            match result {
                Ok(()) => out.info("connections", format!("connection '{name}': OK")),
                Err(e) => out.failure("connections", format!("connection '{name}': FAILED — {e}")),
            }
        }
    } else {
        out.note(
            "connections",
            format!(
                "{} SQL connection(s) were not opened (connection checks are off); opening one can create an absent SQLite database file",
                config.connections.len()
            ),
        );
    }

    let method_case = crate::openapi::method_token::MethodCase::from_case_sensitive(config.server.case_sensitive_methods());
    let (count, endpoint_problems) = crate::endpoint::validate_endpoint_files(
        &endpoint_tree,
        &config.security,
        &config.connections,
        config.server.tls.client_identity_enabled(),
        method_case,
    );
    out.info("endpoints", format!("endpoint files: {count} discovered, {} problem(s)", endpoint_problems.len()));
    for problem in &endpoint_problems {
        out.bullet_problem("endpoints", problem.to_string());
    }

    report_mcp(out, &config, &endpoint_tree, root);

    let strict = config.server.strict_open_api();
    for path in crate::endpoint::reserved_stream_key_files(&endpoint_tree, method_case) {
        let message = format!(
            "{}: \"stream\" is reserved for streaming responses, which this frogs version does not implement — serving a single JSON response",
            path.display()
        );
        if strict {
            out.bullet_problem("endpoints", message);
        } else {
            out.warning("endpoints", message);
        }
        out.with_file(path.display().to_string());
    }

    for script_path in sql_script_files(&api_dir.join("datasources/sql")) {
        let Ok(contents) = std::fs::read_to_string(&script_path) else { continue };
        for name in crate::sql::truncated_placeholder_names(&contents) {
            out.failure(
                "sql",
                format!(
                    "{}: placeholder ':{name}' is immediately followed by a non-ASCII character — only ':{name}' is bound, and an unknown name binds as NULL",
                    script_path.display()
                ),
            );
            out.with_file(script_path.display().to_string());
        }
    }

    Ok(())
}

/// The `mcp:` section: printed only when `features.mcp` is on or some endpoint file has an `mcp` block.
fn report_mcp(out: &mut Lines, config: &Config, tree: &crate::openapi::endpoint_tree::EndpointTree, root: &Path) {
    let doc = crate::openapi::load(&root.join(MANIFEST_FILE), config.server.openapi_load_options()).ok();
    let inputs = crate::mcp::StartupInputs {
        server: &config.server,
        security: &config.security,
        connections: &config.connections,
        tree,
        doc: doc.as_ref(),
        client_identity_available: config.server.tls.client_identity_enabled(),
        web_role: root.join("webserve.json").is_file(),
        web_allow_dot_paths: &crate::commands::run::web_allow_dot_paths(root, root.join("webserve.json").is_file()),
    };
    let Some(report) = crate::mcp::validate_findings(&inputs) else { return };
    let errors = report.findings.iter().filter(|(severity, _)| *severity == crate::mcp::Severity::Error).count();
    out.info("mcp", format!("mcp: {} tool(s), {errors} problem(s)", report.tools));
    for (severity, message) in &report.findings {
        match severity {
            crate::mcp::Severity::Error => out.bullet_problem("mcp", message.as_str()),
            crate::mcp::Severity::Warning => out.warning("mcp", message.as_str()),
        }
    }
}

/// Reports a loaded spec's issues: every dropped-path (`Severity::Error`)
/// issue, every Windows-portability finding on any OS (even where the path
/// was kept), and — under `strictOpenApi` — every strict-class issue count
/// as problems. Everything else is a warning.
fn report_spec_issues_lines(out: &mut Lines, doc: &crate::openapi::OpenApiDocument, strict: bool) {
    let mut would_be_errors = 0usize;
    for issue in &doc.issues {
        let is_problem =
            issue.severity == crate::openapi::Severity::Error || issue.kind == crate::openapi::IssueKind::WindowsPortability || (strict && issue.kind.is_strict_error());
        if is_problem {
            out.error("openapi", issue.message.as_str());
        } else {
            out.warning("openapi", issue.message.as_str());
            if issue.kind.is_strict_error() {
                would_be_errors += 1;
            }
        }
    }
    if would_be_errors > 0 {
        out.note("openapi", format!("{would_be_errors} issue(s) would be errors with \"strictOpenApi\": true"));
    }
}

/// Every `*.sql` file under `root`, recursively — an empty vec for a missing
/// directory (a project may legitimately have no SQL sources at all), never
/// an error.
fn sql_script_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect_sql_scripts(root, &mut out);
    out
}

fn collect_sql_scripts(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_sql_scripts(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("sql") {
            out.push(path);
        }
    }
}

/// A TLS dry run for one listener's config: the I/O-free structure checks,
/// then (for `manual` mode) the very same `build_server_config` `frogs run`
/// uses — cert/key, CA bundle and CRLs all read and parsed, nothing bound.
/// An already-lapsed CRL is a problem under `failClosed` (every
/// certificate-presenting client would be refused) and a warning otherwise.
fn validate_tls_lines(out: &mut Lines, label: &str, tls: &TlsConfig, tls_base: &Path) {
    if let Err(message) = tls.validate_structure() {
        out.failure("tls", format!("{label}: tls FAILED — {message}"));
        return;
    }
    if tls.mode != TlsMode::Manual {
        return;
    }
    let built = match build_server_config(tls, tls_base) {
        Ok(built) => built,
        Err(e) => {
            out.failure("tls", format!("{label}: tls FAILED — {e}"));
            return;
        }
    };
    out.info("tls", format!("{label}: tls OK"));
    for warning in &built.warnings {
        out.warning("tls", warning.as_str());
    }

    let fail_closed = tls.client_auth.as_ref().is_some_and(|c| c.effective_crl_policy() == CrlPolicy::FailClosed);
    for (path, next_update, status) in crl_freshness(&built.crl_next_updates, chrono::Utc::now()) {
        match status {
            CrlStatus::Expired if fail_closed => out.failure(
                "tls",
                format!(
                    "{label}: CRL {} expired at {next_update} and crlPolicy is failClosed — every client presenting a certificate would be rejected",
                    path.display()
                ),
            ),
            CrlStatus::Expired => out.warning(
                "tls",
                format!("CRL {} expired at {next_update} — revocations since then are not seen", path.display()),
            ),
            CrlStatus::ExpiringSoon => out.warning(
                "tls",
                format!(
                    "CRL {} expires at {next_update} (within {CRL_EXPIRY_WARNING_DAYS} days) — replace it and restart before then",
                    path.display()
                ),
            ),
        }
    }
}

fn validate_web_lines(root: &Path, out: &mut Lines) {
    out.plain("web", format!("static-content project at {}", root.display()));
    let config = match crate::webserve::load(&root.join(crate::project::WEBSERVE_FILE)) {
        Ok(config) => config,
        Err(e) => {
            out.failure("web", format!("webserve.json: FAILED — {e}"));
            return;
        }
    };
    out.info("web", format!("webserve.json: OK (startPage: {})", config.start_page));

    let has_api = root.join(MANIFEST_FILE).is_file();
    let mut protected = crate::webserve::ProtectedPaths::default();
    protected.add_dir("logging.directory", &crate::server::logging::resolve_log_directory(root, has_api).0);
    if has_api && let Ok(api_config) = Config::load(&crate::project::api_base(root)) {
        protected.add_tls(&api_config.server.tls, &crate::project::api_base(root));
        protected.add_sqlite(&api_config.connections, root);
    }

    let (page_problems, page_warnings) = crate::webserve::page_problems(root, &config, &protected);
    for message in &page_problems {
        out.failure("web", message.as_str());
    }
    for message in &page_warnings {
        out.warning("web", message.as_str());
    }
    for message in crate::webserve::site_identity_warnings(root, &config, &protected) {
        out.warning("web", message);
    }
    if root.join(".well-known").is_dir() && config.allow_dot_paths.is_empty() {
        out.warning(
            "web",
            ".well-known/ at the project root is never served (every dot-prefixed path is denied); to serve part of it, list the paths in webserve.json's \"allowDotPaths\", e.g. [\".well-known/acme-challenge\"]",
        );
    }
    if !has_api && crate::project::api_base(root).read_dir().is_ok_and(|mut entries| entries.next().is_some()) {
        out.warning("web", "api/ in a web-only project is never served");
    }

    // With an API role present the single listener is configured by
    // config/server.json (validated above); webserve.json's own tls
    // is ignored then, so a dry run of it would only mislead.
    if !has_api {
        validate_tls_lines(out, "webserve.json", &config.tls, root);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    /// `run()` itself calls `std::process::exit(1)` on any problem (project
    /// not found, config load failure, or a nonzero problem count) — the
    /// same posture every other command already has, and just as
    /// untestable directly for the same reason (it would kill the test
    /// process). These tests exercise `validate_api`/`validate_web`
    /// directly instead, since neither of *those* ever exits on their own —
    /// they only return a problem count for `run()` to act on — plus
    /// `run()`'s real happy path, which returns `Ok(())` without exiting.
    /// The exit-on-failure behavior itself is covered by live verification
    /// against the real binary, matching how `commands::run`'s own exit
    /// paths are handled.
    fn temp_project() -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "frogs-validate-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn write_minimal_openapi(root: &Path) {
        fs::write(root.join(MANIFEST_FILE), "openapi: 3.0.3\ninfo: { title: t, version: '1' }\npaths: {}\n").unwrap();
    }

    #[tokio::test]
    async fn validate_api_reports_zero_problems_for_a_clean_minimal_project() {
        let root = temp_project();
        write_minimal_openapi(&root);
        fs::create_dir_all(root.join("api/config")).unwrap();

        assert_eq!(validate_api(&root).await, 0);
    }

    #[tokio::test]
    async fn validate_api_counts_an_endpoint_files_bad_security_scheme_as_a_problem() {
        let root = temp_project();
        write_minimal_openapi(&root);
        fs::create_dir_all(root.join("api/datasources/endpoints/things")).unwrap();
        fs::write(
            root.join("api/datasources/endpoints/things/endpoint.get.json"),
            r#"{ "operationId": "getThings", "security": "noSuchScheme", "sources": {}, "response": {} }"#,
        )
        .unwrap();

        assert_eq!(validate_api(&root).await, 1);
    }

    #[tokio::test]
    async fn validate_api_counts_a_connection_with_an_uncompiled_driver_as_a_problem() {
        let root = temp_project();
        write_minimal_openapi(&root);
        fs::create_dir_all(root.join("api/config")).unwrap();
        // "nosuchdriver" has no match arm in `sql::connect_one` regardless of
        // which `--features` this test binary happens to be built with —
        // the same deterministic choice `sql::mod`'s own tests make.
        // Deliberately not "mssql" (which now has a real match arm, gated on
        // the `mssql` feature — see `mssql.rs`): "nosuchdriver" is guaranteed
        // to never become a real driver, so this stays deterministic no
        // matter which optional features this test binary is built with.
        fs::write(root.join("api/config/connections.json"), r#"{ "db": { "driver": "nosuchdriver" } }"#).unwrap();

        assert_eq!(validate_api(&root).await, 1);
    }

    /// `frogs run` only clamps (and warns) an over-ceiling `sourceCallTimeoutMs`
    /// rather than refusing to start — `frogs validate` is where this is
    /// surfaced as a real problem a user can catch without a live run (see
    /// `ServerConfig::effective_source_call_timeout_ms`).
    #[tokio::test]
    async fn validate_api_counts_a_server_json_source_call_timeout_ms_over_the_ceiling_as_a_problem() {
        let root = temp_project();
        write_minimal_openapi(&root);
        fs::create_dir_all(root.join("api/config")).unwrap();
        fs::write(root.join("api/config/server.json"), r#"{ "sourceCallTimeoutMs": 999999 }"#).unwrap();

        assert_eq!(validate_api(&root).await, 1);
    }

    #[tokio::test]
    async fn validate_api_does_not_flag_an_under_ceiling_server_json_source_call_timeout_ms() {
        let root = temp_project();
        write_minimal_openapi(&root);
        fs::create_dir_all(root.join("api/config")).unwrap();
        fs::write(root.join("api/config/server.json"), r#"{ "sourceCallTimeoutMs": 60000 }"#).unwrap();

        assert_eq!(validate_api(&root).await, 0);
    }

    /// `é` right after `:id` means only the ASCII prefix `id` is actually
    /// bound — a scripted-but-wrong placeholder name, reported (not
    /// fatal to startup) via `truncated_placeholder_names`.
    #[tokio::test]
    async fn validate_api_reports_a_sql_script_with_a_truncated_placeholder_as_one_problem() {
        let root = temp_project();
        write_minimal_openapi(&root);
        fs::create_dir_all(root.join("api/config")).unwrap();
        fs::create_dir_all(root.join("api/datasources/sql/db")).unwrap();
        fs::write(root.join("api/datasources/sql/db/query.sql"), "SELECT * FROM cars WHERE id = :idé").unwrap();

        assert_eq!(validate_api(&root).await, 1);
    }

    /// The same check must stay silent for an all-ASCII script — only a
    /// `:name` truncated by a trailing non-ASCII byte is ever flagged.
    #[tokio::test]
    async fn validate_api_does_not_flag_an_all_ascii_sql_script() {
        let root = temp_project();
        write_minimal_openapi(&root);
        fs::create_dir_all(root.join("api/config")).unwrap();
        fs::create_dir_all(root.join("api/datasources/sql/db")).unwrap();
        fs::write(root.join("api/datasources/sql/db/query.sql"), "SELECT * FROM cars WHERE id = :id").unwrap();

        assert_eq!(validate_api(&root).await, 0);
    }

    #[tokio::test]
    async fn validate_api_reports_a_malformed_openapi_yaml_as_a_problem() {
        let root = temp_project();
        fs::write(root.join(MANIFEST_FILE), "paths: [this, is, not, a, map").unwrap();
        fs::create_dir_all(root.join("api/config")).unwrap();

        assert_eq!(validate_api(&root).await, 1);
    }

    #[test]
    fn validate_web_reports_zero_problems_for_a_valid_webserve_json() {
        let root = temp_project();
        fs::write(root.join("webserve.json"), r#"{ "startPage": "index.html" }"#).unwrap();

        assert_eq!(validate_web(&root), 0);
    }

    #[test]
    fn validate_web_reports_one_problem_for_a_malformed_webserve_json() {
        let root = temp_project();
        fs::write(root.join("webserve.json"), "{ not valid json").unwrap();

        assert_eq!(validate_web(&root), 1);
    }

    #[test]
    fn validate_web_counts_a_start_page_that_is_never_served_as_one_problem() {
        let root = temp_project();
        fs::create_dir_all(root.join("api/config")).unwrap();
        fs::write(root.join("api/config/connections.json"), "{}").unwrap();
        fs::write(root.join("webserve.json"), r#"{ "startPage": "api/config/connections.json" }"#).unwrap();

        assert_eq!(validate_web(&root), 1);
    }

    #[test]
    fn validate_web_counts_a_denied_start_page_and_a_denied_not_found_page_separately() {
        let root = temp_project();
        fs::write(root.join(".env"), "x").unwrap();
        fs::write(root.join("webserve.json"), r#"{ "startPage": ".env", "notFoundPage": "openapi.yaml" }"#).unwrap();

        assert_eq!(validate_web(&root), 2);
    }

    #[test]
    fn validate_web_counts_a_start_page_that_names_the_web_tls_key_as_a_problem() {
        let root = temp_project();
        fs::write(root.join("key.pem"), "x").unwrap();
        fs::write(
            root.join("webserve.json"),
            r#"{ "startPage": "key.pem", "tls": { "mode": "off", "manual": { "certPath": "cert.pem", "keyPath": "key.pem" } } }"#,
        )
        .unwrap();

        assert_eq!(validate_web(&root), 1);
    }

    #[test]
    fn validate_web_counts_an_unresolvable_protected_path_as_one_problem() {
        let root = temp_project();
        fs::write(root.join("index.html"), "x").unwrap();
        fs::write(
            root.join("webserve.json"),
            r#"{ "startPage": "index.html", "tls": { "mode": "off", "manual": { "certPath": "", "keyPath": "key.pem" } } }"#,
        )
        .unwrap();

        assert_eq!(validate_web(&root), 1);
    }

    #[test]
    fn validate_web_only_warns_about_a_web_only_api_folder_and_a_well_known_folder() {
        let root = temp_project();
        fs::write(root.join("index.html"), "x").unwrap();
        fs::write(root.join("webserve.json"), r#"{ "startPage": "index.html" }"#).unwrap();
        fs::create_dir_all(root.join("api")).unwrap();
        fs::write(root.join("api/index.html"), "x").unwrap();
        fs::create_dir_all(root.join(".well-known")).unwrap();
        fs::write(root.join(".well-known/security.txt"), "x").unwrap();

        assert_eq!(validate_web(&root), 0);
    }

    #[tokio::test]
    async fn run_succeeds_for_a_clean_api_only_project() {
        let root = temp_project();
        write_minimal_openapi(&root);
        fs::create_dir_all(root.join("api/config")).unwrap();

        assert!(run(&root).await.is_ok());
    }

    #[tokio::test]
    async fn run_succeeds_for_a_clean_web_only_project() {
        let root = temp_project();
        // `require_project_root` needs an `.html` file (or `openapi.yaml`)
        // to recognize the directory as a project root at all —
        // `webserve.json`'s own presence isn't itself a root marker (see
        // `project::is_project_root`), same as a real `generate --role web`
        // project always has real HTML assets alongside `webserve.json`.
        fs::write(root.join("index.html"), "<html></html>").unwrap();
        fs::write(root.join("webserve.json"), r#"{ "startPage": "index.html" }"#).unwrap();

        assert!(run(&root).await.is_ok());
    }

    #[tokio::test]
    async fn run_succeeds_for_a_clean_project_serving_both_roles() {
        let root = temp_project();
        write_minimal_openapi(&root);
        fs::create_dir_all(root.join("api/config")).unwrap();
        fs::write(root.join("webserve.json"), r#"{ "startPage": "index.html" }"#).unwrap();

        assert!(run(&root).await.is_ok());
    }
}

#[cfg(test)]
mod mtls_tests;

#[cfg(test)]
mod ref_tests;

#[cfg(test)]
mod spec_hardening_tests {
    use super::*;
    use std::fs;

    fn temp_project() -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "frogs-validate-m1-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn write_spec(root: &Path, version_line: &str, paths: &[&str]) {
        let mut yaml = format!("{version_line}info: {{ title: t, version: '1' }}\npaths:\n");
        if paths.is_empty() {
            yaml = format!("{version_line}info: {{ title: t, version: '1' }}\npaths: {{}}\n");
        }
        for (i, p) in paths.iter().enumerate() {
            yaml.push_str(&format!(
                "  '{p}':\n    get:\n      operationId: op{i}\n      responses:\n        '200': {{ description: ok }}\n"
            ));
        }
        fs::write(root.join(MANIFEST_FILE), yaml).unwrap();
    }

    fn make_strict(root: &Path) {
        fs::create_dir_all(root.join("api/config")).unwrap();
        fs::write(root.join("api/config/server.json"), r#"{ "strictOpenApi": true }"#).unwrap();
    }

    #[tokio::test]
    async fn a_path_with_a_colon_is_one_problem_on_every_os() {
        let root = temp_project();
        write_spec(&root, "openapi: 3.1.0\n", &["/items:batchGet"]);
        assert_eq!(validate_api(&root).await, 1);
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn case_only_colliding_paths_count_as_problems() {
        let root = temp_project();
        write_spec(&root, "openapi: 3.1.0\n", &["/Cars", "/cars"]);
        assert!(validate_api(&root).await >= 1);
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn an_unsafe_path_is_a_problem_even_without_strict() {
        let root = temp_project();
        write_spec(&root, "openapi: 3.1.0\n", &["/a/../b", "/fine"]);
        assert_eq!(validate_api(&root).await, 1);
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_missing_version_is_no_problem_normally_and_one_problem_under_strict() {
        let lax = temp_project();
        write_spec(&lax, "", &[]);
        assert_eq!(validate_api(&lax).await, 0);

        let strict = temp_project();
        make_strict(&strict);
        write_spec(&strict, "", &[]);
        assert_eq!(validate_api(&strict).await, 1);
        let _ = fs::remove_dir_all(&lax);
        let _ = fs::remove_dir_all(&strict);
    }

    #[tokio::test]
    async fn a_trailing_slash_is_a_warning_normally_and_a_problem_under_strict() {
        let lax = temp_project();
        write_spec(&lax, "openapi: 3.1.0\n", &["/cars/"]);
        assert_eq!(validate_api(&lax).await, 0);

        let strict = temp_project();
        make_strict(&strict);
        write_spec(&strict, "openapi: 3.1.0\n", &["/cars/"]);
        assert_eq!(validate_api(&strict).await, 1);
        let _ = fs::remove_dir_all(&lax);
        let _ = fs::remove_dir_all(&strict);
    }

    #[tokio::test]
    async fn not_served_operations_are_never_problems_even_under_strict() {
        let root = temp_project();
        make_strict(&root);
        fs::write(
            root.join(MANIFEST_FILE),
            "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths:\n  /s:\n    query:\n      operationId: q\n      responses: { '200': { description: ok } }\n",
        )
        .unwrap();
        assert_eq!(validate_api(&root).await, 0);
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_case_variant_endpoint_folder_on_disk_is_a_problem_and_validate_writes_nothing() {
        let root = temp_project();
        write_spec(&root, "openapi: 3.1.0\n", &["/cars"]);
        fs::create_dir_all(root.join("api/datasources/endpoints/Cars")).unwrap();
        let before: Vec<_> = fs::read_dir(root.join("api/datasources/endpoints"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();

        assert!(validate_api(&root).await >= 1);

        let after: Vec<_> = fs::read_dir(root.join("api/datasources/endpoints"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(before, after);
        assert_eq!(fs::read_dir(root.join("api/datasources/endpoints/Cars")).unwrap().count(), 0);
        assert!(!root.join("api/datasources/components").exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_clean_project_with_a_declared_version_still_reports_zero_problems() {
        let root = temp_project();
        write_spec(&root, "openapi: 3.0.3\n", &["/cars", "/cars/{vin}"]);
        assert_eq!(validate_api(&root).await, 0);
        let _ = fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod m2_validate_tests {
    use super::*;
    use std::fs;

    fn temp_project() -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "frogs-validate-m2-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn write_spec_body(root: &Path, body: &str) {
        fs::write(root.join(MANIFEST_FILE), format!("openapi: 3.2.0\ninfo: {{ title: t, version: '1' }}\n{body}")).unwrap();
    }

    fn make_strict(root: &Path) {
        fs::create_dir_all(root.join("api/config")).unwrap();
        fs::write(root.join("api/config/server.json"), r#"{ "strictOpenApi": true }"#).unwrap();
    }

    const S9: &str = "paths:\n  /a:\n    get:\n      operationId: a\n      responses:\n        '200':\n          description: ok\n          content:\n            application/json: { $ref: '#/components/mediaTypes/Missing' }\n";
    const S10: &str = "paths: {}\ncomponents:\n  schemas:\n    V: { oneOf: [ { type: string } ], discriminator: { propertyName: k, defaultMapping: Nope } }\n";
    const S11: &str = "paths:\n  /a:\n    get:\n      operationId: a\n      security: [ { 'https://x/y': [] } ]\n      responses:\n        '200':\n          description: ok\n          content:\n            application/json: { schema: { type: string } }\n";

    #[test]
    fn report_spec_issues_counts_s9_always_but_s10_and_s11_only_under_strict() {
        for (body, always) in [(S9, true), (S10, false), (S11, false)] {
            let root = temp_project();
            write_spec_body(&root, body);
            let doc = crate::openapi::load(&root.join(MANIFEST_FILE), crate::openapi::LoadOptions::default()).unwrap();
            assert_eq!(report_spec_issues(&doc, false), usize::from(always), "{body}");
            assert_eq!(report_spec_issues(&doc, true), 1, "{body}");
            let _ = fs::remove_dir_all(&root);
        }
    }

    #[test]
    fn w2_w3_and_w4_are_never_problems_even_under_strict() {
        let root = temp_project();
        write_spec_body(
            &root,
            "paths:\n  /e:\n    get:\n      operationId: e\n      security: [ { old: [] } ]\n      responses:\n        '200':\n          description: ok\n          content:\n            text/event-stream: {}\n  /u:\n    post:\n      operationId: u\n      requestBody:\n        content:\n          multipart/form-data: { schema: { type: object } }\n      responses:\n        '200': { description: ok }\ncomponents:\n  securitySchemes:\n    old: { type: apiKey, in: header, name: k, deprecated: true }\n",
        );
        let doc = crate::openapi::load(&root.join(MANIFEST_FILE), crate::openapi::LoadOptions::default()).unwrap();
        assert!(doc.issues.len() >= 3);
        assert_eq!(report_spec_issues(&doc, true), 0);
        assert_eq!(report_spec_issues(&doc, false), 0);
        let _ = fs::remove_dir_all(&root);
    }

    fn project_with_stream_key_file(strict: bool) -> PathBuf {
        let root = temp_project();
        write_spec_body(
            &root,
            "paths:\n  /things:\n    get:\n      operationId: getThings\n      responses: { '200': { description: ok } }\n",
        );
        if strict {
            make_strict(&root);
        } else {
            fs::create_dir_all(root.join("api/config")).unwrap();
        }
        fs::create_dir_all(root.join("api/datasources/endpoints/things")).unwrap();
        fs::write(
            root.join("api/datasources/endpoints/things/endpoint.get.json"),
            r#"{ "operationId": "getThings", "stream": {}, "sources": {}, "response": {} }"#,
        )
        .unwrap();
        root
    }

    #[tokio::test]
    async fn a_reserved_stream_key_file_is_only_a_warning_when_not_strict() {
        let root = project_with_stream_key_file(false);
        assert_eq!(validate_api(&root).await, 0);
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_reserved_stream_key_file_is_a_problem_under_strict() {
        let root = project_with_stream_key_file(true);
        assert_eq!(validate_api(&root).await, 1);
        let _ = fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod m2_7_validate_security_tests {
    use super::*;
    use std::fs;

    fn project(server_json: &str, endpoint: &str) -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "frogs-validate-m27-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(root.join("api/config")).unwrap();
        fs::create_dir_all(root.join("api/datasources/endpoints/things")).unwrap();
        fs::write(root.join("api/config/server.json"), server_json).unwrap();
        fs::write(root.join("api/datasources/endpoints/things/endpoint.get.json"), endpoint).unwrap();
        root
    }

    fn write_spec(root: &Path, security_line: &str) {
        fs::write(
            root.join(MANIFEST_FILE),
            format!("openapi: 3.2.0\ninfo: {{ title: t, version: '1' }}\npaths:\n  /things:\n    get:\n      operationId: getThings\n{security_line}      responses:\n        '200': {{ description: ok }}\n"),
        )
        .unwrap();
    }

    const UNPROTECTED: &str = r#"{ "operationId": "getThings", "sources": {}, "response": {} }"#;
    const PROTECTED_B: &str = r#"{ "operationId": "getThings", "security": "b", "sources": {}, "response": {} }"#;

    #[tokio::test]
    async fn a_security_mismatch_is_a_problem_even_with_strict_off() {
        let root = project("{}", UNPROTECTED);
        write_spec(&root, "      security: [ { a: [] } ]\n");
        assert!(validate_api(&root).await >= 1);
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn stricter_files_and_unmatched_files_are_warnings_not_problems() {
        let root = project("{}", PROTECTED_B);
        // spec declares no security for /things; the file adds one (stricter). Scheme b is
        // undefined in schemes.json, so subtract that known, separate problem.
        write_spec(&root, "");
        let baseline_endpoint_problem = validate_api(&root).await;
        fs::write(root.join("api/datasources/endpoints/things/endpoint.get.json"), UNPROTECTED).unwrap();
        let clean = validate_api(&root).await;
        assert_eq!(clean, 0, "an open route with an open spec is clean");
        assert!(baseline_endpoint_problem <= 1, "stricter adds at most the unrelated unknown-scheme problem");

        fs::create_dir_all(root.join("api/datasources/endpoints/ghost")).unwrap();
        fs::write(root.join("api/datasources/endpoints/ghost/endpoint.get.json"), UNPROTECTED).unwrap();
        assert_eq!(validate_api(&root).await, 0, "an unmatched file is only a warning");
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_collapsed_and_requirement_is_a_warning_only() {
        let root = project("{}", UNPROTECTED);
        fs::write(
            root.join(MANIFEST_FILE),
            "openapi: 3.2.0\ninfo: { title: t, version: '1' }\ncomponents:\n  securitySchemes:\n    a: { type: apiKey, in: header, name: k }\n    b: { type: apiKey, in: header, name: k2 }\npaths:\n  /other:\n    get:\n      operationId: o\n      security: [ { a: [], b: [] } ]\n      responses:\n        '200': { description: ok }\n  /things:\n    get:\n      operationId: getThings\n      responses:\n        '200': { description: ok }\n",
        )
        .unwrap();
        assert_eq!(validate_api(&root).await, 0);
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn validate_reports_the_same_skip_for_an_unresolvable_scheme_that_build_router_applies() {
        // Parity: a file whose scheme isn't in security/schemes.json is a validate problem
        // (build_router refuses to register it), independent of the spec check.
        let root = project("{}", PROTECTED_B);
        fs::write(root.join(MANIFEST_FILE), "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths: {}\n").unwrap();
        assert!(validate_api(&root).await >= 1);
        let _ = fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod m3_validate_tests {
    use super::*;
    use std::fs;

    fn project(server_json: &str) -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "frogs-validate-m3-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(root.join("api/config")).unwrap();
        fs::create_dir_all(root.join("api/datasources/endpoints/things")).unwrap();
        fs::write(root.join("api/config/server.json"), server_json).unwrap();
        fs::write(
            root.join(MANIFEST_FILE),
            "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths:\n  /things:\n    get:\n      operationId: getThings\n      responses:\n        '200': { description: ok }\n",
        )
        .unwrap();
        fs::write(
            root.join("api/datasources/endpoints/things/endpoint.get.json"),
            r#"{ "operationId": "getThings", "sources": {}, "response": {} }"#,
        )
        .unwrap();
        root
    }

    fn add_non_canonical(root: &Path) {
        let dir = root.join("api/datasources/endpoints/other");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("endpoint.GET.json"), r#"{ "operationId": "o", "sources": {}, "response": {} }"#).unwrap();
    }

    #[tokio::test]
    async fn a_missing_case_sensitive_methods_key_is_never_counted_as_a_problem() {
        for server in [
            "{}",
            r#"{ "caseSensitiveMethods": false }"#,
            r#"{ "caseSensitiveMethods": true }"#,
            r#"{ "strictOpenApi": true }"#,
        ] {
            let root = project(server);
            assert_eq!(validate_api(&root).await, 0, "{server}");
            let _ = fs::remove_dir_all(&root);
        }
    }

    #[tokio::test]
    async fn a_case_twin_orphan_is_only_a_warning_in_validate_because_generate_archives_it() {
        let root = project("{}");
        let dir = root.join("api/datasources/endpoints/things");
        fs::write(dir.join("_endpoint.GET.json"), r#"{ "operationId": "old", "sources": {}, "response": {} }"#).unwrap();
        fs::remove_file(dir.join("endpoint.get.json")).unwrap();
        assert_eq!(validate_api(&root).await, 0, "an archivable orphan twin is not a problem");
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_non_canonical_stub_name_is_a_warning_normally_and_a_problem_under_strict() {
        let root = project("{}");
        add_non_canonical(&root);
        assert_eq!(validate_api(&root).await, 0, "warning only");
        fs::write(root.join("api/config/server.json"), r#"{ "strictOpenApi": true }"#).unwrap();
        assert_eq!(validate_api(&root).await, 1, "one problem per non-canonical file under strict");
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_query_operation_in_a_3_1_spec_is_a_problem_only_under_strict() {
        let root = project("{}");
        let spec = "openapi: 3.1.0\ninfo: { title: t, version: '1' }\npaths:\n  /things:\n    query:\n      operationId: q\n      responses:\n        '200': { description: ok }\n";
        fs::write(root.join(MANIFEST_FILE), spec).unwrap();
        fs::write(
            root.join("api/datasources/endpoints/things/endpoint.get.json"),
            r#"{ "operationId": "q", "sources": {}, "response": {} }"#,
        )
        .unwrap();
        assert_eq!(validate_api(&root).await, 0);
        fs::write(root.join("api/config/server.json"), r#"{ "strictOpenApi": true }"#).unwrap();
        assert!(validate_api(&root).await >= 1);
        let _ = fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod m4_validate_tests {
    use super::*;
    use std::fs;

    fn project(server_json: &str, spec: &str, files: &[(&str, &str)]) -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "frogs-validate-m4-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(root.join("api/config")).unwrap();
        fs::write(root.join("api/config/server.json"), server_json).unwrap();
        fs::write(root.join(MANIFEST_FILE), spec).unwrap();
        for (folder, name) in files {
            let dir = root.join("api/datasources/endpoints").join(folder);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join(name), r#"{ "operationId": "o", "sources": {}, "response": {} }"#).unwrap();
        }
        root
    }

    const EMPTY_SPEC: &str = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths: {}\n";
    const PURGE_LOWER: &str = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths:\n  /x:\n    additionalOperations:\n      purge:\n        operationId: p\n        responses: { '200': { description: ok } }\n";
    const PURGE_UPPER: &str = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths:\n  /x:\n    additionalOperations:\n      PURGE:\n        operationId: p\n        responses: { '200': { description: ok } }\n";
    const DUPLICATES: &str = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths:\n  /x:\n    additionalOperations:\n      purge:\n        operationId: a\n        responses: { '200': { description: ok } }\n      PURGE:\n        operationId: b\n        responses: { '200': { description: ok } }\n";

    #[tokio::test]
    async fn a_clean_extension_project_validates_with_zero_problems_in_both_modes() {
        let ok = project(r#"{ "caseSensitiveMethods": false }"#, PURGE_UPPER, &[("x", "endpoint.PURGE.json")]);
        assert_eq!(validate_api(&ok).await, 0);
        let exact = project(r#"{ "caseSensitiveMethods": true }"#, PURGE_LOWER, &[("x", "endpoint.~purge.json")]);
        assert_eq!(validate_api(&exact).await, 0, "a W1 warning is not a problem");
        let _ = fs::remove_dir_all(&ok);
        let _ = fs::remove_dir_all(&exact);
    }

    #[tokio::test]
    async fn a_wrong_mode_file_is_a_problem_even_without_strict() {
        let root = project(r#"{ "caseSensitiveMethods": false }"#, EMPTY_SPEC, &[("gone", "endpoint.~purge.json")]);
        assert_eq!(validate_api(&root).await, 1);
        fs::write(root.join("api/config/server.json"), r#"{ "caseSensitiveMethods": true }"#).unwrap();
        assert_eq!(validate_api(&root).await, 0, "the same file is valid under the other setting");
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_case_only_mismatch_between_a_stub_and_the_spec_is_a_problem_without_strict() {
        // default -> exact: endpoint.PURGE.json still on disk while the spec says purge
        let a = project(r#"{ "caseSensitiveMethods": true }"#, PURGE_LOWER, &[("x", "endpoint.PURGE.json")]);
        assert_eq!(validate_api(&a).await, 1);
        // exact -> default: endpoint.~purge.json on disk (WrongMode) while the spec now resolves to PURGE
        let b = project(r#"{ "caseSensitiveMethods": false }"#, PURGE_LOWER, &[("x", "endpoint.~purge.json")]);
        assert_eq!(validate_api(&b).await, 1, "the mismatch is counted once, not again as a bare wrong-mode file");
        let _ = fs::remove_dir_all(&a);
        let _ = fs::remove_dir_all(&b);
    }

    #[tokio::test]
    async fn an_invalid_token_file_is_a_warning_without_strict_and_a_problem_under_strict() {
        let root = project(r#"{ "caseSensitiveMethods": false }"#, EMPTY_SPEC, &[("gone", "endpoint.purge.json")]);
        assert_eq!(validate_api(&root).await, 0);
        fs::write(root.join("api/config/server.json"), r#"{ "caseSensitiveMethods": false, "strictOpenApi": true }"#).unwrap();
        assert_eq!(validate_api(&root).await, 1);
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn duplicate_case_variant_keys_are_problems_and_an_existing_stub_for_them_adds_one_more() {
        let without = project(r#"{ "caseSensitiveMethods": false }"#, DUPLICATES, &[]);
        let base = validate_api(&without).await;
        assert!(base >= 1, "the S4 issue is an error-level problem");
        let with_file = project(r#"{ "caseSensitiveMethods": false }"#, DUPLICATES, &[("x", "endpoint.PURGE.json")]);
        assert_eq!(
            validate_api(&with_file).await,
            base + 1,
            "the file the spec can no longer vouch for is one more problem"
        );
        let _ = fs::remove_dir_all(&without);
        let _ = fs::remove_dir_all(&with_file);
    }

    #[tokio::test]
    async fn the_same_duplicate_keys_in_exact_mode_are_two_distinct_methods_and_cost_nothing_but_a_warning() {
        let root = project(
            r#"{ "caseSensitiveMethods": true }"#,
            DUPLICATES,
            &[("x", "endpoint.~purge.json"), ("x", "endpoint.PURGE.json")],
        );
        assert_eq!(validate_api(&root).await, 0);
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn an_s3_key_is_a_problem_and_still_counts_under_strict() {
        let spec = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths:\n  /x:\n    additionalOperations:\n      OPTIONS:\n        operationId: o\n        responses: { '200': { description: ok } }\n";
        let root = project("{}", spec, &[]);
        assert!(validate_api(&root).await >= 1);
        fs::write(root.join("api/config/server.json"), r#"{ "strictOpenApi": true }"#).unwrap();
        assert!(validate_api(&root).await >= 1);
        let _ = fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod symlink_tests;

#[cfg(test)]
mod route_tests;

#[cfg(test)]
mod m5_route_validate_tests {
    use super::*;
    use std::fs;

    const OPEN: &str = r#"{ "operationId": "x", "sources": {}, "response": {} }"#;

    fn project(spec_paths: &str) -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "frogs-validate-m5-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(root.join("api/config")).unwrap();
        fs::create_dir_all(root.join("api/security")).unwrap();
        fs::write(root.join("api/config/server.json"), "{}").unwrap();
        fs::write(root.join("api/security/schemes.json"), "{}").unwrap();
        fs::write(
            root.join(MANIFEST_FILE),
            format!(
                "openapi: 3.2.0\ninfo: {{ title: t, version: '1' }}\ncomponents:\n  securitySchemes:\n    a: {{ type: apiKey, in: header, name: k }}\npaths:\n{spec_paths}"
            ),
        )
        .unwrap();
        root
    }

    fn endpoint(root: &Path, folder: &str) {
        let dir = root.join("api/datasources/endpoints").join(folder);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("endpoint.get.json"), OPEN).unwrap();
    }

    fn get_op(path: &str, id: &str, secured: bool) -> String {
        let security = if secured { "      security: [ { a: [] } ]\n" } else { "" };
        format!("  '{path}':\n    get:\n      operationId: {id}\n{security}      responses: {{ '200': {{ description: ok }} }}\n")
    }

    #[tokio::test]
    async fn an_unroutable_percent_folder_is_a_validate_problem() {
        let root = project(&get_op("/ok", "ok", false));
        endpoint(&root, "ok");
        assert_eq!(validate_api(&root).await, 0, "baseline");
        endpoint(&root, "a%41");
        assert!(validate_api(&root).await >= 1);
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn conflicting_parameter_names_at_one_position_are_a_validate_problem() {
        let root = project(&get_op("/ok", "ok", false));
        endpoint(&root, "ok");
        endpoint(&root, "cars/{id}");
        assert_eq!(validate_api(&root).await, 0, "one parameter name is fine");
        endpoint(&root, "cars/{vin}");
        assert!(validate_api(&root).await >= 1);
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_secured_operation_answered_by_an_open_parameter_route_is_a_validate_problem() {
        let paths = get_op("/cars/admin", "adm", true) + &get_op("/cars/{id}", "byId", false);
        let root = project(&paths);
        endpoint(&root, "cars/{id}");
        assert!(validate_api(&root).await >= 1);
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_secured_partial_template_with_a_fitting_open_literal_folder_is_a_validate_problem() {
        let root = project(&get_op("/files/report.{ext}", "rep", true));
        endpoint(&root, "files/other.pdf");
        assert_eq!(validate_api(&root).await, 0, "a folder that does not fit the template is no problem");
        endpoint(&root, "files/report.pdf");
        assert!(validate_api(&root).await >= 1);
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_secured_operation_without_a_file_is_a_problem_once_a_web_catch_all_would_answer_it() {
        let root = project(&(get_op("/ok", "ok", false) + &get_op("/admin", "adm", true)));
        endpoint(&root, "ok");
        assert_eq!(validate_api(&root).await, 0, "API only: nothing answers /admin");
        fs::write(root.join("webserve.json"), "{}").unwrap();
        assert!(validate_api(&root).await >= 1, "the static catch-all would answer /admin without security");
        let _ = fs::remove_dir_all(&root);
    }
}
