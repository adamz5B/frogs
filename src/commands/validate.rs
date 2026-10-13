use std::io;
use std::path::{Path, PathBuf};

use crate::config::{ClientAuthMode, Config, CrlPolicy, TlsConfig, TlsMode};
use crate::project::{MANIFEST_FILE, api_base, require_project_root};
use crate::server::tls::{CRL_EXPIRY_WARNING_DAYS, CrlStatus, build_server_config, crl_freshness};

/// A finding that's worth printing but doesn't fail the run (and isn't
/// counted in the problem total) — e.g. revocation not being checked is a
/// legitimate (if risky) choice, not a misconfiguration.
fn warn(message: &str) {
    println!("  warning: {message}");
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
    let has_api = root.join(MANIFEST_FILE).is_file();
    let has_web = root.join("webserve.json").is_file();

    if !has_api && !has_web {
        eprintln!("error: no {MANIFEST_FILE} or webserve.json found at {} — run `frogs generate` first", root.display());
        std::process::exit(1);
    }

    let mut problems = 0usize;
    if has_api {
        problems += validate_api(&root).await;
    }
    if has_web {
        problems += validate_web(&root);
    }

    if problems == 0 {
        println!("frogs validate: OK, no problems found");
        Ok(())
    } else {
        eprintln!("frogs validate: {problems} problem(s) found");
        std::process::exit(1);
    }
}

async fn validate_api(root: &Path) -> usize {
    let api_dir = api_base(root);
    println!("API project at {}", api_dir.display());
    let mut problems = 0usize;

    // Exits immediately with a clear message on a genuine config problem —
    // same posture as every other command; there's nothing left worth
    // checking (SQL connections, endpoint files) if the config that
    // describes them didn't even load.
    let config = Config::load_or_exit(&api_dir);
    println!(
        "  config: OK ({} connection(s), {} error code(s), {} security scheme(s))",
        config.connections.len(),
        config.errors.len(),
        config.security.schemes.len()
    );

    // `frogs run` clamps this at startup rather than refusing to start (see
    // `ServerConfig::effective_source_call_timeout_ms`) — reported here so
    // it's visible without a live run.
    if config.server.source_call_timeout_ms.get() > crate::config::MAX_SOURCE_CALL_TIMEOUT_MS {
        println!(
            "  server.json: sourceCallTimeoutMs {} exceeds the hard ceiling of {} — it will be clamped at startup",
            config.server.source_call_timeout_ms.get(),
            crate::config::MAX_SOURCE_CALL_TIMEOUT_MS
        );
        problems += 1;
    }

    problems += validate_tls("config/server.json", &config.server.tls, &api_dir);
    if config.server.tls.client_auth.as_ref().is_some_and(|c| c.mode == ClientAuthMode::Required)
        && (config.server.features.readyz_check || config.server.features.metrics || config.server.docs_ui.mode != crate::config::DocsUiMode::Off)
    {
        warn(
            "tls.clientAuth.mode is \"required\" while readyz/metrics/docsUi is enabled — load-balancer probes and browsers without a client certificate \
             can't even connect to those; use \"optional\" and let routes decide",
        );
    }

    match crate::openapi::load(&root.join(MANIFEST_FILE)) {
        Ok(doc) => {
            println!("  {MANIFEST_FILE}: OK ({} operation(s))", doc.operations.len());
            for op in &doc.operations {
                let Some(scheme) = &op.security else { continue };
                if doc.security_scheme_types.get(scheme).map(String::as_str) != Some("mutualTLS") {
                    continue;
                }
                if let Some(verifier) = config.security.verifiers.get(scheme)
                    && !verifier.requires_client_cert()
                {
                    println!(
                        "  {MANIFEST_FILE}: {} {} uses the mutualTLS scheme '{scheme}', but its verifier never looks at the client certificate \
                         (use an mtls verifier or a cert.* parameter)",
                        op.method.to_uppercase(),
                        op.path
                    );
                    problems += 1;
                }
            }
        }
        Err(e) => {
            println!("  {MANIFEST_FILE}: FAILED — {e}");
            problems += 1;
        }
    }

    if config.connections.is_empty() {
        println!("  SQL connections: none configured");
    } else {
        for (name, result) in crate::sql::try_connect_each(&config.connections).await {
            match result {
                Ok(()) => println!("  connection '{name}': OK"),
                Err(e) => {
                    println!("  connection '{name}': FAILED — {e}");
                    problems += 1;
                }
            }
        }
    }

    let endpoints_root = api_dir.join("datasources/endpoints");
    let (count, endpoint_problems) =
        crate::endpoint::validate_endpoint_files(&endpoints_root, &config.security, &config.connections, config.server.tls.client_identity_enabled());
    println!("  endpoint files: {count} discovered, {} problem(s)", endpoint_problems.len());
    for problem in &endpoint_problems {
        println!("    - {problem}");
    }
    problems += endpoint_problems.len();

    for script_path in sql_script_files(&api_dir.join("datasources/sql")) {
        let Ok(contents) = std::fs::read_to_string(&script_path) else { continue };
        for name in crate::sql::truncated_placeholder_names(&contents) {
            println!(
                "  {}: placeholder ':{name}' is immediately followed by a non-ASCII character — only ':{name}' is bound, and an unknown name binds as NULL",
                script_path.display()
            );
            problems += 1;
        }
    }

    problems
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
fn validate_tls(label: &str, tls: &TlsConfig, tls_base: &Path) -> usize {
    if let Err(message) = tls.validate_structure() {
        println!("  {label}: tls FAILED — {message}");
        return 1;
    }
    if tls.mode != TlsMode::Manual {
        return 0;
    }
    let built = match build_server_config(tls, tls_base) {
        Ok(built) => built,
        Err(e) => {
            println!("  {label}: tls FAILED — {e}");
            return 1;
        }
    };
    println!("  {label}: tls OK");
    for warning in &built.warnings {
        warn(warning);
    }

    let fail_closed = tls.client_auth.as_ref().is_some_and(|c| c.effective_crl_policy() == CrlPolicy::FailClosed);
    let mut problems = 0usize;
    for (path, next_update, status) in crl_freshness(&built.crl_next_updates, chrono::Utc::now()) {
        match status {
            CrlStatus::Expired if fail_closed => {
                println!(
                    "  {label}: CRL {} expired at {next_update} and crlPolicy is failClosed — every client presenting a certificate would be rejected",
                    path.display()
                );
                problems += 1;
            }
            CrlStatus::Expired => warn(&format!("CRL {} expired at {next_update} — revocations since then are not seen", path.display())),
            CrlStatus::ExpiringSoon => warn(&format!(
                "CRL {} expires at {next_update} (within {CRL_EXPIRY_WARNING_DAYS} days) — replace it and restart before then",
                path.display()
            )),
        }
    }
    problems
}

fn validate_web(root: &Path) -> usize {
    println!("static-content project at {}", root.display());
    match crate::webserve::load(&root.join("webserve.json")) {
        Ok(config) => {
            println!("  webserve.json: OK (startPage: {})", config.start_page);
            // With an API role present the single listener is configured by
            // config/server.json (validated above); webserve.json's own tls
            // is ignored then, so a dry run of it would only mislead.
            if root.join(MANIFEST_FILE).is_file() {
                0
            } else {
                validate_tls("webserve.json", &config.tls, root)
            }
        }
        Err(e) => {
            println!("  webserve.json: FAILED — {e}");
            1
        }
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
