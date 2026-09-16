//! `frogs run`'s two-stage tracing setup — a stdout-only "bootstrap"
//! subscriber every other subcommand (and `run` itself, until its own role
//! is known) uses, and the real persistent stdout+file subscriber `run`
//! installs once it knows the project's role and `logging` config. See
//! `docs/frogs-persistent-logging.md` for the full design record.

use std::path::{Path, PathBuf};

use tracing_subscriber::prelude::*;

use crate::config::{LogLevel, LoggingConfig, ServerConfig};

/// The same stdout-only, `RUST_LOG`-or-`info` subscriber every non-`Run`
/// subcommand has always installed — extracted verbatim from `main`'s old
/// inline setup, just swapping the panicking `.init()` for `.try_init()` (a
/// second install attempt in the same process, e.g. under `cargo test`,
/// should be a silent no-op, not a panic).
pub fn install_bootstrap_subscriber() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")))
        .try_init();
}

/// Held only for its `Drop` side effect — `tracing_appender`'s non-blocking
/// writer flushes its buffered file writes when its `WorkerGuard` drops, so
/// the caller must keep this alive for as long as file logging should keep
/// working. `None` when there is no file writer at all (the self-heal path
/// in `install_run_subscriber`, or a web-only project — though today every
/// path always attempts a file writer).
pub struct LoggingHandles(#[allow(dead_code)] Option<tracing_appender::non_blocking::WorkerGuard>);

fn level_filter_directive(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Off => "off",
        LogLevel::Error => "error",
        LogLevel::Warn => "warn",
        LogLevel::Info => "info",
        LogLevel::Debug => "debug",
        LogLevel::Trace => "trace",
    }
}

/// Installs the real subscriber for a `frogs run` process: stdout plus a
/// UTC daily-rolling file under `log_dir` (`frogs.log.<date>`, via
/// `tracing_appender::rolling::daily` — no `local-time` feature, see this
/// dependency's own Cargo.toml comment), both sharing one `EnvFilter` built
/// from `level` unless `RUST_LOG` overrides it (same precedence the old
/// hardcoded bootstrap subscriber already had).
///
/// `log_dir` creation is attempted (`create_dir_all`) before the file writer
/// is built; on failure this self-heals to stdout-only rather than panicking
/// or aborting startup — the returned `LoggingHandles` then holds no file
/// guard. Built as one `tracing_subscriber::registry()`/`.try_init()` call
/// site with the file layer wrapped in `Option` (a no-op `Layer` when
/// `None`), specifically so the healthy and self-healed paths can't diverge
/// in behavior (same filter, same stdout layer, either way).
pub fn install_run_subscriber(log_dir: &Path, level: LogLevel) -> LoggingHandles {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level_filter_directive(level)));

    let (file_layer, guard, dir_error) = match std::fs::create_dir_all(log_dir) {
        Ok(()) => {
            let file_appender = tracing_appender::rolling::daily(log_dir, "frogs.log");
            let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
            let layer = tracing_subscriber::fmt::layer().with_writer(non_blocking).with_ansi(false);
            (Some(layer), Some(guard), None)
        }
        Err(e) => (None, None, Some(e)),
    };

    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .with(file_layer)
        .try_init();

    // Logged *after* the subscriber above is installed, so it actually
    // reaches somewhere (stdout) instead of vanishing into the default noop
    // subscriber — this is the "self-heal, log a warning" path `logging`'s
    // own doc comment on `LoggingConfig`/this function's callers describes.
    if let Some(e) = dir_error {
        tracing::warn!(
            "failed to create log directory {}: {e} — persistent file logging is disabled for this run, stdout logging continues",
            log_dir.display()
        );
    }

    LoggingHandles(guard)
}

/// Lenient, best-effort read of `config/server.json`'s `logging` block —
/// falls all the way back to `LoggingConfig::default()` on any read/parse
/// error. This is *not* the fail-closed authority on a project's config:
/// `Config::load_or_exit` still runs moments later in `build_api_router` and
/// remains the real one — this pre-parse exists purely so the log directory
/// can be created, and a subscriber installed, before that later, stricter
/// load happens.
fn read_logging_config_best_effort(api_dir: &Path) -> LoggingConfig {
    std::fs::read_to_string(api_dir.join("config/server.json"))
        .ok()
        .and_then(|contents| serde_json::from_str::<ServerConfig>(&contents).ok())
        .map(|config| config.logging)
        .unwrap_or_default()
}

/// Shared by `resolve_log_directory` and `peek_logging_directory` so the two
/// can never disagree on where the log directory actually is.
fn resolve_logging_config(root: &Path, has_api: bool) -> (PathBuf, LoggingConfig) {
    if has_api {
        let api_dir = crate::project::api_base(root);
        let logging = read_logging_config_best_effort(&api_dir);
        let dir = api_dir.join(&logging.directory);
        (dir, logging)
    } else {
        // No `api/` folder, no `webserve.json` logging surface in v1 (see
        // `LoggingConfig`'s doc comment) — a web-only project always gets
        // the plain default, resolved against the project root itself.
        let logging = LoggingConfig::default();
        let dir = root.join(&logging.directory);
        (dir, logging)
    }
}

/// Resolves the log directory and level a `frogs run` process should use,
/// for a project whose role (`has_api`) is already known to the caller —
/// see `resolve_logging_config` for the actual (lenient, best-effort) read.
pub fn resolve_log_directory(root: &Path, has_api: bool) -> (PathBuf, LogLevel) {
    let (dir, logging) = resolve_logging_config(root, has_api);
    (dir, logging.level)
}

/// The directory-only half of `resolve_log_directory`, for a caller that
/// doesn't already know (or care about) the project's role or log level —
/// `service::install`'s macOS branch, which only needs somewhere to point
/// launchd's `StandardOutPath`/`StandardErrorPath` at. Detects `has_api`
/// itself via the same marker `resolve_log_directory`'s callers use.
///
/// Only actually called from the macOS-only branch of `service::install` —
/// `#[allow(dead_code)]` because that makes this function genuinely unused
/// on a non-macOS build, the same "used only by a platform-gated caller
/// elsewhere" situation `escape_xml`/`escape_systemd_exec_arg` already have.
#[allow(dead_code)]
pub fn peek_logging_directory(root: &Path) -> PathBuf {
    let has_api = root.join(crate::project::MANIFEST_FILE).is_file();
    resolve_logging_config(root, has_api).0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_project() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "frogs-logging-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn level_filter_directive_maps_every_variant_to_its_lowercase_tracing_directive() {
        assert_eq!(level_filter_directive(LogLevel::Off), "off");
        assert_eq!(level_filter_directive(LogLevel::Error), "error");
        assert_eq!(level_filter_directive(LogLevel::Warn), "warn");
        assert_eq!(level_filter_directive(LogLevel::Info), "info");
        assert_eq!(level_filter_directive(LogLevel::Debug), "debug");
        assert_eq!(level_filter_directive(LogLevel::Trace), "trace");
    }

    /// `has_api=true` with an explicit, non-default `logging` block — both
    /// the custom directory and the custom level must actually be picked
    /// up, and the directory must resolve relative to `api/`, not the
    /// project root itself.
    #[test]
    fn resolve_log_directory_with_api_reads_the_projects_own_explicit_logging_block() {
        let root = temp_project();
        let api_dir = root.join("api");
        std::fs::create_dir_all(api_dir.join("config")).unwrap();
        std::fs::write(
            api_dir.join("config/server.json"),
            r#"{ "logging": { "directory": "logs/custom", "level": "trace" } }"#,
        )
        .unwrap();

        let (dir, level) = resolve_log_directory(&root, true);
        assert_eq!(dir, api_dir.join("logs/custom"));
        assert_eq!(level, LogLevel::Trace);
    }

    #[test]
    fn peek_logging_directory_agrees_with_resolve_log_directory_for_an_api_project() {
        let root = temp_project();
        std::fs::write(root.join("openapi.yaml"), "openapi: 3.0.3\ninfo: { title: t, version: '1' }\npaths: {}\n").unwrap();
        let api_dir = root.join("api");
        std::fs::create_dir_all(api_dir.join("config")).unwrap();
        std::fs::write(api_dir.join("config/server.json"), r#"{ "logging": { "directory": "custom-logs" } }"#).unwrap();

        let (expected_dir, _) = resolve_log_directory(&root, true);
        assert_eq!(expected_dir, api_dir.join("custom-logs"));
        assert_eq!(
            peek_logging_directory(&root),
            expected_dir,
            "peek_logging_directory must never disagree with resolve_log_directory"
        );
    }

    /// No `api/config/server.json` at all — must fall back to
    /// `LoggingConfig::default()` (`api/runtime-logs`, `Info`) without
    /// erroring.
    #[test]
    fn resolve_log_directory_with_api_falls_back_to_defaults_when_server_json_is_missing() {
        let root = temp_project();

        let (dir, level) = resolve_log_directory(&root, true);
        assert_eq!(dir, root.join("api").join("runtime-logs"));
        assert_eq!(level, LogLevel::Info);
    }

    /// A `config/server.json` that exists but doesn't even parse as JSON —
    /// same graceful fallback as a missing file, never a panic.
    #[test]
    fn resolve_log_directory_with_api_falls_back_to_defaults_when_server_json_is_malformed() {
        let root = temp_project();
        let api_dir = root.join("api");
        std::fs::create_dir_all(api_dir.join("config")).unwrap();
        std::fs::write(api_dir.join("config/server.json"), "{ this is not valid json").unwrap();

        let (dir, level) = resolve_log_directory(&root, true);
        assert_eq!(dir, api_dir.join("runtime-logs"), "a malformed server.json must gracefully fall back, not panic");
        assert_eq!(level, LogLevel::Info);
    }

    #[test]
    fn resolve_log_directory_without_api_resolves_relative_to_the_project_root_itself() {
        let root = temp_project();
        std::fs::write(root.join("index.html"), "<html></html>").unwrap();

        let (dir, level) = resolve_log_directory(&root, false);
        assert_eq!(dir, root.join("runtime-logs"));
        assert_eq!(level, LogLevel::Info);
    }

    #[test]
    fn peek_logging_directory_detects_a_web_only_project_via_the_absence_of_openapi_yaml() {
        let root = temp_project();
        std::fs::write(root.join("index.html"), "<html></html>").unwrap();
        // No openapi.yaml at all — `has_api` should resolve to false, even
        // though nothing here checks for the .html marker specifically.
        assert_eq!(peek_logging_directory(&root), root.join("runtime-logs"));
    }

    #[test]
    fn install_run_subscriber_creates_the_log_directory_and_holds_a_real_guard_on_success() {
        let root = temp_project();
        let log_dir = root.join("runtime-logs");
        assert!(!log_dir.exists());

        let handles = install_run_subscriber(&log_dir, LogLevel::Info);

        assert!(log_dir.is_dir(), "the log directory should have been created");
        assert!(handles.0.is_some(), "a successfully created log directory should yield a real file-writer guard");
    }

    /// The self-heal path: `log_dir` sits underneath an ordinary *file*, so
    /// `create_dir_all` can never succeed — must not panic, and must return
    /// `LoggingHandles` holding no file-writer guard rather than aborting
    /// startup.
    #[test]
    fn install_run_subscriber_self_heals_without_panicking_when_the_log_directory_cannot_be_created() {
        let root = temp_project();
        let blocking_file = root.join("not-a-directory");
        std::fs::write(&blocking_file, "i am a file, not a directory").unwrap();
        let log_dir = blocking_file.join("runtime-logs");

        let handles = install_run_subscriber(&log_dir, LogLevel::Info);

        assert!(
            handles.0.is_none(),
            "a log directory that can't be created should self-heal to stdout-only logging, not panic"
        );
    }
}
