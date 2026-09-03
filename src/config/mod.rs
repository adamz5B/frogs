mod connections;
mod server;

pub use connections::ConnectionConfig;
pub use server::{ManualTlsConfig, ServerConfig, TlsConfig, TlsMode};

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;

use crate::errors::{DiscoveredErrors, ErrorRegistry, LoadError as ErrorsLoadError};
use crate::security::{SecurityConfig, SecurityLoadError};

#[derive(Debug)]
pub enum ConfigLoadError {
    Io { file: PathBuf, source: std::io::Error },
    Parse { file: PathBuf, source: serde_json::Error },
    Errors(ErrorsLoadError),
    Security(SecurityLoadError),
}

impl fmt::Display for ConfigLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigLoadError::Io { file, source } => {
                write!(f, "failed to read {}: {source}", file.display())
            }
            ConfigLoadError::Parse { file, source } => {
                write!(f, "failed to parse {}: {source}", file.display())
            }
            ConfigLoadError::Errors(source) => write!(f, "{source}"),
            ConfigLoadError::Security(source) => write!(f, "{source}"),
        }
    }
}

impl std::error::Error for ConfigLoadError {}

/// Reads and parses a JSON file, or `None` if it simply doesn't exist yet —
/// every file under `config/` is optional, since a project fills them in
/// incrementally rather than needing all of them from the start.
fn load_json_file<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, ConfigLoadError> {
    match fs::read_to_string(path) {
        Ok(contents) => {
            let value = serde_json::from_str(&contents).map_err(|source| ConfigLoadError::Parse {
                file: path.to_path_buf(),
                source,
            })?;
            Ok(Some(value))
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(ConfigLoadError::Io {
            file: path.to_path_buf(),
            source,
        }),
    }
}

/// A fully loaded project configuration: everything under `<project root>/config/`,
/// plus the sibling `<project root>/security/` directory.
#[derive(Debug)]
pub struct Config {
    pub server: ServerConfig,
    pub connections: HashMap<String, ConnectionConfig>,
    pub errors: ErrorRegistry,
    pub discovered_errors: DiscoveredErrors,
    pub security: SecurityConfig,
    /// `config/services.json` — a logical name → base URL lookup an HTTP
    /// source can reference via `{{services.<name>}}` instead of a
    /// hardcoded base URL. Only ever loaded (non-empty) when
    /// `server.features.service_registry` is on — same "the toggle actually
    /// gates behavior, not just documents intent" posture `readyz_check`/
    /// `metrics` already have in `commands::run`.
    pub services: HashMap<String, String>,
}

impl Config {
    /// Loads every config file under `<project_root>/config/`. Missing
    /// individual files (or a missing `config/` directory entirely) fall
    /// back to sensible defaults — the only hard failures are malformed
    /// JSON and conflicting error-registry definitions, both of which are
    /// real configuration mistakes worth failing loudly for.
    pub fn load(project_root: &Path) -> Result<Self, ConfigLoadError> {
        let config_dir = project_root.join("config");

        let server = load_json_file::<ServerConfig>(&config_dir.join("server.json"))?.unwrap_or_default();

        let connections = load_json_file::<HashMap<String, ConnectionConfig>>(&config_dir.join("connections.json"))?.unwrap_or_default();

        let errors = ErrorRegistry::load(&config_dir.join("errors")).map_err(ConfigLoadError::Errors)?;

        let discovered_errors_path = config_dir.join("errors.discovered.json");
        let discovered_errors = DiscoveredErrors::load(&discovered_errors_path).map_err(|source| ConfigLoadError::Io {
            file: discovered_errors_path,
            source,
        })?;

        let security = SecurityConfig::load(&project_root.join("security")).map_err(ConfigLoadError::Security)?;

        // Gated on the feature flag, not just the file's presence — a
        // project that's turned `serviceRegistry` off gets an empty map
        // (every `{{services.*}}` reference resolves to an empty string,
        // same as any other unresolvable template placeholder) even if a
        // `services.json` happens to still be sitting on disk from before
        // the toggle was flipped off.
        let services = if server.features.service_registry {
            load_json_file::<HashMap<String, String>>(&config_dir.join("services.json"))?.unwrap_or_default()
        } else {
            HashMap::new()
        };

        Ok(Config {
            server,
            connections,
            errors,
            discovered_errors,
            security,
            services,
        })
    }

    /// Like `load`, but exits the process with a clear message on failure —
    /// the shared failure path for CLI subcommands that need a loaded
    /// config, mirroring `project::require_project_root`.
    pub fn load_or_exit(project_root: &Path) -> Self {
        Self::load(project_root).unwrap_or_else(|err| {
            eprintln!("error: failed to load config for project at {}:\n{err}", project_root.display());
            std::process::exit(1);
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn loads_every_config_file_under_the_project_root() {
        let root = tempdir();
        fs::create_dir_all(root.path().join("config/errors")).unwrap();
        fs::create_dir_all(root.path().join("security/verifiers")).unwrap();

        fs::write(
            root.path().join("config/server.json"),
            r#"{
                "debugMode": false,
                "features": { "metrics": true, "requestValidation": true, "rateLimiting": false }
            }"#,
        )
        .unwrap();
        fs::write(
            root.path().join("config/connections.json"),
            r#"{ "vehicles_db": { "driver": "postgres", "host": "localhost" } }"#,
        )
        .unwrap();
        fs::write(
            root.path().join("config/errors/core.json"),
            r#"{ "auth.invalid_credentials": { "httpStatus": 401, "exposeDetail": true } }"#,
        )
        .unwrap();
        fs::write(
            root.path().join("security/schemes.json"),
            r#"{ "apiKeyAuth": { "verifier": "apiKeyVerifier.json" } }"#,
        )
        .unwrap();
        fs::write(
            root.path().join("security/verifiers/apiKeyVerifier.json"),
            r#"{ "type": "sql", "connection": "vehicles_db", "script": "verify_api_key.sql", "validIf": "row.active = true" }"#,
        )
        .unwrap();

        let config = Config::load(root.path()).expect("fixture should load cleanly");

        assert!(!config.server.debug_mode);
        assert!(config.server.features.metrics);
        assert!(config.server.features.request_validation);
        assert!(!config.server.features.rate_limiting);

        let vehicles_db = config.connections.get("vehicles_db").expect("connections.json should define vehicles_db");
        assert_eq!(vehicles_db.driver, "postgres");

        assert!(config.errors.get("auth.invalid_credentials").is_some());
        assert!(config.discovered_errors.is_empty());

        assert_eq!(config.security.schemes["apiKeyAuth"].verifier, "apiKeyVerifier.json");
        assert!(config.security.verifiers.contains_key("apiKeyAuth"));
    }

    #[test]
    fn missing_config_directory_falls_back_to_defaults() {
        let root = tempdir();
        let config = Config::load(root.path()).expect("a fresh project with no config/ should still load");

        assert!(!config.server.debug_mode);
        assert!(config.server.features.request_correlation);
        assert!(config.connections.is_empty());
        assert!(config.errors.get(crate::errors::UNEXPECTED_ERROR_CODE).is_some());
        assert!(config.services.is_empty());
    }

    #[test]
    fn services_json_loads_when_the_service_registry_feature_is_on() {
        let root = tempdir();
        fs::create_dir_all(root.path().join("config")).unwrap();
        fs::write(root.path().join("config/server.json"), r#"{ "features": { "serviceRegistry": true } }"#).unwrap();
        fs::write(root.path().join("config/services.json"), r#"{ "pricing": "https://pricing.example.com" }"#).unwrap();

        let config = Config::load(root.path()).expect("fixture should load cleanly");
        assert_eq!(config.services.get("pricing"), Some(&"https://pricing.example.com".to_string()));
    }

    #[test]
    fn services_json_is_ignored_when_the_service_registry_feature_is_off() {
        // Off by default, and explicitly off here — a `services.json` still
        // sitting on disk (e.g. left over from testing with the feature on)
        // must not leak in once the toggle is flipped back off.
        let root = tempdir();
        fs::create_dir_all(root.path().join("config")).unwrap();
        fs::write(root.path().join("config/server.json"), r#"{ "features": { "serviceRegistry": false } }"#).unwrap();
        fs::write(root.path().join("config/services.json"), r#"{ "pricing": "https://pricing.example.com" }"#).unwrap();

        let config = Config::load(root.path()).expect("fixture should load cleanly");
        assert!(config.services.is_empty());
    }

    #[test]
    fn malformed_server_json_is_a_clear_error() {
        let root = tempdir();
        fs::create_dir_all(root.path().join("config")).unwrap();
        let mut f = fs::File::create(root.path().join("config/server.json")).unwrap();
        f.write_all(b"{ not valid json").unwrap();

        let err = Config::load(root.path()).expect_err("malformed server.json must fail to load");
        match err {
            ConfigLoadError::Parse { file, .. } => {
                assert!(file.ends_with("server.json"));
            }
            other => panic!("expected Parse error, got {other:?}"),
        }
    }

    #[test]
    fn conflicting_error_codes_surface_through_config_load() {
        let root = tempdir();
        let errors_dir = root.path().join("config/errors");
        fs::create_dir_all(&errors_dir).unwrap();
        fs::write(
            errors_dir.join("a.json"),
            r#"{ "auth.invalid_credentials": { "httpStatus": 401, "exposeDetail": true } }"#,
        )
        .unwrap();
        fs::write(
            errors_dir.join("b.json"),
            r#"{ "auth.invalid_credentials": { "httpStatus": 403, "exposeDetail": true } }"#,
        )
        .unwrap();

        let err = Config::load(root.path()).expect_err("conflicting error codes must fail to load");
        assert!(matches!(err, ConfigLoadError::Errors(ErrorsLoadError::Conflicts(_))));
    }

    /// `security::SecurityConfig::load`'s own failure modes are covered in
    /// its own unit tests — this proves the failure actually propagates
    /// through `Config::load`, the real entry point `frogs run` uses, and
    /// not just the lower-level function in isolation. This is the
    /// fail-closed property the whole security module depends on: a broken
    /// `security/` directory must prevent the server from starting at all,
    /// never fall back to serving with security silently unconfigured.
    #[test]
    fn a_broken_security_directory_fails_the_whole_config_load() {
        let root = tempdir();
        let security_dir = root.path().join("security");
        fs::create_dir_all(&security_dir).unwrap();
        // A scheme naming a verifier file that was never written — same
        // shape as `security::mod`'s own `a_scheme_naming_a_verifier_file_
        // that_does_not_exist_fails_closed` test, but exercised here through
        // the full config-loading entry point.
        fs::write(security_dir.join("schemes.json"), r#"{ "apiKeyAuth": { "verifier": "apiKeyVerifier.json" } }"#).unwrap();

        let err = Config::load(root.path()).expect_err("a broken security/ directory must fail the whole config load");
        assert!(matches!(err, ConfigLoadError::Security(_)));
    }

    fn tempdir() -> TempDir {
        // A per-process atomic counter alongside PID+nanosecond timestamp —
        // the timestamp alone has occasionally collided under heavy parallel
        // `cargo test` load on Windows (coarser effective clock resolution
        // than raw nanoseconds suggest); see the same fix in
        // `commands::generate`'s own test helper.
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "frogs-config-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        TempDir { path }
    }

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
