mod cache;
mod schemes;
mod valid_if;
mod verifier;
mod verify;

pub use cache::VerifierCache;
pub use schemes::SchemeConfig;
pub use valid_if::{ValidIf, ValidIfParseError};
pub use verifier::VerifierDef;
pub use verify::verify;

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum SecurityLoadError {
    Io { file: PathBuf, source: std::io::Error },
    Parse { file: PathBuf, source: serde_json::Error },
    /// A scheme in `schemes.json` names a verifier file that isn't in
    /// `security/verifiers/` — caught at startup rather than left to fail
    /// the first time a protected endpoint is actually hit.
    MissingVerifierFile { scheme: String, file: PathBuf },
    /// A verifier file parses fine as JSON but its `validIf` string doesn't
    /// match the `<source>.<field> = <value>` grammar — also caught at
    /// startup, same reasoning as `MissingVerifierFile`.
    InvalidValidIf { scheme: String, file: PathBuf, source: ValidIfParseError },
}

impl fmt::Display for SecurityLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityLoadError::Io { file, source } => write!(f, "failed to read {}: {source}", file.display()),
            SecurityLoadError::Parse { file, source } => write!(f, "failed to parse {}: {source}", file.display()),
            SecurityLoadError::MissingVerifierFile { scheme, file } => write!(
                f,
                "security scheme '{scheme}' names verifier file {} which doesn't exist",
                file.display()
            ),
            SecurityLoadError::InvalidValidIf { scheme, file, source } => write!(
                f,
                "verifier {} (scheme '{scheme}') has an invalid validIf: {source}",
                file.display()
            ),
        }
    }
}

impl std::error::Error for SecurityLoadError {}

/// A verifier file, fully loaded: its raw `sql`/`http` definition plus its
/// `validIf` expression already parsed once at startup rather than on every
/// request that hits a protected endpoint.
#[derive(Debug)]
pub struct LoadedVerifier {
    pub def: VerifierDef,
    pub valid_if: ValidIf,
}

/// Everything under `<project root>/security/`: which OpenAPI security
/// schemes exist, and the (fully parsed) verifier each one runs. Both
/// `schemes.json` and the whole `security/` directory are optional — a
/// project with no security configured at all has no protected endpoints,
/// which is a valid (if unusual) starting point, the same posture already
/// established for `config/connections.json`.
#[derive(Debug, Default)]
pub struct SecurityConfig {
    pub schemes: HashMap<String, SchemeConfig>,
    /// Keyed by scheme name (not by verifier filename) — request handling
    /// looks a verifier up from the scheme name an endpoint's `security`
    /// field names, never from a file path.
    pub verifiers: HashMap<String, LoadedVerifier>,
}

impl SecurityConfig {
    /// Loads `schemes.json` and, for every scheme it declares, the verifier
    /// file it names (parsing its `validIf` too) — failing closed (a
    /// startup error, not a silently unprotected endpoint) if a scheme
    /// points at a verifier file that doesn't exist, doesn't parse, or has
    /// a malformed `validIf`.
    pub fn load(security_dir: &Path) -> Result<Self, SecurityLoadError> {
        let schemes_path = security_dir.join("schemes.json");
        let schemes: HashMap<String, SchemeConfig> = match fs::read_to_string(&schemes_path) {
            Ok(contents) => serde_json::from_str(&contents)
                .map_err(|source| SecurityLoadError::Parse { file: schemes_path.clone(), source })?,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(source) => return Err(SecurityLoadError::Io { file: schemes_path, source }),
        };

        let verifiers_dir = security_dir.join("verifiers");
        let mut verifiers = HashMap::new();
        for (scheme_name, scheme) in &schemes {
            let verifier_path = verifiers_dir.join(&scheme.verifier);
            let contents = match fs::read_to_string(&verifier_path) {
                Ok(contents) => contents,
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                    return Err(SecurityLoadError::MissingVerifierFile {
                        scheme: scheme_name.clone(),
                        file: verifier_path,
                    });
                }
                Err(source) => return Err(SecurityLoadError::Io { file: verifier_path, source }),
            };
            let def: VerifierDef = serde_json::from_str(&contents)
                .map_err(|source| SecurityLoadError::Parse { file: verifier_path.clone(), source })?;
            let valid_if = ValidIf::parse(def.valid_if()).map_err(|source| SecurityLoadError::InvalidValidIf {
                scheme: scheme_name.clone(),
                file: verifier_path.clone(),
                source,
            })?;
            verifiers.insert(scheme_name.clone(), LoadedVerifier { def, valid_if });
        }

        Ok(SecurityConfig { schemes, verifiers })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn loads_a_scheme_and_its_sql_verifier() {
        let dir = tempdir();
        write_file(dir.path(), "schemes.json", r#"{ "apiKeyAuth": { "verifier": "apiKeyVerifier.json" } }"#);
        fs::create_dir_all(dir.path().join("verifiers")).unwrap();
        write_file(
            &dir.path().join("verifiers"),
            "apiKeyVerifier.json",
            r#"{
                "type": "sql",
                "connection": "vehicles_db",
                "script": "verify_api_key.sql",
                "parameters": [{ "name": "key", "from": "header.X-Api-Key" }],
                "validIf": "row.active = true",
                "cacheTtlSeconds": 30
            }"#,
        );

        let config = SecurityConfig::load(dir.path()).expect("fixture should load cleanly");

        assert_eq!(config.schemes.len(), 1);
        assert_eq!(config.schemes["apiKeyAuth"].verifier, "apiKeyVerifier.json");

        let verifier = &config.verifiers["apiKeyAuth"];
        assert_eq!(verifier.def.valid_if(), "row.active = true");
        assert_eq!(verifier.def.cache_ttl_seconds(), Some(30));
        assert!(matches!(&verifier.def, VerifierDef::Sql { connection, .. } if connection == "vehicles_db"));
        assert!(verifier.valid_if.evaluate(&serde_json::json!({ "active": true })));
        assert!(!verifier.valid_if.evaluate(&serde_json::json!({ "active": false })));
    }

    #[test]
    fn missing_security_directory_yields_an_empty_config_not_an_error() {
        let dir = tempdir();
        let missing = dir.path().join("does-not-exist");
        let config = SecurityConfig::load(&missing).expect("missing dir should not fail load");
        assert!(config.schemes.is_empty());
        assert!(config.verifiers.is_empty());
    }

    #[test]
    fn malformed_schemes_json_is_a_clear_parse_error() {
        let dir = tempdir();
        write_file(dir.path(), "schemes.json", "{ not valid json");
        let err = SecurityConfig::load(dir.path()).expect_err("malformed schemes.json must fail to load");
        assert!(matches!(err, SecurityLoadError::Parse { .. }));
    }

    #[test]
    fn a_scheme_naming_a_verifier_file_that_does_not_exist_fails_closed() {
        let dir = tempdir();
        write_file(
            dir.path(),
            "schemes.json",
            r#"{ "apiKeyAuth": { "verifier": "apiKeyVerifier.json" } }"#,
        );
        let err = SecurityConfig::load(dir.path()).expect_err("a missing verifier file must fail startup");
        match err {
            SecurityLoadError::MissingVerifierFile { scheme, file } => {
                assert_eq!(scheme, "apiKeyAuth");
                assert!(file.ends_with("verifiers/apiKeyVerifier.json"));
            }
            other => panic!("expected MissingVerifierFile, got {other:?}"),
        }
    }

    #[test]
    fn a_verifier_with_an_unparseable_valid_if_fails_closed_at_startup() {
        let dir = tempdir();
        write_file(
            dir.path(),
            "schemes.json",
            r#"{ "apiKeyAuth": { "verifier": "apiKeyVerifier.json" } }"#,
        );
        fs::create_dir_all(dir.path().join("verifiers")).unwrap();
        write_file(
            &dir.path().join("verifiers"),
            "apiKeyVerifier.json",
            r#"{ "type": "sql", "connection": "db", "script": "q.sql", "validIf": "not a valid expression" }"#,
        );

        let err = SecurityConfig::load(dir.path()).expect_err("an unparseable validIf must fail startup");
        match err {
            SecurityLoadError::InvalidValidIf { scheme, .. } => assert_eq!(scheme, "apiKeyAuth"),
            other => panic!("expected InvalidValidIf, got {other:?}"),
        }
    }

    #[test]
    fn malformed_verifier_json_is_a_clear_parse_error() {
        let dir = tempdir();
        write_file(
            dir.path(),
            "schemes.json",
            r#"{ "apiKeyAuth": { "verifier": "apiKeyVerifier.json" } }"#,
        );
        fs::create_dir_all(dir.path().join("verifiers")).unwrap();
        write_file(&dir.path().join("verifiers"), "apiKeyVerifier.json", "{ not valid json");

        let err = SecurityConfig::load(dir.path()).expect_err("malformed verifier JSON must fail to load");
        assert!(matches!(err, SecurityLoadError::Parse { .. }));
    }

    fn write_file(dir: &Path, name: &str, contents: &str) {
        let mut f = fs::File::create(dir.join(name)).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
    }

    fn tempdir() -> TempDir {
        let path = std::env::temp_dir().join(format!(
            "frogs-security-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
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
