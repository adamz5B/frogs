use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The reserved catch-all code for any error that doesn't match a known
/// classification. Always present in a loaded registry, even if the
/// project's own `config/errors/*.json` never defines it.
pub const UNEXPECTED_ERROR_CODE: &str = "unexpected.error";

fn default_unexpected_error() -> ErrorDefinition {
    ErrorDefinition {
        http_status: 500,
        expose_detail: false,
        include_exception_name: false,
    }
}

/// One entry in the error registry: what HTTP status a code maps to, and
/// whether its detail is safe to show a caller.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorDefinition {
    #[serde(rename = "httpStatus")]
    pub http_status: u16,
    #[serde(rename = "exposeDetail")]
    pub expose_detail: bool,
    // `skip_serializing_if` so `errors freeze` (the only writer of these,
    // currently) doesn't clutter a frozen file with `"includeExceptionName": false`
    // on every entry — the field is still readable/settable by hand either way.
    #[serde(rename = "includeExceptionName", default, skip_serializing_if = "is_false")]
    pub include_exception_name: bool,
}

fn is_false(b: &bool) -> bool {
    !b
}

/// Two files in `config/errors/` define the same code with different
/// values — an ambiguity the registry refuses to resolve silently.
#[derive(Debug)]
pub struct ConflictingCode {
    pub code: String,
    pub first_file: PathBuf,
    pub second_file: PathBuf,
}

#[derive(Debug)]
pub enum LoadError {
    Io { file: PathBuf, source: std::io::Error },
    Parse { file: PathBuf, source: serde_json::Error },
    Conflicts(Vec<ConflictingCode>),
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::Io { file, source } => {
                write!(f, "failed to read {}: {source}", file.display())
            }
            LoadError::Parse { file, source } => {
                write!(f, "failed to parse {}: {source}", file.display())
            }
            LoadError::Conflicts(conflicts) => {
                writeln!(f, "conflicting error code definitions:")?;
                for c in conflicts {
                    writeln!(
                        f,
                        "  '{}' is defined differently in {} and {}",
                        c.code,
                        c.first_file.display(),
                        c.second_file.display()
                    )?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for LoadError {}

/// The merged, code → definition error registry, loaded once at startup
/// from every `*.json` file in `config/errors/`.
#[derive(Debug)]
pub struct ErrorRegistry {
    codes: HashMap<String, ErrorDefinition>,
}

impl ErrorRegistry {
    /// Loads every `*.json` file directly inside `errors_dir` and merges
    /// them into one code → definition map, matching the directory-loaded
    /// (not single-file) registry design. An identical duplicate definition
    /// across two files is allowed; a differing one is a startup error
    /// covering every conflict found, not just the first.
    pub fn load(errors_dir: &Path) -> Result<Self, LoadError> {
        // A brand-new project has no config/errors/ yet — that's an empty
        // registry (just the synthesized unexpected.error below), not a
        // startup failure.
        let mut files: Vec<PathBuf> = match fs::read_dir(errors_dir) {
            Ok(read_dir) => read_dir
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
                .collect(),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(source) => {
                return Err(LoadError::Io {
                    file: errors_dir.to_path_buf(),
                    source,
                });
            }
        };
        // Deterministic merge order so conflict messages are stable across
        // runs, regardless of what order the OS happens to list files in.
        files.sort();

        let mut codes: HashMap<String, ErrorDefinition> = HashMap::new();
        let mut origin: HashMap<String, PathBuf> = HashMap::new();
        let mut conflicts = Vec::new();

        for file in files {
            let contents = fs::read_to_string(&file).map_err(|source| LoadError::Io {
                file: file.clone(),
                source,
            })?;
            let defs: HashMap<String, ErrorDefinition> = serde_json::from_str(&contents)
                .map_err(|source| LoadError::Parse {
                    file: file.clone(),
                    source,
                })?;

            for (code, def) in defs {
                match codes.get(&code) {
                    None => {
                        codes.insert(code.clone(), def);
                        origin.insert(code, file.clone());
                    }
                    Some(existing) if *existing == def => {
                        eprintln!(
                            "warning: '{code}' is defined identically in both {} and {} — harmless, but worth deduplicating",
                            origin[&code].display(),
                            file.display()
                        );
                    }
                    Some(_) => {
                        conflicts.push(ConflictingCode {
                            code: code.clone(),
                            first_file: origin[&code].clone(),
                            second_file: file.clone(),
                        });
                    }
                }
            }
        }

        if !conflicts.is_empty() {
            return Err(LoadError::Conflicts(conflicts));
        }

        codes
            .entry(UNEXPECTED_ERROR_CODE.to_string())
            .or_insert_with(default_unexpected_error);

        Ok(ErrorRegistry { codes })
    }

    /// The canonical definition for `code`, or `None` if it isn't in the
    /// merged registry — distinct from `lookup`, which always resolves to
    /// something (falling back to `unexpected.error`).
    pub fn get(&self, code: &str) -> Option<&ErrorDefinition> {
        self.codes.get(code)
    }

    /// The definition for `code`, falling back to `unexpected.error` if
    /// unclassified. `unexpected.error` is always present after `load`, so
    /// this never panics.
    pub fn lookup(&self, code: &str) -> &ErrorDefinition {
        self.codes
            .get(code)
            .unwrap_or_else(|| &self.codes[UNEXPECTED_ERROR_CODE])
    }

    pub fn len(&self) -> usize {
        self.codes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_json(dir: &Path, name: &str, contents: &str) {
        let mut f = fs::File::create(dir.join(name)).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
    }

    #[test]
    fn loads_a_directory_of_error_definitions() {
        let dir = tempdir();
        write_json(
            dir.path(),
            "core.json",
            r#"{
                "auth.invalid_credentials": { "httpStatus": 401, "exposeDetail": true },
                "validation.missing_parameter": { "httpStatus": 400, "exposeDetail": true }
            }"#,
        );
        let registry = ErrorRegistry::load(dir.path()).expect("fixture should load cleanly");
        assert!(registry.get(UNEXPECTED_ERROR_CODE).is_some());
        assert_eq!(registry.lookup("auth.invalid_credentials").http_status, 401);
    }

    #[test]
    fn missing_directory_yields_an_empty_registry_not_an_error() {
        let dir = tempdir();
        let missing = dir.path().join("does-not-exist");
        let registry = ErrorRegistry::load(&missing).expect("missing dir should not fail load");
        assert_eq!(registry.len(), 1); // just the synthesized unexpected.error
        assert!(registry.get(UNEXPECTED_ERROR_CODE).is_some());
    }

    #[test]
    fn defaults_unexpected_error_when_absent() {
        let dir = tempdir();
        write_json(
            dir.path(),
            "core.json",
            r#"{ "validation.missing_parameter": { "httpStatus": 400, "exposeDetail": true } }"#,
        );
        let registry = ErrorRegistry::load(dir.path()).unwrap();
        let fallback = registry.lookup("something.unclassified");
        assert_eq!(fallback.http_status, 500);
        assert!(!fallback.expose_detail);
    }

    #[test]
    fn identical_duplicate_across_files_is_allowed() {
        let dir = tempdir();
        write_json(
            dir.path(),
            "a.json",
            r#"{ "auth.invalid_credentials": { "httpStatus": 401, "exposeDetail": true } }"#,
        );
        write_json(
            dir.path(),
            "b.json",
            r#"{ "auth.invalid_credentials": { "httpStatus": 401, "exposeDetail": true } }"#,
        );
        let registry = ErrorRegistry::load(dir.path()).expect("identical duplicates are fine");
        assert_eq!(registry.lookup("auth.invalid_credentials").http_status, 401);
    }

    #[test]
    fn differing_duplicate_across_files_is_a_conflict() {
        let dir = tempdir();
        write_json(
            dir.path(),
            "a.json",
            r#"{ "auth.invalid_credentials": { "httpStatus": 401, "exposeDetail": true } }"#,
        );
        write_json(
            dir.path(),
            "b.json",
            r#"{ "auth.invalid_credentials": { "httpStatus": 403, "exposeDetail": true } }"#,
        );
        let err = ErrorRegistry::load(dir.path()).expect_err("differing duplicates must fail");
        match err {
            LoadError::Conflicts(conflicts) => {
                assert_eq!(conflicts.len(), 1);
                assert_eq!(conflicts[0].code, "auth.invalid_credentials");
            }
            other => panic!("expected Conflicts, got {other:?}"),
        }
    }

    // Minimal throwaway temp-dir helper — avoids pulling in a dev-dependency
    // just to create a scratch directory for these tests.
    fn tempdir() -> TempDir {
        let path = std::env::temp_dir().join(format!(
            "frogs-errors-test-{}-{}",
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
