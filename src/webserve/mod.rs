mod serve;

use std::path::Path;

use serde::{Deserialize, Serialize};

pub(crate) use serve::router;

fn default_port() -> u16 {
    8080
}

/// `<project root>/webserve.json` — a static-content project's own config,
/// created once by `frogs generate --role web` and never overwritten
/// afterward (same permanence rule as `connections.json` or a hand-edited
/// endpoint stub). Its presence at the project root is what `frogs run`
/// uses to decide a project serves static content rather than an API —
/// see `commands::run`. A frogs project is one role or the other, never
/// both (see `commands::generate`'s `--role` handling).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WebServeConfig {
    #[serde(rename = "startPage")]
    pub start_page: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// A file, relative to the project root, to serve instead of a plain
    /// built-in 404 when a request doesn't resolve to a real file. `None`
    /// (the field omitted) falls back to that generic 404 — see
    /// `webserve::serve::not_found_response`.
    #[serde(rename = "notFoundPage", default, skip_serializing_if = "Option::is_none")]
    pub not_found_page: Option<String>,
}

#[derive(Debug)]
pub enum WebServeLoadError {
    Io(std::io::Error),
    Parse(serde_json::Error),
}

impl std::fmt::Display for WebServeLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebServeLoadError::Io(e) => write!(f, "failed to read webserve.json: {e}"),
            WebServeLoadError::Parse(e) => write!(f, "failed to parse webserve.json: {e}"),
        }
    }
}

impl std::error::Error for WebServeLoadError {}

pub fn load(path: &Path) -> Result<WebServeConfig, WebServeLoadError> {
    let contents = std::fs::read_to_string(path).map_err(WebServeLoadError::Io)?;
    serde_json::from_str(&contents).map_err(WebServeLoadError::Parse)
}

/// `frogs generate --role web`'s writer — called only when `webserve.json`
/// doesn't already exist (see `commands::generate`), so this never
/// overwrites a hand-edited config.
pub fn save_to(path: &Path, config: &WebServeConfig) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(config).expect("WebServeConfig always serializes");
    std::fs::write(path, json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_minimal_config_with_defaults() {
        let json = r#"{ "startPage": "index.html" }"#;
        let config: WebServeConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.start_page, "index.html");
        assert_eq!(config.port, 8080);
        assert_eq!(config.not_found_page, None);
    }

    #[test]
    fn parses_a_full_config() {
        let json = r#"{ "startPage": "index.html", "port": 9090, "notFoundPage": "404.html" }"#;
        let config: WebServeConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.port, 9090);
        assert_eq!(config.not_found_page, Some("404.html".to_string()));
    }

    #[test]
    fn a_missing_not_found_page_is_omitted_from_the_written_file() {
        let config = WebServeConfig { start_page: "index.html".to_string(), port: 8080, not_found_page: None };
        let json = serde_json::to_string(&config).unwrap();
        assert!(!json.contains("notFoundPage"));
    }

    #[test]
    fn round_trips_through_save_to() {
        let config = WebServeConfig {
            start_page: "index.html".to_string(),
            port: 8081,
            not_found_page: Some("404.html".to_string()),
        };
        let dir = std::env::temp_dir().join(format!(
            "frogs-webserve-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("webserve.json");

        save_to(&path, &config).unwrap();
        let reloaded = load(&path).expect("freshly written file should parse cleanly");
        assert_eq!(reloaded, config);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn malformed_json_is_a_clear_parse_error() {
        let dir = std::env::temp_dir().join(format!(
            "frogs-webserve-test-malformed-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("webserve.json");
        std::fs::write(&path, "{ not valid json").unwrap();

        let err = load(&path).expect_err("malformed JSON must fail to load");
        assert!(matches!(err, WebServeLoadError::Parse(_)));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_file_is_a_clear_io_error() {
        let path = std::env::temp_dir().join("frogs-webserve-definitely-does-not-exist.json");
        let err = load(&path).expect_err("a missing file must fail to load");
        assert!(matches!(err, WebServeLoadError::Io(_)));
    }
}
