use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}

fn default_warn_threshold() -> u32 {
    20
}

fn default_port() -> u16 {
    8080
}

fn default_requests_per_second() -> u32 {
    20
}

fn default_burst() -> u32 {
    40
}

/// Token-bucket parameters for `features.rateLimiting` — a single shared
/// bucket for the whole process (not one per client), a deliberate scope
/// choice: fair per-client throttling needs real client-IP plumbing (harder
/// to get right behind a reverse proxy without also handling
/// `X-Forwarded-For`) that nothing in this server does yet, while a global
/// cap is still a legitimate backend-protection safety valve on its own.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitConfig {
    #[serde(default = "default_requests_per_second")]
    pub requests_per_second: u32,
    #[serde(default = "default_burst")]
    pub burst: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        RateLimitConfig {
            requests_per_second: default_requests_per_second(),
            burst: default_burst(),
        }
    }
}

/// `config/server.json`'s `cors` block — only actually consulted when
/// `features.cors` is on, same "the file can hold settings for a feature
/// that's currently off" posture `rateLimit` already has. An empty
/// `allowedOrigins` (the default) means the feature can be turned on without
/// opening anything up by accident — `frogs run` logs a warning in that case
/// rather than silently serving with no CORS headers at all. A literal `"*"`
/// entry means "any origin", handled distinctly from an explicit list (see
/// `server::apply_cors`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CorsConfig {
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

/// TLS mode for `frogs run`'s listener — `off` (default, unchanged plain
/// HTTP) or `manual` (a user-supplied cert+key PEM pair). `acme` (automatic
/// Let's Encrypt provisioning, per `docs/frogs-https-development.md`) is a
/// deliberate follow-up, not built yet — `"mode": "acme"` fails to parse
/// with a clear error rather than silently falling back to plain HTTP,
/// since quietly serving plaintext instead of whatever TLS mode was
/// actually configured would be exactly the wrong failure mode here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    #[default]
    Off,
    Manual,
}

/// A user-supplied certificate + private key PEM pair — the "boring,
/// expected option, for anyone already managing certs another way" per
/// `docs/frogs-https-development.md`. Paths are relative to the project
/// root, same convention `connections.json`'s SQLite `database` field
/// already uses.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManualTlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

/// `config/server.json`'s `tls` block (also reused by `webserve.json` for a
/// purely static-content project — see `webserve::WebServeConfig::tls` —
/// since either config surface can be the one and only listener a project
/// actually serves). `manual` is only actually read when `mode` is
/// `Manual` — same "the file can hold settings for a mode that isn't
/// active" posture `rateLimit`/`services.json` already have.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsConfig {
    #[serde(default)]
    pub mode: TlsMode,
    #[serde(default)]
    pub manual: Option<ManualTlsConfig>,
}

/// Visibility for the docs UI console (`/docs`) — modeled as its own mode
/// enum, the same shape as `TlsMode`, rather than a `features.docsUi` bool
/// plus a separate visibility setting, since "off" is already one of the
/// modes: `off` (default — the routes aren't even registered, not just
/// hidden behind a check, same posture `readyz`/`metrics` have when their
/// own feature is off), `localhost` (registered, but gated to the real TCP
/// peer being loopback — see `server::docs_ui_localhost_gate`'s doc comment
/// for what that does and doesn't cover), or `public` (no gating at all).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DocsUiMode {
    #[default]
    Off,
    Localhost,
    Public,
}

fn default_docs_ui_path() -> String {
    "docs".to_string()
}

/// `config/server.json`'s `docsUi` block — a wrapper struct (matching
/// `CorsConfig`/`TlsConfig`'s shape even though they started single-field
/// too) rather than putting `DocsUiMode` directly on `ServerConfig`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DocsUiConfig {
    #[serde(default)]
    pub mode: DocsUiMode,
    /// The path segment `/docs` mounts under — `"docs"` by default (and
    /// when the field is absent entirely), but a project can rename it
    /// (e.g. `"internal-docs"`) for its own reasons. Stored raw, exactly as
    /// written in the file — leading/trailing slashes and blank values are
    /// tolerated the same lenient way `apiRoot` is, but only normalized at
    /// mount time (`server::normalize_docs_ui_path`), not here, matching
    /// `apiRoot`'s own "store raw, normalize at the point of use" split.
    #[serde(default = "default_docs_ui_path")]
    pub path: String,
}

impl Default for DocsUiConfig {
    fn default() -> Self {
        DocsUiConfig {
            mode: DocsUiMode::default(),
            path: default_docs_ui_path(),
        }
    }
}

/// Independently toggleable capabilities — none of them imply a deployment
/// "mode"; a monolith and a split-out microservice both just pick whichever
/// of these they need. `metrics`/`readyzCheck`/`requestCorrelation` and
/// `requestValidation` are on by default because they cost nothing and help
/// every shape; `rateLimiting`/`serviceRegistry`/`cors` are opt-in — `cors`
/// specifically because it's a real cross-origin access decision an operator
/// should make deliberately, not something that should start working the
/// moment a project is generated.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Features {
    #[serde(default = "default_true")]
    pub metrics: bool,
    #[serde(default = "default_true")]
    pub readyz_check: bool,
    #[serde(default = "default_true")]
    pub request_correlation: bool,
    #[serde(default)]
    pub rate_limiting: bool,
    #[serde(default)]
    pub service_registry: bool,
    #[serde(default = "default_true")]
    pub request_validation: bool,
    #[serde(default)]
    pub cors: bool,
}

impl Default for Features {
    fn default() -> Self {
        Features {
            metrics: true,
            readyz_check: true,
            request_correlation: true,
            rate_limiting: false,
            service_registry: false,
            request_validation: true,
            cors: false,
        }
    }
}

/// `config/server.json` — global settings. Every field is optional in the
/// file itself; a project with no `server.json` at all gets
/// `ServerConfig::default()`. `generate` now writes this file out with its
/// defaults on first run (see `commands::generate::generate_api`), so in
/// practice a project always has one — the in-file optionality just means a
/// hand-deleted or hand-trimmed `server.json` still loads fine.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerConfig {
    #[serde(default)]
    pub debug_mode: bool,
    #[serde(default)]
    pub features: Features,
    #[serde(default = "default_true")]
    pub auto_migrate_endpoints: bool,
    #[serde(default = "default_warn_threshold")]
    pub discovered_errors_warn_threshold: u32,
    /// Only actually consulted when `features.rateLimiting` is on — same
    /// "the file can hold settings for a feature that's currently off"
    /// posture the rest of `server.json` already has.
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    /// Only actually consulted when `features.cors` is on — see
    /// `CorsConfig`'s own doc comment.
    #[serde(default)]
    pub cors: CorsConfig,
    /// `off` by default — see `DocsUiMode`'s own doc comment.
    #[serde(default)]
    pub docs_ui: DocsUiConfig,
    /// Off by default — see `TlsMode`'s doc comment. When `manual`, `frogs
    /// run` serves HTTPS via `axum-server`'s rustls acceptor instead of
    /// plain HTTP, using this same field's `manual.certPath`/`keyPath`.
    #[serde(default)]
    pub tls: TlsConfig,
    /// Not part of the original design doc (which never pins down a port) —
    /// a sensible default so `frogs run` has somewhere to bind.
    #[serde(default = "default_port")]
    pub port: u16,
    /// The URL prefix the API is mounted under, via `Router::nest` —
    /// empty by default (today's unprefixed behavior), regardless of
    /// whether this project also serves static content. Unlike
    /// `project::api_base`'s `api/` folder (a fixed, unconfigurable name),
    /// this is a real user-editable setting: a both-role project only gets
    /// URL-level separation from its static content if this is set.
    #[serde(default)]
    pub api_root: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            debug_mode: false,
            features: Features::default(),
            auto_migrate_endpoints: true,
            discovered_errors_warn_threshold: 20,
            rate_limit: RateLimitConfig::default(),
            cors: CorsConfig::default(),
            docs_ui: DocsUiConfig::default(),
            tls: TlsConfig::default(),
            port: 8080,
            api_root: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_root_defaults_to_empty_when_absent_from_the_file() {
        let config: ServerConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(config.api_root, "");
    }

    #[test]
    fn api_root_is_read_as_camel_case() {
        let config: ServerConfig = serde_json::from_str(r#"{ "apiRoot": "/api" }"#).unwrap();
        assert_eq!(config.api_root, "/api");
    }

    #[test]
    fn default_config_serializes_with_a_visible_empty_api_root() {
        let json = serde_json::to_string(&ServerConfig::default()).unwrap();
        assert!(json.contains(r#""apiRoot":"""#), "apiRoot should be written out, not hidden, even when empty: {json}");
    }

    #[test]
    fn rate_limit_defaults_when_absent_from_the_file() {
        let config: ServerConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(config.rate_limit.requests_per_second, 20);
        assert_eq!(config.rate_limit.burst, 40);
    }

    #[test]
    fn rate_limit_is_read_as_camel_case() {
        let config: ServerConfig = serde_json::from_str(r#"{ "rateLimit": { "requestsPerSecond": 5, "burst": 15 } }"#).unwrap();
        assert_eq!(config.rate_limit.requests_per_second, 5);
        assert_eq!(config.rate_limit.burst, 15);
    }

    #[test]
    fn cors_defaults_to_off_with_no_allowed_origins_when_absent_from_the_file() {
        let config: ServerConfig = serde_json::from_str("{}").unwrap();
        assert!(!config.features.cors);
        assert!(config.cors.allowed_origins.is_empty());
    }

    #[test]
    fn cors_is_read_as_camel_case() {
        let config: ServerConfig = serde_json::from_str(r#"{ "features": { "cors": true }, "cors": { "allowedOrigins": ["https://example.com"] } }"#).unwrap();
        assert!(config.features.cors);
        assert_eq!(config.cors.allowed_origins, vec!["https://example.com".to_string()]);
    }

    #[test]
    fn docs_ui_defaults_to_off_when_absent_from_the_file() {
        let config: ServerConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(config.docs_ui.mode, DocsUiMode::Off);
    }

    #[test]
    fn docs_ui_mode_is_read_as_camel_case() {
        let config: ServerConfig = serde_json::from_str(r#"{ "docsUi": { "mode": "localhost" } }"#).unwrap();
        assert_eq!(config.docs_ui.mode, DocsUiMode::Localhost);
    }

    #[test]
    fn docs_ui_mode_public_parses() {
        let config: ServerConfig = serde_json::from_str(r#"{ "docsUi": { "mode": "public" } }"#).unwrap();
        assert_eq!(config.docs_ui.mode, DocsUiMode::Public);
    }

    #[test]
    fn docs_ui_mode_rejects_an_unknown_value_rather_than_falling_back_to_off() {
        let err = serde_json::from_str::<ServerConfig>(r#"{ "docsUi": { "mode": "everyone" } }"#)
            .expect_err("an unrecognized docsUi.mode must fail to parse, not silently disable the feature");
        assert!(err.to_string().to_lowercase().contains("unknown variant"));
    }

    #[test]
    fn docs_ui_path_defaults_to_docs_when_absent_from_the_file() {
        let config: ServerConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(config.docs_ui.path, "docs");
    }

    #[test]
    fn docs_ui_path_is_read_as_written_with_no_normalization_at_parse_time() {
        let config: ServerConfig = serde_json::from_str(r#"{ "docsUi": { "path": "/internal-docs/" } }"#).unwrap();
        assert_eq!(config.docs_ui.path, "/internal-docs/", "normalization happens at mount time, not here");
    }

    #[test]
    fn tls_defaults_to_off_with_no_manual_config_when_absent_from_the_file() {
        let config: ServerConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(config.tls.mode, TlsMode::Off);
        assert!(config.tls.manual.is_none());
    }

    #[test]
    fn tls_manual_mode_is_read_as_camel_case() {
        let config: ServerConfig =
            serde_json::from_str(r#"{ "tls": { "mode": "manual", "manual": { "certPath": "tls/cert.pem", "keyPath": "tls/key.pem" } } }"#).unwrap();
        assert_eq!(config.tls.mode, TlsMode::Manual);
        let manual = config.tls.manual.expect("manual config should be present");
        assert_eq!(manual.cert_path, "tls/cert.pem");
        assert_eq!(manual.key_path, "tls/key.pem");
    }

    #[test]
    fn tls_mode_acme_is_not_yet_a_recognized_value() {
        // Deliberate: `acme` isn't built yet (see `TlsMode`'s doc comment) —
        // this must fail to parse, not silently fall back to `off`.
        let err = serde_json::from_str::<ServerConfig>(r#"{ "tls": { "mode": "acme" } }"#)
            .expect_err("an unimplemented TLS mode must fail to parse, not silently serve plain HTTP");
        assert!(err.to_string().contains("acme") || err.to_string().to_lowercase().contains("unknown variant"));
    }

    #[test]
    fn round_trips_through_serialize_and_deserialize() {
        let config = ServerConfig {
            api_root: "/api".to_string(),
            port: 9090,
            ..ServerConfig::default()
        };

        let json = serde_json::to_string(&config).unwrap();
        let reloaded: ServerConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(reloaded.api_root, "/api");
        assert_eq!(reloaded.port, 9090);
    }
}
