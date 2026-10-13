use std::num::NonZeroU64;

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

/// Deliberately below both `sql::DEFAULT_POOL_ACQUIRE_TIMEOUT_SECS` (30s)
/// and a nested-many source's `rowTimeoutMs` default (30s), so "our own
/// configured call bound elapsed" and "the pool/row bound elapsed" are
/// temporally distinguishable in logs instead of racing at the same value.
fn default_source_call_timeout_ms() -> NonZeroU64 {
    NonZeroU64::new(10_000).expect("10_000 is non-zero")
}

/// Hard ceiling on any resolved source-call timeout — a declared per-source
/// `callTimeoutMs` above this is a validation problem (see
/// `endpoint::validate_source_call_timeout`), while a `server.json`
/// `sourceCallTimeoutMs` above it is clamped by
/// `ServerConfig::effective_source_call_timeout_ms`. Shares
/// `resolve::MAX_NESTED_MANY_ROW_TIMEOUT_MS`'s 5-minute value, independently
/// stated: the two bound different mechanisms.
pub const MAX_SOURCE_CALL_TIMEOUT_MS: u64 = 300_000;

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
    /// mTLS: whether (and how strictly) this listener asks clients for a
    /// certificate. Absent, or `mode: off`, is today's behavior exactly —
    /// and a default config serializes without this key at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_auth: Option<ClientAuthConfig>,
}

/// Whether the TLS listener requests a client certificate. Deliberately has
/// no `Default`/serde default: a `clientAuth` block that omits `mode` fails
/// to parse rather than quietly picking one (an accidental `required` would
/// lock out every cert-less client, an accidental `optional` is a silent
/// security posture change).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientAuthMode {
    Off,
    /// The handshake succeeds with or without a certificate (a presented one
    /// must still fully validate); routes decide.
    Optional,
    /// No valid certificate, no connection.
    Required,
}

/// What to do when a presented certificate's revocation status can't be
/// established from the loaded CRLs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CrlPolicy {
    /// A certificate whose issuer has no loaded CRL, or whose CRL has
    /// expired, is rejected (the default whenever `crlPaths` is non-empty).
    FailClosed,
    /// Accepts a certificate whose issuer has no loaded CRL and doesn't
    /// enforce CRL expiry; a loaded, current CRL still rejects what it lists.
    BestEffort,
}

/// `tls.clientAuth` — see `docs/frogs-mtls.md`. Paths resolve against the
/// same base as `tls.manual`'s `certPath`/`keyPath`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientAuthConfig {
    pub mode: ClientAuthMode,
    /// PEM bundle of the CA(s) allowed to issue client certificates. Never
    /// merged with the OS trust store — client CAs are a private PKI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_path: Option<String>,
    /// Static CRL files (PEM with one or more `X509 CRL` blocks, or a single
    /// DER CRL). Empty means revocation is not checked at all.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub crl_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crl_policy: Option<CrlPolicy>,
    /// Defaults to `true`: the leaf certificate must carry an extended key
    /// usage extension listing `clientAuth`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_client_auth_eku: Option<bool>,
}

impl ClientAuthConfig {
    pub fn effective_crl_policy(&self) -> CrlPolicy {
        self.crl_policy.unwrap_or(CrlPolicy::FailClosed)
    }

    pub fn effective_require_client_auth_eku(&self) -> bool {
        self.require_client_auth_eku.unwrap_or(true)
    }
}

impl TlsConfig {
    /// Whether this listener will request client certificates (so request
    /// handlers can ever see a `ClientCertIdentity`).
    pub fn client_identity_enabled(&self) -> bool {
        self.mode == TlsMode::Manual && self.client_auth.as_ref().is_some_and(|c| c.mode != ClientAuthMode::Off)
    }

    /// The I/O-free half of `clientAuth` validation, shared by `serve` and
    /// `frogs validate`: contradictory or incomplete combinations fail here
    /// by naming the offending field.
    pub fn validate_structure(&self) -> Result<(), String> {
        let Some(client_auth) = &self.client_auth else { return Ok(()) };
        if client_auth.mode == ClientAuthMode::Off {
            let stray = [
                ("caPath", client_auth.ca_path.is_some()),
                ("crlPaths", !client_auth.crl_paths.is_empty()),
                ("crlPolicy", client_auth.crl_policy.is_some()),
                ("requireClientAuthEku", client_auth.require_client_auth_eku.is_some()),
            ];
            if let Some((field, _)) = stray.iter().find(|(_, set)| *set) {
                return Err(format!(
                    "tls.clientAuth.{field} is set but tls.clientAuth.mode is \"off\" — remove it or enable clientAuth"
                ));
            }
            return Ok(());
        }
        if self.mode != TlsMode::Manual {
            return Err("tls.clientAuth is enabled but tls.mode is not \"manual\" — client certificates only make sense over TLS".to_string());
        }
        if client_auth.ca_path.as_deref().is_none_or(|p| p.trim().is_empty()) {
            return Err("tls.clientAuth.caPath is required when tls.clientAuth.mode is not \"off\"".to_string());
        }
        if client_auth.crl_policy.is_some() && client_auth.crl_paths.is_empty() {
            return Err("tls.clientAuth.crlPolicy is set but tls.clientAuth.crlPaths is empty — a policy only applies to loaded CRLs".to_string());
        }
        Ok(())
    }
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

/// Verbosity for `frogs run`'s persistent file logging (see
/// `server::logging`) — also governs the stdout layer for that same run,
/// since both share one `EnvFilter`. `RUST_LOG` still overrides this when
/// set, same precedence the old hardcoded bootstrap subscriber already had.
/// An unrecognized value fails to parse rather than silently falling back to
/// `info` — same fail-closed posture `TlsMode`/`DocsUiMode` already have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Off,
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

fn default_log_directory() -> String {
    "runtime-logs".to_string()
}

/// `config/server.json`'s `logging` block — directory relative to
/// `project::api_base` (or the project root itself for a web-only project,
/// which has no `api/` folder — see `server::logging::resolve_log_directory`).
/// This is the first case of a config-trusted path being used for directory
/// *creation* (a `std::fs::create_dir_all` write), not just a file *read*
/// the way `TlsConfig`'s `certPath`/`keyPath` are — same trust model as
/// everywhere else (project config is trusted, not attacker-controlled), but
/// worth naming the distinction since it's a new kind of filesystem effect
/// for this config surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoggingConfig {
    #[serde(default = "default_log_directory")]
    pub directory: String,
    #[serde(default)]
    pub level: LogLevel,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        LoggingConfig {
            directory: default_log_directory(),
            level: LogLevel::default(),
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
    /// Persistent file logging for `frogs run` — see `LoggingConfig`'s own
    /// doc comment and `server::logging`. Defaults to a `runtime-logs`
    /// directory (relative to `project::api_base`) at `LogLevel::Info`.
    #[serde(default)]
    pub logging: LoggingConfig,
    /// The project-wide fallback bound on one ordinary (non-`allowNestedMany`)
    /// source's real SQL `query()`/HTTP `execute()` call, in milliseconds —
    /// a source's own `callTimeoutMs` wins when it sets one. Never read
    /// directly when bounding a real call: go through
    /// `effective_source_call_timeout_ms` below, which is what applies the
    /// `MAX_SOURCE_CALL_TIMEOUT_MS` ceiling.
    #[serde(default = "default_source_call_timeout_ms")]
    pub source_call_timeout_ms: NonZeroU64,
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
            logging: LoggingConfig::default(),
            source_call_timeout_ms: default_source_call_timeout_ms(),
            port: 8080,
            api_root: String::new(),
        }
    }
}

impl ServerConfig {
    /// The one producer of a real source-call bound: `source_call_timeout_ms`
    /// clamped to `MAX_SOURCE_CALL_TIMEOUT_MS`, warning once if the file
    /// asked for more. Call this at startup/router-assembly time only (once
    /// per process or test run — `commands::run::assemble_api_router` and
    /// `commands::test::record` are its only call sites), never from the
    /// request path: a misconfigured `server.json` would otherwise emit this
    /// warning on every single request and drown out real signal.
    pub fn effective_source_call_timeout_ms(&self) -> NonZeroU64 {
        if self.source_call_timeout_ms.get() > MAX_SOURCE_CALL_TIMEOUT_MS {
            tracing::warn!(
                "server.json: sourceCallTimeoutMs {} exceeds the hard ceiling of {MAX_SOURCE_CALL_TIMEOUT_MS} — using {MAX_SOURCE_CALL_TIMEOUT_MS}",
                self.source_call_timeout_ms.get()
            );
            return NonZeroU64::new(MAX_SOURCE_CALL_TIMEOUT_MS).expect("MAX_SOURCE_CALL_TIMEOUT_MS is non-zero");
        }
        self.source_call_timeout_ms
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
    fn logging_defaults_to_runtime_logs_at_info_when_absent_from_the_file() {
        let config: ServerConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(config.logging.directory, "runtime-logs");
        assert_eq!(config.logging.level, LogLevel::Info);
    }

    #[test]
    fn logging_directory_and_level_are_read_from_the_file() {
        let config: ServerConfig = serde_json::from_str(r#"{ "logging": { "directory": "logs/custom", "level": "debug" } }"#).unwrap();
        assert_eq!(config.logging.directory, "logs/custom");
        assert_eq!(config.logging.level, LogLevel::Debug);
    }

    #[test]
    fn every_log_level_variant_parses_from_its_lowercase_name() {
        for (raw, expected) in [
            ("off", LogLevel::Off),
            ("error", LogLevel::Error),
            ("warn", LogLevel::Warn),
            ("info", LogLevel::Info),
            ("debug", LogLevel::Debug),
            ("trace", LogLevel::Trace),
        ] {
            let config: ServerConfig = serde_json::from_str(&format!(r#"{{ "logging": {{ "level": "{raw}" }} }}"#)).unwrap();
            assert_eq!(config.logging.level, expected, "level {raw} should parse to {expected:?}");
        }
    }

    #[test]
    fn log_level_rejects_an_unknown_value_rather_than_silently_falling_back_to_info() {
        let err = serde_json::from_str::<ServerConfig>(r#"{ "logging": { "level": "verbose" } }"#)
            .expect_err("an unrecognized logging.level must fail to parse, not silently default to info");
        assert!(err.to_string().to_lowercase().contains("unknown variant"));
    }

    #[test]
    fn logging_round_trips_through_serialize_and_deserialize() {
        let config = ServerConfig {
            logging: LoggingConfig {
                directory: "logs/custom".to_string(),
                level: LogLevel::Trace,
            },
            ..ServerConfig::default()
        };

        let json = serde_json::to_string(&config).unwrap();
        let reloaded: ServerConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(reloaded.logging.directory, "logs/custom");
        assert_eq!(reloaded.logging.level, LogLevel::Trace);
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

    #[test]
    fn source_call_timeout_ms_defaults_to_10_seconds_when_absent_from_the_file() {
        let config: ServerConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(config.source_call_timeout_ms.get(), 10_000);
    }

    #[test]
    fn source_call_timeout_ms_is_read_as_camel_case() {
        let config: ServerConfig = serde_json::from_str(r#"{ "sourceCallTimeoutMs": 2500 }"#).unwrap();
        assert_eq!(config.source_call_timeout_ms.get(), 2500);
    }

    #[test]
    fn effective_source_call_timeout_ms_returns_the_default_10000_when_absent() {
        let config = ServerConfig::default();
        assert_eq!(config.effective_source_call_timeout_ms().get(), 10_000);
    }

    #[test]
    fn effective_source_call_timeout_ms_passes_through_an_under_ceiling_configured_value_unchanged() {
        let config: ServerConfig = serde_json::from_str(r#"{ "sourceCallTimeoutMs": 60000 }"#).unwrap();
        assert_eq!(config.effective_source_call_timeout_ms().get(), 60_000);
    }

    #[test]
    fn effective_source_call_timeout_ms_clamps_an_over_ceiling_configured_value_down_to_the_ceiling() {
        let config: ServerConfig = serde_json::from_str(r#"{ "sourceCallTimeoutMs": 999999 }"#).unwrap();
        assert_eq!(
            config.effective_source_call_timeout_ms().get(),
            MAX_SOURCE_CALL_TIMEOUT_MS,
            "an over-ceiling configured value must be clamped down to MAX_SOURCE_CALL_TIMEOUT_MS, not passed through or defaulted"
        );
    }

    #[test]
    fn effective_source_call_timeout_ms_treats_a_value_exactly_at_the_ceiling_as_not_over_it() {
        let config: ServerConfig = serde_json::from_str(&format!(r#"{{ "sourceCallTimeoutMs": {MAX_SOURCE_CALL_TIMEOUT_MS} }}"#)).unwrap();
        assert_eq!(config.effective_source_call_timeout_ms().get(), MAX_SOURCE_CALL_TIMEOUT_MS);
    }
}

#[cfg(test)]
mod mtls_tests;
