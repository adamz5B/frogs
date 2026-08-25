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
        RateLimitConfig { requests_per_second: default_requests_per_second(), burst: default_burst() }
    }
}

/// Independently toggleable capabilities — none of them imply a deployment
/// "mode"; a monolith and a split-out microservice both just pick whichever
/// of these they need. `metrics`/`readyzCheck`/`requestCorrelation` and
/// `requestValidation` are on by default because they cost nothing and help
/// every shape; `rateLimiting`/`serviceRegistry` are opt-in.
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
        let config: ServerConfig =
            serde_json::from_str(r#"{ "rateLimit": { "requestsPerSecond": 5, "burst": 15 } }"#).unwrap();
        assert_eq!(config.rate_limit.requests_per_second, 5);
        assert_eq!(config.rate_limit.burst, 15);
    }

    #[test]
    fn round_trips_through_serialize_and_deserialize() {
        let mut config = ServerConfig::default();
        config.api_root = "/api".to_string();
        config.port = 9090;

        let json = serde_json::to_string(&config).unwrap();
        let reloaded: ServerConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(reloaded.api_root, "/api");
        assert_eq!(reloaded.port, 9090);
    }
}
