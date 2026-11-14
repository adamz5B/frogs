//! Interprets `mcp.accessScheme` and `mcp.protectedResource`, which `McpConfig` keeps as lenient
//! values so an MCP-off `server.json` never fails to load over them. Everything here is checked
//! once at startup; nothing request-derived ever reaches a header or the metadata document.

use std::collections::HashSet;

use axum::http::HeaderValue;
use reqwest::Url;
use serde_json::Value;

use super::transport::normalise_host;
use crate::config::{McpConfig, ServerConfig};
use crate::openapi::untrusted;

const MAX_AUTHORIZATION_SERVERS: usize = 8;
const MAX_SCOPES_SUPPORTED: usize = 64;
const MAX_SCOPE_TOKEN_BYTES: usize = 128;
const METADATA_PREFIX: &str = "/.well-known/oauth-protected-resource";
const LOOPBACK_HOSTS: [&str; 3] = ["localhost", "127.0.0.1", "::1"];

/// RFC 6749 section 3.3: `scope-token = 1*( %x21 / %x23-5B / %x5D-7E )`, capped at 128 bytes.
pub(crate) fn is_scope_token(text: &str) -> bool {
    !text.is_empty() && text.len() <= MAX_SCOPE_TOKEN_BYTES && text.bytes().all(|b| b == 0x21 || (0x23..=0x5B).contains(&b) || (0x5D..=0x7E).contains(&b))
}

/// The path `/mcp` is registered at, after `apiRoot` nesting.
pub(crate) fn final_path(server: &ServerConfig) -> String {
    match crate::server::normalize_api_root(&server.api_root) {
        Some(prefix) => crate::openapi::route_syntax::path_for_nested_route(&prefix, super::MCP_PATH),
        None => super::MCP_PATH.to_string(),
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct AuthSettings {
    pub access_scheme: Option<String>,
    pub protected: Option<ProtectedResource>,
}

#[derive(Debug, Clone)]
pub(crate) struct ProtectedResource {
    pub resource: String,
    /// Absolute path the metadata document is served at (origin root, never under `apiRoot`).
    pub metadata_path: String,
    pub metadata_url: String,
    pub authorization_servers: Vec<String>,
    pub scopes_supported: Vec<String>,
    /// The resource host, normalised the way the `/mcp` Host guard normalises request hosts.
    pub host: String,
}

fn is_loopback(host: &str) -> bool {
    LOOPBACK_HOSTS.contains(&host)
}

/// Text that may end up in a response header or the metadata body: printable ASCII, no quote or backslash.
fn header_safe(text: &str) -> bool {
    text.bytes().all(|b| (0x20..0x7F).contains(&b)) && !text.contains(['"', '\\']) && HeaderValue::from_str(text).is_ok()
}

/// Shared by `resource` and `authorizationServers`: absolute `https` (or `http` on loopback), no
/// userinfo, query or fragment.
fn parse_absolute_url(text: &str) -> Result<(Url, String), String> {
    if !header_safe(text) {
        return Err("must be printable ASCII without a double quote or backslash".to_string());
    }
    let url = Url::parse(text).map_err(|_| "is not an absolute URL".to_string())?;
    let host = url.host_str().map(normalise_host).ok_or_else(|| "has no host".to_string())?;
    match url.scheme() {
        "https" => {}
        "http" if is_loopback(&host) => {}
        "http" => return Err("must use https (plain http is accepted only for localhost, 127.0.0.1 or ::1)".to_string()),
        _ => return Err("must use https".to_string()),
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("must not carry userinfo".to_string());
    }
    if url.query().is_some() || url.fragment().is_some() || text.contains(['?', '#']) {
        return Err("must not carry a query or fragment".to_string());
    }
    Ok((url, host))
}

/// The text after the authority, exactly as written.
fn raw_path(text: &str) -> &str {
    let after_scheme = text.split_once("://").map_or(text, |(_, rest)| rest);
    match after_scheme.find('/') {
        Some(at) => &after_scheme[at..],
        None => "",
    }
}

struct ResourceParts {
    host: String,
    metadata_path: String,
    metadata_url: String,
}

fn parse_resource(text: &str, final_mcp_path: &str) -> Result<ResourceParts, String> {
    let (url, host) = parse_absolute_url(text)?;
    let raw = raw_path(text);
    if raw.contains('%') {
        return Err("must not contain percent-encoding".to_string());
    }
    if raw.split('/').skip(1).any(|segment| matches!(segment, "" | "." | "..")) {
        return Err("has an empty, '.' or '..' path segment".to_string());
    }
    if raw != url.path() {
        return Err("changes when normalised — write the path exactly as it is served".to_string());
    }
    if raw != final_mcp_path {
        return Err(format!(
            "has path '{}' but this server's MCP endpoint is '{}' (apiRoot + /mcp) — they must match exactly",
            untrusted(raw),
            untrusted(final_mcp_path)
        ));
    }
    let metadata_path = format!("{METADATA_PREFIX}{final_mcp_path}");
    let metadata_url = format!("{}{metadata_path}", url.origin().ascii_serialization());
    if !header_safe(&metadata_url) {
        return Err("yields a metadata URL that is not header-safe".to_string());
    }
    Ok(ResourceParts {
        host,
        metadata_path,
        metadata_url,
    })
}

fn string_list<'a>(value: &'a Value, what: &str, max: usize, errors: &mut Vec<String>) -> Vec<&'a str> {
    let Some(items) = value.as_array() else {
        errors.push(format!("mcp.protectedResource.{what} must be an array of strings"));
        return Vec::new();
    };
    if items.len() > max {
        errors.push(format!("mcp.protectedResource.{what} has {} entries, over the limit of {max}", items.len()));
        return Vec::new();
    }
    let mut out = Vec::new();
    for item in items {
        match item.as_str() {
            Some(text) => out.push(text),
            None => errors.push(format!("mcp.protectedResource.{what} must be an array of strings")),
        }
    }
    out
}

fn parse_protected(value: &Value, final_mcp_path: &str, errors: &mut Vec<String>) -> Option<ProtectedResource> {
    let Some(map) = value.as_object() else {
        errors.push("mcp.protectedResource must be an object".to_string());
        return None;
    };
    let before = errors.len();
    if let Some(key) = map
        .keys()
        .find(|key| !matches!(key.as_str(), "resource" | "authorizationServers" | "scopesSupported"))
    {
        errors.push(format!(
            "mcp.protectedResource has an unknown key '{}' (allowed: resource, authorizationServers, scopesSupported)",
            untrusted(key)
        ));
    }

    let mut resolved = None;
    match map.get("resource").and_then(Value::as_str) {
        Some(text) => match parse_resource(text, final_mcp_path) {
            Ok(parsed) => resolved = Some(parsed),
            Err(problem) => errors.push(format!("mcp.protectedResource.resource '{}' {problem}", untrusted(text))),
        },
        None => errors.push("mcp.protectedResource.resource must be a string".to_string()),
    }

    let mut servers: Vec<String> = Vec::new();
    match map.get("authorizationServers") {
        Some(list) => {
            let items = string_list(list, "authorizationServers", MAX_AUTHORIZATION_SERVERS, errors);
            if list.as_array().is_some_and(Vec::is_empty) {
                errors.push("mcp.protectedResource.authorizationServers must list at least one authorization server".to_string());
            }
            let mut seen = HashSet::new();
            for text in items {
                match parse_absolute_url(text) {
                    Ok(_) if !seen.insert(text) => errors.push(format!("mcp.protectedResource.authorizationServers lists '{}' more than once", untrusted(text))),
                    Ok(_) => servers.push(text.to_string()),
                    Err(problem) => errors.push(format!("mcp.protectedResource.authorizationServers entry '{}' {problem}", untrusted(text))),
                }
            }
        }
        None => errors.push("mcp.protectedResource.authorizationServers is required (1-8 absolute https URLs)".to_string()),
    }

    let mut scopes: Vec<String> = Vec::new();
    if let Some(list) = map.get("scopesSupported") {
        let mut seen = HashSet::new();
        for text in string_list(list, "scopesSupported", MAX_SCOPES_SUPPORTED, errors) {
            if !is_scope_token(text) {
                errors.push(format!(
                    "mcp.protectedResource.scopesSupported entry '{}' is not a valid scope token (1-128 printable ASCII characters, no space, double quote or backslash)",
                    untrusted(text)
                ));
            } else if !seen.insert(text) {
                errors.push(format!("mcp.protectedResource.scopesSupported lists '{}' more than once", untrusted(text)));
            } else {
                scopes.push(text.to_string());
            }
        }
    }

    if errors.len() != before {
        return None;
    }
    let parts = resolved?;
    Some(ProtectedResource {
        resource: map.get("resource").and_then(Value::as_str)?.to_string(),
        metadata_path: parts.metadata_path,
        metadata_url: parts.metadata_url,
        authorization_servers: servers,
        scopes_supported: scopes,
        host: parts.host,
    })
}

/// What the `mcp` block says about access control, plus every problem with it. On any problem
/// `protected` is `None`; callers refuse startup (MCP on) or warn (MCP off).
pub(crate) fn parse_auth_settings(settings: &McpConfig, final_mcp_path: &str) -> (AuthSettings, Vec<String>) {
    let mut errors = Vec::new();
    let mut auth = AuthSettings::default();
    match &settings.access_scheme {
        None => {}
        Some(Value::String(name)) if !name.is_empty() => auth.access_scheme = Some(name.clone()),
        Some(_) => errors.push("mcp.accessScheme must be the name of a security scheme (a non-empty string)".to_string()),
    }
    if let Some(value) = &settings.protected_resource {
        auth.protected = parse_protected(value, final_mcp_path, &mut errors);
    }
    (auth, errors)
}
