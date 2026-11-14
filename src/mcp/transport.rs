//! Everything the `/mcp` route decides from the request parts alone, before a single body byte is
//! read: Host, Origin, method, content type and declared size. A refusal here carries a generic
//! JSON-RPC body that never echoes the request or names a setting; the detail goes to the log.
//!
//! The Host allowlist is a DNS-rebinding defence for a server a browser can be tricked into
//! reaching, not network access control: anyone who can reach the port can send any Host.

use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::body::{Body, Bytes};
use axum::http::request::Parts;
use axum::http::uri::Authority;
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::Response;

use super::protocol::generic_error;
use crate::config::{MAX_MCP_LIST_TTL_MS, McpConfig};

pub(crate) const MAX_MCP_REQUEST_BYTES: usize = 2 * 1024 * 1024;

const DEFAULT_ALLOWED_HOSTS: [&str; 3] = ["localhost", "127.0.0.1", "::1"];

static REJECTION_WARNED: AtomicBool = AtomicBool::new(false);

/// The normalised host names and the exact origins a request may carry.
pub(crate) struct Guard {
    hosts: HashSet<String>,
    origins: HashSet<String>,
}

impl Guard {
    pub(crate) fn new(settings: &McpConfig) -> Self {
        let mut hosts: HashSet<String> = DEFAULT_ALLOWED_HOSTS.iter().map(|host| (*host).to_string()).collect();
        hosts.extend(settings.allowed_hosts.iter().map(|host| normalise_host(host)));
        Guard {
            hosts,
            origins: settings.allowed_origins.iter().cloned().collect(),
        }
    }

    /// The published resource's own host name is a name clients legitimately reach this server by.
    pub(crate) fn with_resource_host(mut self, host: &str) -> Self {
        self.hosts.insert(host.to_string());
        self
    }
}

pub(crate) struct Reject {
    status: StatusCode,
    client_message: &'static str,
    allow_post: bool,
    log_hint: String,
}

impl Reject {
    fn new(status: StatusCode, client_message: &'static str, log_hint: String) -> Self {
        Reject {
            status,
            client_message,
            allow_post: false,
            log_hint,
        }
    }

    fn bad_request(log_hint: String) -> Self {
        Reject::new(StatusCode::BAD_REQUEST, "Bad Request", log_hint)
    }

    fn forbidden(log_hint: String) -> Self {
        Reject::new(StatusCode::FORBIDDEN, "Forbidden", log_hint)
    }

    pub(crate) fn into_response(self) -> Response {
        tracing::debug!(status = self.status.as_u16(), "refused a request to the MCP endpoint: {}", self.log_hint);
        if !REJECTION_WARNED.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                "a request to the MCP endpoint was refused before it was read (Host, Origin, method, content type or size check); \
                 if it was legitimate, add its host name to mcp.allowedHosts — that allowlist is a DNS-rebinding defence, not network access control"
            );
        }
        let mut response = generic_error(self.status, self.client_message);
        if self.allow_post {
            response.headers_mut().insert(header::ALLOW, HeaderValue::from_static("POST"));
        }
        response
    }
}

/// Lowercase, no port, no IPv6 brackets, one trailing dot removed.
pub(crate) fn normalise_host(host: &str) -> String {
    let lowered = host.trim().to_ascii_lowercase();
    let unbracketed = lowered.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')).unwrap_or(&lowered);
    unbracketed.strip_suffix('.').unwrap_or(unbracketed).to_string()
}

/// `None` for anything that isn't a plain `host[:port]` (userinfo included).
fn authority_host(text: &str) -> Option<String> {
    if text.contains('@') {
        return None;
    }
    let authority = Authority::from_str(text).ok()?;
    Some(normalise_host(authority.host()))
}

fn check_host(parts: &Parts, guard: &Guard) -> Result<(), Reject> {
    let host_values: Vec<&HeaderValue> = parts.headers.get_all(header::HOST).iter().collect();
    if host_values.len() > 1 {
        return Err(Reject::bad_request("more than one Host header".to_string()));
    }
    let from_header = match host_values.first() {
        Some(value) => {
            let Some(host) = value.to_str().ok().and_then(authority_host) else {
                return Err(Reject::bad_request("unusable Host header".to_string()));
            };
            Some(host)
        }
        None => None,
    };
    let from_uri = match parts.uri.authority() {
        Some(authority) => {
            let Some(host) = authority_host(authority.as_str()) else {
                return Err(Reject::bad_request("unusable URI authority".to_string()));
            };
            Some(host)
        }
        None => None,
    };
    let host = match (from_header, from_uri) {
        (None, None) => return Err(Reject::bad_request("no Host".to_string())),
        (Some(a), Some(b)) if a != b => return Err(Reject::bad_request("Host and URI authority differ".to_string())),
        (Some(host), _) | (None, Some(host)) => host,
    };
    if guard.hosts.contains(&host) {
        Ok(())
    } else {
        Err(Reject::forbidden(format!("Host '{}' is not in the allowed set", crate::openapi::untrusted(&host))))
    }
}

fn check_origin(parts: &Parts, guard: &Guard) -> Result<(), Reject> {
    let mut values = parts.headers.get_all(header::ORIGIN).iter();
    let Some(origin) = values.next() else { return Ok(()) };
    if values.next().is_some() {
        return Err(Reject::bad_request("more than one Origin header".to_string()));
    }
    match origin.to_str() {
        Ok(text) if guard.origins.contains(text) => Ok(()),
        Ok(text) => Err(Reject::forbidden(format!(
            "Origin '{}' is not in mcp.allowedOrigins",
            crate::openapi::untrusted(text)
        ))),
        Err(_) => Err(Reject::forbidden("non-ASCII Origin".to_string())),
    }
}

fn is_json_content_type(parts: &Parts) -> bool {
    parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|text| text.split(';').next())
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
}

/// Host, Origin, method, content type and declared size, in that order. Cheap CSRF hardening
/// included: a cross-site form can't send `application/json`.
pub(crate) fn check_parts(parts: &Parts, guard: &Guard) -> Result<(), Reject> {
    check_host(parts, guard)?;
    check_origin(parts, guard)?;
    if parts.method != Method::POST {
        let mut reject = Reject::new(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed", format!("method {} is not POST", parts.method));
        reject.allow_post = true;
        return Err(reject);
    }
    if !is_json_content_type(parts) {
        return Err(Reject::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Unsupported Media Type",
            "content type is not application/json".to_string(),
        ));
    }
    let declared = parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|text| text.trim().parse::<u64>().ok());
    if declared.is_some_and(|length| length > MAX_MCP_REQUEST_BYTES as u64) {
        return Err(Reject::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Payload Too Large",
            "declared Content-Length is over the limit".to_string(),
        ));
    }
    Ok(())
}

/// The only body limit on this route: the handler takes the raw request, so axum's implicit
/// `DefaultBodyLimit` does not apply.
pub(crate) async fn read_body_capped(body: Body) -> Result<Bytes, Reject> {
    match axum::body::to_bytes(body, MAX_MCP_REQUEST_BYTES).await {
        Ok(bytes) => Ok(bytes),
        Err(error) => {
            // `to_bytes` reports its cap through an error type this crate can't name, so look for its text in the chain.
            let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&error);
            while let Some(current) = source {
                if current.to_string().contains("length limit exceeded") {
                    return Err(Reject::new(StatusCode::PAYLOAD_TOO_LARGE, "Payload Too Large", "body is over the limit".to_string()));
                }
                source = current.source();
            }
            Err(Reject::bad_request("the body could not be read".to_string()))
        }
    }
}

fn host_entry_problem(entry: &str) -> Option<&'static str> {
    if entry.is_empty() {
        return Some("is empty");
    }
    if !entry.is_ascii() {
        return Some("must be ASCII");
    }
    if entry.contains('@') || entry.contains('/') || entry.contains('*') || entry.contains("://") || entry.contains(char::is_whitespace) {
        return Some("must be a bare host name or IP address (no scheme, userinfo, path or wildcard)");
    }
    let literal = entry.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')).unwrap_or(entry);
    if IpAddr::from_str(literal).is_ok() {
        return None;
    }
    if entry.contains(':') {
        return Some("must not carry a port");
    }
    let name = entry.strip_suffix('.').unwrap_or(entry);
    let valid = !name.is_empty()
        && name
            .split('.')
            .all(|label| !label.is_empty() && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
    if valid { None } else { Some("is not a valid host name") }
}

fn origin_entry_problem(entry: &str) -> Option<&'static str> {
    if entry == "null" {
        return None;
    }
    if entry.contains('*') {
        return Some("must not contain a wildcard");
    }
    let Some((scheme, authority)) = entry.split_once("://") else {
        return Some("must look like scheme://host[:port]");
    };
    if scheme.is_empty() || !scheme.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'.') {
        return Some("has an invalid scheme");
    }
    if authority.is_empty() || authority.contains(['/', '?', '#', '@']) || Authority::from_str(authority).is_err() {
        return Some("must be scheme://host[:port] with no path, query or userinfo");
    }
    None
}

/// Problems that refuse startup (or are `frogs validate` errors) when MCP is on.
pub(crate) fn settings_errors(settings: &McpConfig) -> Vec<String> {
    let mut problems = Vec::new();
    if let Some(ttl) = settings.list_ttl_ms
        && ttl > MAX_MCP_LIST_TTL_MS
    {
        problems.push(format!("mcp.listTtlMs {ttl} exceeds the maximum of {MAX_MCP_LIST_TTL_MS}"));
    }
    for entry in &settings.allowed_hosts {
        if let Some(problem) = host_entry_problem(entry) {
            problems.push(format!("mcp.allowedHosts entry '{}' {problem}", crate::openapi::untrusted(entry)));
        }
    }
    for entry in &settings.allowed_origins {
        if let Some(problem) = origin_entry_problem(entry) {
            problems.push(format!("mcp.allowedOrigins entry '{}' {problem}", crate::openapi::untrusted(entry)));
        }
    }
    problems
}

pub(crate) fn settings_warnings(settings: &McpConfig) -> Vec<String> {
    let mut warnings = Vec::new();
    if settings.allowed_origins.iter().any(|origin| origin == "null") {
        warnings.push("mcp.allowedOrigins contains \"null\": sandboxed pages and local files send that Origin, so it admits them".to_string());
    }
    warnings
}
