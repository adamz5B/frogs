//! Where a tool call's authentication outcome becomes an HTTP-level or tool-level result, the
//! `WWW-Authenticate` challenges (built once at startup from config, never from a request) and
//! the fixed bodies of the `accessScheme` gate.

use std::collections::HashMap;

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use serde_json::value::RawValue;

use super::protocol::{self, Era, ProtoError};
use super::settings::{AuthSettings, ProtectedResource};
use crate::endpoint::AuthFailureKind;

const MAX_CHALLENGE_BYTES: usize = 4 * 1024;

/// The error codes that mean "the caller failed to authenticate" (as opposed to an upstream
/// datasource answering 401): only these may turn into a transport-level 401/403.
pub(crate) const CALLER_AUTH_CODES: [&str; 4] = [
    "auth.invalid_credentials",
    "auth.client_cert_missing",
    "auth.client_cert_expired",
    "auth.insufficient_scope",
];

/// The one place the transport-auth rule lives: a caller-auth code whose resolved HTTP status is
/// 401 or 403. Anything else (an upstream `onError: 401` with a `datasource.*` code, a caller-auth
/// code an operator re-mapped to 500, `auth.verifier_unavailable`) stays a tool error.
pub(crate) fn transport_auth_status(code: &str, status: u16) -> Option<StatusCode> {
    if !CALLER_AUTH_CODES.contains(&code) {
        return None;
    }
    match status {
        401 => Some(StatusCode::UNAUTHORIZED),
        403 => Some(StatusCode::FORBIDDEN),
        _ => None,
    }
}

/// What `tools/list` may be cached as: `private` once an `accessScheme` gates it. `server/discover`
/// is always `public` and never asks.
pub(crate) fn cache_scope(auth: &AuthSettings) -> &'static str {
    if auth.access_scheme.is_some() { "private" } else { "public" }
}

/// Every `WWW-Authenticate` value `/mcp` can send, pre-built and validated at startup.
pub(crate) struct Challenges {
    default_401: HeaderValue,
    tool_401: HashMap<String, HeaderValue>,
    tool_403: HashMap<String, HeaderValue>,
}

fn header_value(text: String) -> Result<HeaderValue, String> {
    if text.len() > MAX_CHALLENGE_BYTES {
        return Err(format!(
            "a WWW-Authenticate challenge would be {} bytes, over the {MAX_CHALLENGE_BYTES}-byte limit — shorten the scope lists",
            text.len()
        ));
    }
    HeaderValue::from_str(&text).map_err(|_| "a WWW-Authenticate challenge is not a valid header value".to_string())
}

impl Challenges {
    /// `tools` is each exposed tool's name and its configured `securityScopes`.
    pub(crate) fn build<'a>(protected: &ProtectedResource, tools: impl Iterator<Item = (&'a str, &'a [String])>) -> Result<Challenges, String> {
        let metadata = &protected.metadata_url;
        let challenge_401 = |scopes: &[String]| {
            if scopes.is_empty() {
                format!("Bearer resource_metadata=\"{metadata}\"")
            } else {
                format!("Bearer resource_metadata=\"{metadata}\", scope=\"{}\"", scopes.join(" "))
            }
        };
        let default_401 = header_value(challenge_401(&protected.scopes_supported))?;
        let mut tool_401 = HashMap::new();
        let mut tool_403 = HashMap::new();
        for (name, scopes) in tools {
            if scopes.is_empty() {
                continue;
            }
            tool_401.insert(name.to_string(), header_value(challenge_401(scopes))?);
            tool_403.insert(
                name.to_string(),
                header_value(format!(
                    "Bearer error=\"insufficient_scope\", scope=\"{}\", resource_metadata=\"{metadata}\"",
                    scopes.join(" ")
                ))?,
            );
        }
        Ok(Challenges { default_401, tool_401, tool_403 })
    }

    /// The challenge for a tool-call failure that became a transport 401/403, if one applies.
    /// Cert codes and an operator-remapped 403 `auth.invalid_credentials` get none.
    pub(crate) fn challenge_for(&self, code: &str, status: u16, tool: &str) -> Option<&HeaderValue> {
        match (code, status) {
            ("auth.invalid_credentials", 401) => Some(self.tool_401.get(tool).unwrap_or(&self.default_401)),
            ("auth.insufficient_scope", 403) => self.tool_403.get(tool),
            _ => None,
        }
    }

    pub(crate) fn gate_401(&self) -> &HeaderValue {
        &self.default_401
    }
}

pub(crate) fn with_challenge(mut response: Response, challenge: Option<&HeaderValue>) -> Response {
    if let Some(challenge) = challenge {
        response.headers_mut().insert(header::WWW_AUTHENTICATE, challenge.clone());
    }
    response
}

/// How the `accessScheme` gate answers. Deliberately built from the failure *kind* only: no
/// registry status, no `errorOverrides`, no verifier text, no `debugMode` detail.
pub(crate) enum GateOutcome {
    Deny { challenge: bool },
    Outage,
}

pub(crate) fn gate_outcome(kind: AuthFailureKind) -> GateOutcome {
    match kind {
        AuthFailureKind::Credentials => GateOutcome::Deny { challenge: true },
        AuthFailureKind::CertMissing | AuthFailureKind::CertExpired => GateOutcome::Deny { challenge: false },
        AuthFailureKind::InsufficientScope | AuthFailureKind::Unavailable => GateOutcome::Outage,
    }
}

pub(crate) fn gate_denied(id: &RawValue, challenge: Option<&HeaderValue>) -> Response {
    with_challenge(
        protocol::rpc_error_fixed(StatusCode::UNAUTHORIZED, id, protocol::INVALID_REQUEST, "Unauthorized"),
        challenge,
    )
}

pub(crate) fn gate_list_outage(era: Era, id: &RawValue) -> Response {
    ProtoError::internal_error().into_response(era, Some(id))
}

/// The `tools/call` outage body: the code and name only, identical for every tool name.
pub(crate) fn gate_call_outage_body() -> serde_json::Value {
    serde_json::json!({ "code": 500, "name": "auth.verifier_unavailable" })
}
