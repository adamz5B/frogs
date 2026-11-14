//! Milestone 2: the pre-built `WWW-Authenticate` challenges and the fixed bodies of the `accessScheme` gate.

use axum::http::header;
use serde_json::value::RawValue;

use super::auth::*;
use super::protocol::Era;
use super::settings::{AuthSettings, ProtectedResource};
use crate::endpoint::AuthFailureKind;

fn resource(scopes_supported: &[&str]) -> ProtectedResource {
    ProtectedResource {
        resource: "https://api.example.com/mcp".to_string(),
        metadata_path: "/.well-known/oauth-protected-resource/mcp".to_string(),
        metadata_url: "https://api.example.com/.well-known/oauth-protected-resource/mcp".to_string(),
        authorization_servers: vec!["https://auth.example.com".to_string()],
        scopes_supported: scopes_supported.iter().map(|s| s.to_string()).collect(),
        host: "api.example.com".to_string(),
    }
}

fn scoped(name: &'static str, scopes: &[&str]) -> (&'static str, Vec<String>) {
    (name, scopes.iter().map(|s| s.to_string()).collect())
}

fn build(protected: &ProtectedResource, tools: &[(&'static str, Vec<String>)]) -> Challenges {
    Challenges::build(protected, tools.iter().map(|(name, scopes)| (*name, scopes.as_slice()))).unwrap()
}

fn text(value: Option<&axum::http::HeaderValue>) -> Option<String> {
    value.map(|v| v.to_str().unwrap().to_string())
}

fn raw_id(text: &str) -> Box<RawValue> {
    RawValue::from_string(text.to_string()).unwrap()
}

async fn body_of(response: axum::response::Response) -> (u16, Vec<(String, String)>, String) {
    let status = response.status().as_u16();
    let headers = response.headers().iter().map(|(k, v)| (k.to_string(), v.to_str().unwrap().to_string())).collect();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (status, headers, String::from_utf8(bytes.to_vec()).unwrap())
}

#[test]
fn the_caller_auth_code_set_is_exactly_these_four_and_nothing_else() {
    let mut codes: Vec<&str> = CALLER_AUTH_CODES.to_vec();
    codes.sort_unstable();
    assert_eq!(
        codes,
        [
            "auth.client_cert_expired",
            "auth.client_cert_missing",
            "auth.insufficient_scope",
            "auth.invalid_credentials"
        ]
    );
    assert!(transport_auth_status("auth.verifier_unavailable", 403).is_none());
}

#[test]
fn the_401_challenge_carries_the_metadata_url_and_the_supported_scopes_when_there_are_any() {
    let with = build(&resource(&["cars.read", "cars.write"]), &[]);
    assert_eq!(
        text(with.challenge_for("auth.invalid_credentials", 401, "anyTool")).unwrap(),
        "Bearer resource_metadata=\"https://api.example.com/.well-known/oauth-protected-resource/mcp\", scope=\"cars.read cars.write\""
    );
    let without = build(&resource(&[]), &[]);
    assert_eq!(
        text(without.challenge_for("auth.invalid_credentials", 401, "anyTool")).unwrap(),
        "Bearer resource_metadata=\"https://api.example.com/.well-known/oauth-protected-resource/mcp\""
    );
}

#[test]
fn a_tool_with_its_own_scopes_gets_them_in_the_401_challenge_instead_of_scopes_supported() {
    let challenges = build(&resource(&["cars.read", "cars.write"]), &[scoped("adminTool", &["admin"]), scoped("plain", &[])]);
    assert_eq!(
        text(challenges.challenge_for("auth.invalid_credentials", 401, "adminTool")).unwrap(),
        "Bearer resource_metadata=\"https://api.example.com/.well-known/oauth-protected-resource/mcp\", scope=\"admin\""
    );
    assert_eq!(
        text(challenges.challenge_for("auth.invalid_credentials", 401, "plain")).unwrap(),
        text(challenges.challenge_for("auth.invalid_credentials", 401, "nobody")).unwrap(),
        "a tool without its own scopes, and an unknown name, get the default challenge"
    );
}

#[test]
fn the_403_insufficient_scope_challenge_names_the_tools_configured_scopes_only() {
    let challenges = build(&resource(&["cars.read"]), &[scoped("adminTool", &["admin", "cars.write"])]);
    assert_eq!(
        text(challenges.challenge_for("auth.insufficient_scope", 403, "adminTool")).unwrap(),
        "Bearer error=\"insufficient_scope\", scope=\"admin cars.write\", resource_metadata=\"https://api.example.com/.well-known/oauth-protected-resource/mcp\""
    );
    assert!(
        challenges.challenge_for("auth.insufficient_scope", 403, "unknown").is_none(),
        "a tool with no securityScopes can never produce insufficient_scope, and there is nothing request-derived to put in a challenge"
    );
}

#[test]
fn certificate_codes_and_an_operator_remapped_403_invalid_credentials_get_no_challenge() {
    let challenges = build(&resource(&["a"]), &[scoped("t", &["a"])]);
    for status in [401u16, 403] {
        assert!(challenges.challenge_for("auth.client_cert_missing", status, "t").is_none());
        assert!(challenges.challenge_for("auth.client_cert_expired", status, "t").is_none());
    }
    assert!(challenges.challenge_for("auth.invalid_credentials", 403, "t").is_none());
    assert!(challenges.challenge_for("auth.insufficient_scope", 401, "t").is_none());
    assert!(challenges.challenge_for("auth.verifier_unavailable", 401, "t").is_none());
    assert!(challenges.challenge_for("datasource.http_error", 401, "t").is_none());
}

#[test]
fn a_challenge_over_four_kibibytes_is_refused_at_build_time() {
    let big: Vec<String> = (0..40).map(|n| format!("{}{n}", "s".repeat(100))).collect();
    let refs: Vec<&str> = big.iter().map(String::as_str).collect();
    let error = Challenges::build(&resource(&refs), std::iter::empty()).err().expect("over the cap");
    assert!(error.contains("4096"), "{error}");
    let tool = [("t", big.clone())];
    assert!(Challenges::build(&resource(&[]), tool.iter().map(|(n, s)| (*n, s.as_slice()))).is_err());
}

#[test]
fn the_gate_401_challenge_is_the_default_one() {
    let challenges = build(&resource(&["cars.read"]), &[scoped("t", &["admin"])]);
    assert_eq!(
        text(Some(challenges.gate_401())),
        text(challenges.challenge_for("auth.invalid_credentials", 401, "unknown"))
    );
}

#[tokio::test]
async fn the_gate_denial_body_is_the_exact_fixed_bytes_with_no_data_and_the_challenge_header() {
    let challenges = build(&resource(&[]), &[]);
    let (status, headers, body) = body_of(gate_denied(&raw_id("7"), Some(challenges.gate_401()))).await;
    assert_eq!(status, 401);
    assert_eq!(body, r#"{"jsonrpc":"2.0","id":7,"error":{"code":-32600,"message":"Unauthorized"}}"#);
    assert!(
        headers.iter().any(|(k, v)| k == "www-authenticate" && v.starts_with("Bearer resource_metadata=")),
        "{headers:?}"
    );
    let (_, headers, body) = body_of(gate_denied(&raw_id("\"abc\""), None)).await;
    assert_eq!(body, r#"{"jsonrpc":"2.0","id":"abc","error":{"code":-32600,"message":"Unauthorized"}}"#);
    assert!(headers.iter().all(|(k, _)| k != "www-authenticate"));
}

#[tokio::test]
async fn the_gate_list_outage_is_a_fixed_internal_error_500_modern_and_200_legacy() {
    let (status, _, body) = body_of(gate_list_outage(Era::Modern, &raw_id("1"))).await;
    assert_eq!(status, 500);
    assert_eq!(body, r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"Internal error"}}"#);
    let (status, _, legacy_body) = body_of(gate_list_outage(Era::Legacy, &raw_id("1"))).await;
    assert_eq!(status, 200);
    assert_eq!(legacy_body, body);
}

#[test]
fn the_gate_call_outage_body_is_only_a_code_and_the_verifier_unavailable_name() {
    assert_eq!(gate_call_outage_body().to_string(), r#"{"code":500,"name":"auth.verifier_unavailable"}"#);
}

#[test]
fn the_gate_maps_a_failure_kind_to_a_fixed_outcome() {
    assert!(matches!(gate_outcome(AuthFailureKind::Credentials), GateOutcome::Deny { challenge: true }));
    assert!(matches!(gate_outcome(AuthFailureKind::CertMissing), GateOutcome::Deny { challenge: false }));
    assert!(matches!(gate_outcome(AuthFailureKind::CertExpired), GateOutcome::Deny { challenge: false }));
    assert!(matches!(gate_outcome(AuthFailureKind::Unavailable), GateOutcome::Outage));
    assert!(matches!(gate_outcome(AuthFailureKind::InsufficientScope), GateOutcome::Outage));
}

#[test]
fn with_challenge_sets_the_header_only_when_given_one() {
    let value = axum::http::HeaderValue::from_static("Bearer x");
    let response = with_challenge(axum::response::Response::new(axum::body::Body::empty()), Some(&value));
    assert_eq!(response.headers().get(header::WWW_AUTHENTICATE).unwrap(), "Bearer x");
    let bare = with_challenge(axum::response::Response::new(axum::body::Body::empty()), None);
    assert!(bare.headers().get(header::WWW_AUTHENTICATE).is_none());
}

#[test]
fn the_list_cache_scope_is_private_exactly_when_an_access_scheme_gates_it() {
    let gated = AuthSettings {
        access_scheme: Some("oauth".to_string()),
        protected: None,
    };
    assert_eq!(cache_scope(&gated), "private");
    assert_eq!(cache_scope(&AuthSettings::default()), "public");
    let ungated_but_protected = AuthSettings {
        access_scheme: None,
        protected: Some(resource(&[])),
    };
    assert_eq!(cache_scope(&ungated_but_protected), "public");
}
