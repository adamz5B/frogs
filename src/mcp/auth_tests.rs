use axum::http::StatusCode;

use super::auth::*;
use super::settings::AuthSettings;

#[test]
fn a_caller_auth_code_with_a_401_or_403_status_becomes_a_transport_error() {
    for code in CALLER_AUTH_CODES {
        assert_eq!(transport_auth_status(code, 401), Some(StatusCode::UNAUTHORIZED), "{code}");
        assert_eq!(transport_auth_status(code, 403), Some(StatusCode::FORBIDDEN), "{code}");
    }
}

#[test]
fn a_caller_auth_code_the_operator_re_mapped_to_another_status_stays_a_tool_error() {
    for status in [200u16, 400, 404, 429, 500, 502, 503] {
        assert_eq!(transport_auth_status("auth.invalid_credentials", status), None, "{status}");
    }
}

#[test]
fn an_upstream_datasource_401_is_a_tool_error_not_a_transport_error() {
    assert_eq!(transport_auth_status("datasource.http_error", 401), None);
    assert_eq!(transport_auth_status("datasource.unavailable", 403), None);
    assert_eq!(transport_auth_status("", 401), None);
}

#[test]
fn a_verifier_outage_is_never_a_transport_auth_error() {
    assert_eq!(transport_auth_status("auth.verifier_unavailable", 500), None);
    assert_eq!(transport_auth_status("auth.verifier_unavailable", 401), None);
}

#[test]
fn the_anonymous_list_is_cacheable_publicly() {
    assert_eq!(cache_scope(&AuthSettings::default()), "public");
}
