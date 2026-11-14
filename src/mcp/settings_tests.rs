//! `mcp.accessScheme` / `mcp.protectedResource` interpretation: the resource URL matrix, the
//! authorization-server and scope-token rules, and what a Host guard does with the resource host.

use axum::http::{Request, header};
use serde_json::{Value, json};

use super::settings::*;
use super::transport::Guard;
use crate::config::McpConfig;

fn config(mcp: Value) -> McpConfig {
    serde_json::from_value(mcp).unwrap()
}

fn parse(mcp: Value, final_path: &str) -> (AuthSettings, Vec<String>) {
    parse_auth_settings(&config(mcp), final_path)
}

fn with_resource(resource: &str, final_path: &str) -> (AuthSettings, Vec<String>) {
    parse(
        json!({ "protectedResource": { "resource": resource, "authorizationServers": ["https://auth.example.com"] } }),
        final_path,
    )
}

fn assert_refused(resource: &str, final_path: &str, needle: &str) {
    let (auth, errors) = with_resource(resource, final_path);
    assert!(auth.protected.is_none(), "{resource:?} must not produce a resource");
    assert!(errors.iter().any(|e| e.contains(needle)), "{resource:?}: expected '{needle}' in {errors:?}");
}

#[test]
fn an_https_resource_matching_the_mcp_path_yields_the_origin_root_metadata_url_and_host() {
    let (auth, errors) = with_resource("https://api.example.com/mcp", "/mcp");
    assert!(errors.is_empty(), "{errors:?}");
    let protected = auth.protected.unwrap();
    assert_eq!(protected.resource, "https://api.example.com/mcp");
    assert_eq!(protected.metadata_path, "/.well-known/oauth-protected-resource/mcp");
    assert_eq!(protected.metadata_url, "https://api.example.com/.well-known/oauth-protected-resource/mcp");
    assert_eq!(protected.host, "api.example.com");
    assert_eq!(protected.authorization_servers, ["https://auth.example.com"]);
    assert!(protected.scopes_supported.is_empty());
}

#[test]
fn a_resource_with_a_port_keeps_it_in_the_metadata_url_but_not_in_the_host() {
    let protected = with_resource("https://api.example.com:8443/mcp", "/mcp").0.protected.unwrap();
    assert_eq!(protected.metadata_url, "https://api.example.com:8443/.well-known/oauth-protected-resource/mcp");
    assert_eq!(protected.host, "api.example.com");
}

#[test]
fn a_resource_under_a_non_empty_api_root_must_carry_the_api_root_in_its_path() {
    let (auth, errors) = with_resource("https://api.example.com/api/mcp", "/api/mcp");
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(auth.protected.unwrap().metadata_path, "/.well-known/oauth-protected-resource/api/mcp");
    assert_refused("https://api.example.com/mcp", "/api/mcp", "must match exactly");
    assert_refused("https://api.example.com/api/mcp", "/mcp", "must match exactly");
}

#[test]
fn plain_http_is_accepted_for_the_three_loopback_names_only() {
    for resource in [
        "http://localhost:8080/mcp",
        "http://127.0.0.1:8080/mcp",
        "http://[::1]:8080/mcp",
        "http://LOCALHOST/mcp",
    ] {
        let (auth, errors) = with_resource(resource, "/mcp");
        assert!(errors.is_empty(), "{resource}: {errors:?}");
        assert!(auth.protected.is_some(), "{resource}");
    }
    assert_refused("http://api.example.com/mcp", "/mcp", "must use https");
    assert_refused("http://10.0.0.5/mcp", "/mcp", "must use https");
    assert_refused("ftp://api.example.com/mcp", "/mcp", "must use https");
}

#[test]
fn a_bracketed_ipv6_loopback_resource_registers_the_unbracketed_host_for_the_host_guard() {
    let protected = with_resource("http://[::1]:8080/mcp", "/mcp").0.protected.unwrap();
    assert_eq!(protected.host, "::1");
    assert_eq!(protected.metadata_url, "http://[::1]:8080/.well-known/oauth-protected-resource/mcp");
}

#[test]
fn a_resource_with_userinfo_query_or_fragment_is_refused() {
    assert_refused("https://user@api.example.com/mcp", "/mcp", "userinfo");
    assert_refused("https://user:pw@api.example.com/mcp", "/mcp", "userinfo");
    assert_refused("https://api.example.com/mcp?a=1", "/mcp", "query or fragment");
    assert_refused("https://api.example.com/mcp?", "/mcp", "query or fragment");
    assert_refused("https://api.example.com/mcp#frag", "/mcp", "query or fragment");
    assert_refused("https://api.example.com/mcp#", "/mcp", "query or fragment");
}

#[test]
fn a_resource_path_that_could_be_normalised_is_refused_before_the_exact_compare() {
    assert_refused("https://api.example.com/api%2Fmcp", "/api/mcp", "percent-encoding");
    assert_refused("https://api.example.com/%6Dcp", "/mcp", "percent-encoding");
    assert_refused("https://api.example.com/./mcp", "/mcp", "'.' or '..'");
    assert_refused("https://api.example.com/x/../mcp", "/mcp", "'.' or '..'");
    assert_refused("https://api.example.com//mcp", "/mcp", "'.' or '..'");
    assert_refused("https://api.example.com/api//mcp", "/api/mcp", "'.' or '..'");
}

#[test]
fn a_trailing_slash_or_a_different_case_is_not_folded_into_the_mcp_path() {
    assert_refused("https://api.example.com/mcp/", "/mcp", "empty");
    assert_refused("https://api.example.com/MCP", "/mcp", "must match exactly");
    assert_refused("https://api.example.com/Api/mcp", "/api/mcp", "must match exactly");
    assert_refused("https://api.example.com", "/mcp", "");
}

#[test]
fn a_resource_that_cannot_be_a_header_value_or_is_not_absolute_is_refused() {
    assert_refused("https://api.example.com/mc\"p", "/mcp", "printable ASCII");
    assert_refused("https://api.example.com/mc\\p", "/mcp", "printable ASCII");
    assert_refused("https://api.example.com/mcp\u{e9}", "/mcp", "printable ASCII");
    assert_refused("https://api.example.com/mcp\n", "/mcp", "printable ASCII");
    assert_refused("/mcp", "/mcp", "not an absolute URL");
    assert_refused("api.example.com/mcp", "/mcp", "");
}

#[test]
fn a_resource_host_is_normalised_like_the_host_guard_does_it() {
    let protected = with_resource("https://API.Example.COM./mcp", "/mcp").0.protected.unwrap();
    assert_eq!(protected.host, "api.example.com");
}

#[test]
fn the_host_guard_accepts_the_resource_host_in_any_spelling_a_client_sends() {
    let protected = with_resource("https://API.Example.COM./mcp", "/mcp").0.protected.unwrap();
    let guard = Guard::new(&McpConfig::default()).with_resource_host(&protected.host);
    for host in ["api.example.com", "API.EXAMPLE.COM", "api.example.com:8443", "api.example.com."] {
        let request = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header(header::HOST, host)
            .header(header::CONTENT_TYPE, "application/json")
            .body(())
            .unwrap();
        let (parts, _) = request.into_parts();
        assert!(super::transport::check_parts(&parts, &guard).is_ok(), "{host}");
    }
    let other = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::HOST, "evil.example")
        .header(header::CONTENT_TYPE, "application/json")
        .body(())
        .unwrap();
    assert!(super::transport::check_parts(&other.into_parts().0, &guard).is_err());
}

#[test]
fn a_protected_resource_needs_a_string_resource_and_rejects_unknown_keys() {
    let (auth, errors) = parse(json!({ "protectedResource": { "authorizationServers": ["https://a.example"] } }), "/mcp");
    assert!(
        auth.protected.is_none() && errors.iter().any(|e| e.contains("resource must be a string")),
        "{errors:?}"
    );
    let (auth, errors) = parse(
        json!({ "protectedResource": { "resource": 5, "authorizationServers": ["https://a.example"] } }),
        "/mcp",
    );
    assert!(auth.protected.is_none() && !errors.is_empty());
    let (auth, errors) = parse(
        json!({ "protectedResource": { "resource": "https://api.example.com/mcp", "authorizationServers": ["https://a.example"], "jwksUri": "x" } }),
        "/mcp",
    );
    assert!(auth.protected.is_none() && errors.iter().any(|e| e.contains("unknown key 'jwksUri'")), "{errors:?}");
    let (auth, errors) = parse(json!({ "protectedResource": "https://api.example.com/mcp" }), "/mcp");
    assert!(auth.protected.is_none() && errors.iter().any(|e| e.contains("must be an object")), "{errors:?}");
}

fn servers(list: Value) -> (AuthSettings, Vec<String>) {
    parse(
        json!({ "protectedResource": { "resource": "https://api.example.com/mcp", "authorizationServers": list } }),
        "/mcp",
    )
}

#[test]
fn authorization_servers_are_one_to_eight_unique_absolute_https_urls() {
    let (auth, errors) = servers(json!(["https://auth.example.com", "https://auth2.example.com/tenant", "http://localhost:9000"]));
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(auth.protected.unwrap().authorization_servers.len(), 3);

    let (auth, errors) = servers(json!([]));
    assert!(auth.protected.is_none() && errors.iter().any(|e| e.contains("at least one")), "{errors:?}");
    let nine: Vec<String> = (0..9).map(|n| format!("https://as{n}.example.com")).collect();
    let (auth, errors) = servers(json!(nine));
    assert!(auth.protected.is_none() && errors.iter().any(|e| e.contains("over the limit of 8")), "{errors:?}");
    let eight: Vec<String> = (0..8).map(|n| format!("https://as{n}.example.com")).collect();
    assert!(servers(json!(eight)).0.protected.is_some());
}

#[test]
fn a_bad_authorization_server_entry_refuses_with_the_entry_named() {
    for (entry, needle) in [
        ("http://auth.example.com", "must use https"),
        ("https://u:p@auth.example.com", "userinfo"),
        ("https://auth.example.com/?x=1", "query or fragment"),
        ("https://auth.example.com/#f", "query or fragment"),
        ("auth.example.com", "not an absolute URL"),
        ("https://auth.example.com/\"x", "printable ASCII"),
    ] {
        let (auth, errors) = servers(json!([entry]));
        assert!(auth.protected.is_none(), "{entry}");
        assert!(errors.iter().any(|e| e.contains(needle)), "{entry}: {errors:?}");
    }
    let (auth, errors) = servers(json!(["https://auth.example.com", "https://auth.example.com"]));
    assert!(auth.protected.is_none() && errors.iter().any(|e| e.contains("more than once")), "{errors:?}");
    let (auth, errors) = servers(json!([5]));
    assert!(auth.protected.is_none() && errors.iter().any(|e| e.contains("array of strings")), "{errors:?}");
    let (auth, errors) = parse(json!({ "protectedResource": { "resource": "https://api.example.com/mcp" } }), "/mcp");
    assert!(
        auth.protected.is_none() && errors.iter().any(|e| e.contains("authorizationServers is required")),
        "{errors:?}"
    );
}

fn scopes(list: Value) -> (AuthSettings, Vec<String>) {
    parse(
        json!({ "protectedResource": { "resource": "https://api.example.com/mcp", "authorizationServers": ["https://a.example"], "scopesSupported": list } }),
        "/mcp",
    )
}

#[test]
fn scopes_supported_are_kept_in_order_and_may_be_empty() {
    let (auth, errors) = scopes(json!(["cars.read", "cars:write", "https://x/y"]));
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(auth.protected.unwrap().scopes_supported, ["cars.read", "cars:write", "https://x/y"]);
    assert!(scopes(json!([])).0.protected.is_some());
}

#[test]
fn an_invalid_duplicate_or_excessive_scopes_supported_entry_refuses() {
    for bad in ["", "a b", "a\"b", "a\\b", "\u{e9}", "a\tb", &"x".repeat(129)] {
        let (auth, errors) = scopes(json!([bad]));
        assert!(auth.protected.is_none(), "{bad:?}");
        assert!(errors.iter().any(|e| e.contains("not a valid scope token")), "{bad:?}: {errors:?}");
    }
    let (auth, errors) = scopes(json!(["a", "a"]));
    assert!(auth.protected.is_none() && errors.iter().any(|e| e.contains("more than once")), "{errors:?}");
    let many: Vec<String> = (0..65).map(|n| format!("s{n}")).collect();
    let (auth, errors) = scopes(json!(many));
    assert!(auth.protected.is_none() && errors.iter().any(|e| e.contains("over the limit of 64")), "{errors:?}");
    let sixty_four: Vec<String> = (0..64).map(|n| format!("s{n}")).collect();
    assert!(scopes(json!(sixty_four)).0.protected.is_some());
    assert!(scopes(json!("cars.read")).0.protected.is_none());
}

#[test]
fn the_scope_token_grammar_is_rfc_6749_printable_ascii_without_space_quote_or_backslash_up_to_128_bytes() {
    for ok in ["a", "cars.read", "a:b/c", "!", "~", "#", "[", "]", &"x".repeat(128)] {
        assert!(is_scope_token(ok), "{ok}");
    }
    for bad in ["", " ", "a b", "\"", "\\", "\u{7f}", "\u{80}", "é", "a\nb", &"x".repeat(129)] {
        assert!(!is_scope_token(bad), "{bad:?}");
    }
}

#[test]
fn access_scheme_must_be_a_non_empty_string() {
    let (auth, errors) = parse(json!({ "accessScheme": "oauth" }), "/mcp");
    assert!(errors.is_empty());
    assert_eq!(auth.access_scheme.as_deref(), Some("oauth"));
    assert!(auth.protected.is_none());
    for bad in [json!(""), json!(5), json!(["a"]), json!({})] {
        let (auth, errors) = parse(json!({ "accessScheme": bad }), "/mcp");
        assert!(auth.access_scheme.is_none() && errors.iter().any(|e| e.contains("accessScheme")), "{bad}: {errors:?}");
    }
    let (auth, errors) = parse(json!({}), "/mcp");
    assert!(errors.is_empty() && auth.access_scheme.is_none() && auth.protected.is_none());
}

#[test]
fn final_path_prepends_the_normalised_api_root() {
    let mut server = crate::config::ServerConfig::default();
    assert_eq!(final_path(&server), "/mcp");
    server.api_root = "/api".to_string();
    assert_eq!(final_path(&server), "/api/mcp");
    server.api_root = "api/".to_string();
    assert_eq!(final_path(&server), "/api/mcp", "slashes are normalised the way the router normalises them");
    server.api_root = "/v1/cars".to_string();
    assert_eq!(final_path(&server), "/v1/cars/mcp");
}
