//! Host/Origin/method/content-type/size checks and the settings validators of `mcp::transport`.

use axum::body::Body;
use axum::http::request::Parts;
use axum::http::{Request, StatusCode, header};
use axum::response::Response;

use super::transport::*;
use crate::config::McpConfig;

fn settings(json: &str) -> McpConfig {
    serde_json::from_str(json).unwrap()
}

fn guard(json: &str) -> Guard {
    Guard::new(&settings(json))
}

/// A POST with a JSON content type; `extra` headers are appended (so a repeated name stays repeated).
fn parts(uri: &str, host: Option<&str>, extra: &[(&str, &str)]) -> Parts {
    let mut builder = Request::builder().method("POST").uri(uri).header(header::CONTENT_TYPE, "application/json");
    if let Some(host) = host {
        builder = builder.header(header::HOST, host);
    }
    for (name, value) in extra {
        builder = builder.header(*name, *value);
    }
    builder.body(()).unwrap().into_parts().0
}

fn refusal(result: Result<(), Reject>) -> Response {
    match result {
        Ok(()) => panic!("expected a refusal"),
        Err(reject) => reject.into_response(),
    }
}

async fn body_text(response: Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[test]
fn loopback_host_names_are_accepted_by_default_in_every_spelling() {
    let g = guard("{}");
    for host in [
        "localhost",
        "LOCALHOST",
        "localhost:8080",
        "localhost.",
        "127.0.0.1",
        "127.0.0.1:3000",
        "[::1]",
        "[::1]:8080",
    ] {
        assert!(check_parts(&parts("/mcp", Some(host), &[]), &g).is_ok(), "{host}");
    }
}

#[tokio::test]
async fn an_unlisted_host_is_403_and_the_body_names_neither_the_host_nor_any_setting() {
    let g = guard(r#"{ "allowedHosts": ["configured.internal"] }"#);
    let response = refusal(check_parts(&parts("/mcp", Some("evil.example"), &[]), &g));
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let text = body_text(response).await;
    assert!(!text.contains("evil.example"), "{text}");
    assert!(!text.contains("configured.internal"), "{text}");
    assert!(!text.contains("allowedHosts"), "{text}");
    assert!(text.contains("Forbidden"), "{text}");
}

#[test]
fn a_configured_host_matches_case_insensitively_ignoring_port_and_trailing_dot() {
    let g = guard(r#"{ "allowedHosts": ["Api.Example.COM."] }"#);
    for host in ["api.example.com", "API.EXAMPLE.COM:8443", "api.example.com."] {
        assert!(check_parts(&parts("/mcp", Some(host), &[]), &g).is_ok(), "{host}");
    }
    assert!(check_parts(&parts("/mcp", Some("other.example.com"), &[]), &g).is_err());
    assert!(check_parts(&parts("/mcp", Some("xapi.example.com"), &[]), &g).is_err());
}

#[test]
fn a_missing_host_is_400() {
    let response = refusal(check_parts(&parts("/mcp", None, &[]), &guard("{}")));
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn two_host_headers_are_400_even_when_both_are_allowed() {
    let p = parts("/mcp", Some("localhost"), &[("host", "127.0.0.1")]);
    assert_eq!(refusal(check_parts(&p, &guard("{}"))).status(), StatusCode::BAD_REQUEST);
}

#[test]
fn a_uri_authority_that_differs_from_the_host_header_is_400_and_one_that_agrees_is_fine() {
    let g = guard(r#"{ "allowedHosts": ["good.example"] }"#);
    let differ = parts("http://good.example/mcp", Some("localhost"), &[]);
    assert_eq!(refusal(check_parts(&differ, &g)).status(), StatusCode::BAD_REQUEST);
    let agree = parts("http://GOOD.example:80/mcp", Some("good.example"), &[]);
    assert!(check_parts(&agree, &g).is_ok());
    let authority_only = parts("http://good.example/mcp", None, &[]);
    assert!(check_parts(&authority_only, &g).is_ok(), "HTTP/2 style: authority without a Host header");
}

#[test]
fn userinfo_in_the_host_header_is_400_even_if_the_host_part_is_allowed() {
    for host in ["user@localhost", "evil.example@localhost", "localhost@evil.example", "a:b@localhost"] {
        let p = parts("/mcp", Some(host), &[]);
        assert_eq!(refusal(check_parts(&p, &guard("{}"))).status(), StatusCode::BAD_REQUEST, "{host}");
    }
}

#[test]
fn x_forwarded_host_is_never_consulted() {
    let p = parts("/mcp", Some("evil.example"), &[("x-forwarded-host", "localhost")]);
    assert_eq!(refusal(check_parts(&p, &guard("{}"))).status(), StatusCode::FORBIDDEN);
    let ok = parts("/mcp", Some("localhost"), &[("x-forwarded-host", "evil.example")]);
    assert!(check_parts(&ok, &guard("{}")).is_ok());
}

#[test]
fn an_absent_origin_passes_and_a_listed_origin_must_match_byte_for_byte() {
    let g = guard(r#"{ "allowedOrigins": ["https://app.example"] }"#);
    assert!(check_parts(&parts("/mcp", Some("localhost"), &[]), &g).is_ok());
    assert!(check_parts(&parts("/mcp", Some("localhost"), &[("origin", "https://app.example")]), &g).is_ok());
    for origin in [
        "https://APP.example",
        "https://app.example/",
        "http://app.example",
        "https://app.example:443",
        "https://evil.example",
        "",
    ] {
        let p = parts("/mcp", Some("localhost"), &[("origin", origin)]);
        assert_eq!(refusal(check_parts(&p, &g)).status(), StatusCode::FORBIDDEN, "{origin:?}");
    }
}

#[test]
fn any_origin_is_refused_when_none_are_configured() {
    let p = parts("/mcp", Some("localhost"), &[("origin", "https://claude.ai")]);
    assert_eq!(refusal(check_parts(&p, &guard("{}"))).status(), StatusCode::FORBIDDEN);
}

#[test]
fn two_origin_headers_are_400_even_when_both_are_allowed() {
    let g = guard(r#"{ "allowedOrigins": ["https://a.example", "https://b.example"] }"#);
    let p = parts("/mcp", Some("localhost"), &[("origin", "https://a.example"), ("origin", "https://b.example")]);
    assert_eq!(refusal(check_parts(&p, &g)).status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn any_method_but_post_is_405_with_allow_post_and_a_generic_body() {
    for method in ["GET", "DELETE", "HEAD", "OPTIONS", "PUT", "PATCH"] {
        let p = Request::builder()
            .method(method)
            .uri("/mcp")
            .header(header::HOST, "localhost")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let response = refusal(check_parts(&p, &guard("{}")));
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED, "{method}");
        assert_eq!(response.headers()[header::ALLOW], "POST", "{method}");
        let text = body_text(response).await;
        assert!(
            text.contains("Method Not Allowed") && text.contains("-32600") && text.contains("\"id\":null"),
            "{text}"
        );
    }
}

#[test]
fn the_host_and_origin_checks_run_before_the_method_check() {
    let p = Request::builder()
        .method("GET")
        .uri("/mcp")
        .header(header::HOST, "evil.example")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    assert_eq!(
        refusal(check_parts(&p, &guard("{}"))).status(),
        StatusCode::FORBIDDEN,
        "a probe must not learn the method rule"
    );
}

#[test]
fn only_application_json_is_accepted_parameters_and_case_aside() {
    let g = guard("{}");
    for ok in [
        "application/json",
        "Application/JSON",
        "application/json; charset=utf-8",
        "application/json;charset=UTF-8",
        " application/json ",
    ] {
        let p = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header(header::HOST, "localhost")
            .header(header::CONTENT_TYPE, ok)
            .body(())
            .unwrap()
            .into_parts()
            .0;
        assert!(check_parts(&p, &g).is_ok(), "{ok}");
    }
    for bad in [
        "text/plain",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "application/jsonx",
        "application/json-patch+json",
        "application/",
    ] {
        let p = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header(header::HOST, "localhost")
            .header(header::CONTENT_TYPE, bad)
            .body(())
            .unwrap()
            .into_parts()
            .0;
        assert_eq!(refusal(check_parts(&p, &g)).status(), StatusCode::UNSUPPORTED_MEDIA_TYPE, "{bad}");
    }
    let none = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::HOST, "localhost")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    assert_eq!(refusal(check_parts(&none, &g)).status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[test]
fn a_declared_content_length_over_the_cap_is_413_and_exactly_the_cap_is_fine() {
    let g = guard("{}");
    let over = (MAX_MCP_REQUEST_BYTES + 1).to_string();
    let at = MAX_MCP_REQUEST_BYTES.to_string();
    assert_eq!(
        refusal(check_parts(&parts("/mcp", Some("localhost"), &[("content-length", &over)]), &g)).status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert!(check_parts(&parts("/mcp", Some("localhost"), &[("content-length", &at)]), &g).is_ok());
}

#[test]
fn a_content_length_far_beyond_u32_is_still_413() {
    let huge = "99999999999999999";
    let p = parts("/mcp", Some("localhost"), &[("content-length", huge)]);
    assert_eq!(refusal(check_parts(&p, &guard("{}"))).status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn a_body_over_the_cap_is_413_and_one_at_the_cap_is_read_whole() {
    let over = read_body_capped(Body::from(vec![b'x'; MAX_MCP_REQUEST_BYTES + 1])).await;
    let Err(reject) = over else { panic!("over the cap") };
    assert_eq!(reject.into_response().status(), StatusCode::PAYLOAD_TOO_LARGE);
    let at = read_body_capped(Body::from(vec![b'x'; MAX_MCP_REQUEST_BYTES])).await.ok().expect("at the cap");
    assert_eq!(at.len(), MAX_MCP_REQUEST_BYTES);
}

#[tokio::test]
async fn a_chunked_body_over_the_cap_is_413_without_a_declared_length() {
    let chunk = vec![b'x'; 256 * 1024];
    let chunks: Vec<Result<Vec<u8>, std::io::Error>> = (0..9).map(|_| Ok(chunk.clone())).collect();
    let body = Body::from_stream(futures_util::stream::iter(chunks));
    let result = read_body_capped(body).await;
    let Err(reject) = result else { panic!("over the cap") };
    assert_eq!(reject.into_response().status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[test]
fn host_entries_that_are_not_bare_ascii_hosts_are_startup_errors() {
    for bad in [
        "https://example.com",
        "example.com:8080",
        "example.com/path",
        "*.example.com",
        "",
        "user@example.com",
        "ex ample.com",
        "caf\u{e9}.example",
        "a..b",
    ] {
        let problems = settings_errors(&settings(&format!(r#"{{ "allowedHosts": [{}] }}"#, serde_json::to_string(bad).unwrap())));
        assert_eq!(problems.len(), 1, "{bad:?}: {problems:?}");
        assert!(problems[0].contains("allowedHosts"), "{problems:?}");
    }
}

#[test]
fn bare_host_names_and_ip_literals_are_valid_host_entries() {
    let ok = settings(r#"{ "allowedHosts": ["localhost", "api.example.com", "api.example.com.", "10.1.2.3", "::1", "[::1]", "my_host.internal"] }"#);
    assert!(settings_errors(&ok).is_empty(), "{:?}", settings_errors(&ok));
}

#[test]
fn origin_entries_must_be_scheme_host_port_with_no_path_wildcard_or_userinfo() {
    for bad in [
        "claude.ai",
        "https://",
        "https://x.example/",
        "https://x.example/path",
        "https://*.example.com",
        "https://u@x.example",
        "ht tp://x",
        "https://x.example?q=1",
    ] {
        let problems = settings_errors(&settings(&format!(r#"{{ "allowedOrigins": [{}] }}"#, serde_json::to_string(bad).unwrap())));
        assert_eq!(problems.len(), 1, "{bad:?}: {problems:?}");
        assert!(problems[0].contains("allowedOrigins"), "{problems:?}");
    }
    let ok = settings(r#"{ "allowedOrigins": ["https://claude.ai", "http://localhost:3000", "null"] }"#);
    assert!(settings_errors(&ok).is_empty(), "{:?}", settings_errors(&ok));
}

#[test]
fn a_null_origin_entry_is_a_warning_not_an_error() {
    let s = settings(r#"{ "allowedOrigins": ["null"] }"#);
    assert!(settings_errors(&s).is_empty());
    assert_eq!(settings_warnings(&s).len(), 1);
    assert!(settings_warnings(&settings("{}")).is_empty());
}

#[test]
fn list_ttl_over_the_maximum_is_an_error_and_exactly_the_maximum_is_fine() {
    assert!(settings_errors(&settings(r#"{ "listTtlMs": 86400000 }"#)).is_empty());
    assert!(settings_errors(&settings(r#"{ "listTtlMs": 0 }"#)).is_empty());
    let problems = settings_errors(&settings(r#"{ "listTtlMs": 86400001 }"#));
    assert_eq!(problems.len(), 1);
    assert!(problems[0].contains("listTtlMs"), "{problems:?}");
}
