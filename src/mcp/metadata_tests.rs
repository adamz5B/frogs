//! The RFC 9728 metadata router in isolation: body, methods and the absence of any request-derived data.

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use tower_service::Service;

use super::metadata::router;
use super::settings::ProtectedResource;

fn resource(scopes: &[&str]) -> ProtectedResource {
    ProtectedResource {
        resource: "https://api.example.com/mcp".to_string(),
        metadata_path: "/.well-known/oauth-protected-resource/mcp".to_string(),
        metadata_url: "https://api.example.com/.well-known/oauth-protected-resource/mcp".to_string(),
        authorization_servers: vec!["https://auth.example.com".to_string(), "https://auth2.example.com/t".to_string()],
        scopes_supported: scopes.iter().map(|s| s.to_string()).collect(),
        host: "api.example.com".to_string(),
    }
}

async fn send(app: &Router, method: &str, path: &str, host: Option<&str>) -> (StatusCode, axum::http::HeaderMap, String) {
    let mut builder = Request::builder().method(Method::from_bytes(method.as_bytes()).unwrap()).uri(path);
    if let Some(host) = host {
        builder = builder.header(header::HOST, host);
    }
    let response = app.clone().call(builder.body(Body::empty()).unwrap()).await.unwrap();
    let (parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, 1 << 20).await.unwrap();
    (parts.status, parts.headers, String::from_utf8(bytes.to_vec()).unwrap())
}

const PATH: &str = "/.well-known/oauth-protected-resource/mcp";

#[tokio::test]
async fn the_document_is_the_exact_json_with_scopes_and_the_fixed_bearer_method() {
    let app = router(&resource(&["cars.read", "cars.write"])).unwrap();
    let (status, headers, body) = send(&app, "GET", PATH, Some("api.example.com")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get(header::CONTENT_TYPE).unwrap(), "application/json");
    assert_eq!(
        body,
        r#"{"resource":"https://api.example.com/mcp","authorization_servers":["https://auth.example.com","https://auth2.example.com/t"],"scopes_supported":["cars.read","cars.write"],"bearer_methods_supported":["header"]}"#
    );
}

#[tokio::test]
async fn scopes_supported_is_omitted_entirely_when_none_are_configured() {
    let app = router(&resource(&[])).unwrap();
    let (_, _, body) = send(&app, "GET", PATH, None).await;
    assert!(!body.contains("scopes_supported"), "{body}");
    assert!(body.ends_with(r#""bearer_methods_supported":["header"]}"#), "{body}");
}

#[tokio::test]
async fn a_hostile_host_or_query_never_changes_one_byte_of_the_document() {
    let app = router(&resource(&["a"])).unwrap();
    let (_, _, baseline) = send(&app, "GET", PATH, Some("api.example.com")).await;
    for host in ["evil.example", "evil.example:1234", "api.example.com.evil.example", "[::1]", "\"><script>"] {
        let (status, _, body) = send(&app, "GET", PATH, Some(host)).await;
        assert_eq!(status, StatusCode::OK, "{host}");
        assert_eq!(body, baseline, "{host}");
    }
    let (_, _, no_host) = send(&app, "GET", PATH, None).await;
    assert_eq!(no_host, baseline);
    let (_, _, with_query) = send(&app, "GET", &format!("{PATH}?resource=https://evil.example"), Some("evil.example")).await;
    assert_eq!(with_query, baseline);
    assert!(!baseline.contains("evil"));
}

#[tokio::test]
async fn head_answers_200_with_the_json_content_type() {
    // The body of a HEAD response is stripped by the HTTP server, not the router: see the served test in commands::run.
    let app = router(&resource(&[])).unwrap();
    let (status, headers, _) = send(&app, "HEAD", PATH, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get(header::CONTENT_TYPE).unwrap(), "application/json");
}

#[tokio::test]
async fn every_other_method_is_405_with_allow_get_head_and_no_document() {
    let app = router(&resource(&["a"])).unwrap();
    for method in ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "QUERY", "PURGE", "PROPFIND"] {
        let (status, headers, body) = send(&app, method, PATH, None).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{method}");
        assert_eq!(headers.get(header::ALLOW).unwrap(), "GET, HEAD", "{method}");
        assert!(body.is_empty(), "{method}: {body:?}");
    }
}

#[tokio::test]
async fn the_unsuffixed_well_known_path_and_other_paths_are_not_served() {
    let app = router(&resource(&[])).unwrap();
    for path in [
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/",
        "/mcp",
        "/.well-known/oauth-protected-resource/mcp/x",
    ] {
        let (status, _, _) = send(&app, "GET", path, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
    }
}

#[tokio::test]
async fn a_path_under_an_api_root_resource_is_served_only_at_its_full_suffixed_path() {
    let mut under_root = resource(&[]);
    under_root.resource = "https://api.example.com/api/mcp".to_string();
    under_root.metadata_path = "/.well-known/oauth-protected-resource/api/mcp".to_string();
    let app = router(&under_root).unwrap();
    assert_eq!(send(&app, "GET", "/.well-known/oauth-protected-resource/api/mcp", None).await.0, StatusCode::OK);
    assert_eq!(
        send(&app, "GET", "/api/.well-known/oauth-protected-resource/api/mcp", None).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(send(&app, "GET", "/.well-known/oauth-protected-resource/mcp", None).await.0, StatusCode::NOT_FOUND);
}
