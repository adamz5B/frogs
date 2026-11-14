//! RFC 9728 protected-resource metadata. The document is serialised once at startup from config
//! alone, so no request data (a `Host` header included) can ever reach it.

use std::io;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::Response;
use axum::routing::any;
use serde_json::json;

use super::settings::ProtectedResource;

/// Serves the document at `<origin>/.well-known/oauth-protected-resource<resource path>`:
/// GET/HEAD answer 200, every other method 405.
pub(crate) fn router(resource: &ProtectedResource) -> io::Result<Router> {
    let mut document = json!({
        "resource": resource.resource,
        "authorization_servers": resource.authorization_servers,
    });
    if !resource.scopes_supported.is_empty() {
        document["scopes_supported"] = json!(resource.scopes_supported);
    }
    document["bearer_methods_supported"] = json!(["header"]);
    let body = serde_json::to_vec(&document).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "the protected-resource metadata could not be serialised"))?;
    Ok(Router::new().route(&resource.metadata_path, any(handle)).with_state(Bytes::from(body)))
}

async fn handle(State(body): State<Bytes>, request: Request) -> Response {
    let method = request.method();
    if method != Method::GET && method != Method::HEAD {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
        response.headers_mut().insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
        return response;
    }
    let mut response = Response::new(Body::from(body));
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}
