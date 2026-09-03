use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use axum::Router;
use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use chrono::{DateTime, Utc};

use super::WebServeConfig;

/// Extension -> MIME type for what a hand-built static site actually ships.
/// Not exhaustive by design — anything not listed here falls back to
/// `application/octet-stream` rather than guessing, matching the "don't
/// build for hypothetical needs" ethos the rest of this project follows.
const MIME_TYPES: &[(&str, &str)] = &[
    ("html", "text/html; charset=utf-8"),
    ("htm", "text/html; charset=utf-8"),
    ("css", "text/css; charset=utf-8"),
    ("js", "text/javascript; charset=utf-8"),
    ("mjs", "text/javascript; charset=utf-8"),
    ("json", "application/json"),
    ("map", "application/json"),
    ("svg", "image/svg+xml"),
    ("png", "image/png"),
    ("jpg", "image/jpeg"),
    ("jpeg", "image/jpeg"),
    ("gif", "image/gif"),
    ("webp", "image/webp"),
    ("ico", "image/x-icon"),
    ("woff", "font/woff"),
    ("woff2", "font/woff2"),
    ("ttf", "font/ttf"),
    ("txt", "text/plain; charset=utf-8"),
    ("xml", "application/xml"),
    ("pdf", "application/pdf"),
    ("wasm", "application/wasm"),
];

const DEFAULT_MIME: &str = "application/octet-stream";

fn mime_for(path: &Path) -> &'static str {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return DEFAULT_MIME;
    };
    let ext = ext.to_ascii_lowercase();
    MIME_TYPES
        .iter()
        .find(|(candidate, _)| *candidate == ext)
        .map(|(_, mime)| *mime)
        .unwrap_or(DEFAULT_MIME)
}

/// Everything one static-serving router needs, baked in at startup —
/// mirrors `endpoint::RouteState`'s "build once, share across every
/// request" shape.
struct ServeState {
    root: PathBuf,
    /// Canonicalized once at startup; every request's resolved path is
    /// checked against this to catch a symlink inside `root` that points
    /// somewhere else on disk — `resolve_relative`'s own `..`-rejection
    /// only protects against traversal spelled out in the request path
    /// itself, not a link that resolves outside `root` from a single,
    /// otherwise-innocent-looking segment.
    canonical_root: PathBuf,
    /// `webserve.json` must never be served, no matter what path resolves
    /// to it — computed once so every request's containment check is a
    /// plain comparison instead of a fresh canonicalize + string compare.
    canonical_webserve_json: Option<PathBuf>,
    config: WebServeConfig,
}

/// Builds a router that serves `root` as a static site per `config`: `/`
/// resolves to `config.startPage`, everything else resolves directly to a
/// matching file on disk, and a request that doesn't resolve to a real,
/// contained file gets `config.notFoundPage` (if set and itself resolves)
/// or a generic 404.
pub fn router(root: PathBuf, config: WebServeConfig) -> Router {
    let canonical_root = std::fs::canonicalize(&root).unwrap_or_else(|_| root.clone());
    let canonical_webserve_json = std::fs::canonicalize(root.join("webserve.json")).ok();
    let state = Arc::new(ServeState {
        root,
        canonical_root,
        canonical_webserve_json,
        config,
    });

    Router::new().route("/", get(handle_root)).route("/*path", get(handle_path)).with_state(state)
}

async fn handle_root(State(state): State<Arc<ServeState>>, headers: HeaderMap) -> Response {
    let start_page = state.config.start_page.clone();
    serve(&state, &start_page, &headers)
}

async fn handle_path(State(state): State<Arc<ServeState>>, AxumPath(path): AxumPath<String>, headers: HeaderMap) -> Response {
    serve(&state, &path, &headers)
}

fn serve(state: &ServeState, relative: &str, headers: &HeaderMap) -> Response {
    match safe_existing_file(state, relative) {
        Some(path) => file_response(StatusCode::OK, &path, Some(headers)),
        // Conditional requests only make sense against real content — a
        // 404 (custom page or generic) is never itself cacheable.
        None => not_found_response(state),
    }
}

/// Joins `relative`'s segments onto `root` one at a time, rejecting a `..`
/// segment outright rather than ever letting one reach the filesystem —
/// axum's `Path` extractor already percent-decodes `relative` before this
/// runs, so this sees the real, final segments a request is asking for.
fn resolve_relative(root: &Path, relative: &str) -> Option<PathBuf> {
    let mut result = root.to_path_buf();
    for segment in relative.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." {
            return None;
        }
        result.push(segment);
    }
    Some(result)
}

/// Resolves `relative` to a real file strictly inside `state.root`, or
/// `None` if it doesn't exist, escapes `root` (via a symlink — see
/// `ServeState::canonical_root`), or is `webserve.json` itself.
fn safe_existing_file(state: &ServeState, relative: &str) -> Option<PathBuf> {
    let candidate = resolve_relative(&state.root, relative)?;
    let canonical = std::fs::canonicalize(&candidate).ok()?;
    if !canonical.is_file() {
        return None;
    }
    if !canonical.starts_with(&state.canonical_root) {
        return None;
    }
    if state.canonical_webserve_json.as_deref() == Some(canonical.as_path()) {
        return None;
    }
    Some(canonical)
}

/// A weak validator (mtime + size, like nginx/Apache's own defaults) — cheap
/// to compute from metadata alone, no file content read needed just to
/// answer a conditional request.
fn weak_etag(len: u64, modified: SystemTime) -> String {
    let secs = modified.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_secs();
    format!("W/\"{len:x}-{secs:x}\"")
}

/// RFC 7231 IMF-fixdate, the only HTTP-date format a response is allowed to
/// generate (chrono's `%a`/`%b` are always English abbreviations regardless
/// of system locale, which is exactly what this format requires).
fn http_date(time: SystemTime) -> String {
    let datetime: DateTime<Utc> = time.into();
    datetime.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

fn parse_http_date(value: &str) -> Option<DateTime<Utc>> {
    let naive = chrono::NaiveDateTime::parse_from_str(value, "%a, %d %b %Y %H:%M:%S GMT").ok()?;
    Some(DateTime::from_naive_utc_and_offset(naive, Utc))
}

/// Weak comparison per RFC 7232 §2.3.2: the `W/` prefix is stripped from
/// both sides before comparing, and `If-None-Match: *` always matches.
fn if_none_match_matches(header_value: &str, etag: &str) -> bool {
    fn strip_weak(tag: &str) -> &str {
        tag.strip_prefix("W/").unwrap_or(tag)
    }
    if header_value.trim() == "*" {
        return true;
    }
    header_value.split(',').any(|candidate| strip_weak(candidate.trim()) == strip_weak(etag))
}

fn insert_cache_headers(headers: &mut HeaderMap, etag: &str, last_modified: &str) {
    if let Ok(v) = HeaderValue::from_str(etag) {
        headers.insert(header::ETAG, v);
    }
    if let Ok(v) = HeaderValue::from_str(last_modified) {
        headers.insert(header::LAST_MODIFIED, v);
    }
}

fn not_modified_response(etag: &str, last_modified: &str) -> Response {
    let mut response = StatusCode::NOT_MODIFIED.into_response();
    insert_cache_headers(response.headers_mut(), etag, last_modified);
    response
}

/// Reads and serves `path`, honoring `If-None-Match`/`If-Modified-Since`
/// when `request_headers` is given. Per RFC 7232 §3.3, `If-None-Match` —
/// when present — is authoritative and `If-Modified-Since` is only
/// consulted as a fallback.
fn file_response(status: StatusCode, path: &Path, request_headers: Option<&HeaderMap>) -> Response {
    let cache = std::fs::metadata(path).ok().and_then(|meta| {
        let modified = meta.modified().ok()?;
        Some((weak_etag(meta.len(), modified), http_date(modified), modified))
    });

    if let (Some(request_headers), Some((etag, last_modified, modified))) = (request_headers, &cache) {
        let not_modified = if let Some(if_none_match) = request_headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) {
            if_none_match_matches(if_none_match, etag)
        } else if let Some(if_modified_since) = request_headers.get(header::IF_MODIFIED_SINCE).and_then(|v| v.to_str().ok()) {
            // HTTP-date only has second granularity, so both sides are
            // compared at that resolution.
            parse_http_date(if_modified_since).is_some_and(|client_date| DateTime::<Utc>::from(*modified).timestamp() <= client_date.timestamp())
        } else {
            false
        };

        if not_modified {
            return not_modified_response(etag, last_modified);
        }
    }

    match std::fs::read(path) {
        Ok(bytes) => {
            let mut response = (status, [(header::CONTENT_TYPE, mime_for(path))], bytes).into_response();
            if let Some((etag, last_modified, _)) = &cache {
                insert_cache_headers(response.headers_mut(), etag, last_modified);
            }
            response
        }
        Err(e) => {
            tracing::warn!("failed to read {}: {e}", path.display());
            (StatusCode::INTERNAL_SERVER_ERROR, "failed to read file").into_response()
        }
    }
}

fn not_found_response(state: &ServeState) -> Response {
    if let Some(page) = &state.config.not_found_page
        && let Some(path) = safe_existing_file(state, page)
    {
        return file_response(StatusCode::NOT_FOUND, &path, None);
    }
    (StatusCode::NOT_FOUND, [(header::CONTENT_TYPE, "text/plain; charset=utf-8")], "404 Not Found").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn temp_site() -> PathBuf {
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "frogs-webserve-serve-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    async fn spawn(router: Router) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        addr
    }

    #[test]
    fn mime_for_known_extensions() {
        assert_eq!(mime_for(Path::new("index.html")), "text/html; charset=utf-8");
        assert_eq!(mime_for(Path::new("app.JS")), "text/javascript; charset=utf-8");
        assert_eq!(mime_for(Path::new("photo.PNG")), "image/png");
    }

    #[test]
    fn mime_for_unknown_extension_falls_back_to_octet_stream() {
        assert_eq!(mime_for(Path::new("data.bin")), DEFAULT_MIME);
        assert_eq!(mime_for(Path::new("no_extension")), DEFAULT_MIME);
    }

    #[test]
    fn resolve_relative_rejects_a_dot_dot_segment() {
        let root = Path::new("/site");
        assert_eq!(resolve_relative(root, "../secret.txt"), None);
        assert_eq!(resolve_relative(root, "css/../../secret.txt"), None);
    }

    #[test]
    fn resolve_relative_joins_plain_segments_onto_root() {
        let root = Path::new("/site");
        assert_eq!(resolve_relative(root, "css/style.css"), Some(root.join("css").join("style.css")));
        assert_eq!(resolve_relative(root, "/index.html"), Some(root.join("index.html")));
    }

    #[tokio::test]
    async fn serves_the_start_page_at_root() {
        let dir = temp_site();
        std::fs::write(dir.join("index.html"), "<html>hi</html>").unwrap();
        let config = WebServeConfig {
            start_page: "index.html".to_string(),
            port: 8080,
            not_found_page: None,
            tls: Default::default(),
        };
        let addr = spawn(router(dir.clone(), config)).await;

        let response = reqwest::get(format!("http://{addr}/")).await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers().get(header::CONTENT_TYPE).unwrap(), "text/html; charset=utf-8");
        assert_eq!(response.text().await.unwrap(), "<html>hi</html>");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn serves_a_nested_file_by_its_own_path() {
        let dir = temp_site();
        std::fs::write(dir.join("index.html"), "home").unwrap();
        std::fs::create_dir_all(dir.join("css")).unwrap();
        std::fs::write(dir.join("css/style.css"), "body { color: red; }").unwrap();
        let config = WebServeConfig {
            start_page: "index.html".to_string(),
            port: 8080,
            not_found_page: None,
            tls: Default::default(),
        };
        let addr = spawn(router(dir.clone(), config)).await;

        let response = reqwest::get(format!("http://{addr}/css/style.css")).await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers().get(header::CONTENT_TYPE).unwrap(), "text/css; charset=utf-8");
        assert_eq!(response.text().await.unwrap(), "body { color: red; }");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_missing_file_with_no_not_found_page_gets_a_generic_404() {
        let dir = temp_site();
        std::fs::write(dir.join("index.html"), "home").unwrap();
        let config = WebServeConfig {
            start_page: "index.html".to_string(),
            port: 8080,
            not_found_page: None,
            tls: Default::default(),
        };
        let addr = spawn(router(dir.clone(), config)).await;

        let response = reqwest::get(format!("http://{addr}/nope.html")).await.unwrap();
        assert_eq!(response.status(), 404);
        assert_eq!(response.text().await.unwrap(), "404 Not Found");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_missing_file_with_a_custom_not_found_page_serves_it_with_404_status() {
        let dir = temp_site();
        std::fs::write(dir.join("index.html"), "home").unwrap();
        std::fs::write(dir.join("404.html"), "<html>not here</html>").unwrap();
        let config = WebServeConfig {
            start_page: "index.html".to_string(),
            port: 8080,
            not_found_page: Some("404.html".to_string()),
            tls: Default::default(),
        };
        let addr = spawn(router(dir.clone(), config)).await;

        let response = reqwest::get(format!("http://{addr}/nope.html")).await.unwrap();
        assert_eq!(response.status(), 404);
        assert_eq!(response.headers().get(header::CONTENT_TYPE).unwrap(), "text/html; charset=utf-8");
        assert_eq!(response.text().await.unwrap(), "<html>not here</html>");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_path_traversal_attempt_is_never_served() {
        // `reqwest` (like a browser) normalizes `..` segments out of a URL
        // during parsing, before the request is ever sent — so a request
        // built through `reqwest::get` can't actually exercise the server's
        // own guard against a raw `..` in the request line. A raw TCP
        // request bypasses that client-side normalization, proving
        // `resolve_relative`'s rejection (not the HTTP client) is what's
        // stopping this.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let dir = temp_site();
        std::fs::write(dir.join("index.html"), "home").unwrap();
        // A real file that must stay unreachable, sitting right outside the
        // served root — proves containment, not just the `..` string check.
        std::fs::write(dir.join("../frogs-webserve-outside-secret.txt"), "top secret").unwrap();
        let config = WebServeConfig {
            start_page: "index.html".to_string(),
            port: 8080,
            not_found_page: None,
            tls: Default::default(),
        };
        let addr = spawn(router(dir.clone(), config)).await;

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /../frogs-webserve-outside-secret.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 404"), "expected a 404, got: {response}");
        assert!(!response.contains("top secret"), "the outside file's content must never be served");

        let _ = std::fs::remove_file(dir.join("../frogs-webserve-outside-secret.txt"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn webserve_json_itself_is_never_served() {
        let dir = temp_site();
        std::fs::write(dir.join("index.html"), "home").unwrap();
        std::fs::write(dir.join("webserve.json"), r#"{"startPage":"index.html"}"#).unwrap();
        let config = WebServeConfig {
            start_page: "index.html".to_string(),
            port: 8080,
            not_found_page: None,
            tls: Default::default(),
        };
        let addr = spawn(router(dir.clone(), config)).await;

        let response = reqwest::get(format!("http://{addr}/webserve.json")).await.unwrap();
        assert_eq!(response.status(), 404);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn requesting_a_directory_is_treated_as_not_found() {
        let dir = temp_site();
        std::fs::write(dir.join("index.html"), "home").unwrap();
        std::fs::create_dir_all(dir.join("css")).unwrap();
        let config = WebServeConfig {
            start_page: "index.html".to_string(),
            port: 8080,
            not_found_page: None,
            tls: Default::default(),
        };
        let addr = spawn(router(dir.clone(), config)).await;

        let response = reqwest::get(format!("http://{addr}/css")).await.unwrap();
        assert_eq!(response.status(), 404);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn weak_etag_format() {
        let modified = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(0x5f);
        assert_eq!(weak_etag(0x10, modified), "W/\"10-5f\"");
    }

    #[test]
    fn http_date_uses_english_rfc7231_imf_fixdate_format() {
        // 2024-01-06 is a Saturday — proves the weekday/month names come out
        // right, not just the numeric fields.
        let modified = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_704_531_045);
        assert_eq!(http_date(modified), "Sat, 06 Jan 2024 08:50:45 GMT");
    }

    #[test]
    fn parse_http_date_round_trips_with_http_date() {
        let modified = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_704_531_045);
        let formatted = http_date(modified);
        let parsed = parse_http_date(&formatted).unwrap();
        assert_eq!(parsed.timestamp(), 1_704_531_045);
    }

    #[test]
    fn if_none_match_matches_a_star_wildcard() {
        assert!(if_none_match_matches("*", "W/\"1-2\""));
    }

    #[test]
    fn if_none_match_ignores_the_weak_prefix_on_both_sides() {
        assert!(if_none_match_matches("\"1-2\"", "W/\"1-2\""));
        assert!(if_none_match_matches("W/\"1-2\", \"3-4\"", "W/\"1-2\""));
        assert!(!if_none_match_matches("\"9-9\"", "W/\"1-2\""));
    }

    #[tokio::test]
    async fn a_fresh_request_gets_etag_and_last_modified_headers() {
        let dir = temp_site();
        std::fs::write(dir.join("index.html"), "home").unwrap();
        let config = WebServeConfig {
            start_page: "index.html".to_string(),
            port: 8080,
            not_found_page: None,
            tls: Default::default(),
        };
        let addr = spawn(router(dir.clone(), config)).await;

        let response = reqwest::get(format!("http://{addr}/")).await.unwrap();
        assert_eq!(response.status(), 200);
        let etag = response.headers().get(header::ETAG).expect("ETag must be present").to_str().unwrap().to_string();
        assert!(etag.starts_with("W/\""), "expected a weak ETag, got {etag}");
        assert!(response.headers().get(header::LAST_MODIFIED).is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_matching_if_none_match_gets_a_304_with_no_body() {
        let dir = temp_site();
        std::fs::write(dir.join("index.html"), "home").unwrap();
        let config = WebServeConfig {
            start_page: "index.html".to_string(),
            port: 8080,
            not_found_page: None,
            tls: Default::default(),
        };
        let addr = spawn(router(dir.clone(), config)).await;
        let client = reqwest::Client::new();

        let first = client.get(format!("http://{addr}/")).send().await.unwrap();
        let etag = first.headers().get(header::ETAG).unwrap().to_str().unwrap().to_string();

        let second = client.get(format!("http://{addr}/")).header(header::IF_NONE_MATCH, &etag).send().await.unwrap();
        assert_eq!(second.status(), 304);
        assert_eq!(second.headers().get(header::ETAG).unwrap().to_str().unwrap(), etag);
        assert!(second.bytes().await.unwrap().is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_non_matching_if_none_match_gets_a_fresh_200() {
        let dir = temp_site();
        std::fs::write(dir.join("index.html"), "home").unwrap();
        let config = WebServeConfig {
            start_page: "index.html".to_string(),
            port: 8080,
            not_found_page: None,
            tls: Default::default(),
        };
        let addr = spawn(router(dir.clone(), config)).await;
        let client = reqwest::Client::new();

        let response = client
            .get(format!("http://{addr}/"))
            .header(header::IF_NONE_MATCH, "\"not-the-real-tag\"")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.text().await.unwrap(), "home");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_matching_if_modified_since_gets_a_304() {
        let dir = temp_site();
        std::fs::write(dir.join("index.html"), "home").unwrap();
        let config = WebServeConfig {
            start_page: "index.html".to_string(),
            port: 8080,
            not_found_page: None,
            tls: Default::default(),
        };
        let addr = spawn(router(dir.clone(), config)).await;
        let client = reqwest::Client::new();

        let first = client.get(format!("http://{addr}/")).send().await.unwrap();
        let last_modified = first.headers().get(header::LAST_MODIFIED).unwrap().to_str().unwrap().to_string();

        let second = client
            .get(format!("http://{addr}/"))
            .header(header::IF_MODIFIED_SINCE, &last_modified)
            .send()
            .await
            .unwrap();
        assert_eq!(second.status(), 304);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn an_if_modified_since_from_before_the_files_mtime_gets_a_fresh_200() {
        let dir = temp_site();
        std::fs::write(dir.join("index.html"), "home").unwrap();
        let config = WebServeConfig {
            start_page: "index.html".to_string(),
            port: 8080,
            not_found_page: None,
            tls: Default::default(),
        };
        let addr = spawn(router(dir.clone(), config)).await;
        let client = reqwest::Client::new();

        let response = client
            .get(format!("http://{addr}/"))
            .header(header::IF_MODIFIED_SINCE, "Thu, 01 Jan 1970 00:00:00 GMT")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.text().await.unwrap(), "home");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn if_none_match_takes_precedence_over_if_modified_since() {
        // RFC 7232 §3.3: If-Modified-Since must be ignored whenever
        // If-None-Match is present, even if If-None-Match itself doesn't
        // match — a stale If-None-Match must not fall back to a (possibly
        // matching) If-Modified-Since and produce a false 304.
        let dir = temp_site();
        std::fs::write(dir.join("index.html"), "home").unwrap();
        let config = WebServeConfig {
            start_page: "index.html".to_string(),
            port: 8080,
            not_found_page: None,
            tls: Default::default(),
        };
        let addr = spawn(router(dir.clone(), config)).await;
        let client = reqwest::Client::new();

        let first = client.get(format!("http://{addr}/")).send().await.unwrap();
        let last_modified = first.headers().get(header::LAST_MODIFIED).unwrap().to_str().unwrap().to_string();

        let second = client
            .get(format!("http://{addr}/"))
            .header(header::IF_NONE_MATCH, "\"not-the-real-tag\"")
            .header(header::IF_MODIFIED_SINCE, &last_modified)
            .send()
            .await
            .unwrap();
        assert_eq!(second.status(), 200);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
