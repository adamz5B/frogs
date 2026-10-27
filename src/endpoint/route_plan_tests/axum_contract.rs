//! Tripwires for the axum 0.7 / matchit 0.7 behaviours the route table, the
//! canonical request path and the shadow-security analysis are built on. These
//! use bare axum (none of frogs's wrappers), so after an axum or matchit upgrade
//! a failure here names the assumption that moved; the design notes are in
//! `docs/openapi32/m5-route-table-and-shadow-security.md` sections 1 and 6.

use axum::Router;
use axum::extract::Path as AxumPath;
use axum::routing::get;

use crate::server::raw_request;

async fn serve_bare(router: Router) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    addr
}

async fn fetch(addr: std::net::SocketAddr, method: &str, target: &str) -> (u16, String) {
    let request = format!("{method} {target} HTTP/1.1\r\nHost: frogs.test\r\nConnection: close\r\n\r\n");
    let (status_line, _headers, body, _closed) = raw_request(addr, request.as_bytes()).await;
    let status = status_line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// A route answering its own label, and a parameter route answering the decoded value it received.
fn labelled(label: &'static str) -> axum::routing::MethodRouter<()> {
    get(move || async move { label })
}

fn echo_param() -> axum::routing::MethodRouter<()> {
    get(|AxumPath(p): AxumPath<String>| async move { format!("param={p}") })
}

#[tokio::test]
async fn nest_flattens_its_routes_and_does_not_reserve_the_prefix_so_a_catch_all_answers_unmatched_paths_under_it() {
    // Why a secured operation without an endpoint file can be answered by static content even when `apiRoot` is set.
    let app = Router::new()
        .nest("/api", Router::new().route("/x", labelled("api-x")))
        .route("/*path", labelled("catch-all"));
    let addr = serve_bare(app).await;
    assert_eq!(fetch(addr, "GET", "/api/x").await, (200, "api-x".to_string()));
    assert_eq!(
        fetch(addr, "GET", "/api/y").await,
        (200, "catch-all".to_string()),
        "an unmatched path under the prefix falls through"
    );
    assert_eq!(fetch(addr, "GET", "/api").await, (200, "catch-all".to_string()), "so does the bare prefix");
    assert_eq!(fetch(addr, "GET", "/other").await, (200, "catch-all".to_string()));
}

#[tokio::test]
async fn a_matched_path_with_the_wrong_method_answers_405_and_never_falls_through_to_a_catch_all() {
    let app = Router::new()
        .nest("/api", Router::new().route("/x", labelled("api-x")))
        .route("/*path", labelled("catch-all"));
    let addr = serve_bare(app).await;
    assert_eq!(fetch(addr, "POST", "/api/x").await.0, 405);
    assert_eq!(fetch(addr, "POST", "/api/y").await.0, 405, "the catch-all route itself only registers GET");
}

#[tokio::test]
async fn a_literal_segment_is_matched_against_the_raw_wire_bytes_while_a_parameter_receives_the_decoded_value() {
    // Why every request path is canonicalised before routing and literal routes are registered percent-encoded.
    let raw = Router::new().route("/café/menu", labelled("literal")).route("/:p/menu", echo_param());
    let addr = serve_bare(raw).await;
    assert_eq!(
        fetch(addr, "GET", "/caf%C3%A9/menu").await,
        (200, "param=café".to_string()),
        "the encoded spelling misses a raw-registered literal"
    );
    assert_eq!(fetch(addr, "GET", "/café/menu").await, (200, "literal".to_string()), "the raw UTF-8 spelling hits it");

    let encoded = Router::new().route("/caf%C3%A9/menu", labelled("literal")).route("/:p/menu", echo_param());
    let addr = serve_bare(encoded).await;
    assert_eq!(
        fetch(addr, "GET", "/caf%C3%A9/menu").await,
        (200, "literal".to_string()),
        "registered in encoded form, the encoded spelling hits it"
    );
    assert_eq!(
        fetch(addr, "GET", "/caf%c3%a9/menu").await,
        (200, "param=café".to_string()),
        "a different hex case does not"
    );

    let percent = Router::new().route("/%41/x", labelled("literal-%41")).route("/:p/x", echo_param());
    let addr = serve_bare(percent).await;
    assert_eq!(
        fetch(addr, "GET", "/%41/x").await,
        (200, "literal-%41".to_string()),
        "a literal `%41` is matched as three bytes, not as `A`"
    );
    assert_eq!(fetch(addr, "GET", "/A/x").await, (200, "param=A".to_string()));
    assert_eq!(
        fetch(addr, "GET", "/%2541/x").await,
        (200, "param=%41".to_string()),
        "a parameter is decoded exactly once"
    );
}

#[tokio::test]
async fn a_literal_route_beats_a_sibling_parameter_route_whatever_the_registration_order() {
    for literal_first in [true, false] {
        let mut app = Router::new();
        if literal_first {
            app = app.route("/cars/admin", labelled("admin")).route("/cars/:id", echo_param());
        } else {
            app = app.route("/cars/:id", echo_param()).route("/cars/admin", labelled("admin"));
        }
        let addr = serve_bare(app).await;
        assert_eq!(fetch(addr, "GET", "/cars/admin").await, (200, "admin".to_string()), "literal_first={literal_first}");
        assert_eq!(
            fetch(addr, "GET", "/cars/other").await,
            (200, "param=other".to_string()),
            "literal_first={literal_first}"
        );
    }
}

#[test]
fn the_build_resolves_a_single_matchit_so_the_route_table_probe_matches_the_router_exactly() {
    // `RoutePlan` probes with the direct `matchit` dependency; if axum ever pulled a different matchit the probe would
    // answer a different question than the real router does.
    let lock = include_str!("../../../Cargo.lock");
    let versions: Vec<&str> = lock
        .split("[[package]]")
        .filter(|block| block.lines().any(|l| l.trim() == "name = \"matchit\""))
        .filter_map(|block| block.lines().find_map(|l| l.trim().strip_prefix("version = ")))
        .collect();
    assert_eq!(
        versions.len(),
        1,
        "expected exactly one matchit in Cargo.lock, found {versions:?} — re-verify the route table against axum's matcher"
    );
    assert_eq!(
        versions[0], "\"0.7.3\"",
        "matchit changed: re-run these contract tests and the route_plan fuzz, then update this pin"
    );
}
