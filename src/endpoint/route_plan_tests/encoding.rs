//! Percent-encoding canonicalisation: the registered route paths, the probe, the
//! served stack (`CanonicalPath`) and the web / control-plane shadow checks must
//! all agree on one spelling per resource.

use super::security::{SEC_A, analyse, analyse_ctx, counts, fixed, shadow_messages, spec};
use super::*;
use crate::openapi::path_encoding::encode_literal_segment;
use crate::openapi::path_rules::{PortabilityPolicy, validate_path};
use crate::openapi::route_syntax::{axum_registration_path, classify_route_segment, probe_path};
use crate::server::{raw_request, spawn_served};
use axum::extract::Path as AxumPath;

// ------------------------------------------------------------------ helpers

async fn fetch(addr: std::net::SocketAddr, target: &str) -> (u16, String) {
    fetch_with(addr, "GET", target).await
}

async fn fetch_with(addr: std::net::SocketAddr, method: &str, target: &str) -> (u16, String) {
    let request = format!("{method} {target} HTTP/1.1\r\nHost: frogs.test\r\nConnection: close\r\n\r\n");
    let (status_line, _headers, body, _closed) = raw_request(addr, request.as_bytes()).await;
    let status = status_line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    (status, String::from_utf8_lossy(&body).into_owned())
}

fn labeled(label: &str) -> MethodRouter<()> {
    let label = label.to_string();
    get(move || {
        let label = label.clone();
        async move { label }
    })
}

/// A router registering each `url_path` (axum style, decoded literals) the way `build_router` does, answering with the path itself.
fn registered_router(url_paths: &[&str]) -> Router {
    let mut router = Router::new();
    for path in url_paths {
        router = router.route(&axum_registration_path(path), labeled(path));
    }
    router
}

fn site_config() -> crate::webserve::WebServeConfig {
    serde_json::from_str(r#"{ "startPage": "index.html" }"#).unwrap()
}

// ------------------------------------------------------- route_syntax / rules

#[test]
fn a_percent_sign_in_any_route_segment_is_not_a_valid_route_segment() {
    for seg in ["%41", "a%20b", "%", "{a%b}", "x%"] {
        assert!(classify_route_segment(seg).is_err(), "{seg}");
    }
    assert!(classify_route_segment("café").is_ok());
}

#[test]
fn a_spec_path_with_a_percent_sign_is_an_unsafe_path_under_both_portability_policies() {
    for policy in [PortabilityPolicy::Skip, PortabilityPolicy::Warn] {
        for path in ["/a%20b", "/%41", "/x/{a%b}"] {
            let result = validate_path(path, policy);
            assert!(
                matches!(&result, Err((crate::openapi::IssueKind::UnsafePath, _))),
                "{path} under {policy:?}: {:?}",
                result.as_ref().map(|_| ()).map_err(|(k, m)| (format!("{k:?}"), m.clone()))
            );
        }
    }
}

#[test]
fn the_probe_encodes_literal_segments_and_refuses_a_percent_sign() {
    assert_eq!(probe_path("/café/menu").unwrap(), "/caf%C3%A9/menu");
    assert_eq!(probe_path("/q\"t/{id}").unwrap(), "/q%22t/:frogs-probe");
    assert_eq!(probe_path("/a b/x").unwrap(), "/a%20b/x");
    assert!(probe_path("/a%41").is_err());
    assert!(probe_path("/%").is_err());
}

#[test]
fn axum_registration_path_encodes_literals_and_leaves_parameters_alone() {
    assert_eq!(axum_registration_path("/café/:id/x.{ext}"), "/caf%C3%A9/:id/x.%7Bext%7D");
    assert_eq!(axum_registration_path("/"), "/");
    assert_eq!(axum_registration_path("/a/:b"), "/a/:b");
    assert_eq!(axum_registration_path("/v1;x/:id"), "/v1;x/:id");
}

#[test]
fn a_folder_with_a_percent_sign_is_unroutable_and_excluded() {
    let inventory = inv(&[("%41", "get")]);
    let plan = RoutePlan::from_inventory(&inventory, &endpoints_only());
    assert!(has_kind(&plan, RouteProblemKind::Unroutable), "{:?}", plan.problems);
    assert!(plan.problems.iter().any(|p| p.is_refusal(false)));
    assert!(plan.is_excluded(&inventory.entries[0].url_path));
}

#[test]
fn an_api_root_or_docs_path_with_a_non_pchar_character_is_an_invalid_config_route_and_a_plain_pchar_is_accepted() {
    for bad in ["apí", "a b", "a%20b", "a\"b", "/api/a b"] {
        let ctx = RouteContext {
            api_root: bad.to_string(),
            ..api_ctx()
        };
        let plan = RoutePlan::from_inventory(&inv(&[("x", "get")]), &ctx);
        assert!(has_kind(&plan, RouteProblemKind::InvalidConfigRoute), "apiRoot {bad:?}: {:?}", plan.problems);
        let ctx = RouteContext {
            docs: true,
            docs_path: bad.to_string(),
            ..api_ctx()
        };
        let plan = RoutePlan::from_inventory(&inv(&[("x", "get")]), &ctx);
        assert!(has_kind(&plan, RouteProblemKind::InvalidConfigRoute), "docsUi.path {bad:?}: {:?}", plan.problems);
    }
    let ctx = RouteContext {
        api_root: "v1;x".to_string(),
        docs: true,
        docs_path: "d;x".to_string(),
        ..api_ctx()
    };
    let plan = RoutePlan::from_inventory(&inv(&[("x", "get")]), &ctx);
    assert!(!has_kind(&plan, RouteProblemKind::InvalidConfigRoute), "{:?}", plan.problems);
}

#[test]
fn a_planned_literal_route_is_registered_percent_encoded_while_keeping_its_decoded_path() {
    let plan = RoutePlan::from_inventory(&inv(&[("café/{id}", "get")]), &endpoints_only());
    let route = plan.routes.iter().find(|r| !r.files.is_empty()).unwrap();
    assert_eq!(route.path, "/café/:id");
    assert_eq!(route.registered, "/caf%C3%A9/:id");
    assert_eq!(plan.resolve(&probe_path("/café/x").unwrap()).unwrap().path, "/café/:id");
}

fn web_ctx(api_root: &str) -> RouteContext {
    RouteContext {
        api_root: api_root.to_string(),
        extras: RootExtras { web: true, control_plane: false },
        ..api_ctx()
    }
}

fn cp_ctx(api_root: &str) -> RouteContext {
    RouteContext {
        api_root: api_root.to_string(),
        extras: RootExtras { web: false, control_plane: true },
        ..api_ctx()
    }
}

#[test]
fn with_the_web_role_an_unfiled_path_resolves_to_the_static_catch_all_even_under_an_api_root() {
    for api_root in ["", "/api"] {
        let plan = RoutePlan::from_inventory(&inv(&[("cars", "get")]), &web_ctx(api_root));
        let hit = plan.resolve("/unfiled").unwrap_or_else(|| panic!("apiRoot {api_root:?}: nothing resolved"));
        assert_eq!(hit.builtin.as_ref().map(|b| b.remedy), Some(BuiltinRemedy::StaticContent), "apiRoot {api_root:?}");
        let deep = plan.resolve("/a/b/c/d/e/f/g/h/i").expect("deeper than any endpoint must still reach the catch-all");
        assert!(deep.builtin.is_some());
        let own = plan.resolve("/cars").unwrap();
        assert!(!own.files.is_empty(), "a filed endpoint beats the catch-all");
    }
    let no_web = RoutePlan::from_inventory(
        &inv(&[("cars", "get")]),
        &RouteContext {
            api_root: "/api".into(),
            ..api_ctx()
        },
    );
    assert!(no_web.resolve("/unfiled").is_none());
}

#[test]
fn the_control_plane_route_is_at_the_server_root_whatever_the_api_root_is() {
    let at = |api_root: &str, probe: &str| {
        let plan = RoutePlan::from_inventory(&inv(&[("x", "get")]), &cp_ctx(api_root));
        plan.resolve(probe).and_then(|r| r.builtin.as_ref().map(|b| b.remedy))
    };
    assert_eq!(at("", "/_frogs/scenario"), Some(BuiltinRemedy::ControlPlane));
    assert_eq!(at("/_frogs", "/scenario"), Some(BuiltinRemedy::ControlPlane));
    assert_eq!(at("/api", "/_frogs/scenario"), None);
}

// ------------------------------------------------ differential: probe == axum

const FIRST: [&str; 6] = ["café", "a b", "q\"t", "A", "日本", "{p}"];
const SECOND: [Option<&str>; 3] = [None, Some("menu"), Some("{id}")];

fn spelling_variants(lit: &str, state: &mut u64) -> Vec<(String, bool)> {
    let bytes = lit.as_bytes();
    let canonical = encode_literal_segment(lit).into_owned();
    let lower: String = {
        let mut out = String::new();
        let mut chars = canonical.chars().peekable();
        while let Some(c) = chars.next() {
            out.push(c);
            if c == '%' {
                for _ in 0..2 {
                    if let Some(h) = chars.next() {
                        out.push(h.to_ascii_lowercase());
                    }
                }
            }
        }
        out
    };
    let all_encoded: String = bytes.iter().map(|b| format!("%{b:02X}")).collect();
    let mixed: String = bytes
        .iter()
        .map(|b| match lcg(state) % 3 {
            0 => format!("%{b:02X}"),
            1 if b.is_ascii_alphanumeric() => format!("%{b:02x}"),
            _ if b.is_ascii() && !b.is_ascii_alphanumeric() => format!("%{b:02x}"),
            _ => format!("%{b:02X}"),
        })
        .collect();
    // The bool marks the raw spelling: hyper may legitimately reject it with 400.
    vec![(canonical, false), (lower, false), (all_encoded, false), (mixed, false), (lit.to_string(), true)]
}

fn plan_label(route: &route_plan::PlannedRoute) -> String {
    match route.builtin.as_ref().map(|b| b.remedy) {
        Some(BuiltinRemedy::StaticContent) => "web".to_string(),
        Some(_) => "healthz".to_string(),
        None => route.path.clone(),
    }
}

#[tokio::test]
async fn the_probe_resolves_every_spelling_of_a_literal_path_to_the_route_the_served_stack_really_picks() {
    let mut served = 0usize;
    let mut compared = 0usize;
    let mut literal_hits = 0usize;
    for seed in 0..120u64 {
        let mut state = seed.wrapping_mul(0x9E37).wrapping_add(11);
        let mut folders: Vec<String> = Vec::new();
        for first in FIRST {
            for second in SECOND {
                if lcg(&mut state).is_multiple_of(2) {
                    folders.push(match second {
                        Some(s) => format!("{first}/{s}"),
                        None => first.to_string(),
                    });
                }
            }
        }
        if folders.is_empty() {
            continue;
        }
        let api_root = if lcg(&mut state).is_multiple_of(2) { "/api" } else { "" };
        let web = lcg(&mut state).is_multiple_of(2);
        let ctx = RouteContext {
            api_root: api_root.to_string(),
            extras: RootExtras { web, control_plane: false },
            ..api_ctx()
        };
        let pairs: Vec<(&str, &str)> = folders.iter().map(|f| (f.as_str(), "get")).collect();
        let inventory = inv(&pairs);
        let plan = RoutePlan::from_inventory(&inventory, &ctx);
        if !plan.refusals(false).is_empty() {
            continue;
        }
        served += 1;

        let mut endpoint_router = Router::new().route("/healthz", labeled("healthz"));
        for e in &inventory.entries {
            endpoint_router = endpoint_router.route(&axum_registration_path(&e.url_path), labeled(&e.url_path));
        }
        let mut router = crate::server::mount_under(endpoint_router, api_root);
        if web {
            router = router.merge(Router::new().route("/", labeled("web")).route("/*path", labeled("web")));
        }
        let addr = spawn_served(router, false).await;

        for folder in &folders {
            let segments: Vec<&str> = folder.split('/').collect();
            let spec_path = format!("/{folder}");
            let probe = probe_path(&spec_path).unwrap();
            let expected = plan.resolve(&probe).map(plan_label);
            // Every combination of one spelling per literal segment (spellings picked per variant index).
            let per_segment: Vec<Vec<(String, bool)>> = segments
                .iter()
                .map(|s| {
                    if s.starts_with('{') {
                        vec![("zz".to_string(), false); 5]
                    } else {
                        spelling_variants(s, &mut state)
                    }
                })
                .collect();
            for variant in 0..5 {
                let wire_path: Vec<&str> = per_segment.iter().map(|v| v[variant].0.as_str()).collect();
                let raw = per_segment.iter().any(|v| v[variant].1);
                let (status, body) = fetch(addr, &format!("{api_root}/{}", wire_path.join("/"))).await;
                if raw && (status == 400 || status == 0) {
                    continue;
                }
                compared += 1;
                match &expected {
                    Some(label) => {
                        assert_eq!(
                            (status, body.as_str()),
                            (200, label.as_str()),
                            "seed {seed} api {api_root:?} web {web} folder {folder:?} wire {wire_path:?}"
                        );
                        if !label.contains(':') && label != "web" {
                            literal_hits += 1;
                        }
                    }
                    None => assert_eq!(status, 404, "seed {seed} folder {folder:?} wire {wire_path:?} body {body:?}"),
                }
            }
        }
        for stray in ["/unfiled", "/zzz/menu", "/a/b/c/d/e/f"] {
            let probe = probe_path(stray).unwrap();
            let expected = plan.resolve(&probe).map(plan_label);
            let (status, body) = fetch(addr, &format!("{api_root}{stray}")).await;
            match expected {
                Some(label) => assert_eq!((status, body), (200, label), "seed {seed} api {api_root:?} web {web} stray {stray}"),
                None => assert_eq!(status, 404, "seed {seed} api {api_root:?} web {web} stray {stray}"),
            }
        }
    }
    assert!(
        served > 40 && compared > 400 && literal_hits > 100,
        "weak fuzz: served {served}, compared {compared}, literal hits {literal_hits}"
    );
}

// -------------------------------------------------- served stack, real bytes

#[tokio::test]
async fn every_spelling_of_a_literal_route_reaches_it_and_never_the_sibling_parameter_route() {
    let addr = spawn_served(registered_router(&["/café/menu", "/:p/menu"]), false).await;
    for target in ["/caf%C3%A9/menu", "/caf%c3%a9/menu", "/caf%C3%a9/menu", "/café/menu", "/%63af%C3%A9/menu"] {
        assert_eq!(fetch(addr, target).await, (200, "/café/menu".to_string()), "{target}");
    }
    assert_eq!(fetch(addr, "/cafe/menu").await, (200, "/:p/menu".to_string()));
}

#[tokio::test]
async fn a_literal_folder_with_a_space_is_matched_by_its_encoded_spelling_and_a_raw_space_is_rejected() {
    let addr = spawn_served(registered_router(&["/a b/x", "/:p/x"]), false).await;
    assert_eq!(fetch(addr, "/a%20b/x").await, (200, "/a b/x".to_string()));
    assert_eq!(fetch(addr, "/a%20B/x").await, (200, "/:p/x".to_string()), "%20B is a different segment (a B)");
    assert!(
        matches!(fetch(addr, "/a b/x").await.0, 0 | 400),
        "a raw space in the request target must be rejected, never routed"
    );
}

#[tokio::test]
async fn an_encoded_unreserved_character_names_the_literal_and_a_double_encoded_one_is_a_parameter_value() {
    let router = registered_router(&["/A/x"]).route("/:p/x", get(|AxumPath(p): AxumPath<String>| async move { format!("param:{p}") }));
    let addr = spawn_served(router, false).await;
    assert_eq!(fetch(addr, "/%41/x").await, (200, "/A/x".to_string()));
    assert_eq!(fetch(addr, "/A/x").await, (200, "/A/x".to_string()));
    assert_eq!(fetch(addr, "/%2541/x").await, (200, "param:%41".to_string()));
}

#[tokio::test]
async fn a_literal_folder_containing_a_quote_matches_raw_and_percent_encoded_requests() {
    let addr = spawn_served(registered_router(&["/q\"t/x", "/:p/x"]), false).await;
    assert_eq!(fetch(addr, "/q%22t/x").await, (200, "/q\"t/x".to_string()));
    let (raw_status, raw_body) = fetch(addr, "/q\"t/x").await;
    assert!(
        matches!(raw_status, 0 | 400) || (raw_status, raw_body.as_str()) == (200, "/q\"t/x"),
        "{raw_status} {raw_body}"
    );
}

#[tokio::test]
async fn parameter_values_reach_the_handler_exactly_as_axum_decodes_them_without_canonicalisation_side_effects() {
    let router = Router::new().route("/v/:p", get(|AxumPath(p): AxumPath<String>| async move { p }));
    let addr = spawn_served(router, false).await;
    for (target, expected) in [
        ("/v/a%2Fb", "a/b"),
        ("/v/a%2fb", "a/b"),
        ("/v/%2E%2E", ".."),
        ("/v/%2e%2e", ".."),
        ("/v/%zz", "%zz"),
        ("/v/%25zz", "%zz"),
        ("/v/%41", "A"),
        ("/v/caf%C3%A9", "café"),
    ] {
        assert_eq!(fetch(addr, target).await, (200, expected.to_string()), "{target}");
    }
}

#[tokio::test]
async fn the_query_string_reaches_the_handler_byte_identical_even_when_the_path_is_rewritten() {
    let router = Router::new().route(
        &axum_registration_path("/café"),
        get(|axum::extract::RawQuery(q): axum::extract::RawQuery| async move { q.unwrap_or_else(|| "<none>".to_string()) }),
    );
    let addr = spawn_served(router, false).await;
    assert_eq!(fetch(addr, "/caf%c3%a9?a=%41&b=caf%C3%A9&c=%zz").await, (200, "a=%41&b=caf%C3%A9&c=%zz".to_string()));
    assert_eq!(fetch(addr, "/caf%C3%A9").await, (200, "<none>".to_string()));
}

#[tokio::test]
async fn an_absolute_form_request_target_is_canonicalised_like_an_origin_form_one() {
    let addr = spawn_served(registered_router(&["/café/menu", "/:p/menu"]), false).await;
    assert_eq!(fetch(addr, "http://h/caf%c3%a9/menu").await, (200, "/café/menu".to_string()));
}

#[tokio::test]
async fn an_asterisk_form_request_and_a_lowercase_method_do_not_break_the_stack() {
    let addr = spawn_served(registered_router(&["/x"]), false).await;
    let (status_line, _, _, _) = raw_request(addr, b"OPTIONS * HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n").await;
    assert!(status_line.starts_with("HTTP/1.1 "), "{status_line}");
    assert_eq!(
        fetch_with(addr, "get", "/x").await,
        (200, "/x".to_string()),
        "lowercase method normalisation still applies"
    );
    assert_eq!(fetch(addr, "/x").await.0, 200, "the server survived");
}

// ------------------------------------------------- static traversal (web role)

struct Site {
    base: PathBuf,
    root: PathBuf,
}

impl Drop for Site {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

fn site() -> Site {
    let base = temp_root("site");
    let root = base.join("site");
    std::fs::create_dir_all(root.join("a")).unwrap();
    std::fs::write(base.join("secret.txt"), "TOPSECRET").unwrap();
    std::fs::write(root.join("index.html"), "INDEX").unwrap();
    std::fs::write(root.join("café.txt"), "CAFE").unwrap();
    Site { base, root }
}

#[tokio::test]
async fn encoded_dot_dot_traversal_never_serves_a_file_outside_the_site_root_in_either_role() {
    let site = site();
    let web = crate::webserve::router(site.root.clone(), site_config(), crate::webserve::ProtectedPaths::default());
    let both = crate::server::mount_under(registered_router(&["/ping"]), "/api").merge(crate::webserve::router(
        site.root.clone(),
        site_config(),
        crate::webserve::ProtectedPaths::default(),
    ));
    for router in [web, both] {
        let addr = spawn_served(router, false).await;
        for target in [
            "/%2E%2E/secret.txt",
            "/%2e%2e/secret.txt",
            "/a/%2e%2e/%2e%2e/secret.txt",
            "/..%2Fsecret.txt",
            "/%2E%2E%2Fsecret.txt",
            "/..%5Csecret.txt",
            "/../secret.txt",
            "/a/../../secret.txt",
            "/%252E%252E/secret.txt",
        ] {
            let (status, body) = fetch(addr, target).await;
            assert!(!body.contains("TOPSECRET"), "{target} leaked the secret");
            assert_eq!(status, 404, "{target}");
        }
        assert_eq!(fetch(addr, "/index.html").await, (200, "INDEX".to_string()));
    }
}

#[tokio::test]
async fn a_non_ascii_static_file_is_served_from_every_encoded_spelling() {
    let site = site();
    let addr = spawn_served(
        crate::webserve::router(site.root.clone(), site_config(), crate::webserve::ProtectedPaths::default()),
        false,
    )
    .await;
    for target in ["/caf%C3%A9.txt", "/caf%c3%a9.txt", "/caf%C3%a9.txt"] {
        assert_eq!(fetch(addr, target).await, (200, "CAFE".to_string()), "{target}");
    }
    let (status, body) = fetch(addr, "/café.txt").await;
    assert!(matches!(status, 0 | 400) || (status, body.as_str()) == (200, "CAFE"), "{status} {body}");
}

// --------------------------------------------- build_router through the stack

fn status_endpoint(status: u16) -> String {
    format!(r#"{{ "operationId": "x", "successStatus": {status}, "sources": {{}}, "response": {{}} }}"#)
}

#[tokio::test]
async fn build_router_registers_a_non_ascii_folder_so_every_spelling_beats_the_sibling_parameter_route() {
    let root = temp_root("served-cafe");
    let _cleanup = Cleanup(root.clone());
    write_endpoint(&root, "café/menu", "get", &status_endpoint(201));
    write_endpoint(&root, "{p}/menu", "get", &status_endpoint(202));
    write_endpoint(&root, "a b/x", "get", &status_endpoint(203));
    write_endpoint(&root, "A/y", "get", &status_endpoint(204));
    write_endpoint(&root, "{p}/y", "get", &status_endpoint(205));
    let addr = spawn_served(router_for(&root), false).await;
    for target in ["/caf%C3%A9/menu", "/caf%c3%a9/menu", "/café/menu"] {
        assert_eq!(fetch(addr, target).await.0, 201, "{target}");
    }
    assert_eq!(fetch(addr, "/cafe/menu").await.0, 202);
    assert_eq!(fetch(addr, "/a%20b/x").await.0, 203);
    assert!(
        matches!(fetch(addr, "/a b/x").await.0, 0 | 400),
        "a raw space in the request target must be rejected, never routed"
    );
    assert_eq!(fetch(addr, "/%41/y").await.0, 204);
    assert_eq!(fetch(addr, "/%2541/y").await.0, 205);
}

#[tokio::test]
async fn a_secured_post_with_only_a_get_file_answers_405_and_the_probe_resolves_to_that_endpoint_not_the_catch_all() {
    let root = temp_root("served-405");
    let _cleanup = Cleanup(root.clone());
    write_endpoint(&root, "admin", "get", &status_endpoint(200));
    let router = router_for(&root).merge(crate::webserve::router(root.clone(), site_config(), crate::webserve::ProtectedPaths::default()));
    let addr = spawn_served(router, false).await;
    assert_eq!(fetch_with(addr, "POST", "/admin").await.0, 405);
    let plan = RoutePlan::build(
        &tree_for_tests(&root.join("datasources/endpoints")),
        crate::openapi::method_token::MethodCase::Default,
        &web_ctx(""),
    );
    let hit = plan.resolve(&probe_path("/admin").unwrap()).unwrap();
    assert!(!hit.files.is_empty() && hit.builtin.is_none(), "{hit:?}");
}

// ---------------------------------------------------------- security shadows

fn builtin_refusals(spec_yaml: &str, files: &[(&str, &str, Option<&str>)], ctx: &RouteContext) -> Vec<String> {
    let a = analyse_ctx(spec_yaml, files, ctx);
    a.check.builtin_refusals.iter().map(|m| m.message()).collect()
}

#[test]
fn a_secured_literal_operation_with_its_own_file_is_not_shadowed_by_an_open_sibling_parameter_route() {
    let spec = spec("", &(fixed("/café/menu", "get", "menu", SEC_A) + &fixed("/{p}/menu", "get", "byP", "")));
    let a = analyse(&spec, &[("café/menu", "get", Some("a")), ("{p}/menu", "get", None)]);
    assert_eq!(counts(&a), (0, 0, 0, 0, 0), "{:?}", shadow_messages(&a));
}

#[test]
fn a_secured_operation_with_no_file_under_a_non_ascii_path_is_still_shadowed_by_the_open_parameter_route() {
    let spec = spec("", &(fixed("/café/menu", "get", "menu", SEC_A) + &fixed("/{p}/menu", "get", "byP", "")));
    let a = analyse(&spec, &[("{p}/menu", "get", None)]);
    assert_eq!(a.check.shadowed.len(), 1, "{:?}", shadow_messages(&a));
    assert_eq!(a.check.shadowed[0].served_route, "/:p/menu");
}

#[test]
fn a_secured_operation_whose_path_cannot_be_registered_is_an_unverifiable_refusal() {
    let spec = spec("", &fixed("/a%20b", "get", "pct", SEC_A));
    let a = analyse(&spec, &[]);
    assert_eq!(a.check.unverifiable.len(), 1, "{:?}", counts(&a));
}

#[test]
fn with_both_roles_a_secured_operation_without_an_endpoint_file_is_refused_because_the_static_route_would_answer_it() {
    for api_root in ["", "/api"] {
        let spec = spec("", &fixed("/admin", "get", "adm", SEC_A));
        let messages = builtin_refusals(&spec, &[], &web_ctx(api_root));
        assert_eq!(messages.len(), 1, "apiRoot {api_root:?}: {messages:?}");
        assert!(
            messages[0].contains("has no endpoint file of its own") && messages[0].contains("frogs generate") && messages[0].contains("setting apiRoot does not help"),
            "{}",
            messages[0]
        );
    }
}

#[test]
fn a_secured_operation_with_its_own_file_or_only_a_file_for_another_method_is_not_refused_by_the_web_catch_all() {
    for api_root in ["", "/api"] {
        let own = builtin_refusals(&spec("", &fixed("/admin", "get", "adm", SEC_A)), &[("admin", "get", Some("a"))], &web_ctx(api_root));
        assert!(own.is_empty(), "{own:?}");
        let other_method = builtin_refusals(&spec("", &fixed("/admin", "get", "adm", SEC_A)), &[("admin", "post", Some("a"))], &web_ctx(api_root));
        assert!(other_method.is_empty(), "a POST-only file makes GET a 405, not static content: {other_method:?}");
    }
}

#[test]
fn an_inherited_document_wide_security_default_is_never_exempt_from_the_static_catch_all_refusal() {
    let spec = spec("security: [ { a: [] } ]\n", &fixed("/admin", "get", "adm", ""));
    let messages = builtin_refusals(&spec, &[], &web_ctx(""));
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert!(messages[0].contains("security: []"), "{}", messages[0]);
}

#[test]
fn an_unsecured_operation_with_no_file_is_not_refused_by_the_static_catch_all() {
    let spec = spec("", &fixed("/admin", "get", "adm", ""));
    assert!(builtin_refusals(&spec, &[], &web_ctx("")).is_empty());
}

#[test]
fn an_unresolvable_path_item_is_refused_under_the_web_role_as_if_secured_for_every_method() {
    let spec = spec("", "  /admin:\n    $ref: '#/components/pathItems/missing'\n");
    let messages = builtin_refusals(&spec, &[], &web_ctx(""));
    assert!(!messages.is_empty(), "an unresolved path item must fail closed");
}

#[test]
fn a_skipped_secured_operation_that_the_static_route_would_answer_points_at_the_spec_path_not_at_generate() {
    let spec = spec("", &fixed("/ad\\min", "get", "bad", SEC_A));
    let a = analyse_ctx(&spec, &[], &web_ctx(""));
    let messages: Vec<String> = a
        .check
        .builtin_refusals
        .iter()
        .map(|m| m.message())
        .chain(a.check.unverifiable.iter().map(|m| m.message()))
        .collect();
    assert!(!messages.is_empty(), "must refuse");
    if !a.check.builtin_refusals.is_empty() {
        assert!(messages.iter().any(|m| m.contains("fix the path in openapi.yaml")), "{messages:?}");
    }
}

#[test]
fn a_secured_operation_at_the_control_plane_path_is_refused_when_the_api_root_puts_it_there_and_not_otherwise() {
    let no_file = |api_root: &str, path: &str| builtin_refusals(&spec("", &fixed(path, "get", "cp", SEC_A)), &[], &cp_ctx(api_root));
    let bare = no_file("", "/_frogs/scenario");
    assert_eq!(bare.len(), 1, "{bare:?}");
    assert!(bare[0].contains("control plane") && bare[0].contains("rename"), "{}", bare[0]);
    assert_eq!(no_file("/_frogs", "/scenario").len(), 1);
    assert!(no_file("/api", "/_frogs/scenario").is_empty());
}

#[tokio::test]
async fn a_decomposed_spelling_reaches_the_literal_folder_but_a_parameter_value_keeps_its_spelling() {
    use crate::server::ServeShape;
    let shape = ServeShape {
        case_sensitive_methods: false,
        literals: std::sync::Arc::new(["caf\u{e9}".to_string()].into()),
    };
    let addr = spawn_served(registered_router(&["/café/menu", "/:p/menu"]), shape.clone()).await;
    for target in ["/cafe%CC%81/menu", "/cafe\u{301}/menu", "/caf%C3%A9/menu"] {
        assert_eq!(fetch(addr, target).await, (200, "/café/menu".to_string()), "{target}");
    }
    // Without the registered literal nothing is rewritten, so the sibling parameter route answers.
    let plain = spawn_served(registered_router(&["/café/menu", "/:p/menu"]), false).await;
    assert_eq!(fetch(plain, "/cafe%CC%81/menu").await, (200, "/:p/menu".to_string()));
    // A segment that is not a registered literal is never normalised.
    let other = spawn_served(registered_router(&["/x/:p"]), shape).await;
    assert_eq!(fetch(other, "/x/cafe%CC%81").await, (200, "/x/:p".to_string()));
}
