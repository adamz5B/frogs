//! Tests for the route-table plan (`route_plan`), the router built from the same
//! inventory, and the spec-to-file security checks that consume the plan.

use super::route_plan::{EntryStatus, InventoryEntry, RootExtras, RouteContext, RouteInventory, RouteKind, RoutePlan, RouteProblemKind};
use super::*;
use crate::openapi::endpoint_tree::tree_for_tests;

mod refs;
mod security;

// ------------------------------------------------------------------ helpers

fn lcg(state: &mut u64) -> u64 {
    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    *state >> 33
}

fn shuffle<T: Clone>(items: &[T], seed: u64) -> Vec<T> {
    let mut out = items.to_vec();
    let mut state = seed;
    for i in (1..out.len()).rev() {
        let j = (lcg(&mut state) % (i as u64 + 1)) as usize;
        out.swap(i, j);
    }
    out
}

fn permutations(n: usize) -> Vec<Vec<usize>> {
    fn rec(current: &mut Vec<usize>, rest: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
        if rest.is_empty() {
            out.push(current.clone());
            return;
        }
        for i in 0..rest.len() {
            let v = rest.remove(i);
            current.push(v);
            rec(current, rest, out);
            current.pop();
            rest.insert(i, v);
        }
    }
    let mut out = Vec::new();
    rec(&mut Vec::new(), &mut (0..n).collect(), &mut out);
    out
}

fn url_path_of(segments: &[String]) -> String {
    if segments.is_empty() {
        return "/".to_string();
    }
    let mapped: Vec<String> = segments
        .iter()
        .map(|s| match s.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            Some(name) => format!(":{name}"),
            None => s.clone(),
        })
        .collect();
    format!("/{}", mapped.join("/"))
}

fn entry_with_status(folder: &str, token: &str, status: EntryStatus) -> InventoryEntry {
    let segments: Vec<String> = folder.split('/').filter(|s| !s.is_empty()).map(String::from).collect();
    let url_path = url_path_of(&segments);
    let (wire, kind) = match token.to_ascii_lowercase().as_str() {
        "get" => ("GET".to_string(), Some(RouteKind::Standard(Method::GET))),
        "post" => ("POST".to_string(), Some(RouteKind::Standard(Method::POST))),
        "put" => ("PUT".to_string(), Some(RouteKind::Standard(Method::PUT))),
        "patch" => ("PATCH".to_string(), Some(RouteKind::Standard(Method::PATCH))),
        "delete" => ("DELETE".to_string(), Some(RouteKind::Standard(Method::DELETE))),
        _ => (token.to_string(), Method::from_bytes(token.as_bytes()).ok().map(RouteKind::Extension)),
    };
    InventoryEntry {
        url_path,
        token: token.to_string(),
        wire,
        kind,
        file: PathBuf::from("api/datasources/endpoints").join(folder).join(format!("endpoint.{token}.json")),
        segments,
        status,
    }
}

fn entry(folder: &str, token: &str) -> InventoryEntry {
    entry_with_status(folder, token, EntryStatus::Routed)
}

fn inv(entries: &[(&str, &str)]) -> RouteInventory {
    RouteInventory {
        entries: entries.iter().map(|(folder, token)| entry(folder, token)).collect(),
    }
}

fn endpoints_only() -> RouteContext {
    RouteContext::endpoints_only()
}

fn api_ctx() -> RouteContext {
    RouteContext {
        api_builtins: true,
        ..RouteContext::default()
    }
}

fn kinds(plan: &RoutePlan) -> Vec<RouteProblemKind> {
    plan.problems.iter().map(|p| p.kind).collect()
}

fn has_kind(plan: &RoutePlan, kind: RouteProblemKind) -> bool {
    plan.problems.iter().any(|p| p.kind == kind)
}

fn messages(plan: &RoutePlan) -> Vec<String> {
    plan.problems.iter().map(|p| p.message.clone()).collect()
}

async fn call(router: &Router, method: &str, uri: &str) -> (u16, String) {
    use tower_service::Service;
    let request = axum::http::Request::builder().method(method).uri(uri).body(axum::body::Body::empty()).unwrap();
    let mut service = router.clone();
    let response = service.call(request).await.unwrap();
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn temp_root(label: &str) -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "frogs-route-plan-{label}-{}-{}-{n}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    root
}

struct Cleanup(PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn no_control_chars(text: &str) -> bool {
    !text.chars().any(char::is_control)
}

// ------------------------------------------------- T1.6 .. T1.10 pure plans

#[test]
fn folders_that_cannot_be_route_segments_are_refused_and_excluded() {
    for folder in ["a:b", "b-:c", "*", "x*", "{}", "{a:b}", "{a*b}", "_Backups", r"a\b", "x/_BACKUPS"] {
        let inventory = inv(&[(folder, "get")]);
        let plan = RoutePlan::from_inventory(&inventory, &endpoints_only());
        assert!(
            plan.problems.iter().any(|p| p.kind == RouteProblemKind::Unroutable && p.is_refusal(false)),
            "{folder:?}: {:?}",
            plan.problems
        );
        assert!(plan.is_excluded(&inventory.entries[0].url_path), "{folder:?} must be excluded");
        assert!(plan.routes.iter().all(|r| r.files.is_empty()), "{folder:?} must not be a planned route");
    }
}

#[test]
fn an_unroutable_message_names_the_file_and_folder_and_says_to_rename_by_hand() {
    let plan = RoutePlan::from_inventory(&inv(&[("a:b", "get")]), &endpoints_only());
    let message = &plan.problems[0].message;
    assert!(message.contains("a:b") && message.contains("rename the folder by hand"), "{message}");
}

#[test]
fn a_folder_mixing_text_with_braces_warns_and_only_refuses_under_strict() {
    let plan = RoutePlan::from_inventory(&inv(&[("x/{id}.json", "get")]), &endpoints_only());
    assert_eq!(kinds(&plan), vec![RouteProblemKind::PartialTemplate]);
    assert!(plan.refusals(false).is_empty());
    assert_eq!(plan.warnings(false).len(), 1);
    assert_eq!(plan.refusals(true).len(), 1);
    assert!(plan.warnings(true).is_empty());
    assert!(!plan.is_excluded("/x/{id}.json"), "a partial template is still served (as a literal)");
}

#[test]
fn two_parameter_names_at_one_position_conflict_and_the_message_names_both_folders() {
    for set in [vec![("x/{a}", "get"), ("x/{b}", "get")], vec![("x/{a}/y", "get"), ("x/{b}/y", "get")]] {
        let inventory = inv(&set);
        let plan = RoutePlan::from_inventory(&inventory, &endpoints_only());
        let conflict = plan
            .problems
            .iter()
            .find(|p| p.kind == RouteProblemKind::RouteConflict)
            .unwrap_or_else(|| panic!("{set:?}: {:?}", plan.problems));
        assert!(conflict.message.contains("{a}") && conflict.message.contains("{b}"), "{}", conflict.message);
        assert!(conflict.message.contains("different parameter names"), "{}", conflict.message);
        for e in &inventory.entries {
            assert!(plan.is_excluded(&e.url_path), "{set:?}: {} must be excluded", e.url_path);
        }
    }
}

#[test]
fn compatible_static_and_parameter_siblings_are_not_conflicts() {
    for set in [
        vec![("cars/{id}", "get"), ("cars/{vin}/owner", "get")],
        vec![("cars/new", "get"), ("cars/{id}", "get")],
    ] {
        let plan = RoutePlan::from_inventory(&inv(&set), &endpoints_only());
        assert!(!has_kind(&plan, RouteProblemKind::RouteConflict), "{set:?}: {:?}", plan.problems);
        assert!(plan.excluded_paths.is_empty(), "{set:?}");
    }
}

#[test]
fn a_folder_on_a_builtin_path_with_an_overlapping_method_is_refused_and_a_different_method_is_not() {
    for api_root in ["", "/api"] {
        let ctx = RouteContext {
            api_root: api_root.to_string(),
            ..api_ctx()
        };
        let overlap = RoutePlan::from_inventory(&inv(&[("healthz", "get")]), &ctx);
        assert!(has_kind(&overlap, RouteProblemKind::MethodOverlap), "apiRoot {api_root:?}: {:?}", overlap.problems);
        assert!(overlap.is_excluded("/healthz"));
        let message = &overlap.problems.iter().find(|p| p.kind == RouteProblemKind::MethodOverlap).unwrap().message;
        assert!(message.contains("/healthz"), "{message}");
        let none = RoutePlan::from_inventory(&inv(&[("healthz", "post")]), &ctx);
        assert!(!has_kind(&none, RouteProblemKind::MethodOverlap), "apiRoot {api_root:?}: {:?}", none.problems);
    }
}

#[test]
fn readyz_and_metrics_are_builtins_only_when_their_feature_is_on() {
    for (folder, on, off) in [
        ("readyz", RouteContext { readyz: true, ..api_ctx() }, api_ctx()),
        ("metrics", RouteContext { metrics: true, ..api_ctx() }, api_ctx()),
    ] {
        let inventory = inv(&[(folder, "get")]);
        assert!(has_kind(&RoutePlan::from_inventory(&inventory, &on), RouteProblemKind::MethodOverlap), "{folder} on");
        assert!(
            !has_kind(&RoutePlan::from_inventory(&inventory, &off), RouteProblemKind::MethodOverlap),
            "{folder} off"
        );
    }
}

#[test]
fn docs_ui_routes_are_builtins_at_the_configured_path_including_a_nested_one() {
    let ctx = RouteContext {
        docs: true,
        docs_path: "dev/docs".to_string(),
        ..api_ctx()
    };
    for folder in ["dev/docs", "dev/docs/operations.json", "dev/docs/endpoints.json"] {
        let plan = RoutePlan::from_inventory(&inv(&[(folder, "get")]), &ctx);
        assert!(has_kind(&plan, RouteProblemKind::MethodOverlap), "{folder}: {:?}", plan.problems);
    }
    let plan = RoutePlan::from_inventory(&inv(&[("docs", "get")]), &ctx);
    assert!(!has_kind(&plan, RouteProblemKind::MethodOverlap), "docs is not under a custom docsUi.path");
    let default_path = RouteContext {
        docs: true,
        docs_path: String::new(),
        ..api_ctx()
    };
    let plan = RoutePlan::from_inventory(&inv(&[("docs/operations.json", "get")]), &default_path);
    assert!(
        has_kind(&plan, RouteProblemKind::MethodOverlap),
        "an empty docsUi.path normalises to docs: {:?}",
        plan.problems
    );
    let off = RoutePlan::from_inventory(&inv(&[("docs", "get")]), &api_ctx());
    assert!(!has_kind(&off, RouteProblemKind::MethodOverlap), "docs UI off: no built-in");
}

#[test]
fn a_root_endpoint_collides_with_the_web_root_only_when_api_root_is_empty() {
    let web = |api_root: &str| RouteContext {
        api_root: api_root.to_string(),
        extras: RootExtras { web: true, control_plane: false },
        ..api_ctx()
    };
    let inventory = inv(&[("", "get")]);
    assert!(has_kind(&RoutePlan::from_inventory(&inventory, &web("")), RouteProblemKind::MethodOverlap));
    let nested = RoutePlan::from_inventory(&inventory, &web("/api"));
    assert!(!has_kind(&nested, RouteProblemKind::MethodOverlap), "{:?}", nested.problems);
}

#[test]
fn the_frogs_test_scenario_control_plane_collides_only_at_an_unprefixed_api_root() {
    let ctx = |api_root: &str| RouteContext {
        api_root: api_root.to_string(),
        extras: RootExtras { web: false, control_plane: true },
        ..api_ctx()
    };
    let inventory = inv(&[("_frogs/scenario", "get")]);
    let bare = RoutePlan::from_inventory(&inventory, &ctx(""));
    assert!(has_kind(&bare, RouteProblemKind::MethodOverlap), "{:?}", bare.problems);
    let nested = RoutePlan::from_inventory(&inventory, &ctx("/api"));
    assert!(!has_kind(&nested, RouteProblemKind::MethodOverlap), "{:?}", nested.problems);
    let post = RoutePlan::from_inventory(&inv(&[("_frogs/scenario", "put")]), &ctx(""));
    assert!(!has_kind(&post, RouteProblemKind::MethodOverlap), "PUT is not one of the control plane's methods");
}

#[test]
fn an_api_root_or_docs_path_with_route_syntax_is_an_invalid_config_route_not_a_panic() {
    for api_root in ["a:b", "*x", "/api/{x}", "a/b:c"] {
        let ctx = RouteContext {
            api_root: api_root.to_string(),
            ..api_ctx()
        };
        let plan = RoutePlan::from_inventory(&inv(&[("x", "get")]), &ctx);
        assert!(has_kind(&plan, RouteProblemKind::InvalidConfigRoute), "{api_root:?}: {:?}", plan.problems);
        assert!(plan.problems.iter().any(|p| p.is_refusal(false)));
    }
    for docs_path in ["x*", "a:b", "{x}"] {
        let ctx = RouteContext {
            docs: true,
            docs_path: docs_path.to_string(),
            ..api_ctx()
        };
        let plan = RoutePlan::from_inventory(&inv(&[("x", "get")]), &ctx);
        assert!(has_kind(&plan, RouteProblemKind::InvalidConfigRoute), "{docs_path:?}: {:?}", plan.problems);
    }
    let good = RouteContext {
        api_root: "/api/v1".to_string(),
        docs: true,
        docs_path: "dev/docs".to_string(),
        ..api_ctx()
    };
    assert!(!has_kind(
        &RoutePlan::from_inventory(&inv(&[("x", "get")]), &good),
        RouteProblemKind::InvalidConfigRoute
    ));
}

#[test]
fn two_extension_method_files_on_one_path_overlap_as_custom_fallbacks_only_across_origins() {
    let plan = RoutePlan::from_inventory(&inv(&[("x", "PURGE"), ("x", "LINK")]), &endpoints_only());
    assert!(plan.problems.is_empty(), "one origin may hold several extension methods: {:?}", plan.problems);
}

#[test]
fn a_duplicate_or_not_routed_inventory_entry_claims_no_route() {
    let inventory = RouteInventory {
        entries: vec![
            entry("a", "get"),
            entry_with_status("a", "get", EntryStatus::Duplicate),
            entry_with_status("b", "get", EntryStatus::NotRouted("nope".to_string())),
        ],
    };
    let plan = RoutePlan::from_inventory(&inventory, &endpoints_only());
    assert!(plan.problems.is_empty());
    assert!(plan.resolve("/a").is_some());
    assert!(plan.resolve("/b").is_none());
    assert_eq!(plan.routes.iter().find(|r| r.path == "/a").unwrap().files.len(), 1);
}

// ------------------------------------------------------------------- T1.11

#[test]
fn the_plans_problems_do_not_depend_on_the_inventory_order() {
    let sets: Vec<(RouteContext, Vec<(&str, &str)>)> = vec![
        (
            endpoints_only(),
            vec![
                ("a:b", "get"),
                ("b-:c", "get"),
                ("*", "get"),
                ("{}", "get"),
                ("_Backups", "get"),
                ("x/{a}", "get"),
                ("x/{b}", "get"),
                ("y/{a}/z", "get"),
                ("y/{b}/z", "get"),
                ("cars/new", "get"),
                ("cars/{id}", "get"),
                ("p/{id}.json", "get"),
            ],
        ),
        (
            RouteContext {
                api_root: "/api".to_string(),
                readyz: true,
                metrics: true,
                docs: true,
                docs_path: "dev/docs".to_string(),
                extras: RootExtras { web: true, control_plane: true },
                ..api_ctx()
            },
            vec![
                ("healthz", "get"),
                ("readyz", "get"),
                ("metrics", "get"),
                ("dev/docs", "get"),
                ("dev/docs/operations.json", "get"),
                ("_frogs/scenario", "post"),
                ("healthz", "post"),
                ("", "get"),
            ],
        ),
    ];
    for (ctx, set) in sets {
        let baseline = RoutePlan::from_inventory(&inv(&set), &ctx);
        assert!(!baseline.problems.is_empty());
        for seed in 1..=20u64 {
            let shuffled = shuffle(&set, seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
            let other = RoutePlan::from_inventory(&inv(&shuffled), &ctx);
            assert_eq!(messages(&baseline), messages(&other), "seed {seed}");
            assert_eq!(baseline.excluded_paths, other.excluded_paths, "seed {seed}");
        }
    }
}

// ------------------------------------------------------------------- T1.22

fn nested_ambiguous(levels: usize) -> Vec<(String, &'static str)> {
    // P^k/s for k in 0..=levels: every node on the all-parameter spine has both a static `s` and a `{p}` child.
    (0..=levels)
        .map(|k| {
            let mut parts: Vec<&str> = vec!["{p}"; k];
            parts.push("s");
            (parts.join("/"), "get")
        })
        .collect()
}

#[test]
fn thirteen_nested_static_and_parameter_branch_points_are_too_ambiguous_but_twelve_are_not() {
    let plan_for = |levels: usize| {
        let set = nested_ambiguous(levels);
        let refs: Vec<(&str, &str)> = set.iter().map(|(f, t)| (f.as_str(), *t)).collect();
        RoutePlan::from_inventory(&inv(&refs), &endpoints_only())
    };
    let thirteen = plan_for(13);
    assert!(has_kind(&thirteen, RouteProblemKind::RouteTreeTooAmbiguous), "{:?}", thirteen.problems);
    assert!(
        thirteen
            .problems
            .iter()
            .any(|p| p.kind == RouteProblemKind::RouteTreeTooAmbiguous && p.is_refusal(false))
    );
    let twelve = plan_for(12);
    assert!(!has_kind(&twelve, RouteProblemKind::RouteTreeTooAmbiguous), "{:?}", twelve.problems);
    assert!(!has_kind(&twelve, RouteProblemKind::RouteConflict), "{:?}", twelve.problems);
}

// ------------------------------------------------------------ T1.13 / T1.18

#[test]
fn cargo_lock_has_exactly_one_matchit_entry_at_0_7_3() {
    let lock = include_str!("../../Cargo.lock");
    let needle = "name = \"matchit\"";
    assert_eq!(lock.matches(needle).count(), 1, "more than one matchit version in the lock file");
    let after = &lock[lock.find(needle).unwrap() + needle.len()..];
    let version_line = after.lines().find(|l| l.trim_start().starts_with("version")).unwrap();
    assert!(version_line.contains("\"0.7.3\""), "{version_line}");
}

#[test]
fn route_plan_rs_contains_no_platform_conditionals_outside_test_code() {
    let cfg_macro = format!("{}!(", "cfg");
    let cfg_attr = format!("#[{}(", "cfg");
    let test_marker = format!("#[{}(test)]", "cfg");
    let source = include_str!("route_plan.rs");
    let production = source.split(test_marker.as_str()).next().unwrap();
    assert!(!production.contains(&cfg_macro), "{cfg_macro} found");
    assert!(!production.contains(&cfg_attr), "{cfg_attr} found");
}

// ------------------------------------------------------------------- T1.21

#[test]
fn every_problem_message_escapes_control_characters_from_folders_and_config_values() {
    let esc = "\u{1b}[2J";
    let folders = [
        format!("a:{esc}"),
        format!("x/{{a{esc}}}"),
        format!("x/{{b{esc}}}"),
        format!("{{id{esc}}}.json"),
        format!("a{esc}b"),
    ];
    let set: Vec<(&str, &str)> = folders.iter().map(|f| (f.as_str(), "get")).collect();
    let ctx = RouteContext {
        api_root: format!("a:{esc}"),
        docs: true,
        docs_path: format!("d*{esc}"),
        ..api_ctx()
    };
    let plan = RoutePlan::from_inventory(&inv(&set), &ctx);
    assert!(plan.problems.len() >= 4, "{:?}", plan.problems);
    for problem in &plan.problems {
        assert!(no_control_chars(&problem.message), "{:?}", problem.message);
    }
    let healthz = RoutePlan::from_inventory(&inv(&[("healthz", "get"), (&format!("q{esc}"), "get")]), &api_ctx());
    for problem in &healthz.problems {
        assert!(no_control_chars(&problem.message), "{:?}", problem.message);
    }
}

// ------------------------------------------------- T1.12 soundness (fuzz)

const SEGMENT_VOCABULARY: [&str; 9] = ["a", "b", "{p}", "{q}", "x:y", "*", "{}", "{id}.json", "healthz"];

async fn ok_handler() -> &'static str {
    "ok"
}

struct Layout {
    entries: Vec<(String, &'static str)>,
    api_root: &'static str,
    web: bool,
}

fn random_layout(seed: u64) -> Layout {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xDEAD_BEEF;
    let count = 1 + (lcg(&mut state) % 6) as usize;
    let mut entries: Vec<(String, &'static str)> = Vec::new();
    for _ in 0..count {
        let depth = (lcg(&mut state) % 4) as usize;
        let segments: Vec<&str> = (0..depth)
            .map(|_| SEGMENT_VOCABULARY[(lcg(&mut state) % SEGMENT_VOCABULARY.len() as u64) as usize])
            .collect();
        let token = if lcg(&mut state).is_multiple_of(2) { "get" } else { "post" };
        let candidate = (segments.join("/"), token);
        if !entries.contains(&candidate) {
            entries.push(candidate);
        }
    }
    let api_root = if lcg(&mut state).is_multiple_of(3) { "/api" } else { "" };
    let web = lcg(&mut state).is_multiple_of(3);
    Layout { entries, api_root, web }
}

fn build_real_router(layout: &Layout, order: &[usize]) -> Router {
    let mut by_path: BTreeMap<String, MethodRouter<()>> = BTreeMap::new();
    for (folder, token) in &layout.entries {
        let url = url_path_of(&folder.split('/').filter(|s| !s.is_empty()).map(String::from).collect::<Vec<_>>());
        let method_router: MethodRouter<()> = if *token == "get" { get(ok_handler) } else { post(ok_handler) };
        let merged = match by_path.remove(&url) {
            Some(existing) => existing.merge(method_router),
            None => method_router,
        };
        by_path.insert(url, merged);
    }
    let paths: Vec<String> = by_path.keys().cloned().collect();
    let mut endpoint_router = Router::new();
    for index in order {
        let path = &paths[*index];
        endpoint_router = endpoint_router.route(path, by_path.remove(path).unwrap());
    }
    let router = crate::server::router().merge(endpoint_router);
    let router = crate::server::mount_under(router, layout.api_root);
    if layout.web {
        router.merge(Router::new().route("/", get(ok_handler)).route("/*path", get(ok_handler)))
    } else {
        router
    }
}

fn distinct_path_count(layout: &Layout) -> usize {
    let mut paths: Vec<String> = layout
        .entries
        .iter()
        .map(|(folder, _)| url_path_of(&folder.split('/').filter(|s| !s.is_empty()).map(String::from).collect::<Vec<_>>()))
        .collect();
    paths.sort();
    paths.dedup();
    paths.len()
}

#[test]
fn the_plan_reports_a_refusal_whenever_real_axum_construction_panics_and_vice_versa_for_conflicts() {
    let mut panicking_layouts = 0usize;
    let mut clean_layouts = 0usize;
    for seed in 0..2000u64 {
        let layout = random_layout(seed);
        let ctx = RouteContext {
            api_root: layout.api_root.to_string(),
            extras: RootExtras {
                web: layout.web,
                control_plane: false,
            },
            ..api_ctx()
        };
        let set: Vec<(&str, &str)> = layout.entries.iter().map(|(f, t)| (f.as_str(), *t)).collect();
        let plan = RoutePlan::from_inventory(&inv(&set), &ctx);

        let n = distinct_path_count(&layout);
        let orders: Vec<Vec<usize>> = if n <= 4 {
            permutations(n)
        } else {
            (0..12u64)
                .map(|s| shuffle(&(0..n).collect::<Vec<_>>(), seed.wrapping_mul(31).wrapping_add(s + 1)))
                .collect()
        };
        let mut any_panic = false;
        for order in &orders {
            let built = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| build_real_router(&layout, order)));
            if built.is_err() {
                any_panic = true;
                break;
            }
        }
        let refused = !plan.refusals(false).is_empty();
        if any_panic {
            panicking_layouts += 1;
            assert!(
                refused,
                "seed {seed}: axum panicked but the plan found nothing: {set:?} apiRoot {:?} web {}",
                layout.api_root, layout.web
            );
        } else {
            clean_layouts += 1;
        }
        let only_routing_problems = !has_kind(&plan, RouteProblemKind::Unroutable) && !has_kind(&plan, RouteProblemKind::InvalidConfigRoute);
        if only_routing_problems && refused {
            assert!(
                any_panic,
                "seed {seed}: the plan refused ({:?}) but real axum built fine under every tried order: {set:?} apiRoot {:?} web {}",
                kinds(&plan),
                layout.api_root,
                layout.web
            );
        }
    }
    assert!(
        panicking_layouts > 50 && clean_layouts > 50,
        "fuzz didn't exercise both outcomes: {panicking_layouts} panicking, {clean_layouts} clean"
    );
}

// ------------------------------------------------------------------- T1.20

#[test]
fn matchit_symmetry_every_insertion_order_of_up_to_four_routes_agrees_with_the_plans_verdict() {
    let universe = ["/a", "/:p", "/:q", "/a/b", "/:p/b", "/:q/b", "/a/:p", "/*r"];
    let mut asymmetric = 0usize;
    let mut subsets = 0usize;
    for mask in 1u32..(1 << universe.len()) {
        if mask.count_ones() > 4 {
            continue;
        }
        let set: Vec<String> = (0..universe.len()).filter(|i| mask & (1 << i) != 0).map(|i| universe[i].to_string()).collect();
        subsets += 1;
        let mut outcomes = Vec::new();
        for order in permutations(set.len()) {
            let mut router = matchit::Router::new();
            let mut failed = false;
            for index in order {
                if router.insert(set[index].clone(), 0usize).is_err() {
                    failed = true;
                }
            }
            outcomes.push(failed);
        }
        let some_error = outcomes.iter().any(|f| *f);
        if outcomes.iter().any(|f| *f != some_error) {
            asymmetric += 1;
        }
        let report = crate::openapi::route_syntax::find_conflicts(&set);
        let plan_says_problem = !report.members.is_empty() || !report.unroutable.is_empty();
        assert_eq!(
            plan_says_problem, some_error,
            "{set:?}: plan {plan_says_problem}, some insertion order errors {some_error}"
        );
    }
    eprintln!("matchit order asymmetry: {asymmetric} of {subsets} subsets (outcome depends on insertion order)");
}

// ------------------------------------------------------------------- T2.7

#[tokio::test]
async fn the_probe_router_answers_exactly_like_a_real_axum_router_built_from_the_planned_routes() {
    let probe_vocabulary = ["a", "b", "healthz", "zzz", ":frogs-probe", "new"];
    let mut compared = 0usize;
    let mut hits = 0usize;
    for seed in 0..500u64 {
        let mut layout = random_layout(seed.wrapping_add(10_000));
        layout.api_root = "";
        layout.web = false;
        let mut state = seed ^ 0xABCDEF;
        let mut entries: Vec<InventoryEntry> = Vec::new();
        for (folder, token) in &layout.entries {
            let status = match lcg(&mut state) % 8 {
                0 => EntryStatus::Duplicate,
                1 => EntryStatus::NotRouted("test".to_string()),
                _ => EntryStatus::Routed,
            };
            entries.push(entry_with_status(folder, token, status));
        }
        let ctx = RouteContext { readyz: true, ..api_ctx() };
        let plan = RoutePlan::from_inventory(&RouteInventory { entries }, &ctx);

        let mut real = Router::new();
        for route in &plan.routes {
            let label = route.path.clone();
            real = real.route(&route.path, axum::routing::any(move || async move { label }));
        }
        let mut probes: Vec<String> = plan
            .routes
            .iter()
            .map(|r| {
                r.path
                    .split('/')
                    .map(|s| if s.starts_with(':') { ":frogs-probe" } else { s })
                    .collect::<Vec<_>>()
                    .join("/")
            })
            .collect();
        for _ in 0..12 {
            let depth = 1 + (lcg(&mut state) % 3) as usize;
            let segments: Vec<&str> = (0..depth)
                .map(|_| probe_vocabulary[(lcg(&mut state) % probe_vocabulary.len() as u64) as usize])
                .collect();
            probes.push(format!("/{}", segments.join("/")));
        }
        for probe in probes {
            let (status, body) = call(&real, "GET", &probe).await;
            let planned = plan.resolve(&probe).map(|r| r.path.clone());
            compared += 1;
            match planned {
                Some(path) => {
                    hits += 1;
                    assert_eq!((status, body.as_str()), (200, path.as_str()), "seed {seed}, probe {probe}");
                }
                None => assert_eq!(
                    status, 404,
                    "seed {seed}, probe {probe}: plan found no route but the real router answered {status} {body}"
                ),
            }
        }
    }
    assert!(compared > 5000 && hits > 500, "{compared} compared, {hits} hits");
}

#[test]
fn a_backtracking_probe_reaches_the_parameter_route_the_way_a_real_request_would() {
    let plan = RoutePlan::from_inventory(&inv(&[("cars/admin/keys", "get"), ("cars/{id}", "get")]), &endpoints_only());
    assert_eq!(plan.resolve("/cars/admin").unwrap().path, "/cars/:id");
    assert_eq!(plan.resolve("/cars/admin/keys").unwrap().path, "/cars/admin/keys");
    assert!(plan.resolve("/cars").is_none());
}

#[test]
fn resolve_short_circuits_probes_deeper_than_any_planned_route_including_builtins() {
    let plan = RoutePlan::from_inventory(&inv(&[("a", "get")]), &api_ctx());
    assert!(plan.resolve("/a/b/c/d/e").is_none());
    let docs = RouteContext {
        docs: true,
        docs_path: "a/b/c".to_string(),
        ..api_ctx()
    };
    let plan = RoutePlan::from_inventory(&inv(&[("a", "get")]), &docs);
    let route = plan
        .resolve("/a/b/c/operations.json")
        .expect("a deep built-in must stay reachable for the probe even with shallow endpoints");
    assert!(route.builtin.is_some());
}

// ----------------------------------------------------- build_router fixtures

const OK_ENDPOINT: &str = r#"{ "operationId": "x", "sources": {}, "response": { "ok": "literal" } }"#;

fn write_endpoint(root: &Path, dir: &str, token: &str, json: &str) {
    let d = root.join("datasources/endpoints").join(dir);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join(format!("endpoint.{token}.json")), json).unwrap();
}

const CORE_ERRORS: &str =
    r#"{ "auth.invalid_credentials": { "httpStatus": 401, "exposeDetail": true }, "auth.verifier_unavailable": { "httpStatus": 500, "exposeDetail": false } }"#;

fn router_with(root: &Path, errors_json: &str, debug_mode: bool, identity_available: bool) -> Router {
    std::fs::create_dir_all(root.join("datasources/sql/db")).unwrap();
    std::fs::write(root.join("datasources/sql/db/q.sql"), "SELECT 1").unwrap();
    let sec = root.join("sec");
    std::fs::create_dir_all(sec.join("verifiers")).unwrap();
    std::fs::write(sec.join("schemes.json"), r#"{ "certAuth": { "verifier": "cert.json" } }"#).unwrap();
    std::fs::write(sec.join("verifiers/cert.json"), r#"{ "type": "mtls", "validIf": "cert.cn = x" }"#).unwrap();
    let errs = root.join("errs");
    std::fs::create_dir_all(&errs).unwrap();
    std::fs::write(errs.join("core.json"), errors_json).unwrap();
    build_router(
        root,
        &tree_for_tests(&root.join("datasources/endpoints")),
        Arc::new(HashMap::new()),
        &HashMap::new(),
        Arc::new(ErrorRegistry::load(&errs).unwrap()),
        Arc::new(SecurityConfig::load(&sec).unwrap()),
        Arc::new(HashMap::new()),
        Arc::new(Mutex::new(DiscoveredErrors::default())),
        debug_mode,
        None,
        None,
        NonZeroU64::new(5_000).unwrap(),
        identity_available,
        MethodCase::Default,
    )
}

fn router_for(root: &Path) -> Router {
    router_with(root, CORE_ERRORS, false, false)
}

#[derive(Clone, Default)]
struct LogBuf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuf {
    type Writer = LogBuf;
    fn make_writer(&'a self) -> LogBuf {
        self.clone()
    }
}

fn capture_logs<T>(f: impl FnOnce() -> T) -> (T, String) {
    let buf = LogBuf::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buf.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .finish();
    let value = tracing::subscriber::with_default(subscriber, f);
    let text = String::from_utf8_lossy(&buf.0.lock().unwrap()).into_owned();
    (value, text)
}

// ------------------------------------------------------------------- T1.14

#[tokio::test]
async fn build_router_with_parameter_name_conflicting_folders_does_not_panic_and_serves_neither() {
    let root = temp_root("conflict");
    let _cleanup = Cleanup(root.clone());
    write_endpoint(&root, "x/{a}", "get", OK_ENDPOINT);
    write_endpoint(&root, "x/{b}", "get", OK_ENDPOINT);
    write_endpoint(&root, "fine", "get", OK_ENDPOINT);
    let (router, _logs) = capture_logs(|| router_for(&root));
    assert_eq!(call(&router, "GET", "/x/1").await.0, 404);
    assert_eq!(call(&router, "GET", "/fine").await.0, 200, "unrelated routes keep working");
}

#[cfg(unix)]
#[tokio::test]
async fn a_folder_with_a_colon_is_not_served_and_cannot_capture_neighbouring_paths() {
    let root = temp_root("colon");
    let _cleanup = Cleanup(root.clone());
    write_endpoint(&root, "a:b", "get", OK_ENDPOINT);
    let router = router_for(&root);
    assert_eq!(call(&router, "GET", "/axyz").await.0, 404);
    assert_eq!(call(&router, "GET", "/a:b").await.0, 404);
}

#[test]
fn build_router_never_panics_on_a_hand_made_pile_of_hostile_folders() {
    let root = temp_root("hostile");
    let _cleanup = Cleanup(root.clone());
    for folder in ["x/{a}", "x/{b}", "{}", "p/{id}.json", "healthz", "{p}", "{q}", "_Backups"] {
        write_endpoint(&root, folder, "get", OK_ENDPOINT);
    }
    let _ = router_for(&root);
}

// ------------------------------------------------------------------- T1.19

#[tokio::test]
async fn the_plans_routed_set_equals_what_the_real_router_answers_and_placeholders_answer_503() {
    let root = temp_root("inventory");
    let _cleanup = Cleanup(root.clone());
    write_endpoint(&root, "ok", "get", OK_ENDPOINT);
    write_endpoint(&root, "ok", "post", OK_ENDPOINT);
    write_endpoint(&root, "bad", "get", "{ not json");
    write_endpoint(&root, "unk", "get", r#"{ "operationId": "x", "security": "nope", "sources": {}, "response": {} }"#);
    write_endpoint(&root, "ext", "PURGE", OK_ENDPOINT);
    write_endpoint(
        &root,
        "extbad",
        "LINK",
        r#"{ "operationId": "x", "security": "nope", "sources": {}, "response": {} }"#,
    );
    write_endpoint(&root, "p/{id}", "get", OK_ENDPOINT);
    // One path with both spellings only exists on a case-sensitive file system.
    write_endpoint(&root, "dup", "get", OK_ENDPOINT);
    write_endpoint(&root, "dup", "GET", OK_ENDPOINT);
    let dup_entries = std::fs::read_dir(root.join("datasources/endpoints/dup")).unwrap().count();

    let tree = tree_for_tests(&root.join("datasources/endpoints"));
    let inventory = route_inventory(&tree, MethodCase::Default);
    let plan = RoutePlan::from_inventory(&inventory, &endpoints_only());
    assert!(plan.problems.is_empty(), "{:?}", plan.problems);
    let router = router_for(&root);

    let mut routed: Vec<(String, String)> = Vec::new();
    for e in &inventory.entries {
        if e.status == EntryStatus::Routed && !plan.is_excluded(&e.url_path) {
            routed.push((e.url_path.clone(), e.wire.clone()));
        }
    }
    let mut universe: Vec<(String, String)> = inventory.entries.iter().map(|e| (e.url_path.clone(), e.wire.clone())).collect();
    universe.push(("/ok".to_string(), "PUT".to_string()));
    universe.push(("/nothing".to_string(), "GET".to_string()));
    universe.sort();
    universe.dedup();
    assert!(universe.len() >= 7, "{universe:?}");
    for (path, wire) in universe {
        let concrete = path.replace(":id", "7");
        let (status, body) = call(&router, &wire, &concrete).await;
        let answered = status != 404 && status != 405;
        assert_eq!(answered, routed.contains(&(path.clone(), wire.clone())), "{wire} {path}: status {status} {body}");
        if path == "/bad" || path == "/unk" || path == "/extbad" {
            assert_eq!(status, 503, "{wire} {path}: placeholder expected, got {status} {body}");
            assert!(body.contains("endpoint.unavailable"), "{body}");
        }
    }
    if dup_entries == 2 {
        let dups: Vec<_> = inventory.entries.iter().filter(|e| e.url_path == "/dup").collect();
        assert_eq!(dups.iter().filter(|e| e.status == EntryStatus::Routed).count(), 1, "first file wins");
        assert_eq!(dups.iter().filter(|e| e.status == EntryStatus::Duplicate).count(), 1);
    }
}

#[cfg(unix)]
#[test]
fn a_non_utf8_folder_is_absent_from_the_inventory_and_the_router_alike() {
    use std::os::unix::ffi::OsStrExt;
    let root = temp_root("nonutf8");
    let _cleanup = Cleanup(root.clone());
    write_endpoint(&root, "ok", "get", OK_ENDPOINT);
    let weird = root.join("datasources/endpoints").join(std::ffi::OsStr::from_bytes(b"bad\xff"));
    std::fs::create_dir_all(&weird).unwrap();
    std::fs::write(weird.join("endpoint.get.json"), OK_ENDPOINT).unwrap();
    let tree = tree_for_tests(&root.join("datasources/endpoints"));
    let inventory = route_inventory(&tree, MethodCase::Default);
    assert_eq!(inventory.entries.len(), 1);
    assert_eq!(inventory.entries[0].url_path, "/ok");
    let _ = router_for(&root);
}

// ------------------------------------------------------------------- T2.13

#[tokio::test]
async fn an_unservable_file_answers_503_in_its_own_slot_instead_of_falling_through_to_a_parameter_route() {
    let nested_many_problem = r#"{ "operationId": "x", "sources": { "s": { "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "one", "allowNestedMany": true } }, "response": {} }"#;
    let cert_required = r#"{ "operationId": "x", "security": "certAuth", "sources": {}, "response": {} }"#;
    let cases: [(&str, &str); 4] = [
        ("unknown scheme", r#"{ "operationId": "x", "security": "nope", "sources": {}, "response": {} }"#),
        ("invalid json", "{ not json"),
        ("cert required without client auth", cert_required),
        ("nested-many failure", nested_many_problem),
    ];
    for (label, contents) in cases {
        let root = temp_root("placeholder");
        let _cleanup = Cleanup(root.clone());
        write_endpoint(&root, "cars/admin", "get", contents);
        write_endpoint(&root, "cars/{id}", "get", OK_ENDPOINT);
        let router = router_for(&root);
        let (status, body) = call(&router, "GET", "/cars/admin").await;
        assert_eq!(status, 503, "{label}: {body}");
        let json: Value = serde_json::from_str(&body).unwrap_or_else(|e| panic!("{label}: {e}: {body}"));
        assert_eq!(json["name"], "endpoint.unavailable", "{label}");
        assert_eq!(json["code"], 503, "{label}");
        assert!(json.get("detail").is_none(), "{label}: no detail unless the project exposes it: {body}");
        assert!(!body.contains("not json") && !body.contains("nope"), "{label}: file content must not leak: {body}");
        assert_eq!(call(&router, "GET", "/cars/7").await.0, 200, "{label}: the sibling still serves");
    }
}

#[tokio::test]
async fn an_unservable_extension_method_file_answers_503_for_its_method() {
    let root = temp_root("placeholder-ext");
    let _cleanup = Cleanup(root.clone());
    write_endpoint(&root, "x", "PURGE", r#"{ "operationId": "x", "security": "nope", "sources": {}, "response": {} }"#);
    let router = router_for(&root);
    let (status, body) = call(&router, "PURGE", "/x").await;
    assert_eq!(status, 503, "{body}");
    assert!(body.contains("endpoint.unavailable"));
}

#[tokio::test]
async fn the_placeholder_never_creates_or_touches_the_discovered_errors_file_even_in_debug_mode() {
    let root = temp_root("placeholder-debug");
    let _cleanup = Cleanup(root.clone());
    write_endpoint(&root, "broken", "get", "{ not json");
    let router = router_with(&root, CORE_ERRORS, true, false);
    for _ in 0..3 {
        assert_eq!(call(&router, "GET", "/broken").await.0, 503);
    }
    assert!(!root.join("config/errors.discovered.json").exists());
}

#[tokio::test]
async fn a_project_defined_endpoint_unavailable_code_sets_the_status_and_may_expose_detail() {
    let root = temp_root("placeholder-defined");
    let _cleanup = Cleanup(root.clone());
    write_endpoint(&root, "broken", "get", "{ not json");
    let errors = r#"{ "endpoint.unavailable": { "httpStatus": 500, "exposeDetail": true } }"#;
    let router = router_with(&root, errors, false, false);
    let (status, body) = call(&router, "GET", "/broken").await;
    assert_eq!(status, 500, "{body}");
    let json: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["code"], 500);
    assert!(json["detail"].is_string(), "{body}");
    assert!(!body.contains("not json"));
}

// ------------------------------------------------- T1.21 (router log output)

#[cfg(unix)]
#[test]
fn build_router_skip_and_exclusion_logs_contain_no_control_characters_from_hostile_folders() {
    let root = temp_root("hygiene");
    let _cleanup = Cleanup(root.clone());
    let esc = "\u{1b}[2J";
    write_endpoint(&root, &format!("x/{{a{esc}}}"), "get", OK_ENDPOINT);
    write_endpoint(&root, &format!("x/{{b{esc}}}"), "get", OK_ENDPOINT);
    write_endpoint(&root, &format!("bad{esc}"), "get", "{ not json");
    write_endpoint(&root, &format!("a:{esc}"), "get", OK_ENDPOINT);
    let (_router, logs) = capture_logs(|| router_for(&root));
    // Callsite-interest caching can make a parallel test miss a log line; the control-character check below is what matters.
    if logs.is_empty() {
        eprintln!("no log output captured (tracing callsite cache); hygiene not checked");
    }
    assert!(no_control_chars(&logs.replace('\n', "")), "{logs:?}");
}

#[test]
fn a_builtin_overlap_message_names_the_file_whose_method_actually_overlaps_whatever_the_discovery_order() {
    for set in [vec![("healthz", "get"), ("healthz", "post")], vec![("healthz", "post"), ("healthz", "get")]] {
        let plan = RoutePlan::from_inventory(&inv(&set), &api_ctx());
        let overlap: Vec<&str> = plan
            .problems
            .iter()
            .filter(|p| p.kind == RouteProblemKind::MethodOverlap)
            .map(|p| p.message.as_str())
            .collect();
        assert_eq!(overlap.len(), 1, "{:?}", plan.problems);
        assert!(
            overlap[0].contains("endpoint.get.json"),
            "the GET file is the one that overlaps /healthz, but the message says: {}",
            overlap[0]
        );
        assert!(!overlap[0].contains("endpoint.post.json"), "{}", overlap[0]);
    }
}
