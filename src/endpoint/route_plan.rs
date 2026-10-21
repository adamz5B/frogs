//! The route table frogs is about to hand to axum, computed without building it.
//!
//! axum 0.7 panics when two registered paths conflict (for example `x/{a}` and
//! `x/{b}`), and silently misroutes when a folder name contains `:` or `*`. The
//! plan reproduces matchit's verdict up front so a bad folder layout is a
//! readable startup refusal instead of a panic, and it doubles as a probe
//! router that answers "which registered route would serve this spec path".

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use axum::http::Method;

use crate::openapi::path_rules::{unsafe_segment_reason, untrusted};
use crate::openapi::route_syntax::{SegmentKind, classify_route_segment, find_conflicts, path_for_nested_route};

/// How many positions along one route may have both a static and a parameter
/// sibling before matchit's backtracking per lookup is considered too costly.
const MAX_BRANCHING_DEPTH: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RouteKind {
    Standard(Method),
    Extension(Method),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EntryStatus {
    Routed,
    NotRouted(String),
    Duplicate,
}

#[derive(Debug, Clone)]
pub(crate) struct InventoryEntry {
    pub url_path: String,
    pub token: String,
    pub wire: String,
    pub kind: Option<RouteKind>,
    pub file: PathBuf,
    /// The raw folder names under `datasources/endpoints/` this file sits in.
    pub segments: Vec<String>,
    pub status: EntryStatus,
}

impl InventoryEntry {
    /// The methods this entry claims on its path (`get` also claims HEAD).
    pub(crate) fn claimed_methods(&self) -> Vec<String> {
        match &self.kind {
            Some(RouteKind::Standard(method)) if *method == Method::GET => vec!["GET".to_string(), "HEAD".to_string()],
            Some(RouteKind::Standard(method)) | Some(RouteKind::Extension(method)) => vec![method.as_str().to_string()],
            None => Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct RouteInventory {
    pub entries: Vec<InventoryEntry>,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RootExtras {
    pub web: bool,
    pub control_plane: bool,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct RouteContext {
    pub api_root: String,
    pub docs_path: String,
    pub api_builtins: bool,
    pub readyz: bool,
    pub metrics: bool,
    pub docs: bool,
    pub extras: RootExtras,
}

impl RouteContext {
    pub(crate) fn endpoints_only() -> Self {
        RouteContext::default()
    }

    pub(crate) fn for_server(server: &crate::config::ServerConfig) -> Self {
        RouteContext {
            api_root: server.api_root.clone(),
            docs_path: server.docs_ui.path.clone(),
            api_builtins: true,
            readyz: server.features.readyz_check,
            metrics: server.features.metrics,
            docs: server.docs_ui.mode != crate::config::DocsUiMode::Off,
            extras: RootExtras::default(),
        }
    }

    pub(crate) fn with_extras(mut self, extras: RootExtras) -> Self {
        self.extras = extras;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RouteOrigin {
    Endpoint(PathBuf),
    Builtin(&'static str),
    Web,
    ControlPlane,
}

impl std::fmt::Display for RouteOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouteOrigin::Endpoint(file) => write!(f, "{}", untrusted(&file.display().to_string())),
            RouteOrigin::Builtin(label) => write!(f, "frogs's built-in {label} route"),
            RouteOrigin::Web => write!(f, "the static-content route (webserve.json)"),
            RouteOrigin::ControlPlane => write!(f, "the frogs test /_frogs/scenario control plane"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteProblemKind {
    Unroutable,
    InvalidConfigRoute,
    MethodOverlap,
    RouteConflict,
    RouteTreeTooAmbiguous,
    PartialTemplate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RouteProblem {
    pub kind: RouteProblemKind,
    pub message: String,
}

impl RouteProblem {
    pub(crate) fn message(&self) -> &str {
        &self.message
    }

    pub(crate) fn is_refusal(&self, strict: bool) -> bool {
        self.kind != RouteProblemKind::PartialTemplate || strict
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PlannedFile {
    pub wire: String,
    pub token: String,
    pub file: PathBuf,
}

#[derive(Debug, Clone)]
pub(crate) struct BuiltinInfo {
    pub label: &'static str,
    /// The config switch that turns it off; `None` for the always-on `/healthz`.
    pub field: Option<&'static str>,
    pub methods: Vec<&'static str>,
    /// `/healthz` and `/readyz`: documenting them under a document-wide security default is common.
    pub inherited_exempt: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct PlannedRoute {
    /// apiRoot-relative, axum style.
    pub path: String,
    pub files: Vec<PlannedFile>,
    pub builtin: Option<BuiltinInfo>,
}

pub(crate) struct RoutePlan {
    pub problems: Vec<RouteProblem>,
    pub excluded_paths: BTreeSet<String>,
    pub routes: Vec<PlannedRoute>,
    probe: matchit::Router<usize>,
    max_segments: usize,
}

struct Member {
    origin: RouteOrigin,
    methods: BTreeSet<String>,
    custom_fallback: bool,
    endpoint_path: Option<String>,
    /// Per-file claimed methods, so an overlap can name the file that actually collides.
    files: Vec<(PathBuf, BTreeSet<String>)>,
}

fn segment_count(path: &str) -> usize {
    if path == "/" { 0 } else { path.split('/').count() - 1 }
}

fn config_segment_problem(seg: &str) -> Option<String> {
    if let Some(reason) = unsafe_segment_reason(seg, false) {
        return Some(reason);
    }
    match classify_route_segment(seg) {
        Ok(SegmentKind::Literal) => None,
        Ok(_) => Some("contains braces, which the route table does not accept in a prefix".to_string()),
        Err(reason) => Some(reason),
    }
}

fn param_name_difference(a: &str, b: &str) -> Option<(String, String)> {
    for (x, y) in a.split('/').zip(b.split('/')) {
        match (x.strip_prefix(':'), y.strip_prefix(':')) {
            (Some(nx), Some(ny)) if nx != ny => return Some((nx.to_string(), ny.to_string())),
            _ if x != y && !(x.starts_with(':') && y.starts_with(':')) => return None,
            _ => {}
        }
    }
    None
}

#[derive(Default)]
struct TrieNode {
    statics: BTreeMap<String, TrieNode>,
    param: Option<Box<TrieNode>>,
}

impl TrieNode {
    fn insert(&mut self, segments: &[&str]) {
        let Some((first, rest)) = segments.split_first() else { return };
        let child = if first.starts_with(':') {
            self.param.get_or_insert_with(Default::default).as_mut()
        } else {
            self.statics.entry((*first).to_string()).or_default()
        };
        child.insert(rest);
    }

    fn branching_depth(&self) -> usize {
        let here = usize::from(self.param.is_some() && !self.statics.is_empty());
        let below = self
            .statics
            .values()
            .map(TrieNode::branching_depth)
            .chain(self.param.iter().map(|p| p.branching_depth()))
            .max()
            .unwrap_or(0);
        here + below
    }
}

impl RoutePlan {
    pub(crate) fn build(tree: &crate::openapi::endpoint_tree::EndpointTree, mode: crate::openapi::method_token::MethodCase, ctx: &RouteContext) -> RoutePlan {
        RoutePlan::from_inventory(&super::route_inventory(tree, mode), ctx)
    }

    pub(crate) fn from_inventory(inventory: &RouteInventory, ctx: &RouteContext) -> RoutePlan {
        let mut problems: Vec<RouteProblem> = Vec::new();
        let mut excluded: BTreeSet<String> = BTreeSet::new();

        let mut api_prefix = crate::server::normalize_api_root(&ctx.api_root);
        if let Some(prefix) = &api_prefix
            && let Some((seg, reason)) = prefix[1..].split('/').find_map(|seg| config_segment_problem(seg).map(|r| (seg, r)))
        {
            problems.push(RouteProblem {
                kind: RouteProblemKind::InvalidConfigRoute,
                message: format!(
                    "config/server.json apiRoot '{}' can't be a route prefix: segment '{}' {reason}",
                    untrusted(&ctx.api_root),
                    untrusted(seg)
                ),
            });
            api_prefix = None;
        }
        let mut docs_paths: Option<[String; 3]> = None;
        if ctx.api_builtins && ctx.docs {
            let normalized = crate::server::normalize_docs_ui_path(&ctx.docs_path);
            match normalized.split('/').find_map(|seg| config_segment_problem(seg).map(|r| (seg.to_string(), r))) {
                Some((seg, reason)) => problems.push(RouteProblem {
                    kind: RouteProblemKind::InvalidConfigRoute,
                    message: format!(
                        "config/server.json docsUi.path '{}' can't be a route: segment '{}' {reason}",
                        untrusted(&ctx.docs_path),
                        untrusted(&seg)
                    ),
                }),
                None => docs_paths = Some(crate::server::docs_ui_route_paths(&normalized)),
            }
        }
        let final_of = |relative: &str| match &api_prefix {
            Some(prefix) => path_for_nested_route(prefix, relative),
            None => relative.to_string(),
        };

        let mut by_path: BTreeMap<String, Vec<&InventoryEntry>> = BTreeMap::new();
        for entry in inventory.entries.iter().filter(|e| e.status == EntryStatus::Routed) {
            by_path.entry(entry.url_path.clone()).or_default().push(entry);
        }

        let mut groups: BTreeMap<String, Vec<Member>> = BTreeMap::new();
        let mut endpoint_paths: BTreeMap<String, Vec<&InventoryEntry>> = BTreeMap::new();
        for (path, entries) in by_path {
            let first = entries[0];
            let mut unroutable = false;
            for seg in &first.segments {
                if let Some(reason) = unsafe_segment_reason(seg, false) {
                    problems.push(RouteProblem {
                        kind: RouteProblemKind::Unroutable,
                        message: format!(
                            "{}: folder '{}' can't be a route segment: {reason} — rename the folder by hand",
                            untrusted(&first.file.display().to_string()),
                            untrusted(seg)
                        ),
                    });
                    unroutable = true;
                    break;
                }
                match classify_route_segment(seg) {
                    Err(reason) => {
                        problems.push(RouteProblem {
                            kind: RouteProblemKind::Unroutable,
                            message: format!(
                                "{}: folder '{}' can't be a route segment: {reason} — rename the folder by hand",
                                untrusted(&first.file.display().to_string()),
                                untrusted(seg)
                            ),
                        });
                        unroutable = true;
                        break;
                    }
                    Ok(SegmentKind::PartialTemplate) => problems.push(RouteProblem {
                        kind: RouteProblemKind::PartialTemplate,
                        message: format!(
                            "{}: folder '{}' mixes literal text with braces — it is served as a literal, not a parameter",
                            untrusted(&first.file.display().to_string()),
                            untrusted(seg)
                        ),
                    }),
                    Ok(_) => {}
                }
            }
            if unroutable {
                excluded.insert(path);
                continue;
            }
            let methods: BTreeSet<String> = entries.iter().flat_map(|e| e.claimed_methods()).collect();
            let custom_fallback = entries.iter().any(|e| matches!(e.kind, Some(RouteKind::Extension(_))));
            groups.entry(final_of(&path)).or_default().push(Member {
                origin: RouteOrigin::Endpoint(first.file.clone()),
                methods,
                custom_fallback,
                endpoint_path: Some(path.clone()),
                files: entries.iter().map(|e| (e.file.clone(), e.claimed_methods().into_iter().collect())).collect(),
            });
            endpoint_paths.insert(path, entries);
        }

        let all_get_head = || ["GET", "HEAD"].into_iter().map(String::from).collect::<BTreeSet<String>>();
        let mut builtins: Vec<(String, BuiltinInfo)> = Vec::new();
        if ctx.api_builtins {
            builtins.push((
                crate::server::HEALTHZ_PATH.to_string(),
                BuiltinInfo {
                    label: "/healthz",
                    field: None,
                    methods: vec!["GET", "HEAD"],
                    inherited_exempt: true,
                },
            ));
            if ctx.readyz {
                builtins.push((
                    crate::server::READYZ_PATH.to_string(),
                    BuiltinInfo {
                        label: "/readyz",
                        field: Some("features.readyzCheck"),
                        methods: vec!["GET", "HEAD"],
                        inherited_exempt: true,
                    },
                ));
            }
            if ctx.metrics {
                builtins.push((
                    crate::server::METRICS_PATH.to_string(),
                    BuiltinInfo {
                        label: "/metrics",
                        field: Some("features.metrics"),
                        methods: vec!["GET", "HEAD"],
                        inherited_exempt: false,
                    },
                ));
            }
            if let Some(paths) = &docs_paths {
                for (path, label) in paths.iter().zip(["docs UI page", "docs UI operations.json", "docs UI endpoints.json"]) {
                    builtins.push((
                        path.clone(),
                        BuiltinInfo {
                            label,
                            field: Some("docsUi.mode"),
                            methods: vec!["GET", "HEAD"],
                            inherited_exempt: false,
                        },
                    ));
                }
            }
        }
        for (path, info) in &builtins {
            groups.entry(final_of(path)).or_default().push(Member {
                origin: RouteOrigin::Builtin(info.label),
                methods: all_get_head(),
                custom_fallback: false,
                endpoint_path: None,
                files: Vec::new(),
            });
        }
        if ctx.extras.web {
            for path in crate::webserve::WEB_ROUTES {
                groups.entry(path.to_string()).or_default().push(Member {
                    origin: RouteOrigin::Web,
                    methods: all_get_head(),
                    custom_fallback: false,
                    endpoint_path: None,
                    files: Vec::new(),
                });
            }
        }
        if ctx.extras.control_plane {
            groups.entry(crate::testing::control_plane::SCENARIO_PATH.to_string()).or_default().push(Member {
                origin: RouteOrigin::ControlPlane,
                methods: ["GET", "HEAD", "POST", "DELETE"].into_iter().map(String::from).collect(),
                custom_fallback: false,
                endpoint_path: None,
                files: Vec::new(),
            });
        }

        for (final_path, members) in &groups {
            for (i, a) in members.iter().enumerate() {
                for b in &members[i + 1..] {
                    let shared: Vec<&String> = a.methods.intersection(&b.methods).collect();
                    let what = if let Some(method) = shared.first() {
                        (*method).clone()
                    } else if a.custom_fallback && b.custom_fallback {
                        "extension-method".to_string()
                    } else {
                        continue;
                    };
                    let (first, second) = if matches!(a.origin, RouteOrigin::Endpoint(_)) { (a, b) } else { (b, a) };
                    let hint = match &second.origin {
                        RouteOrigin::Builtin(_) => match builtins
                            .iter()
                            .find(|(_, info)| RouteOrigin::Builtin(info.label) == second.origin)
                            .and_then(|(_, i)| i.field)
                        {
                            Some(field) => format!("rename the folder, set a different apiRoot, or turn {field} off"),
                            None => "rename the folder or set a different apiRoot".to_string(),
                        },
                        _ => "rename the folder, or set a different apiRoot".to_string(),
                    };
                    let first_origin = {
                        let mut files: Vec<&(PathBuf, BTreeSet<String>)> = first.files.iter().filter(|(_, methods)| methods.contains(&what)).collect();
                        files.sort_by(|x, y| x.0.cmp(&y.0));
                        match files.first() {
                            Some((file, _)) => RouteOrigin::Endpoint(file.clone()),
                            None => first.origin.clone(),
                        }
                    };
                    problems.push(RouteProblem {
                        kind: RouteProblemKind::MethodOverlap,
                        message: format!("{first_origin}: {what} {} is also {} — {hint}", untrusted(final_path), second.origin),
                    });
                    for member in [a, b] {
                        if let Some(path) = &member.endpoint_path {
                            excluded.insert(path.clone());
                        }
                    }
                }
            }
        }

        let final_paths: Vec<String> = groups.keys().cloned().collect();
        let report = find_conflicts(&final_paths);
        for conflict in &report.conflicts {
            let origin_of = |p: &str| groups.get(p).and_then(|m| m.first()).map(|m| m.origin.clone());
            let a_origin = origin_of(&conflict.a);
            let message = match &conflict.b {
                Some(b) => {
                    let b_origin = origin_of(b);
                    let folder = |o: &Option<RouteOrigin>| match o {
                        Some(RouteOrigin::Endpoint(file)) => untrusted(&file.parent().unwrap_or(file).display().to_string()),
                        Some(other) => other.to_string(),
                        None => String::new(),
                    };
                    match param_name_difference(&conflict.a, b) {
                        Some((x, y)) if matches!(a_origin, Some(RouteOrigin::Endpoint(_))) && matches!(b_origin, Some(RouteOrigin::Endpoint(_))) => format!(
                            "{} and {} use different parameter names at the same position ({} vs {}) — axum can't route both; give them the same name",
                            folder(&a_origin),
                            folder(&b_origin),
                            untrusted(&x),
                            untrusted(&y)
                        ),
                        _ => format!(
                            "route {} ({}) conflicts with {} ({}): insertion failed due to conflict with a previously registered route",
                            untrusted(&conflict.a),
                            a_origin.map(|o| o.to_string()).unwrap_or_default(),
                            untrusted(b),
                            b_origin.map(|o| o.to_string()).unwrap_or_default()
                        ),
                    }
                }
                None => format!(
                    "route {} ({}) conflicts with a route near '{}': insertion failed due to conflict with a previously registered route",
                    untrusted(&conflict.a),
                    a_origin.map(|o| o.to_string()).unwrap_or_default(),
                    untrusted(conflict.near.as_deref().unwrap_or_default())
                ),
            };
            problems.push(RouteProblem {
                kind: RouteProblemKind::RouteConflict,
                message,
            });
        }
        for (path, text) in &report.unroutable {
            problems.push(RouteProblem {
                kind: RouteProblemKind::Unroutable,
                message: format!("route {} can't be registered: {}", untrusted(path), untrusted(text)),
            });
        }
        for member in report.members.iter().chain(report.unroutable.iter().map(|(p, _)| p)) {
            if let Some(members) = groups.get(member) {
                excluded.extend(members.iter().filter_map(|m| m.endpoint_path.clone()));
            }
        }

        let mut trie = TrieNode::default();
        for path in endpoint_paths.keys().filter(|p| !excluded.contains(*p)) {
            let segments: Vec<&str> = path.split('/').skip(1).filter(|s| !s.is_empty()).collect();
            trie.insert(&segments);
        }
        let depth = trie.branching_depth();
        if depth > MAX_BRANCHING_DEPTH {
            problems.push(RouteProblem {
                kind: RouteProblemKind::RouteTreeTooAmbiguous,
                message: format!(
                    "the endpoint folders branch between a fixed name and a {{parameter}} at {depth} nested positions on one route (limit {MAX_BRANCHING_DEPTH}) — flatten the folders"
                ),
            });
        }

        let mut planned: BTreeMap<String, PlannedRoute> = BTreeMap::new();
        for (path, entries) in &endpoint_paths {
            if excluded.contains(path) {
                continue;
            }
            planned.insert(
                path.clone(),
                PlannedRoute {
                    path: path.clone(),
                    files: entries
                        .iter()
                        .map(|e| PlannedFile {
                            wire: e.wire.clone(),
                            token: e.token.clone(),
                            file: e.file.clone(),
                        })
                        .collect(),
                    builtin: None,
                },
            );
        }
        for (path, info) in builtins {
            planned
                .entry(path.clone())
                .or_insert_with(|| PlannedRoute {
                    path,
                    files: Vec::new(),
                    builtin: None,
                })
                .builtin = Some(info);
        }
        let routes: Vec<PlannedRoute> = planned.into_values().collect();
        let mut probe = matchit::Router::new();
        let mut max_segments = 0usize;
        for (index, route) in routes.iter().enumerate() {
            if probe.insert(route.path.clone(), index).is_ok() {
                max_segments = max_segments.max(segment_count(&route.path));
            }
        }

        problems.sort_by(|a, b| a.message.cmp(&b.message));
        problems.dedup();
        RoutePlan {
            problems,
            excluded_paths: excluded,
            routes,
            probe,
            max_segments,
        }
    }

    pub(crate) fn is_excluded(&self, url_path: &str) -> bool {
        self.excluded_paths.contains(url_path)
    }

    pub(crate) fn refusals(&self, strict: bool) -> Vec<&RouteProblem> {
        self.problems.iter().filter(|p| p.is_refusal(strict)).collect()
    }

    pub(crate) fn warnings(&self, strict: bool) -> Vec<&RouteProblem> {
        self.problems.iter().filter(|p| !p.is_refusal(strict)).collect()
    }

    /// The registered route that would answer a request for `probe` (apiRoot-relative), if any.
    pub(crate) fn resolve(&self, probe: &str) -> Option<&PlannedRoute> {
        if segment_count(probe) > self.max_segments {
            return None;
        }
        let found = self.probe.at(probe).ok()?;
        self.routes.get(*found.value)
    }
}
