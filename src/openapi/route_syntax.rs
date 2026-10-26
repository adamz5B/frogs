use std::borrow::Cow;
use std::collections::BTreeSet;

use matchit::InsertError;

use super::path_encoding::encode_literal_segment;

pub const PARAM_PROBE: &str = ":frogs-probe";
const MAX_PROBE_BYTES: usize = 2048;
const MAX_PROBE_SEGMENTS: usize = 64;
const SHUFFLED_ORDERS: u64 = 8;
const DIAGNOSTIC_PAIR_TEST_CAP: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SegmentKind {
    Literal,
    Param(String),
    /// Contains `{` or `}` without being exactly `{name}`: routed as a literal by axum 0.7.
    PartialTemplate,
}

/// Classifies one raw path segment (spec path or endpoint folder) for the
/// axum 0.7 / matchit 0.7 route syntax, where `:` and `*` are special and
/// `{name}` is frogs's own template convention translated to `:name`.
pub fn classify_route_segment(seg: &str) -> Result<SegmentKind, String> {
    if seg.contains('%') {
        return Err("contains '%', which is ambiguous between a literal percent sign and a percent-encoded character".to_string());
    }
    if let Some(name) = seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
        if name.is_empty() {
            return Err("empty parameter name".to_string());
        }
        if name.contains([':', '*', '{', '}']) {
            return Err("parameter name contains one of : * { }".to_string());
        }
        return Ok(SegmentKind::Param(name.to_string()));
    }
    if seg.contains([':', '*']) {
        return Err("contains ':' or '*', which the route table treats as parameter/wildcard syntax".to_string());
    }
    if seg.contains(['{', '}']) {
        return Ok(SegmentKind::PartialTemplate);
    }
    Ok(SegmentKind::Literal)
}

pub fn is_non_literal_segment(seg: &str) -> bool {
    seg.contains(['{', '}', ':', '*'])
}

/// `{name}` -> `:name`, segment by segment, applied to an OpenAPI path string.
pub fn axum_style(openapi_path: &str) -> String {
    openapi_path
        .split('/')
        .map(|segment| match segment.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            Some(name) => format!(":{name}"),
            None => segment.to_string(),
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// An axum-style url path (`:name` parameters, decoded literal text) as it must
/// be registered: axum matches literal segments against the raw wire bytes,
/// and `CanonicalPath` hands it paths whose non-`pchar` bytes are `%XX`.
pub fn axum_registration_path(url_path: &str) -> String {
    url_path
        .split('/')
        .map(|segment| {
            if segment.starts_with(':') {
                Cow::Borrowed(segment)
            } else {
                encode_literal_segment(segment)
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Copy of axum 0.7.9's `routing::path_router::path_for_nested_route`: where a
/// route registered at `path` inside a router lands once nested at `prefix`.
pub fn path_for_nested_route(prefix: &str, path: &str) -> String {
    if prefix.ends_with('/') {
        format!("{prefix}{}", path.trim_start_matches('/'))
    } else if path == "/" {
        prefix.to_string()
    } else {
        format!("{prefix}{path}")
    }
}

/// The request path used to ask the route table "who would answer this spec
/// path": every segment that is not a plain literal becomes a parameter
/// sentinel no literal route segment can equal, the rest stay as written (a
/// trailing slash is kept, since the router does not normalise it).
pub fn probe_path(raw: &str) -> Result<String, String> {
    if raw.len() > MAX_PROBE_BYTES {
        return Err(format!("longer than {MAX_PROBE_BYTES} bytes"));
    }
    if raw.chars().any(|c| c == '\\' || c.is_control()) {
        return Err("contains a backslash or control character".to_string());
    }
    let with_slash = if raw.starts_with('/') { raw.to_string() } else { format!("/{raw}") };
    if with_slash == "/" {
        return Ok(with_slash);
    }
    let segments: Vec<&str> = with_slash[1..].split('/').collect();
    if segments.len() > MAX_PROBE_SEGMENTS {
        return Err(format!("more than {MAX_PROBE_SEGMENTS} segments"));
    }
    let mut out = String::new();
    for (i, seg) in segments.iter().enumerate() {
        let last = i + 1 == segments.len();
        if seg.is_empty() && !last {
            return Err("empty path segment".to_string());
        }
        if *seg == "." || *seg == ".." {
            return Err(format!("path segment '{seg}' is not allowed"));
        }
        if seg.contains('%') {
            return Err("path segment contains '%', which is ambiguous between a literal percent sign and a percent-encoded character".to_string());
        }
        out.push('/');
        if is_non_literal_segment(seg) {
            out.push_str(PARAM_PROBE);
        } else {
            out.push_str(&encode_literal_segment(seg));
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Conflict {
    /// The path whose insertion failed.
    pub a: String,
    /// The already-registered path it collides with, when that could be pinned down.
    pub b: Option<String>,
    /// matchit's own description of the collision, kept only when `b` is unknown.
    pub near: Option<String>,
}

#[derive(Debug, Default, Clone)]
pub struct ConflictReport {
    pub conflicts: Vec<Conflict>,
    /// Every path that is a member of some conflict.
    pub members: BTreeSet<String>,
    /// Paths matchit refused for a reason other than a conflict.
    pub unroutable: Vec<(String, String)>,
}

fn lcg_next(state: &mut u64) -> u64 {
    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    *state >> 33
}

fn shuffled(items: &[String], seed: u64) -> Vec<String> {
    let mut out = items.to_vec();
    let mut state = seed;
    for i in (1..out.len()).rev() {
        let j = (lcg_next(&mut state) % (i as u64 + 1)) as usize;
        out.swap(i, j);
    }
    out
}

fn pair_conflicts(first: &str, second: &str) -> bool {
    let mut router = matchit::Router::new();
    if router.insert(first.to_string(), 0usize).is_err() {
        return false;
    }
    matches!(router.insert(second.to_string(), 0usize), Err(InsertError::Conflict { .. }))
}

/// Which axum-style paths cannot coexist in one route table. matchit's verdict
/// can depend on insertion order, so the whole set is inserted in sorted,
/// reversed and several fixed-seed shuffled orders and the union reported:
/// a conflict in any order is a conflict.
pub fn find_conflicts(paths: &[String]) -> ConflictReport {
    let mut unique: Vec<String> = paths.to_vec();
    unique.sort();
    unique.dedup();

    let mut orders: Vec<Vec<String>> = vec![unique.clone()];
    let mut reversed = unique.clone();
    reversed.reverse();
    orders.push(reversed);
    for seed in 1..=SHUFFLED_ORDERS {
        orders.push(shuffled(&unique, seed.wrapping_mul(0x9E37_79B9_7F4A_7C15)));
    }

    let mut found: BTreeSet<Conflict> = BTreeSet::new();
    let mut unroutable: BTreeSet<(String, String)> = BTreeSet::new();
    let mut budget = DIAGNOSTIC_PAIR_TEST_CAP;
    for order in &orders {
        let mut router = matchit::Router::new();
        let mut registered: Vec<&str> = Vec::new();
        for path in order {
            match router.insert(path.clone(), 0usize) {
                Ok(()) => registered.push(path),
                Err(InsertError::Conflict { with }) => {
                    let other = if registered.iter().any(|r| *r == with) {
                        Some(with.clone())
                    } else {
                        let mut hit = None;
                        for candidate in &registered {
                            if budget == 0 {
                                break;
                            }
                            budget -= 1;
                            if pair_conflicts(candidate, path) {
                                hit = Some((*candidate).to_string());
                                break;
                            }
                        }
                        hit
                    };
                    let conflict = match other {
                        Some(b) if b < *path => Conflict {
                            a: b,
                            b: Some(path.clone()),
                            near: None,
                        },
                        Some(b) => Conflict {
                            a: path.clone(),
                            b: Some(b),
                            near: None,
                        },
                        None => Conflict {
                            a: path.clone(),
                            b: None,
                            near: Some(with),
                        },
                    };
                    found.insert(conflict);
                }
                Err(other) => {
                    unroutable.insert((path.clone(), other.to_string()));
                }
            }
        }
    }

    let mut members = BTreeSet::new();
    for conflict in &found {
        members.insert(conflict.a.clone());
        if let Some(b) = &conflict.b {
            members.insert(b.clone());
        }
    }
    ConflictReport {
        conflicts: found.into_iter().collect(),
        members,
        unroutable: unroutable.into_iter().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_covers_the_documented_segment_shapes() {
        assert_eq!(classify_route_segment("cars"), Ok(SegmentKind::Literal));
        assert_eq!(classify_route_segment("{id}"), Ok(SegmentKind::Param("id".to_string())));
        for bad in ["{}", "{a:b}", "{a*b}", "{*rest}", "a:b", "*", "x*", "{id}:cancel"] {
            assert!(classify_route_segment(bad).is_err(), "{bad}");
        }
        for partial in ["{id}.json", "a{b}", "{abc", "abc}"] {
            assert_eq!(classify_route_segment(partial), Ok(SegmentKind::PartialTemplate), "{partial}");
        }
    }

    #[test]
    fn probe_replaces_non_literal_segments_and_keeps_a_trailing_slash() {
        assert_eq!(probe_path("/cars/{id}/parts").unwrap(), "/cars/:frogs-probe/parts");
        assert_eq!(probe_path("/x/").unwrap(), "/x/");
        assert_eq!(probe_path("/").unwrap(), "/");
        assert!(probe_path("/a//b").is_err());
        assert!(probe_path("/a/../b").is_err());
    }

    #[test]
    fn differently_named_parameters_at_one_position_conflict() {
        let report = find_conflicts(&["/x/:a".to_string(), "/x/:b".to_string()]);
        assert_eq!(report.conflicts.len(), 1);
        assert!(report.members.contains("/x/:a") && report.members.contains("/x/:b"));
        assert!(find_conflicts(&["/cars/new".to_string(), "/cars/:id".to_string()]).conflicts.is_empty());
    }
}

#[cfg(test)]
mod more_tests {
    use super::*;

    fn s(items: &[&str]) -> Vec<String> {
        items.iter().map(|i| i.to_string()).collect()
    }

    #[test]
    fn this_module_contains_no_platform_conditionals_outside_test_code() {
        let cfg_macro = format!("{}!(", "cfg");
        let cfg_attr = format!("#[{}(", "cfg");
        let test_marker = format!("#[{}(test)]", "cfg");
        for source in [include_str!("route_syntax.rs"), include_str!("path_encoding.rs")] {
            let production = source.split(test_marker.as_str()).next().unwrap();
            assert!(!production.contains(&cfg_macro), "{cfg_macro} found");
            assert!(!production.contains(&cfg_attr), "{cfg_attr} found");
        }
    }

    #[test]
    fn path_for_nested_route_matches_axums_rules_for_root_trailing_slash_and_plain_prefixes() {
        assert_eq!(path_for_nested_route("/api", "/"), "/api");
        assert_eq!(path_for_nested_route("/api", "/x"), "/api/x");
        assert_eq!(path_for_nested_route("/api/", "/x"), "/api/x");
        assert_eq!(path_for_nested_route("/api/", "/"), "/api/");
    }

    #[test]
    fn probe_rejects_control_characters_backslashes_dot_segments_overlong_and_too_deep_paths() {
        assert!(probe_path("/a\u{1b}b").is_err());
        assert!(probe_path(r"/a\b").is_err());
        assert!(probe_path("/a/./b").is_err());
        assert!(probe_path(&format!("/{}", "a".repeat(2100))).is_err());
        assert!(probe_path(&format!("/{}", vec!["a"; 65].join("/"))).is_err());
        assert!(probe_path(&format!("/{}", vec!["a"; 64].join("/"))).is_ok());
    }

    #[test]
    fn probe_turns_every_segment_containing_a_special_character_into_the_sentinel() {
        assert_eq!(probe_path("/v1/{id}:cancel").unwrap(), "/v1/:frogs-probe");
        assert_eq!(probe_path("/a*b/x:y/{z}").unwrap(), "/:frogs-probe/:frogs-probe/:frogs-probe");
        assert_eq!(probe_path("cars").unwrap(), "/cars", "a missing leading slash is added");
    }

    #[test]
    fn axum_style_translates_only_exact_templates() {
        assert_eq!(axum_style("/cars/{vin}/x.{ext}"), "/cars/:vin/x.{ext}");
    }

    #[test]
    fn conflict_detection_is_independent_of_the_input_order() {
        let sets = [
            s(&["/x/:a", "/x/:b", "/x/:c/y"]),
            s(&["/cars/new", "/cars/:id", "/cars/:id/owner"]),
            s(&["/a", "/:p", "/:q", "/a/b", "/:p/b"]),
        ];
        for set in sets {
            let baseline = find_conflicts(&set);
            let mut reversed = set.clone();
            reversed.reverse();
            let other = find_conflicts(&reversed);
            assert_eq!(baseline.members, other.members, "{set:?}");
            assert_eq!(baseline.conflicts, other.conflicts, "{set:?}");
        }
    }

    #[test]
    fn a_dense_pile_of_overlapping_templates_never_panics_and_every_conflict_member_is_one_of_the_inputs() {
        let input = s(&["/a/:x/c", "/a/:y/d", "/a/b/:z", "/a/:w", "/:p", "/:q", "/*r", "/a", "/a/:x"]);
        let report = find_conflicts(&input);
        for member in &report.members {
            assert!(input.contains(member), "{member}");
        }
    }

    #[test]
    fn many_unrelated_routes_report_no_conflicts_quickly_enough_to_finish() {
        let paths: Vec<String> = (0..2000).map(|i| format!("/r{i}/:id/leaf")).collect();
        assert!(find_conflicts(&paths).conflicts.is_empty());
    }

    #[test]
    fn identical_paths_are_deduplicated_not_reported_as_a_conflict() {
        assert!(find_conflicts(&s(&["/a/:x", "/a/:x"])).conflicts.is_empty());
    }
}
