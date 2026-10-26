use std::path::{Component, Path};

use super::dir_index::fold;
use super::route_syntax::{SegmentKind, classify_route_segment};
use super::{IssueKind, Severity};

const MAX_SEGMENT_BYTES: usize = 255;
const MAX_PATH_BYTES: usize = 2048;
pub(crate) const RESERVED_DIR: &str = "_backups";

/// What to do with a path whose segments would be unusable as a Windows file
/// name. `for_host` is the only host-OS branch in the whole path-hardening
/// feature; everything else behaves identically on every OS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortabilityPolicy {
    Skip,
    Warn,
}

impl PortabilityPolicy {
    pub fn for_host() -> Self {
        if cfg!(windows) { PortabilityPolicy::Skip } else { PortabilityPolicy::Warn }
    }
}

pub type RuleIssue = (IssueKind, Severity, String);

#[derive(Debug, Clone, PartialEq)]
pub struct PathCheck {
    pub normalized: String,
    pub issues: Vec<RuleIssue>,
}

/// Escapes and truncates spec-sourced text before it goes into a message, so
/// a hostile spec can't inject terminal control sequences or flood the log.
pub fn untrusted(s: &str) -> String {
    let escaped = s.escape_debug().to_string();
    if escaped.chars().count() > 200 {
        let mut truncated: String = escaped.chars().take(200).collect();
        truncated.push('…');
        truncated
    } else {
        escaped
    }
}

pub fn windows_reserved(seg: &str) -> bool {
    let stem = seg.split('.').next().unwrap_or("").trim_end_matches(' ').to_uppercase();
    matches!(
        stem.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "CONIN$"
            | "CONOUT$"
            | "COM0"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "COM\u{b9}"
            | "COM\u{b2}"
            | "COM\u{b3}"
            | "LPT0"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
            | "LPT\u{b9}"
            | "LPT\u{b2}"
            | "LPT\u{b3}"
    )
}

pub(crate) fn is_single_normal_component(seg: &str) -> bool {
    let mut components = Path::new(seg).components();
    matches!((components.next(), components.next()), (Some(Component::Normal(_)), None))
}

pub(crate) fn unsafe_segment_reason(seg: &str, is_file_name: bool) -> Option<String> {
    if seg.is_empty() {
        return Some("empty path segment".to_string());
    }
    if seg.chars().all(char::is_whitespace) {
        return Some("whitespace-only path segment".to_string());
    }
    if seg == "." || seg == ".." {
        return Some(format!("path segment '{seg}' is not allowed"));
    }
    if seg.contains('\\') || seg.contains('\0') || seg.chars().any(char::is_control) {
        return Some("path segment contains a backslash or control character".to_string());
    }
    if is_file_name && seg.contains('/') {
        return Some("name contains a path separator".to_string());
    }
    if !is_file_name && fold(seg) == RESERVED_DIR {
        return Some(format!("path segment '{seg}' is reserved for generate's backup folders"));
    }
    if seg.len() > MAX_SEGMENT_BYTES {
        return Some(format!("path segment is longer than {MAX_SEGMENT_BYTES} bytes"));
    }
    None
}

fn windows_reason(seg: &str) -> Option<String> {
    if seg.chars().any(|c| matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*')) {
        return Some("contains a character Windows does not allow in file names (<>:\"|?*)".to_string());
    }
    if seg.ends_with('.') || seg.ends_with(' ') {
        return Some("ends with a dot or space, which Windows does not allow in file names".to_string());
    }
    if windows_reserved(seg) {
        return Some("is a reserved Windows device name".to_string());
    }
    None
}

pub fn validate_path(raw: &str, policy: PortabilityPolicy) -> Result<PathCheck, (IssueKind, String)> {
    let shown = untrusted(raw);
    let mut issues: Vec<RuleIssue> = Vec::new();

    let mut normalized = raw.to_string();
    if !normalized.starts_with('/') {
        normalized.insert(0, '/');
        issues.push((
            IssueKind::TrailingSlashNormalised,
            Severity::Warning,
            format!("path '{shown}' does not start with '/' — normalised to '{}'", untrusted(&normalized)),
        ));
    }
    if normalized == "/" {
        return Ok(PathCheck { normalized, issues });
    }
    if normalized.ends_with('/') {
        normalized.pop();
        issues.push((
            IssueKind::TrailingSlashNormalised,
            Severity::Warning,
            format!("path '{shown}' has a trailing slash — normalised to '{}'", untrusted(&normalized)),
        ));
    }
    if normalized.len() > MAX_PATH_BYTES {
        return Err((IssueKind::UnsafePath, format!("path '{shown}' is longer than {MAX_PATH_BYTES} bytes")));
    }
    if normalized == "/" {
        return Err((IssueKind::UnsafePath, format!("path '{shown}' skipped: empty path segment")));
    }

    for seg in normalized[1..].split('/') {
        if let Some(reason) = unsafe_segment_reason(seg, false) {
            return Err((IssueKind::UnsafePath, format!("path '{shown}' skipped: {reason}")));
        }
        match classify_route_segment(seg) {
            Err(reason) => {
                return Err((IssueKind::UnsafePath, format!("path '{shown}' skipped: segment '{}' {reason}", untrusted(seg))));
            }
            Ok(SegmentKind::PartialTemplate) => issues.push((
                IssueKind::PartialPathTemplate,
                Severity::Warning,
                format!(
                    "path '{shown}': segment '{}' mixes literal text with braces — it is served as a literal, not a parameter (use a whole-segment {{name}})",
                    untrusted(seg)
                ),
            )),
            Ok(_) => {}
        }
        let mut windows_hit = false;
        if let Some(reason) = windows_reason(seg) {
            let message = format!("path '{shown}': segment '{}' {reason}", untrusted(seg));
            match policy {
                PortabilityPolicy::Skip => return Err((IssueKind::WindowsPortability, message)),
                PortabilityPolicy::Warn => {
                    issues.push((IssueKind::WindowsPortability, Severity::Warning, message));
                    windows_hit = true;
                }
            }
        }
        // A Windows-portability hit has already been reported (and, on
        // Windows, would have skipped the path above); `C:` is a prefix
        // component only there, and `endpoint_dir` re-checks at use anyway.
        if !windows_hit && !is_single_normal_component(seg) {
            return Err((
                IssueKind::UnsafePath,
                format!("path '{shown}' skipped: segment '{}' is not a plain name", untrusted(seg)),
            ));
        }
    }

    Ok(PathCheck { normalized, issues })
}

/// Same rules as one path segment, for a name that will be joined onto a
/// directory (component cache files). Returns the Windows-portability
/// warnings under `Warn`.
pub fn validate_file_name(name: &str, policy: PortabilityPolicy) -> Result<Vec<RuleIssue>, (IssueKind, String)> {
    let shown = untrusted(name);
    if let Some(reason) = unsafe_segment_reason(name, true) {
        return Err((IssueKind::UnsafeComponentName, format!("component file name '{shown}': {reason}")));
    }
    let mut issues = Vec::new();
    let mut windows_hit = false;
    if let Some(reason) = windows_reason(name) {
        let message = format!("component file name '{shown}' {reason}");
        match policy {
            PortabilityPolicy::Skip => return Err((IssueKind::UnsafeComponentName, message)),
            PortabilityPolicy::Warn => {
                issues.push((IssueKind::WindowsPortability, Severity::Warning, message));
                windows_hit = true;
            }
        }
    }
    if !windows_hit && !is_single_normal_component(name) {
        return Err((IssueKind::UnsafeComponentName, format!("component file name '{shown}' is not a plain name")));
    }
    Ok(issues)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(raw: &str, policy: PortabilityPolicy) -> PathCheck {
        validate_path(raw, policy).unwrap_or_else(|e| panic!("{raw:?} should be accepted, got {e:?}"))
    }

    fn rejected_kind(raw: &str, policy: PortabilityPolicy) -> IssueKind {
        match validate_path(raw, policy) {
            Err((kind, _)) => kind,
            Ok(check) => panic!("{raw:?} should be rejected, got {check:?}"),
        }
    }

    #[test]
    fn the_root_path_and_a_leading_underscore_path_are_accepted_unchanged() {
        for policy in [PortabilityPolicy::Skip, PortabilityPolicy::Warn] {
            let root = ok("/", policy);
            assert_eq!(root.normalized, "/");
            assert!(root.issues.is_empty());
            let health = ok("/_health", policy);
            assert_eq!(health.normalized, "/_health");
            assert!(health.issues.is_empty());
        }
    }

    #[test]
    fn a_trailing_slash_is_removed_with_a_normalisation_warning() {
        let check = ok("/cars/", PortabilityPolicy::Warn);
        assert_eq!(check.normalized, "/cars");
        assert_eq!(check.issues.len(), 1);
        assert_eq!(check.issues[0].0, IssueKind::TrailingSlashNormalised);
        assert_eq!(check.issues[0].1, Severity::Warning);
    }

    #[test]
    fn a_missing_leading_slash_is_added_and_reported_as_a_normalisation() {
        let check = ok("cars", PortabilityPolicy::Warn);
        assert_eq!(check.normalized, "/cars");
        assert_eq!(check.issues.len(), 1);
        assert_eq!(check.issues[0].0, IssueKind::TrailingSlashNormalised);
    }

    #[test]
    fn a_double_trailing_slash_is_rejected_as_an_empty_segment() {
        assert_eq!(rejected_kind("/cars//", PortabilityPolicy::Warn), IssueKind::UnsafePath);
    }

    #[test]
    fn traversal_empty_whitespace_and_control_segments_are_rejected_under_both_policies() {
        let bad = [
            "//",
            "/a//b",
            "/ ",
            "/a/ /b",
            "/a/./b",
            "/a/../b",
            "/{a/../b}",
            r"/a\b",
            "/a\u{0}b",
            "/a\u{7}b",
            "/x/_backups",
            "/x/_Backups",
            "/x/_BACKUPS",
        ];
        for raw in bad {
            for policy in [PortabilityPolicy::Skip, PortabilityPolicy::Warn] {
                assert_eq!(rejected_kind(raw, policy), IssueKind::UnsafePath, "{raw:?} under {policy:?}");
            }
        }
    }

    #[test]
    fn a_255_byte_segment_is_accepted_and_a_256_byte_segment_is_rejected() {
        let fine = format!("/{}", "a".repeat(255));
        assert!(validate_path(&fine, PortabilityPolicy::Warn).is_ok());
        let too_long = format!("/{}", "a".repeat(256));
        assert_eq!(rejected_kind(&too_long, PortabilityPolicy::Warn), IssueKind::UnsafePath);
    }

    #[test]
    fn a_path_longer_than_2048_bytes_is_rejected_even_when_every_segment_is_short() {
        let long = format!("/{}", vec!["abcdefghij"; 200].join("/"));
        assert!(long.len() > 2048);
        assert_eq!(rejected_kind(&long, PortabilityPolicy::Warn), IssueKind::UnsafePath);
    }

    #[test]
    fn a_drive_letter_segment_is_unsafe_under_both_policies() {
        for policy in [PortabilityPolicy::Skip, PortabilityPolicy::Warn] {
            assert_eq!(rejected_kind("/C:/x", policy), IssueKind::UnsafePath);
        }
    }

    #[test]
    fn a_unc_style_path_is_unsafe_under_both_policies() {
        for policy in [PortabilityPolicy::Skip, PortabilityPolicy::Warn] {
            assert_eq!(rejected_kind(r"\\srv\x", policy), IssueKind::UnsafePath);
        }
    }

    #[test]
    fn windows_reserved_names_are_flagged_case_insensitively_and_ignoring_extensions() {
        for name in [
            "CON",
            "con",
            "con.txt",
            "CON .txt",
            "CONIN$",
            "conout$",
            "COM\u{b9}",
            "COM\u{b2}",
            "LPT0",
            "lpt9",
            "NUL",
            "aux.json",
            "PRN",
            "COM0",
        ] {
            assert!(windows_reserved(name), "{name:?} should be reserved");
        }
        for name in ["CONSOLE", "cars", "COM10", "LPT", "COMX", ""] {
            assert!(!windows_reserved(name), "{name:?} should not be reserved");
        }
    }

    #[test]
    fn windows_unfriendly_segments_are_portability_hits_not_unsafe_paths() {
        for raw in ["/CON", "/a/con.txt", "/a.", "/a ", "/a?", "/a<b", "/a|b", "/a\"b", "/a>b"] {
            assert_eq!(rejected_kind(raw, PortabilityPolicy::Skip), IssueKind::WindowsPortability, "{raw:?}");
            let kept = ok(raw, PortabilityPolicy::Warn);
            assert_eq!(kept.normalized, raw);
            assert!(kept.issues.iter().any(|(k, _, _)| *k == IssueKind::WindowsPortability), "{raw:?}");
        }
    }

    #[test]
    fn brace_templates_and_ordinary_names_pass_cleanly_under_both_policies() {
        for policy in [PortabilityPolicy::Skip, PortabilityPolicy::Warn] {
            let check = ok("/cars/{vin}/parts", policy);
            assert_eq!(check.normalized, "/cars/{vin}/parts");
            assert!(check.issues.is_empty());
        }
    }

    #[test]
    fn untrusted_escapes_control_characters_and_truncates_long_input() {
        let escaped = untrusted("a\u{1b}[31mb\nc");
        assert!(!escaped.contains('\u{1b}'));
        assert!(!escaped.contains('\n'));
        let long = untrusted(&"x".repeat(1000));
        assert_eq!(long.chars().count(), 201);
        assert!(long.ends_with('…'));
    }

    #[test]
    fn messages_for_rejected_paths_never_contain_raw_control_characters() {
        let (_, message) = validate_path("/a\u{1b}[2Jb\u{0}", PortabilityPolicy::Warn).unwrap_err();
        assert!(!message.chars().any(char::is_control), "{message:?}");
    }

    #[test]
    fn is_single_normal_component_accepts_names_and_rejects_dots_and_separators() {
        assert!(is_single_normal_component("cars"));
        assert!(is_single_normal_component("{vin}"));
        assert!(!is_single_normal_component(".."));
        assert!(!is_single_normal_component("."));
        assert!(!is_single_normal_component(""));
        assert!(!is_single_normal_component("a/b"));
    }

    #[test]
    fn validate_file_name_rejects_separators_and_traversal_as_unsafe_component_names() {
        for name in ["../../x.json", "a/b.json", r"a\b.json", "..", "", "x\0.json"] {
            for policy in [PortabilityPolicy::Skip, PortabilityPolicy::Warn] {
                let err = validate_file_name(name, policy).unwrap_err();
                assert_eq!(err.0, IssueKind::UnsafeComponentName, "{name:?}");
            }
        }
    }

    #[test]
    fn validate_file_name_treats_a_windows_hit_as_an_error_under_skip_and_a_warning_under_warn() {
        assert_eq!(validate_file_name("CON.json", PortabilityPolicy::Skip).unwrap_err().0, IssueKind::UnsafeComponentName);
        let issues = validate_file_name("CON.json", PortabilityPolicy::Warn).unwrap();
        assert!(issues.iter().any(|(k, _, _)| *k == IssueKind::WindowsPortability));
        assert!(validate_file_name("Car.json", PortabilityPolicy::Skip).unwrap().is_empty());
    }

    #[test]
    fn for_host_picks_skip_on_windows_and_warn_elsewhere() {
        let expected = if cfg!(windows) { PortabilityPolicy::Skip } else { PortabilityPolicy::Warn };
        assert_eq!(PortabilityPolicy::for_host(), expected);
    }
}

#[cfg(test)]
mod route_syntax_tests {
    use super::*;

    const BOTH: [PortabilityPolicy; 2] = [PortabilityPolicy::Skip, PortabilityPolicy::Warn];

    #[test]
    fn paths_with_route_special_characters_are_unsafe_under_both_policies() {
        let bad = [
            "/a:b",
            "/b-:c",
            "/a*b",
            "/*",
            "/x/*rest",
            "/x/{}",
            "/x/{a:b}",
            "/x/{a*b}",
            "/x/{*rest}",
            "/v1/{id}:cancel",
            "/C:/x",
        ];
        for raw in bad {
            for policy in BOTH {
                match validate_path(raw, policy) {
                    Err((kind, _)) => assert_eq!(kind, IssueKind::UnsafePath, "{raw:?} under {policy:?}"),
                    Ok(check) => panic!("{raw:?} under {policy:?} should be rejected, got {check:?}"),
                }
            }
        }
    }

    #[test]
    fn a_segment_mixing_literal_text_with_braces_is_kept_with_one_strict_class_warning() {
        for raw in ["/x/{id}.json", "/x/a{b}", "/x/{abc", "/x/abc}"] {
            for policy in BOTH {
                let check = validate_path(raw, policy).unwrap_or_else(|e| panic!("{raw:?} must be accepted: {e:?}"));
                assert_eq!(check.normalized, raw);
                let partial: Vec<_> = check.issues.iter().filter(|i| i.0 == IssueKind::PartialPathTemplate).collect();
                assert_eq!(partial.len(), 1, "{raw:?}: {:?}", check.issues);
                assert_eq!(partial[0].1, Severity::Warning);
                assert!(IssueKind::PartialPathTemplate.is_strict_error());
            }
        }
    }

    #[test]
    fn ordinary_templates_and_underscore_names_stay_clean() {
        for raw in ["/cars/{vin}/parts", "/{a-b}", "/{a.b}", "/_health"] {
            for policy in BOTH {
                let check = validate_path(raw, policy).unwrap_or_else(|e| panic!("{raw:?}: {e:?}"));
                assert!(check.issues.is_empty(), "{raw:?}: {:?}", check.issues);
            }
        }
    }

    #[test]
    fn the_rejection_message_for_a_colon_path_with_escape_codes_has_no_control_characters() {
        for policy in BOTH {
            let (_, message) = validate_path("/a:\u{1b}[2Jb", policy).unwrap_err();
            assert!(!message.chars().any(char::is_control), "{message:?}");
        }
    }

    #[test]
    fn a_colon_or_star_is_never_a_windows_portability_issue_any_more() {
        for raw in ["/a*b", "/C:/x", "/a:b"] {
            assert_eq!(
                validate_path(raw, PortabilityPolicy::Skip).unwrap_err().0,
                IssueKind::UnsafePath,
                "{raw}: kind must not depend on policy"
            );
        }
    }
}
