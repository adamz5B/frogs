//! Maps the method token in an endpoint file name (`endpoint.<token>.json`) to
//! the HTTP method sent on the wire, and back. Fixed methods use their
//! lowercase field name; extension methods (`additionalOperations`) use a
//! reversible, case-collision-free encoding. Nothing here depends on the host
//! OS.
//!
//! Invariant: every endpoint/reference/test/orphan/backup file name is built
//! from `MethodToken::file_token()` or a `FIXED_FIELDS` constant, never from a
//! wire string, a spec key or a CLI argument directly.

use std::borrow::Cow;
use std::fmt;

use super::path_rules::untrusted;

/// OpenAPI's fixed Path Item operation fields. The order keeps operation order
/// stable for specs written before `query` existed.
pub const FIXED_FIELDS: [&str; 9] = ["get", "put", "post", "delete", "options", "head", "patch", "trace", "query"];

pub const ROUTABLE_FIXED: [&str; 6] = ["get", "post", "put", "patch", "delete", "query"];

const REJECT_ANY_CASE: [&str; 5] = ["CONNECT", "TRACE", "TRACK", "OPTIONS", "HEAD"];
const FIXED_UPPER: [&str; 6] = ["GET", "PUT", "POST", "DELETE", "PATCH", "QUERY"];

/// Real HTTP extension methods are short (the longest registered ones are under 20 bytes). The cap keeps the
/// longest method file name (`endpoint.<token>.<timestamp>.json`) near 130 bytes instead of 228, clear of
/// MAX_PATH trouble in other tools.
const MAX_METHOD_BYTES: usize = 32;
const MAX_ENCODED_TOKEN_BYTES: usize = 1 + 3 * MAX_METHOD_BYTES;

/// How `additionalOperations` keys and method file tokens are interpreted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MethodCase {
    /// `caseSensitiveMethods: false` — the wire method is the uppercased key.
    #[default]
    Default,
    /// `caseSensitiveMethods: true` — the wire method is the key as written.
    Exact,
}

impl MethodCase {
    pub fn from_case_sensitive(case_sensitive: bool) -> Self {
        if case_sensitive { MethodCase::Exact } else { MethodCase::Default }
    }

    pub fn case_sensitive(self) -> bool {
        self == MethodCase::Exact
    }
}

/// A validated extension method (RFC 9110 token, 1-32 bytes, never a method
/// frogs refuses to serve). The field is private: only this module can build one.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExtensionMethod(String);

impl ExtensionMethod {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MethodToken {
    Fixed(&'static str),
    Extension(ExtensionMethod),
}

impl MethodToken {
    /// The method as sent on the wire. Extension methods keep their exact bytes
    /// (they were validated as RFC 9110 tokens on construction).
    pub fn wire(&self) -> Cow<'_, str> {
        match self {
            MethodToken::Fixed(name) => Cow::Owned(name.to_ascii_uppercase()),
            MethodToken::Extension(method) => Cow::Borrowed(method.as_str()),
        }
    }

    /// The `<token>` of `endpoint.<token>.json`.
    pub fn file_token(&self) -> Cow<'_, str> {
        match self {
            MethodToken::Fixed(name) => Cow::Borrowed(name),
            MethodToken::Extension(method) => encode_extension(method.as_str()),
        }
    }

    /// `None` for QUERY (and any extension): those go through the per-path dispatch table.
    pub fn standard_method(&self) -> Option<axum::http::Method> {
        match self {
            MethodToken::Fixed("get") => Some(axum::http::Method::GET),
            MethodToken::Fixed("post") => Some(axum::http::Method::POST),
            MethodToken::Fixed("put") => Some(axum::http::Method::PUT),
            MethodToken::Fixed("patch") => Some(axum::http::Method::PATCH),
            MethodToken::Fixed("delete") => Some(axum::http::Method::DELETE),
            _ => None,
        }
    }
}

fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
        )
}

/// RFC 9110 `token`, 1-32 bytes.
pub fn is_method_token(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_METHOD_BYTES && s.bytes().all(is_tchar)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectKind {
    /// Invalid per the spec or never servable.
    S3,
    /// Collides with a fixed method or another key once case is folded.
    S4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum W1Note {
    /// A case variant of a fixed method, accepted as a different wire method.
    FixedVariant,
    /// Any other extension method that is not all uppercase.
    CaseDistinct,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyClass {
    Accept {
        method: MethodToken,
        note: Option<W1Note>,
    },
    /// `reason` completes "additionalOperations key '<k>' on <path> ...".
    Reject {
        kind: RejectKind,
        reason: String,
    },
}

fn fixed_upper(upper: &str) -> bool {
    FIXED_UPPER.contains(&upper)
}

fn rejected_any_case(upper: &str) -> bool {
    REJECT_ANY_CASE.contains(&upper)
}

/// Classifies one `additionalOperations` key.
pub fn classify_additional_key(key: &str, mode: MethodCase) -> KeyClass {
    if !is_method_token(key) {
        return KeyClass::Reject {
            kind: RejectKind::S3,
            reason: "is not a valid method token (1\u{2013}64 RFC 9110 token characters)".to_string(),
        };
    }
    let upper = key.to_ascii_uppercase();
    if rejected_any_case(&upper) {
        return KeyClass::Reject {
            kind: RejectKind::S3,
            reason: format!("is a method frogs never serves ({upper} is rejected in any spelling)"),
        };
    }
    if key == upper && fixed_upper(&upper) {
        return KeyClass::Reject {
            kind: RejectKind::S3,
            reason: format!("duplicates the fixed field {}", upper.to_ascii_lowercase()),
        };
    }
    match mode {
        MethodCase::Default => {
            if fixed_upper(&upper) {
                KeyClass::Reject {
                    kind: RejectKind::S4,
                    reason: format!("is the fixed method {upper} once uppercased (caseSensitiveMethods is false)"),
                }
            } else {
                KeyClass::Accept {
                    method: MethodToken::Extension(ExtensionMethod(upper)),
                    note: None,
                }
            }
        }
        MethodCase::Exact => {
            let note = if fixed_upper(&upper) {
                Some(W1Note::FixedVariant)
            } else if key != upper {
                Some(W1Note::CaseDistinct)
            } else {
                None
            };
            KeyClass::Accept {
                method: MethodToken::Extension(ExtensionMethod(key.to_string())),
                note,
            }
        }
    }
}

fn is_verbatim(wire: &str) -> bool {
    let bytes = wire.as_bytes();
    matches!(bytes.first(), Some(b) if b.is_ascii_uppercase()) && bytes.iter().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'-')
}

/// The canonical file token of an extension wire method: verbatim when it
/// matches `^[A-Z][A-Z0-9-]*$`, else `~` plus `a-z0-9-` copied and every other
/// byte as `_` and two lowercase hex digits.
fn encode_extension(wire: &str) -> Cow<'_, str> {
    if is_verbatim(wire) {
        return Cow::Borrowed(wire);
    }
    let mut out = String::with_capacity(1 + wire.len() * 3);
    out.push('~');
    for &b in wire.as_bytes() {
        if b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' {
            out.push(b as char);
        } else {
            out.push('_');
            out.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
            out.push(char::from_digit(u32::from(b & 0xf), 16).unwrap_or('0'));
        }
    }
    Cow::Owned(out)
}

fn lower_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Strict inverse of `encode_extension`. The result is a valid method token
/// but not necessarily one whose canonical encoding is `token` (callers
/// re-encode and compare).
fn decode_token(token: &str) -> Option<String> {
    if token.len() > MAX_ENCODED_TOKEN_BYTES {
        return None;
    }
    let Some(rest) = token.strip_prefix('~') else {
        return (is_method_token(token) && is_verbatim(token)).then(|| token.to_string());
    };
    let bytes = rest.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'_' {
            let hi = lower_hex(*bytes.get(i + 1)?)?;
            let lo = lower_hex(*bytes.get(i + 2)?)?;
            decoded.push((hi << 4) | lo);
            i += 3;
        } else if b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' {
            decoded.push(b);
            i += 1;
        } else {
            return None;
        }
    }
    let text = String::from_utf8(decoded).ok()?;
    is_method_token(&text).then_some(text)
}

/// Whether `wire` may be served as an extension method under `mode`.
fn extension_valid(wire: &str, mode: MethodCase) -> bool {
    let upper = wire.to_ascii_uppercase();
    if rejected_any_case(&upper) {
        return false;
    }
    match mode {
        MethodCase::Default => wire == upper && !fixed_upper(&upper),
        MethodCase::Exact => !fixed_upper(wire),
    }
}

/// Outcome of interpreting the `<token>` of an `endpoint.<token>.json` name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenStatus {
    Valid(MethodToken),
    /// A canonical token that is valid under the other `caseSensitiveMethods` setting.
    WrongMode {
        wire: String,
    },
    Invalid,
}

/// `token` is the middle segment of `endpoint.<token>.json`.
pub fn parse_file_token(token: &str, mode: MethodCase) -> TokenStatus {
    if let Some(&fixed) = FIXED_FIELDS.iter().find(|&&f| f == token) {
        return TokenStatus::Valid(MethodToken::Fixed(fixed));
    }
    let Some(wire) = decode_token(token) else {
        return TokenStatus::Invalid;
    };
    if encode_extension(&wire) != token {
        return TokenStatus::Invalid;
    }
    if extension_valid(&wire, mode) {
        return TokenStatus::Valid(MethodToken::Extension(ExtensionMethod(wire)));
    }
    let other = match mode {
        MethodCase::Default => MethodCase::Exact,
        MethodCase::Exact => MethodCase::Default,
    };
    if extension_valid(&wire, other) {
        TokenStatus::WrongMode { wire }
    } else {
        TokenStatus::Invalid
    }
}

pub fn is_routable(token: &MethodToken) -> bool {
    match token {
        MethodToken::Fixed(name) => ROUTABLE_FIXED.contains(name),
        MethodToken::Extension(_) => true,
    }
}

/// `Some(token)` for exactly `endpoint.<token>.json` with no further dots.
pub fn stub_file_token(file_name: &str) -> Option<&str> {
    let middle = file_name.strip_prefix("endpoint.")?.strip_suffix(".json")?;
    if middle.contains('.') { None } else { Some(middle) }
}

/// `None`: not an `endpoint.*.test.json` file. Otherwise the raw token and its status.
pub fn parse_test_file_token(file_name: &str, mode: MethodCase) -> Option<(String, TokenStatus)> {
    let middle = file_name.strip_prefix("endpoint.")?.strip_suffix(".test.json")?;
    Some((middle.to_string(), parse_file_token(middle, mode)))
}

/// The canonical fixed name when `token` is a non-canonical ASCII-case variant of one.
pub fn fixed_case_variant(token: &str) -> Option<&'static str> {
    if FIXED_FIELDS.contains(&token) {
        return None;
    }
    FIXED_FIELDS.iter().find(|f| f.eq_ignore_ascii_case(token)).copied()
}

/// The canonical token a bare method-like name (`purge`) would have if it were
/// accepted in `mode`; `None` when it could never be an accepted method.
pub fn canonical_token_hint(name: &str, mode: MethodCase) -> Option<String> {
    if !is_method_token(name) {
        return None;
    }
    let upper = name.to_ascii_uppercase();
    if rejected_any_case(&upper) {
        return None;
    }
    let wire = match mode {
        MethodCase::Default => upper,
        MethodCase::Exact => name.to_string(),
    };
    if fixed_upper(&wire) {
        return Some(wire.to_ascii_lowercase());
    }
    Some(encode_extension(&wire).into_owned())
}

/// A suggested canonical spelling for an `endpoint.<token>.json` whose token is
/// not accepted: a case variant of a fixed name, a decodable but non-canonical
/// encoding, or a bare method-like name. Only ever a token `parse_file_token`
/// accepts under `mode`.
pub fn canonical_hint(token: &str, mode: MethodCase) -> Option<String> {
    let candidate = if let Some(fixed) = fixed_case_variant(token) {
        fixed.to_string()
    } else if let Some(wire) = decode_token(token) {
        canonical_token_hint(&wire, mode)?
    } else {
        canonical_token_hint(token, mode)?
    };
    (candidate != token && matches!(parse_file_token(&candidate, mode), TokenStatus::Valid(_))).then_some(candidate)
}

/// Wire name for a canonical file token of either mode (fixed or extension).
pub fn wire_from_token(token: &str) -> Option<Cow<'static, str>> {
    if let Some(&fixed) = FIXED_FIELDS.iter().find(|&&f| f == token) {
        return Some(Cow::Owned(fixed.to_ascii_uppercase()));
    }
    let wire = decode_token(token)?;
    (encode_extension(&wire) == token).then_some(Cow::Owned(wire))
}

/// Display form of a file token: the wire name when canonical, else the sanitised token.
pub fn display_token(token: &str) -> String {
    wire_from_token(token).map(Cow::into_owned).unwrap_or_else(|| untrusted(token))
}

/// A spec key or CLI argument for messages: escaped and cut to 80 characters.
pub fn untrusted_short(s: &str) -> String {
    let shown: String = s.chars().take(80).collect();
    let mut out = untrusted(&shown);
    if s.chars().count() > 80 {
        out.push('\u{2026}');
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliMethodError {
    InvalidToken,
    NotServable,
}

impl fmt::Display for CliMethodError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliMethodError::InvalidToken => write!(f, "not a valid method token"),
            CliMethodError::NotServable => write!(f, "a method frogs never serves"),
        }
    }
}

/// Interprets the `<method>` argument of `frogs test record`.
pub fn normalize_cli_method(arg: &str, mode: MethodCase) -> Result<MethodToken, CliMethodError> {
    if !is_method_token(arg) {
        return Err(CliMethodError::InvalidToken);
    }
    let upper = arg.to_ascii_uppercase();
    let lower = arg.to_ascii_lowercase();
    let fixed = FIXED_FIELDS.iter().find(|&&f| f == lower).copied();
    match mode {
        MethodCase::Default => {
            if let Some(f) = fixed {
                return Ok(MethodToken::Fixed(f));
            }
            if matches!(upper.as_str(), "CONNECT" | "TRACK") {
                return Err(CliMethodError::NotServable);
            }
            Ok(MethodToken::Extension(ExtensionMethod(upper)))
        }
        MethodCase::Exact => {
            if let Some(f) = fixed
                && arg == upper
            {
                return Ok(MethodToken::Fixed(f));
            }
            if rejected_any_case(&upper) || (arg == upper && fixed_upper(&upper)) {
                return Err(CliMethodError::NotServable);
            }
            Ok(MethodToken::Extension(ExtensionMethod(arg.to_string())))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid(token: &str, mode: MethodCase) -> MethodToken {
        match parse_file_token(token, mode) {
            TokenStatus::Valid(t) => t,
            other => panic!("{token}: {other:?}"),
        }
    }

    #[test]
    fn fixed_fields_keep_the_historical_order_and_append_query_last() {
        assert_eq!(FIXED_FIELDS, ["get", "put", "post", "delete", "options", "head", "patch", "trace", "query"]);
    }

    #[test]
    fn routable_fixed_is_exactly_the_five_standard_methods_plus_query() {
        let mut sorted = ROUTABLE_FIXED.to_vec();
        sorted.sort_unstable();
        assert_eq!(sorted, ["delete", "get", "patch", "post", "put", "query"]);
        assert!(ROUTABLE_FIXED.iter().all(|m| FIXED_FIELDS.contains(m)));
    }

    #[test]
    fn parse_file_token_accepts_every_byte_exact_lowercase_fixed_name_in_both_modes() {
        for mode in [MethodCase::Default, MethodCase::Exact] {
            for name in FIXED_FIELDS {
                assert_eq!(parse_file_token(name, mode), TokenStatus::Valid(MethodToken::Fixed(name)));
            }
        }
    }

    #[test]
    fn parse_file_token_rejects_case_variants_dotted_empty_and_malformed_names() {
        for mode in [MethodCase::Default, MethodCase::Exact] {
            for bad in [
                "GET",
                "Get",
                "gET",
                "QUERY",
                "Query",
                "get.reference",
                "get.test",
                "",
                "~",
                " get",
                "get ",
                "get\0",
                "~_47_45_54",
                "~_4c_49_4e_4b",
            ] {
                assert_eq!(parse_file_token(bad, mode), TokenStatus::Invalid, "{bad:?}");
            }
        }
    }

    #[test]
    fn extension_tokens_round_trip_and_depend_on_the_mode() {
        assert_eq!(valid("LINK", MethodCase::Default).wire(), "LINK");
        assert_eq!(valid("LINK", MethodCase::Exact).file_token(), "LINK");
        assert_eq!(valid("~x_2ey", MethodCase::Exact).wire(), "x.y");
        assert_eq!(parse_file_token("~purge", MethodCase::Default), TokenStatus::WrongMode { wire: "purge".to_string() });
        assert_eq!(valid("~purge", MethodCase::Exact).file_token(), "~purge");
        assert_eq!(valid("~_50urge", MethodCase::Exact).wire(), "Purge");
        assert_eq!(valid("~_58_2e_59", MethodCase::Default).wire(), "X.Y");
    }

    #[test]
    fn stub_file_token_extracts_only_the_single_segment_between_endpoint_and_json() {
        assert_eq!(stub_file_token("endpoint.get.json"), Some("get"));
        assert_eq!(stub_file_token("endpoint.GET.json"), Some("GET"));
        assert_eq!(stub_file_token("endpoint.get.reference.json"), None);
        assert_eq!(stub_file_token("endpoint.get.test.json"), None);
        assert_eq!(stub_file_token("_endpoint.get.json"), None);
        assert_eq!(stub_file_token("endpoint.get.json.bak"), None);
        assert_eq!(stub_file_token("endpoint.json"), None);
    }

    #[test]
    fn parse_test_file_token_distinguishes_not_a_test_file_canonical_and_non_canonical() {
        let mode = MethodCase::Default;
        assert!(parse_test_file_token("endpoint.get.json", mode).is_none());
        assert!(parse_test_file_token("endpoint.get.reference.json", mode).is_none());
        assert!(parse_test_file_token("other.get.test.json", mode).is_none());
        assert_eq!(
            parse_test_file_token("endpoint.query.test.json", mode),
            Some(("query".to_string(), TokenStatus::Valid(MethodToken::Fixed("query"))))
        );
        assert_eq!(parse_test_file_token("endpoint.GET.test.json", mode), Some(("GET".to_string(), TokenStatus::Invalid)));
        assert_eq!(
            parse_test_file_token("endpoint.purge.test.json", mode),
            Some(("purge".to_string(), TokenStatus::Invalid))
        );
    }

    #[test]
    fn fixed_case_variant_names_the_canonical_spelling_only_for_non_canonical_fixed_names() {
        assert_eq!(fixed_case_variant("GET"), Some("get"));
        assert_eq!(fixed_case_variant("Query"), Some("query"));
        assert_eq!(fixed_case_variant("tRaCe"), Some("trace"));
        assert_eq!(fixed_case_variant("get"), None);
        assert_eq!(fixed_case_variant("purge"), None);
        assert_eq!(fixed_case_variant(""), None);
    }

    #[test]
    fn wire_from_token_decodes_canonical_tokens_and_declines_everything_else() {
        assert_eq!(wire_from_token("query").as_deref(), Some("QUERY"));
        assert_eq!(wire_from_token("get").as_deref(), Some("GET"));
        assert_eq!(wire_from_token("~purge").as_deref(), Some("purge"));
        assert_eq!(wire_from_token("Get"), None);
        assert_eq!(wire_from_token("purge"), None);
    }

    #[test]
    fn display_token_falls_back_to_a_sanitised_form_for_unknown_tokens() {
        assert_eq!(display_token("post"), "POST");
        let shown = display_token("evil\u{1b}[31m\nname");
        assert!(!shown.contains('\u{1b}') && !shown.contains('\n'), "{shown:?}");
    }

    #[test]
    fn options_head_and_trace_are_fixed_but_not_routable() {
        for name in ["options", "head", "trace"] {
            let token = valid(name, MethodCase::Default);
            assert!(!is_routable(&token), "{name}");
            assert!(token.standard_method().is_none(), "{name}");
        }
        for name in ROUTABLE_FIXED {
            assert!(is_routable(&valid(name, MethodCase::Default)), "{name}");
        }
    }

    #[test]
    fn standard_method_is_some_for_the_five_standard_verbs_and_none_for_query() {
        let mode = MethodCase::Default;
        assert_eq!(valid("get", mode).standard_method(), Some(axum::http::Method::GET));
        assert_eq!(valid("post", mode).standard_method(), Some(axum::http::Method::POST));
        assert_eq!(valid("put", mode).standard_method(), Some(axum::http::Method::PUT));
        assert_eq!(valid("patch", mode).standard_method(), Some(axum::http::Method::PATCH));
        assert_eq!(valid("delete", mode).standard_method(), Some(axum::http::Method::DELETE));
        assert_eq!(valid("query", mode).standard_method(), None);
        assert_eq!(valid("query", mode).wire(), "QUERY");
    }

    #[test]
    fn this_module_contains_no_platform_conditionals() {
        let source = include_str!("method_token.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(!production.contains("cfg!"), "cfg! found");
        assert!(!production.contains("#[cfg("), "#[cfg(...)] found");
    }
}

#[cfg(test)]
mod m4_tests {
    use super::*;

    const TCHARS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-.^_`|~";

    fn accepted(key: &str, mode: MethodCase) -> Option<(MethodToken, Option<W1Note>)> {
        match classify_additional_key(key, mode) {
            KeyClass::Accept { method, note } => Some((method, note)),
            KeyClass::Reject { .. } => None,
        }
    }

    fn rejected(key: &str, mode: MethodCase) -> Option<RejectKind> {
        match classify_additional_key(key, mode) {
            KeyClass::Reject { kind, .. } => Some(kind),
            KeyClass::Accept { .. } => None,
        }
    }

    fn valid(token: &str, mode: MethodCase) -> MethodToken {
        match parse_file_token(token, mode) {
            TokenStatus::Valid(t) => t,
            other => panic!("{token}: {other:?}"),
        }
    }

    fn is_accept(key: &str, mode: MethodCase, wire: &str, token: &str, note: Option<W1Note>) {
        let (method, got_note) = accepted(key, mode).unwrap_or_else(|| panic!("{key:?} {mode:?}: expected Accept, got {:?}", classify_additional_key(key, mode)));
        assert_eq!(method.wire(), wire, "{key:?} {mode:?} wire");
        assert_eq!(method.file_token(), token, "{key:?} {mode:?} token");
        assert_eq!(got_note, note, "{key:?} {mode:?} note");
    }

    // ---------------------------------------------------------------- guard

    #[test]
    fn neither_method_token_rs_nor_dir_index_rs_contains_a_platform_conditional_outside_test_code() {
        // Needles are assembled at run time so this test never matches itself.
        let cfg_macro = format!("{}!(", "cfg");
        let cfg_attr = format!("#[{}(", "cfg");
        let test_marker = format!("#[{}(test)]", "cfg");
        for (name, source) in [("method_token.rs", include_str!("method_token.rs")), ("dir_index.rs", include_str!("dir_index.rs"))] {
            let production = source.split(test_marker.as_str()).next().unwrap();
            assert!(!production.contains(&cfg_macro), "{name}: {cfg_macro} found outside the test module");
            assert!(!production.contains(&cfg_attr), "{name}: {cfg_attr} found outside the test module");
        }
    }

    // ------------------------------------------------------- classification

    #[test]
    fn purge_in_any_spelling_is_accepted_in_default_mode_as_uppercase_purge_with_no_note() {
        for key in ["purge", "Purge", "PURGE", "pUrGe"] {
            is_accept(key, MethodCase::Default, "PURGE", "PURGE", None);
        }
    }

    #[test]
    fn purge_in_exact_mode_keeps_its_bytes_and_gets_the_case_distinct_note_unless_already_uppercase() {
        is_accept("purge", MethodCase::Exact, "purge", "~purge", Some(W1Note::CaseDistinct));
        is_accept("Purge", MethodCase::Exact, "Purge", "~_50urge", Some(W1Note::CaseDistinct));
        is_accept("PURGE", MethodCase::Exact, "PURGE", "PURGE", None);
    }

    #[test]
    fn a_lowercase_or_mixed_case_fixed_name_is_s4_in_default_mode_and_a_fixed_variant_w1_in_exact_mode() {
        for key in ["get", "Post", "query", "Put", "delete", "patch", "Query"] {
            assert_eq!(rejected(key, MethodCase::Default), Some(RejectKind::S4), "{key}");
            let (method, note) = accepted(key, MethodCase::Exact).unwrap_or_else(|| panic!("{key} must be accepted in exact mode"));
            assert_eq!(note, Some(W1Note::FixedVariant), "{key}");
            assert_eq!(method.wire(), key, "exact mode keeps the key bytes");
            assert!(method.file_token().starts_with('~'), "{key}: {}", method.file_token());
        }
    }

    #[test]
    fn an_exact_uppercase_fixed_name_is_s3_in_both_modes() {
        for key in ["GET", "PUT", "POST", "DELETE", "PATCH", "QUERY"] {
            for mode in [MethodCase::Default, MethodCase::Exact] {
                assert_eq!(rejected(key, mode), Some(RejectKind::S3), "{key} {mode:?}");
            }
        }
    }

    #[test]
    fn options_head_trace_connect_and_track_are_s3_in_every_spelling_and_both_modes() {
        for key in [
            "options", "OPTIONS", "Options", "Head", "HEAD", "head", "trace", "TRACE", "tRaCe", "connect", "CONNECT", "Connect", "track", "TRACK", "Track",
        ] {
            for mode in [MethodCase::Default, MethodCase::Exact] {
                assert_eq!(rejected(key, mode), Some(RejectKind::S3), "{key} {mode:?}");
            }
        }
    }

    #[test]
    fn ordinary_uppercase_extension_methods_are_accepted_verbatim_in_both_modes() {
        for key in ["LINK", "M-SEARCH", "PROPFIND", "UNLINK"] {
            for mode in [MethodCase::Default, MethodCase::Exact] {
                is_accept(key, mode, key, key, None);
            }
        }
    }

    #[test]
    fn a_dotted_uppercase_method_is_accepted_with_an_escaped_file_token_in_both_modes() {
        for mode in [MethodCase::Default, MethodCase::Exact] {
            is_accept("X.Y", mode, "X.Y", "~_58_2e_59", None);
        }
    }

    #[test]
    fn a_32_byte_key_is_accepted_and_a_33_byte_key_the_empty_key_and_non_token_characters_are_s3() {
        let max = "A".repeat(32);
        for mode in [MethodCase::Default, MethodCase::Exact] {
            is_accept(&max, mode, &max, &max, None);
            assert_eq!(rejected(&"A".repeat(33), mode), Some(RejectKind::S3));
            assert_eq!(rejected("", mode), Some(RejectKind::S3));
            for bad in ["A B", "A/B", "A(B", "A:B", "A\u{e9}B", "A\nB", "A\0B", "A,B", "A\"B", "A=B"] {
                assert_eq!(rejected(bad, mode), Some(RejectKind::S3), "{bad:?} {mode:?}");
            }
        }
    }

    #[test]
    fn a_star_is_a_legal_rfc_9110_method_character_so_a_star_b_is_accepted_with_an_escaped_token() {
        // The milestone doc lists `A*B` as an invalid character; '*' is in fact a `tchar`.
        for mode in [MethodCase::Default, MethodCase::Exact] {
            is_accept("A*B", mode, "A*B", "~_41_2a_42", None);
        }
    }

    // ------------------------------------------------------------ file tokens

    #[test]
    fn tilde_purge_is_wrong_mode_under_default_and_valid_under_exact_while_purge_is_valid_in_both() {
        assert_eq!(parse_file_token("~purge", MethodCase::Default), TokenStatus::WrongMode { wire: "purge".to_string() });
        assert!(matches!(parse_file_token("~purge", MethodCase::Exact), TokenStatus::Valid(_)));
        for mode in [MethodCase::Default, MethodCase::Exact] {
            assert!(matches!(parse_file_token("PURGE", mode), TokenStatus::Valid(_)), "{mode:?}");
        }
    }

    #[test]
    fn tilde_get_is_wrong_mode_under_default_and_valid_under_exact() {
        assert_eq!(parse_file_token("~get", MethodCase::Default), TokenStatus::WrongMode { wire: "get".to_string() });
        assert_eq!(valid("~get", MethodCase::Exact).wire(), "get");
    }

    #[test]
    fn the_escaped_uppercase_dotted_method_token_is_valid_in_both_modes() {
        for mode in [MethodCase::Default, MethodCase::Exact] {
            assert_eq!(valid("~_58_2e_59", mode).wire(), "X.Y");
        }
    }

    #[test]
    fn malformed_and_non_canonical_tokens_are_invalid_in_both_modes() {
        for mode in [MethodCase::Default, MethodCase::Exact] {
            for bad in [
                "GET",
                "Get",
                "~_4c_49_4e_4b",
                "~_47_45_54",
                "~_2F",
                "~_2f",
                "~_00",
                "~",
                "~_5",
                "~A",
                "purge",
                "Purge",
                "~_50URGE",
                "QUERY",
            ] {
                assert_eq!(parse_file_token(bad, mode), TokenStatus::Invalid, "{bad:?} {mode:?}");
            }
        }
    }

    #[test]
    fn an_escaped_mixed_case_fixed_variant_is_valid_in_exact_mode_and_wrong_mode_in_default_mode() {
        assert_eq!(
            parse_file_token("~_51uery", MethodCase::Default),
            TokenStatus::WrongMode { wire: "Query".to_string() }
        );
        assert_eq!(valid("~_51uery", MethodCase::Exact).wire(), "Query");
    }

    #[test]
    fn a_tilde_token_for_a_never_served_method_is_invalid_not_wrong_mode() {
        for mode in [MethodCase::Default, MethodCase::Exact] {
            assert_eq!(parse_file_token("~options", mode), TokenStatus::Invalid, "{mode:?}");
            assert_eq!(parse_file_token("~_54_52_41_43_45", mode), TokenStatus::Invalid, "{mode:?}");
        }
    }

    #[test]
    fn the_longest_legal_method_encodes_to_97_bytes_and_one_byte_more_is_rejected() {
        let worst = "_".repeat(32);
        let encoded = encode_extension(&worst);
        assert_eq!(encoded.len(), 97);
        assert_eq!(decode_token(&encoded).as_deref(), Some(worst.as_str()));
        assert_eq!(valid(&encoded, MethodCase::Exact).wire(), worst.as_str());
        let too_long = format!("~{}", "a".repeat(33));
        assert_eq!(parse_file_token(&too_long, MethodCase::Exact), TokenStatus::Invalid);
        assert_eq!(decode_token(&format!("~{}", "a".repeat(200))), None);
    }

    // ------------------------------------------------------------ the sweep

    struct XorShift(u64);
    impl XorShift {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
    }

    fn sweep_inputs() -> Vec<String> {
        let chars: Vec<char> = TCHARS.chars().collect();
        assert_eq!(chars.len(), 77);
        let mut out: Vec<String> = Vec::new();
        for a in &chars {
            out.push(a.to_string());
            for b in &chars {
                out.push(format!("{a}{b}"));
            }
        }
        let narrow: Vec<char> = "ABCabc012-_.~*X".chars().collect();
        let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
        for i in 0..20_000 {
            let len = 3 + (rng.next() % 30) as usize;
            let alphabet: &[char] = if i % 2 == 0 { &chars } else { &narrow };
            out.push((0..len).map(|_| alphabet[(rng.next() % alphabet.len() as u64) as usize]).collect());
        }
        out
    }

    #[test]
    fn decoding_an_encoding_gives_back_the_method_and_each_method_has_exactly_one_canonical_token() {
        let inputs = sweep_inputs();
        assert!(inputs.len() >= 26_000);
        let mut by_token: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        for wire in &inputs {
            assert!(is_method_token(wire), "{wire:?}");
            let token = encode_extension(wire).into_owned();
            assert_eq!(decode_token(&token).as_deref(), Some(wire.as_str()), "round trip of {wire:?} via {token:?}");
            assert_eq!(encode_extension(wire), token, "encoding is a function");
            assert_eq!(wire_from_token(&token).as_deref(), Some(wire.as_str()));
            if let Some(previous) = by_token.insert(token.clone(), wire.clone()) {
                assert_eq!(&previous, wire, "token {token:?} produced by two different methods");
            }
            assert!(token.len() <= MAX_ENCODED_TOKEN_BYTES && token.len() <= 97, "{token:?}");
            assert!(!token.contains('.') && !token.contains('/') && !token.contains('\\'), "{token:?}");
            if let Some(escaped) = token.strip_prefix('~') {
                assert!(
                    escaped.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_'),
                    "{token:?}"
                );
                let bytes = escaped.as_bytes();
                let mut i = 0;
                while i < bytes.len() {
                    if bytes[i] == b'_' {
                        assert!(
                            bytes.get(i + 1).copied().and_then(lower_hex).is_some() && bytes.get(i + 2).copied().and_then(lower_hex).is_some(),
                            "{token:?}"
                        );
                        i += 3;
                    } else {
                        i += 1;
                    }
                }
            } else {
                assert!(token.as_bytes()[0].is_ascii_uppercase(), "{token:?}");
                assert!(token.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-'), "{token:?}");
            }
        }
    }

    #[test]
    fn every_accepted_method_round_trips_through_its_file_token_in_the_mode_that_accepted_it() {
        let mut tokens_seen: Vec<String> = FIXED_FIELDS.iter().map(|s| s.to_string()).collect();
        for key in sweep_inputs() {
            for mode in [MethodCase::Default, MethodCase::Exact] {
                let KeyClass::Accept { method, .. } = classify_additional_key(&key, mode) else {
                    continue;
                };
                let token = method.file_token().into_owned();
                assert_eq!(parse_file_token(&token, mode), TokenStatus::Valid(method.clone()), "{key:?} {mode:?} {token:?}");
                let other = if mode == MethodCase::Default { MethodCase::Exact } else { MethodCase::Default };
                if let TokenStatus::Valid(m) = parse_file_token(&token, other) {
                    assert_eq!(m, method, "a token valid in both modes means the same method");
                }
                tokens_seen.push(token);
            }
        }
        // Folding: any two valid tokens (plus the fixed names) equal ignoring case are byte-identical.
        let mut by_fold: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        for token in tokens_seen {
            let folded = token.to_ascii_lowercase();
            if let Some(previous) = by_fold.insert(folded, token.clone()) {
                assert_eq!(previous, token, "case-folded collision between two valid file tokens");
            }
        }
    }

    #[test]
    fn a_fixed_name_collides_with_no_accepted_extension_token_even_when_case_folded() {
        for fixed in FIXED_FIELDS {
            for variant in [
                fixed.to_string(),
                fixed.to_ascii_uppercase(),
                format!("{}{}", fixed[..1].to_ascii_uppercase(), &fixed[1..]),
            ] {
                for mode in [MethodCase::Default, MethodCase::Exact] {
                    if let Some((method, _)) = accepted(&variant, mode) {
                        let token = method.file_token();
                        assert!(!token.eq_ignore_ascii_case(fixed), "{variant:?} {mode:?} -> {token}");
                    }
                }
            }
        }
    }

    #[test]
    fn the_wire_name_of_a_fixed_token_is_the_uppercased_field_and_matches_its_file_token_inverse() {
        for fixed in FIXED_FIELDS {
            assert_eq!(MethodToken::Fixed(fixed).wire(), fixed.to_ascii_uppercase());
            assert_eq!(MethodToken::Fixed(fixed).file_token(), fixed);
            assert_eq!(wire_from_token(fixed).as_deref(), Some(fixed.to_ascii_uppercase().as_str()));
        }
    }

    // ------------------------------------------------------------ CLI methods

    #[test]
    fn cli_methods_in_default_mode_fold_case_and_map_fixed_names_to_fixed_tokens() {
        let d = MethodCase::Default;
        assert_eq!(normalize_cli_method("get", d), Ok(MethodToken::Fixed("get")));
        assert_eq!(normalize_cli_method("GET", d), Ok(MethodToken::Fixed("get")));
        assert_eq!(normalize_cli_method("Query", d), Ok(MethodToken::Fixed("query")));
        assert_eq!(normalize_cli_method("link", d).unwrap().file_token(), "LINK");
        assert_eq!(normalize_cli_method("connect", d), Err(CliMethodError::NotServable));
        assert_eq!(normalize_cli_method("Track", d), Err(CliMethodError::NotServable));
        assert_eq!(normalize_cli_method("A B", d), Err(CliMethodError::InvalidToken));
        assert_eq!(normalize_cli_method("", d), Err(CliMethodError::InvalidToken));
        assert_eq!(normalize_cli_method(&"A".repeat(33), d), Err(CliMethodError::InvalidToken));
        let dotted = normalize_cli_method("get.reference", d).unwrap();
        assert!(!dotted.file_token().contains('.'), "a dotted argument can never become a sibling-file name");
    }

    #[test]
    fn cli_methods_in_exact_mode_keep_their_bytes_and_a_lowercase_fixed_name_is_an_extension() {
        let e = MethodCase::Exact;
        assert_eq!(normalize_cli_method("GET", e), Ok(MethodToken::Fixed("get")));
        let lower = normalize_cli_method("get", e).unwrap();
        assert_eq!(lower.wire(), "get");
        assert_eq!(lower.file_token(), "~get");
        assert_eq!(normalize_cli_method("purge", e).unwrap().file_token(), "~purge");
        assert_eq!(normalize_cli_method("LINK", e).unwrap().file_token(), "LINK");
        assert_eq!(normalize_cli_method("connect", e), Err(CliMethodError::NotServable));
        assert_eq!(normalize_cli_method("CONNECT", e), Err(CliMethodError::NotServable));
    }
}

#[cfg(test)]
mod m4_hostile_tests {
    use super::*;

    struct XorShift(u64);
    impl XorShift {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
    }

    fn hostile_inputs() -> Vec<String> {
        let mut out: Vec<String> = [
            "",
            "~",
            "~~",
            "~_",
            "~_x",
            "~_5",
            "~_5g",
            "~_5G",
            "~_4C",
            "~_4c",
            "~_2F",
            "~_2f",
            "~_00",
            "~_ff",
            "~_FF",
            "~a.b",
            "~a_2eb",
            "a.b",
            "A.B",
            "~A",
            "~a~",
            "_41",
            "~_41_",
            "~-",
            "~--",
            "GET",
            "get",
            "~get",
            "PURGE",
            "~purge",
            "~_50urge",
            "LINK",
            "X.Y",
            "~_58_2e_59",
            "\u{e9}",
            "~\u{e9}",
            "A\u{e9}",
            "A\0B",
            "~\0",
            "A:B",
            "~_3a",
            "A/B",
            "A\\B",
            "~_5c",
            "~_2e",
            "~_00_00",
            "~_c3_a9",
            "~_ff_fe",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        // over-long encodings
        out.push(format!("~{}", "a".repeat(32)));
        out.push(format!("~{}", "a".repeat(33)));
        out.push(format!("~{}", "_41".repeat(32)));
        out.push(format!("~{}", "_41".repeat(33)));
        out.push(format!("~{}", "_5f".repeat(32)));
        out.push("A".repeat(32));
        out.push("A".repeat(33));
        out.push(format!("~{}", "a".repeat(400)));
        out.push("A".repeat(400));

        let alphabet: Vec<char> = "~_.0123456789abcdefABCDEFgGxX-/\\:*|!#$%&'+^`\u{0}\u{7f}\u{e9}\u{20ac} \n".chars().collect();
        let mut rng = XorShift(0xD1B5_4A32_D192_ED03);
        for i in 0..30_000 {
            let len = (rng.next() % 220) as usize;
            let s: String = match i % 3 {
                0 => (0..len).map(|_| alphabet[(rng.next() % alphabet.len() as u64) as usize]).collect(),
                // arbitrary bytes, lossily decoded (the only way a file name reaches these functions)
                1 => {
                    let bytes: Vec<u8> = (0..len).map(|_| (rng.next() & 0xff) as u8).collect();
                    String::from_utf8_lossy(&bytes).into_owned()
                }
                // structured: '~' plus escape-looking pieces
                _ => {
                    let mut t = String::from(if rng.next().is_multiple_of(4) { "" } else { "~" });
                    for _ in 0..(len / 3) {
                        match rng.next() % 5 {
                            0 => t.push_str(&format!("_{:02x}", rng.next() & 0xff)),
                            1 => t.push_str(&format!("_{:02X}", rng.next() & 0xff)),
                            2 => t.push('_'),
                            3 => t.push((b'a' + (rng.next() % 26) as u8) as char),
                            _ => t.push((b'0' + (rng.next() % 10) as u8) as char),
                        }
                    }
                    t
                }
            };
            out.push(s);
        }
        out
    }

    fn forbidden_in_file_name(token: &str) -> bool {
        token.chars().any(|c| matches!(c, '/' | '\\' | '.' | '\0' | ':'))
    }

    fn valid_wire(wire: &str) -> bool {
        is_method_token(wire) && wire.len() <= 32
    }

    #[test]
    fn hostile_tokens_never_panic_and_anything_accepted_is_canonical_bounded_and_filename_safe() {
        for input in hostile_inputs() {
            // decode_token
            if let Some(wire) = decode_token(&input) {
                assert!(valid_wire(&wire), "decode_token({input:?}) gave an invalid method {wire:?}");
                assert!(input.len() <= MAX_ENCODED_TOKEN_BYTES, "{input:?}");
            }

            for mode in [MethodCase::Default, MethodCase::Exact] {
                // parse_file_token
                match parse_file_token(&input, mode) {
                    TokenStatus::Valid(token) => {
                        assert_eq!(token.file_token(), input.as_str(), "an accepted token re-encodes to exactly its input ({mode:?})");
                        assert!(valid_wire(&token.wire()), "{input:?}");
                        assert!(!forbidden_in_file_name(&token.file_token()), "{input:?}");
                    }
                    TokenStatus::WrongMode { wire } => {
                        assert!(valid_wire(&wire), "{input:?} -> {wire:?}");
                        assert_eq!(encode_extension(&wire), input.as_str(), "{input:?}");
                        assert!(!forbidden_in_file_name(&input), "{input:?}");
                    }
                    TokenStatus::Invalid => {}
                }

                // parse_test_file_token (a name that is not a test file yields None; otherwise the same rules apply)
                let name = format!("endpoint.{input}.test.json");
                if let Some((raw, status)) = parse_test_file_token(&name, mode) {
                    assert_eq!(raw, input);
                    match status {
                        TokenStatus::Valid(token) => assert_eq!(token.file_token(), raw.as_str()),
                        TokenStatus::WrongMode { wire } => assert_eq!(encode_extension(&wire), raw.as_str()),
                        TokenStatus::Invalid => {}
                    }
                    if input.contains('.') {
                        assert_eq!(parse_file_token(&input, mode), TokenStatus::Invalid, "a dotted token can never be valid: {input:?}");
                    }
                }
                assert!(parse_test_file_token(&format!("endpoint.{input}.json"), mode).is_none());

                // classify_additional_key
                if let KeyClass::Accept { method, .. } = classify_additional_key(&input, mode) {
                    assert!(valid_wire(&method.wire()), "{input:?}");
                    let token = method.file_token().into_owned();
                    assert!(!forbidden_in_file_name(&token), "{input:?} -> {token:?}");
                    assert!(token.len() <= 97, "{input:?}");
                    assert_eq!(parse_file_token(&token, mode), TokenStatus::Valid(method), "{input:?}");
                }

                // normalize_cli_method
                if let Ok(token) = normalize_cli_method(&input, mode) {
                    assert!(valid_wire(&token.wire()), "{input:?}");
                    let file = token.file_token().into_owned();
                    assert!(!forbidden_in_file_name(&file), "{input:?} -> {file:?}");
                    assert!(file.len() <= 97);
                }
            }
        }
    }

    #[test]
    fn the_hostile_sweep_really_exercises_both_accepted_and_rejected_inputs() {
        // Guard against the sweep silently degenerating into "everything is rejected".
        let (mut valid, mut wrong_mode, mut invalid) = (0, 0, 0);
        for input in hostile_inputs() {
            match parse_file_token(&input, MethodCase::Default) {
                TokenStatus::Valid(_) => valid += 1,
                TokenStatus::WrongMode { .. } => wrong_mode += 1,
                TokenStatus::Invalid => invalid += 1,
            }
        }
        assert!(valid >= 4, "valid={valid}");
        assert!(wrong_mode >= 1, "wrong_mode={wrong_mode}");
        assert!(invalid > 20_000, "invalid={invalid}");
    }
}
