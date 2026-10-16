//! Maps the lowercase method token in an endpoint file name
//! (`endpoint.<token>.json`) to the HTTP method sent on the wire. Only the
//! byte-exact lowercase fixed names are ever accepted; nothing here depends on
//! the host OS.

use std::borrow::Cow;

use super::path_rules::untrusted;

/// OpenAPI's fixed Path Item operation fields. The order keeps operation order
/// stable for specs written before `query` existed.
pub const FIXED_FIELDS: [&str; 9] = ["get", "put", "post", "delete", "options", "head", "patch", "trace", "query"];

pub const ROUTABLE_FIXED: [&str; 6] = ["get", "post", "put", "patch", "delete", "query"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MethodToken {
    Fixed(&'static str),
    #[allow(dead_code)] // M4
    Extension(String),
}

impl MethodToken {
    pub fn wire(&self) -> Cow<'static, str> {
        match self {
            MethodToken::Fixed(name) => Cow::Owned(name.to_ascii_uppercase()),
            MethodToken::Extension(name) => Cow::Owned(untrusted(name)),
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

/// `token` is the middle segment of `endpoint.<token>.json`.
pub fn parse_file_token(token: &str) -> Option<MethodToken> {
    FIXED_FIELDS.iter().find(|&&f| f == token).map(|&f| MethodToken::Fixed(f))
}

pub fn is_routable(token: &MethodToken) -> bool {
    match token {
        MethodToken::Fixed(name) => ROUTABLE_FIXED.contains(name),
        MethodToken::Extension(_) => false,
    }
}

/// `Some(token)` for exactly `endpoint.<token>.json` with no further dots.
pub fn stub_file_token(file_name: &str) -> Option<&str> {
    let middle = file_name.strip_prefix("endpoint.")?.strip_suffix(".json")?;
    if middle.contains('.') { None } else { Some(middle) }
}

/// `None`: not an `endpoint.*.test.json` file. `Some(Err(raw))`: a test file
/// whose token is not a canonical lowercase fixed name.
pub fn parse_test_file_token(file_name: &str) -> Option<Result<MethodToken, String>> {
    let middle = file_name.strip_prefix("endpoint.")?.strip_suffix(".test.json")?;
    Some(parse_file_token(middle).ok_or_else(|| middle.to_string()))
}

/// The canonical fixed name when `token` is a non-canonical ASCII-case variant of one.
pub fn fixed_case_variant(token: &str) -> Option<&'static str> {
    if parse_file_token(token).is_some() {
        return None;
    }
    FIXED_FIELDS.iter().find(|f| f.eq_ignore_ascii_case(token)).copied()
}

/// Uppercase wire name for a fixed token; callers fall back to `untrusted(token)`.
pub fn wire_from_token(token: &str) -> Option<Cow<'static, str>> {
    parse_file_token(token).map(|t| t.wire())
}

/// Display form of a file token: the wire name when fixed, else the sanitised token.
pub fn display_token(token: &str) -> String {
    wire_from_token(token).map(Cow::into_owned).unwrap_or_else(|| untrusted(token))
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn parse_file_token_accepts_every_byte_exact_lowercase_fixed_name() {
        for name in FIXED_FIELDS {
            assert_eq!(parse_file_token(name), Some(MethodToken::Fixed(name)));
        }
    }

    #[test]
    fn parse_file_token_rejects_case_variants_dotted_empty_tilde_and_extension_names() {
        for bad in ["GET", "Get", "gET", "QUERY", "Query", "get.reference", "get.test", "", "~get", "purge", " get", "get ", "get\0"] {
            assert_eq!(parse_file_token(bad), None, "{bad:?}");
        }
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
        assert!(parse_test_file_token("endpoint.get.json").is_none());
        assert!(parse_test_file_token("endpoint.get.reference.json").is_none());
        assert!(parse_test_file_token("other.get.test.json").is_none());
        assert_eq!(parse_test_file_token("endpoint.query.test.json"), Some(Ok(MethodToken::Fixed("query"))));
        assert_eq!(parse_test_file_token("endpoint.GET.test.json"), Some(Err("GET".to_string())));
        assert_eq!(parse_test_file_token("endpoint.purge.test.json"), Some(Err("purge".to_string())));
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
    fn wire_from_token_uppercases_fixed_names_and_declines_everything_else() {
        assert_eq!(wire_from_token("query").as_deref(), Some("QUERY"));
        assert_eq!(wire_from_token("get").as_deref(), Some("GET"));
        assert_eq!(wire_from_token("GET"), None);
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
            let token = parse_file_token(name).unwrap();
            assert!(!is_routable(&token), "{name}");
            assert!(token.standard_method().is_none(), "{name}");
        }
        for name in ROUTABLE_FIXED {
            assert!(is_routable(&parse_file_token(name).unwrap()), "{name}");
        }
    }

    #[test]
    fn standard_method_is_some_for_the_five_standard_verbs_and_none_for_query() {
        assert_eq!(parse_file_token("get").unwrap().standard_method(), Some(axum::http::Method::GET));
        assert_eq!(parse_file_token("post").unwrap().standard_method(), Some(axum::http::Method::POST));
        assert_eq!(parse_file_token("put").unwrap().standard_method(), Some(axum::http::Method::PUT));
        assert_eq!(parse_file_token("patch").unwrap().standard_method(), Some(axum::http::Method::PATCH));
        assert_eq!(parse_file_token("delete").unwrap().standard_method(), Some(axum::http::Method::DELETE));
        assert_eq!(parse_file_token("query").unwrap().standard_method(), None);
        assert_eq!(parse_file_token("query").unwrap().wire(), "QUERY");
    }

    #[test]
    fn this_module_contains_no_platform_conditionals() {
        let source = include_str!("method_token.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(!production.contains("cfg!"), "cfg! found");
        assert!(!production.contains("#[cfg("), "#[cfg(...)] found");
    }
}
