use std::fmt;

use serde_json::Value;

/// A parsed `validIf` expression — the design doc's deliberately minimal v1
/// grammar: `<source>.<field> = <value>`, e.g. `row.active = true` or
/// `response.active = true`. The leading `<source>` segment (`row`/
/// `response` in the doc's own examples) is purely a readability label: a
/// verifier only ever has one resolved result to check, so it's dropped
/// during parsing rather than matched against anything. No boolean
/// combinators, no nested scope/expiry logic — that's an explicit non-goal
/// until a real case demands it, same posture as `format`/transform
/// elsewhere in this project.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidIf {
    /// The dot-path to check, *after* dropping the leading label — e.g.
    /// `row.active` becomes just `["active"]`. Kept as more than one
    /// segment is still possible (`response.data.active`), since an HTTP
    /// verifier's `responsePath`-unwrapped result can still be nested.
    path: Vec<String>,
    expected: Value,
}

#[derive(Debug)]
pub enum ValidIfParseError {
    /// No `=` at all — this grammar has nothing else it could mean.
    MissingEquals(String),
    /// The left-hand side isn't `<source>.<field...>` — either no `.` at
    /// all (missing the source label) or an empty segment (`row..active`,
    /// `.active`).
    InvalidPath(String),
    /// The right-hand side is empty (`row.active =`).
    MissingValue(String),
}

impl fmt::Display for ValidIfParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidIfParseError::MissingEquals(expr) => {
                write!(f, "validIf '{expr}' has no '=' — expected '<source>.<field> = <value>'")
            }
            ValidIfParseError::InvalidPath(expr) => {
                write!(f, "validIf '{expr}' has an invalid left-hand side — expected '<source>.<field>'")
            }
            ValidIfParseError::MissingValue(expr) => {
                write!(f, "validIf '{expr}' has no value after '='")
            }
        }
    }
}

impl std::error::Error for ValidIfParseError {}

impl ValidIf {
    /// Parses a raw `validIf` string once (at verifier load time), so a
    /// malformed expression fails startup instead of every request that
    /// hits the protected endpoint.
    pub fn parse(expr: &str) -> Result<Self, ValidIfParseError> {
        let mut parts = expr.splitn(2, '=');
        let left = parts.next().unwrap_or("").trim();
        let right = parts.next().ok_or_else(|| ValidIfParseError::MissingEquals(expr.to_string()))?.trim();

        let segments = parse_result_path(left).ok_or_else(|| ValidIfParseError::InvalidPath(expr.to_string()))?;

        if right.is_empty() {
            return Err(ValidIfParseError::MissingValue(expr.to_string()));
        }

        Ok(ValidIf {
            path: segments,
            expected: parse_literal(right),
        })
    }

    /// Checks `resolved` (a verifier's resolved source result — a SQL row
    /// or an already-`responsePath`-unwrapped HTTP body, either way plain
    /// JSON) against this expression. A path segment that isn't present at
    /// all evaluates to `false` rather than an error — fail closed, the
    /// same posture as an unclassified error code defaulting to
    /// `exposeDetail: false` rather than assuming the best.
    pub fn evaluate(&self, resolved: &Value) -> bool {
        lookup_path(resolved, &self.path) == Some(&self.expected)
    }
}

/// `<label>.<field>[.<field>...]` with the label dropped; `None` for fewer than two segments or an empty one.
fn parse_result_path(text: &str) -> Option<Vec<String>> {
    let mut segments: Vec<String> = text.split('.').map(str::trim).map(str::to_string).collect();
    if segments.len() < 2 || segments.iter().any(String::is_empty) {
        return None;
    }
    segments.remove(0); // drop the source label — see the struct doc comment
    Some(segments)
}

fn lookup_path<'a>(resolved: &'a Value, path: &[String]) -> Option<&'a Value> {
    let mut current = resolved;
    for segment in path {
        current = current.get(segment)?;
    }
    Some(current)
}

const MAX_GRANTED_SCOPES: usize = 64;
const MAX_GRANTED_SCOPES_BYTES: usize = 4 * 1024;

/// A verifier's `scopesFrom`: where in its resolved result the credential's granted scopes live.
/// Same left-hand-side grammar as `validIf`.
#[derive(Debug, Clone, PartialEq)]
pub struct ScopesPath {
    path: Vec<String>,
}

impl ScopesPath {
    pub fn parse(expr: &str) -> Result<Self, String> {
        match parse_result_path(expr) {
            Some(path) => Ok(ScopesPath { path }),
            None => Err(format!("scopesFrom '{expr}' is invalid — expected '<source>.<field>'")),
        }
    }

    /// A string is split on U+0020 only; an array is accepted only when every element is a
    /// string, taken verbatim. Anything else, or more than 64 scopes or 4 KiB, is "no scopes":
    /// fail closed, never truncate.
    pub fn extract(&self, resolved: &Value) -> Option<std::sync::Arc<[String]>> {
        let scopes: Vec<String> = match lookup_path(resolved, &self.path)? {
            Value::String(text) => text.split(' ').filter(|piece| !piece.is_empty()).map(str::to_string).collect(),
            Value::Array(items) => items.iter().map(|item| item.as_str().map(str::to_string)).collect::<Option<Vec<_>>>()?,
            _ => return None,
        };
        if scopes.len() > MAX_GRANTED_SCOPES || scopes.iter().map(String::len).sum::<usize>() > MAX_GRANTED_SCOPES_BYTES {
            tracing::debug!("a verifier result carried more scopes than the cap allows; treating it as granting none");
            return None;
        }
        Some(scopes.into())
    }
}

/// Parses the right-hand side of a `validIf` expression: `true`/`false` as
/// booleans, a bare integer or float as a number, a double-quoted string
/// with the quotes stripped, or — falling back for the common unquoted case
/// the doc's own examples never show but a real one likely will
/// (`row.status = active`) — the raw token as a string.
fn parse_literal(raw: &str) -> Value {
    match raw {
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        _ => {
            if let Ok(n) = raw.parse::<i64>() {
                Value::Number(n.into())
            } else if let Ok(f) = raw.parse::<f64>() {
                serde_json::Number::from_f64(f).map(Value::Number).unwrap_or(Value::Null)
            } else {
                let unquoted = raw.strip_prefix('"').and_then(|s| s.strip_suffix('"')).unwrap_or(raw);
                Value::String(unquoted.to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_boolean_check_dropping_the_source_label() {
        let valid_if = ValidIf::parse("row.active = true").unwrap();
        assert_eq!(
            valid_if,
            ValidIf {
                path: vec!["active".to_string()],
                expected: Value::Bool(true)
            }
        );
    }

    #[test]
    fn the_source_label_can_be_anything_its_never_matched_against() {
        let a = ValidIf::parse("row.active = true").unwrap();
        let b = ValidIf::parse("response.active = true").unwrap();
        let c = ValidIf::parse("whatever.active = true").unwrap();
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    #[test]
    fn parses_a_nested_path_for_an_unwrapped_http_response() {
        let valid_if = ValidIf::parse("response.data.active = true").unwrap();
        assert_eq!(valid_if.path, vec!["data".to_string(), "active".to_string()]);
    }

    #[test]
    fn parses_a_quoted_string_value() {
        let valid_if = ValidIf::parse(r#"row.status = "active""#).unwrap();
        assert_eq!(valid_if.expected, Value::String("active".to_string()));
    }

    #[test]
    fn parses_an_unquoted_string_value() {
        let valid_if = ValidIf::parse("row.status = active").unwrap();
        assert_eq!(valid_if.expected, Value::String("active".to_string()));
    }

    #[test]
    fn parses_a_numeric_value() {
        let valid_if = ValidIf::parse("row.level = 3").unwrap();
        assert_eq!(valid_if.expected, Value::Number(3.into()));
    }

    #[test]
    fn missing_equals_is_a_parse_error() {
        let err = ValidIf::parse("row.active true").expect_err("no '=' should fail to parse");
        assert!(matches!(err, ValidIfParseError::MissingEquals(_)));
    }

    #[test]
    fn a_path_with_no_source_label_is_a_parse_error() {
        let err = ValidIf::parse("active = true").expect_err("a bare field with no source label should fail to parse");
        assert!(matches!(err, ValidIfParseError::InvalidPath(_)));
    }

    #[test]
    fn an_empty_path_segment_is_a_parse_error() {
        let err = ValidIf::parse("row..active = true").expect_err("an empty path segment should fail to parse");
        assert!(matches!(err, ValidIfParseError::InvalidPath(_)));
    }

    #[test]
    fn a_missing_value_is_a_parse_error() {
        let err = ValidIf::parse("row.active =").expect_err("no value after '=' should fail to parse");
        assert!(matches!(err, ValidIfParseError::MissingValue(_)));
    }

    #[test]
    fn evaluates_true_when_the_field_matches() {
        let valid_if = ValidIf::parse("row.active = true").unwrap();
        assert!(valid_if.evaluate(&serde_json::json!({ "active": true })));
    }

    #[test]
    fn evaluates_false_when_the_field_does_not_match() {
        let valid_if = ValidIf::parse("row.active = true").unwrap();
        assert!(!valid_if.evaluate(&serde_json::json!({ "active": false })));
    }

    #[test]
    fn evaluates_false_when_the_field_is_entirely_absent() {
        let valid_if = ValidIf::parse("row.active = true").unwrap();
        assert!(!valid_if.evaluate(&serde_json::json!({ "somethingElse": true })));
    }

    #[test]
    fn evaluates_a_nested_path_against_an_unwrapped_response() {
        let valid_if = ValidIf::parse("response.data.active = true").unwrap();
        assert!(valid_if.evaluate(&serde_json::json!({ "data": { "active": true } })));
        assert!(!valid_if.evaluate(&serde_json::json!({ "data": { "active": false } })));
    }

    #[test]
    fn evaluates_a_string_equality_check() {
        let valid_if = ValidIf::parse("row.status = active").unwrap();
        assert!(valid_if.evaluate(&serde_json::json!({ "status": "active" })));
        assert!(!valid_if.evaluate(&serde_json::json!({ "status": "suspended" })));
    }
}
