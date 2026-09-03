use std::collections::HashMap;

use serde_json::Value;

use super::schema::SaveEntry;

/// One test file's `{{memory.<key>}}` scope. Reset at the start of every
/// file (a fresh `Memory::new()` per file, never shared across files or
/// across separate `frogs test` runs) — cases within *one* file always run
/// in order, which is what makes referencing an earlier case's saved value
/// well defined at all.
#[derive(Debug, Default)]
pub struct Memory {
    values: HashMap<String, Value>,
}

impl Memory {
    pub fn new() -> Self {
        Self::default()
    }

    /// Runs every entry in a case's `save` block against the response the
    /// case just got, storing (or overwriting) each resulting value. An
    /// entry whose `from` path doesn't resolve, or whose `transform`
    /// doesn't parse, is skipped with a warning rather than failing the
    /// whole case — the case's own `expect` already ran and passed or
    /// failed on its own merits by the time `save` happens.
    pub fn save(&mut self, save: &HashMap<String, SaveEntry>, status: u16, body: &Value) {
        for (key, entry) in save {
            let (from, transform) = entry.parts();
            let Some(raw) = resolve_response_path(from, status, body) else {
                eprintln!("warning: save '{key}': '{from}' did not resolve against the response, skipping");
                continue;
            };

            let value = match transform {
                Some(raw_transform) => match Transform::parse(raw_transform) {
                    Ok(transform) => transform.apply(&raw),
                    Err(message) => {
                        eprintln!("warning: save '{key}': {message}, skipping");
                        continue;
                    }
                },
                None => raw,
            };

            self.values.insert(key.clone(), value);
        }
    }

    /// Substitutes every `{{memory.<key>}}` occurrence in `value`. A string
    /// that is *exactly* one placeholder (nothing else around it) is
    /// replaced with the real, structurally-typed memory value — so
    /// `"id": "{{memory.carId}}"` becomes a real JSON number if that's what
    /// was saved, not a quoted string of it. Anything else is textual
    /// splicing (the value's display form spliced into the surrounding
    /// text). Same whole-value-vs-textual-splice distinction
    /// `http::execute`'s body templating already uses for the identical
    /// reason. An unresolvable `{{memory.X}}` is left exactly as written —
    /// visibly wrong in a failed assertion, rather than silently blanked.
    pub fn substitute(&self, value: &Value) -> Value {
        match value {
            Value::String(s) => self.substitute_string(s),
            Value::Array(items) => Value::Array(items.iter().map(|v| self.substitute(v)).collect()),
            Value::Object(map) => Value::Object(map.iter().map(|(k, v)| (k.clone(), self.substitute(v))).collect()),
            other => other.clone(),
        }
    }

    /// The same substitution as `substitute`, applied to every value in a
    /// plain string map — `request.path`/`request.query`/`request.headers`
    /// are always textual anyway, so only the textual-splice form ever
    /// applies (there's no "preserve real JSON type" case for a field
    /// that's a `String` by definition).
    pub fn substitute_string_map(&self, map: &HashMap<String, String>) -> HashMap<String, String> {
        map.iter()
            .map(|(k, v)| {
                let substituted = match self.substitute_string(v) {
                    Value::String(s) => s,
                    other => display(&other),
                };
                (k.clone(), substituted)
            })
            .collect()
    }

    fn substitute_string(&self, s: &str) -> Value {
        if let Some(key) = whole_placeholder(s) {
            return self.values.get(key).cloned().unwrap_or_else(|| Value::String(s.to_string()));
        }

        let mut out = String::with_capacity(s.len());
        let mut rest = s;
        while let Some(start) = rest.find("{{memory.") {
            out.push_str(&rest[..start]);
            let after = &rest[start + 2..]; // skip "{{"
            match after.find("}}") {
                Some(end) => {
                    let key = after[..end].trim().strip_prefix("memory.").unwrap_or(&after[..end]).trim();
                    match self.values.get(key) {
                        Some(v) => out.push_str(&display(v)),
                        None => out.push_str(&format!("{{{{memory.{key}}}}}")),
                    }
                    rest = &after[end + 2..];
                }
                None => {
                    out.push_str("{{");
                    rest = after;
                    break;
                }
            }
        }
        out.push_str(rest);
        Value::String(out)
    }
}

/// `s` is exactly one `{{memory.<key>}}` placeholder — no other characters
/// before or after — if this returns `Some(key)`.
fn whole_placeholder(s: &str) -> Option<&str> {
    s.strip_prefix("{{memory.")?.strip_suffix("}}")
}

fn display(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Resolves a `save` entry's `from` path against the response a case just
/// got: `response.status` (the numeric HTTP status), `response.body` (the
/// whole body), or `response.body.<dotted path>` (a field within it).
fn resolve_response_path(from: &str, status: u16, body: &Value) -> Option<Value> {
    let rest = from.strip_prefix("response.")?;
    if rest == "status" {
        return Some(Value::Number(status.into()));
    }
    let after_body = rest.strip_prefix("body")?;
    if after_body.is_empty() {
        return Some(body.clone());
    }
    let path = after_body.strip_prefix('.')?;
    let mut current = body;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current.clone())
}

/// The design doc's fixed transform vocabulary — "a small, fixed operator
/// set rather than an expression language, matching how `validIf` and
/// `format` were scoped elsewhere." Anything more complex belongs to a
/// plugin or a real integration test, not this tool.
#[derive(Debug, Clone, PartialEq)]
enum Transform {
    Add(i64),
    Subtract(i64),
    Concat(String),
    Uppercase,
    Lowercase,
    Now,
}

impl Transform {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "uppercase" => return Ok(Transform::Uppercase),
            "lowercase" => return Ok(Transform::Lowercase),
            "now" => return Ok(Transform::Now),
            _ => {}
        }
        if let Some(n) = raw.strip_prefix("add:") {
            return n.parse::<i64>().map(Transform::Add).map_err(|_| format!("'{raw}' is not a valid add:N transform"));
        }
        if let Some(n) = raw.strip_prefix("subtract:") {
            return n
                .parse::<i64>()
                .map(Transform::Subtract)
                .map_err(|_| format!("'{raw}' is not a valid subtract:N transform"));
        }
        if let Some(s) = raw.strip_prefix("concat:") {
            return Ok(Transform::Concat(s.to_string()));
        }
        Err(format!("'{raw}' is not a recognized transform"))
    }

    fn apply(&self, value: &Value) -> Value {
        match self {
            Transform::Add(n) => value.as_i64().map(|v| Value::Number((v + n).into())).unwrap_or_else(|| value.clone()),
            Transform::Subtract(n) => value.as_i64().map(|v| Value::Number((v - n).into())).unwrap_or_else(|| value.clone()),
            Transform::Concat(suffix) => Value::String(format!("{}{suffix}", display(value))),
            Transform::Uppercase => value.as_str().map(|s| Value::String(s.to_uppercase())).unwrap_or_else(|| value.clone()),
            Transform::Lowercase => value.as_str().map(|s| Value::String(s.to_lowercase())).unwrap_or_else(|| value.clone()),
            Transform::Now => Value::String(chrono::Utc::now().to_rfc3339()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_response_path_reads_the_status() {
        assert_eq!(resolve_response_path("response.status", 201, &Value::Null), Some(serde_json::json!(201)));
    }

    #[test]
    fn resolve_response_path_reads_the_whole_body() {
        let body = serde_json::json!({ "id": 42 });
        assert_eq!(resolve_response_path("response.body", 200, &body), Some(body));
    }

    #[test]
    fn resolve_response_path_reads_a_nested_body_field() {
        let body = serde_json::json!({ "car": { "vin": "1HGCM82633A004352" } });
        assert_eq!(
            resolve_response_path("response.body.car.vin", 200, &body),
            Some(serde_json::json!("1HGCM82633A004352"))
        );
    }

    #[test]
    fn resolve_response_path_a_missing_field_is_none() {
        let body = serde_json::json!({ "id": 42 });
        assert_eq!(resolve_response_path("response.body.missing", 200, &body), None);
    }

    #[test]
    fn resolve_response_path_rejects_an_unrelated_prefix() {
        assert_eq!(resolve_response_path("request.body.id", 200, &Value::Null), None);
    }

    #[test]
    fn transform_add_and_subtract() {
        assert_eq!(Transform::parse("add:1").unwrap().apply(&serde_json::json!(5)), serde_json::json!(6));
        assert_eq!(Transform::parse("subtract:2").unwrap().apply(&serde_json::json!(5)), serde_json::json!(3));
    }

    #[test]
    fn transform_add_preserves_integer_representation() {
        // A real regression risk: serde_json distinguishes an integer
        // Number from a float Number internally, so `6` and `6.0` are NOT
        // `==` to each other — an add:1 on an integer must stay an integer,
        // or a later exact-match `expect` would fail for a subtly wrong
        // reason (a representation mismatch, not a value mismatch).
        let result = Transform::parse("add:1").unwrap().apply(&serde_json::json!(5));
        assert_eq!(result, serde_json::json!(6));
        assert_ne!(serde_json::to_string(&result).unwrap(), "6.0");
    }

    #[test]
    fn transform_uppercase_and_lowercase() {
        assert_eq!(Transform::parse("uppercase").unwrap().apply(&serde_json::json!("abc")), serde_json::json!("ABC"));
        assert_eq!(Transform::parse("lowercase").unwrap().apply(&serde_json::json!("ABC")), serde_json::json!("abc"));
    }

    #[test]
    fn transform_concat_appends_a_fixed_suffix() {
        assert_eq!(
            Transform::parse("concat:-suffix").unwrap().apply(&serde_json::json!("prefix")),
            serde_json::json!("prefix-suffix")
        );
    }

    #[test]
    fn transform_concat_suffix_may_itself_contain_colons() {
        assert_eq!(Transform::parse("concat:a:b").unwrap(), Transform::Concat("a:b".to_string()));
    }

    #[test]
    fn transform_now_produces_an_rfc3339_string() {
        let Value::String(s) = Transform::parse("now").unwrap().apply(&Value::Null) else {
            panic!("expected a string");
        };
        assert!(chrono::DateTime::parse_from_rfc3339(&s).is_ok());
    }

    #[test]
    fn an_unrecognized_transform_is_a_clear_error() {
        assert!(Transform::parse("frobnicate").is_err());
    }

    #[test]
    fn a_non_numeric_add_argument_is_a_clear_error() {
        assert!(Transform::parse("add:abc").is_err());
    }

    #[test]
    fn save_then_later_substitution_round_trips_a_value() {
        let mut memory = Memory::new();
        let save = HashMap::from([("carId".to_string(), SaveEntry::Plain("response.body.id".to_string()))]);
        memory.save(&save, 201, &serde_json::json!({ "id": 42 }));

        // Whole-value form: the real number, not a quoted string of it.
        let substituted = memory.substitute(&serde_json::json!({ "id": "{{memory.carId}}" }));
        assert_eq!(substituted, serde_json::json!({ "id": 42 }));
    }

    #[test]
    fn save_with_a_transform_stores_the_transformed_value() {
        let mut memory = Memory::new();
        let save = HashMap::from([(
            "nextPosition".to_string(),
            SaveEntry::Detailed {
                from: "response.body.queuePosition".to_string(),
                transform: Some("add:1".to_string()),
            },
        )]);
        memory.save(&save, 200, &serde_json::json!({ "queuePosition": 5 }));

        assert_eq!(memory.substitute(&serde_json::json!("{{memory.nextPosition}}")), serde_json::json!(6));
    }

    #[test]
    fn textual_splicing_applies_when_a_placeholder_has_surrounding_text() {
        let mut memory = Memory::new();
        let save = HashMap::from([("vin".to_string(), SaveEntry::Plain("response.body.vin".to_string()))]);
        memory.save(&save, 200, &serde_json::json!({ "vin": "1HGCM82633A004352" }));

        assert_eq!(
            memory.substitute(&serde_json::json!("vin is {{memory.vin}}!")),
            serde_json::json!("vin is 1HGCM82633A004352!")
        );
    }

    #[test]
    fn an_unresolvable_placeholder_is_left_as_is() {
        let memory = Memory::new();
        assert_eq!(
            memory.substitute(&serde_json::json!("{{memory.neverSaved}}")),
            serde_json::json!("{{memory.neverSaved}}")
        );
    }

    #[test]
    fn substitute_string_map_substitutes_every_value() {
        let mut memory = Memory::new();
        let save = HashMap::from([("carId".to_string(), SaveEntry::Plain("response.body.id".to_string()))]);
        memory.save(&save, 200, &serde_json::json!({ "id": 42 }));

        let map = HashMap::from([("id".to_string(), "{{memory.carId}}".to_string())]);
        assert_eq!(memory.substitute_string_map(&map).get("id"), Some(&"42".to_string()));
    }

    #[test]
    fn substitution_recurses_into_nested_objects_and_arrays() {
        let mut memory = Memory::new();
        let save = HashMap::from([("carId".to_string(), SaveEntry::Plain("response.body.id".to_string()))]);
        memory.save(&save, 200, &serde_json::json!({ "id": 42 }));

        let template = serde_json::json!({ "items": [{ "id": "{{memory.carId}}" }] });
        assert_eq!(memory.substitute(&template), serde_json::json!({ "items": [{ "id": 42 }] }));
    }

    #[test]
    fn an_unresolvable_save_path_is_skipped_not_a_panic() {
        let mut memory = Memory::new();
        let save = HashMap::from([("missing".to_string(), SaveEntry::Plain("response.body.doesNotExist".to_string()))]);
        memory.save(&save, 200, &serde_json::json!({ "id": 42 }));
        assert!(memory.values.is_empty());
    }

    #[test]
    fn a_malformed_transform_is_skipped_not_a_panic() {
        let mut memory = Memory::new();
        let save = HashMap::from([(
            "bad".to_string(),
            SaveEntry::Detailed {
                from: "response.body.id".to_string(),
                transform: Some("frobnicate".to_string()),
            },
        )]);
        memory.save(&save, 200, &serde_json::json!({ "id": 42 }));
        assert!(memory.values.is_empty());
    }
}
