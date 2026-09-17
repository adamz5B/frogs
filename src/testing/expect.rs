use serde_json::Value;

use super::schema::Expectation;

/// One field where the real response didn't match what `expect` declared.
/// `path` uses dot-notation from the case's own point of view (`status`,
/// `body.price`, `body.car.maker`), matching how a person would describe
/// where to look, not an internal representation.
#[derive(Debug, Clone, PartialEq)]
pub struct Mismatch {
    pub path: String,
    pub expected: String,
    pub actual: String,
}

/// Checks a real response against one case's `expect` block, returning
/// every mismatch found (not just the first) — a case with three wrong
/// fields should say so all at once, not make a user fix-and-rerun three
/// times. An empty result means the case passed.
pub fn evaluate(expect: &Expectation, actual_status: u16, actual_body: &Value) -> Vec<Mismatch> {
    let mut mismatches = Vec::new();

    if let Some(expected_status) = expect.status
        && expected_status != actual_status
    {
        mismatches.push(Mismatch {
            path: "status".to_string(),
            expected: expected_status.to_string(),
            actual: actual_status.to_string(),
        });
    }

    if let Some(expected_body) = &expect.body {
        compare(expected_body, actual_body, "body", &mut mismatches);
    }

    mismatches
}

/// Whether `actual` satisfies `expected` under the same partial-compare
/// rules `evaluate` uses for a case's `expect.body` (`$any`/`$type:`
/// matchers included) — what `testing::select` uses to match an inbound
/// request body against a case's declared `request.body`.
pub(crate) fn matches_subset(expected: &Value, actual: &Value) -> bool {
    let mut mismatches = Vec::new();
    compare(expected, actual, "body", &mut mismatches);
    mismatches.is_empty()
}

/// Partial (subset) matching, not exact equality: only keys present in
/// `expected` are checked; extra keys `actual` has that `expected` doesn't
/// mention are never a mismatch. This is what lets the design doc's own
/// examples check just `{"maker": "Honda", "price": 24500}` against a
/// response that actually has several more fields (`model`, `year`, `vin`,
/// `currency`, `listedAt`) without listing every single one — a case
/// declares what it cares about, nothing more.
fn compare(expected: &Value, actual: &Value, path: &str, out: &mut Vec<Mismatch>) {
    if let Value::String(token) = expected
        && let Some(matched) = check_matcher(token, actual)
    {
        if !matched {
            out.push(Mismatch {
                path: path.to_string(),
                expected: token.clone(),
                actual: describe(actual),
            });
        }
        return;
    }

    match expected {
        Value::Object(expected_fields) => {
            let Value::Object(actual_fields) = actual else {
                out.push(Mismatch {
                    path: path.to_string(),
                    expected: "an object".to_string(),
                    actual: describe(actual),
                });
                return;
            };
            for (key, expected_value) in expected_fields {
                let field_path = format!("{path}.{key}");
                match actual_fields.get(key) {
                    Some(actual_value) => compare(expected_value, actual_value, &field_path, out),
                    None => out.push(Mismatch {
                        path: field_path,
                        expected: describe(expected_value),
                        actual: "missing".to_string(),
                    }),
                }
            }
        }
        other => {
            if other != actual {
                out.push(Mismatch {
                    path: path.to_string(),
                    expected: describe(other),
                    actual: describe(actual),
                });
            }
        }
    }
}

/// `expected` is only ever treated as a matcher token when it's an exact
/// `"$any"` or `"$type:<name>"` string — anything else (including a
/// literal string a case is genuinely asserting on) falls through to
/// ordinary equality via `None`, never partially interpreted.
fn check_matcher(expected: &str, actual: &Value) -> Option<bool> {
    if expected == "$any" {
        // "present, value not checked" — every field `build_response`
        // populates is present (defaulting to `null` when unresolved, see
        // `endpoint::resolve::lookup`), so this always matches.
        return Some(true);
    }
    let type_name = expected.strip_prefix("$type:")?;
    Some(match type_name {
        "string" => actual.is_string(),
        "number" => actual.is_number(),
        "boolean" => actual.is_boolean(),
        "object" => actual.is_object(),
        "array" => actual.is_array(),
        "null" => actual.is_null(),
        // An unrecognized `$type:X` is a test-authoring mistake, not a
        // value nothing could ever satisfy — fails loud rather than
        // silently passing (which `None` here, falling through to a
        // literal string compare, would effectively do for most actual
        // values).
        //
        // A nested object's own shape ("does `person` look like a
        // `Person`?") doesn't need a class-name matcher here at all today —
        // compose it instead, asserting each field of interest directly
        // (`"person": { "name": "$type:string", "age": "$type:number" }`),
        // which `compare`'s recursion already supports for free. If a named
        // `$type:<ComponentName>` ever becomes worth adding, the natural
        // shape to check against already exists: the resolved descriptors
        // `generate` writes to `datasources/components/<Name>.json` (see
        // `openapi::schema_walk`) — this match arm is where that would
        // plug in, rather than inventing a separate class registry.
        _ => false,
    })
}

fn describe(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "<unprintable>".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::schema::Expectation;

    fn expect(json: &str) -> Expectation {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn a_fully_matching_response_has_no_mismatches() {
        let expectation = expect(r#"{ "status": 200, "body": { "maker": "Honda", "price": 24500 } }"#);
        let actual = serde_json::json!({ "maker": "Honda", "price": 24500, "vin": "1HGCM82633A004352" });
        assert_eq!(evaluate(&expectation, 200, &actual), vec![]);
    }

    #[test]
    fn extra_fields_in_the_actual_response_are_never_a_mismatch() {
        let expectation = expect(r#"{ "body": { "maker": "Honda" } }"#);
        let actual = serde_json::json!({ "maker": "Honda", "model": "Accord", "year": 2003 });
        assert_eq!(evaluate(&expectation, 0, &actual), vec![]);
    }

    #[test]
    fn a_wrong_status_is_reported() {
        let expectation = expect(r#"{ "status": 200 }"#);
        assert_eq!(
            evaluate(&expectation, 404, &Value::Null),
            vec![Mismatch {
                path: "status".to_string(),
                expected: "200".to_string(),
                actual: "404".to_string()
            }]
        );
    }

    #[test]
    fn a_wrong_field_value_is_reported_with_its_dotted_path() {
        let expectation = expect(r#"{ "body": { "price": 24500 } }"#);
        let actual = serde_json::json!({ "price": 19999 });
        assert_eq!(
            evaluate(&expectation, 0, &actual),
            vec![Mismatch {
                path: "body.price".to_string(),
                expected: "24500".to_string(),
                actual: "19999".to_string()
            }]
        );
    }

    #[test]
    fn a_missing_field_is_distinguished_from_a_null_one() {
        let expectation = expect(r#"{ "body": { "price": 24500 } }"#);
        let actual = serde_json::json!({ "currency": "USD" });
        assert_eq!(
            evaluate(&expectation, 0, &actual),
            vec![Mismatch {
                path: "body.price".to_string(),
                expected: "24500".to_string(),
                actual: "missing".to_string()
            }]
        );
    }

    #[test]
    fn a_present_null_field_is_reported_as_null_not_missing() {
        let expectation = expect(r#"{ "body": { "price": 24500 } }"#);
        let actual = serde_json::json!({ "price": null });
        assert_eq!(
            evaluate(&expectation, 0, &actual),
            vec![Mismatch {
                path: "body.price".to_string(),
                expected: "24500".to_string(),
                actual: "null".to_string()
            }]
        );
    }

    #[test]
    fn nested_objects_are_matched_as_a_partial_subset_too() {
        let expectation = expect(r#"{ "body": { "car": { "maker": "Honda" } } }"#);
        let actual = serde_json::json!({ "car": { "maker": "Honda", "model": "Accord" } });
        assert_eq!(evaluate(&expectation, 0, &actual), vec![]);
    }

    #[test]
    fn dollar_any_matches_any_value_including_null() {
        let expectation = expect(r#"{ "body": { "id": "$any" } }"#);
        assert_eq!(evaluate(&expectation, 0, &serde_json::json!({ "id": 42 })), vec![]);
        assert_eq!(evaluate(&expectation, 0, &serde_json::json!({ "id": "abc" })), vec![]);
        assert_eq!(evaluate(&expectation, 0, &serde_json::json!({ "id": null })), vec![]);
    }

    #[test]
    fn dollar_type_checks_by_type_only() {
        let expectation = expect(r#"{ "body": { "vin": "$type:string" } }"#);
        assert_eq!(evaluate(&expectation, 0, &serde_json::json!({ "vin": "1HGCM82633A004352" })), vec![]);

        let mismatches = evaluate(&expectation, 0, &serde_json::json!({ "vin": 12345 }));
        assert_eq!(
            mismatches,
            vec![Mismatch {
                path: "body.vin".to_string(),
                expected: "$type:string".to_string(),
                actual: "12345".to_string()
            }]
        );
    }

    #[test]
    fn dollar_type_supports_every_json_type_name() {
        for (type_name, value) in [
            ("string", serde_json::json!("x")),
            ("number", serde_json::json!(1)),
            ("boolean", serde_json::json!(true)),
            ("object", serde_json::json!({})),
            ("array", serde_json::json!([])),
            ("null", Value::Null),
        ] {
            let expectation = expect(&format!(r#"{{ "body": {{ "f": "$type:{type_name}" }} }}"#));
            let actual = serde_json::json!({ "f": value });
            assert_eq!(evaluate(&expectation, 0, &actual), vec![], "expected $type:{type_name} to accept {value:?}");
        }
    }

    #[test]
    fn an_unrecognized_type_token_never_matches() {
        let expectation = expect(r#"{ "body": { "f": "$type:frobnicate" } }"#);
        let mismatches = evaluate(&expectation, 0, &serde_json::json!({ "f": "anything" }));
        assert_eq!(mismatches.len(), 1, "an unrecognized $type:X must fail loud, not silently pass");
    }

    #[test]
    fn a_literal_string_that_is_not_a_matcher_token_compares_by_value() {
        let expectation = expect(r#"{ "body": { "maker": "Honda" } }"#);
        assert_eq!(evaluate(&expectation, 0, &serde_json::json!({ "maker": "Ford" })).len(), 1);
        assert_eq!(evaluate(&expectation, 0, &serde_json::json!({ "maker": "Honda" })), vec![]);
    }

    #[test]
    fn an_object_expected_against_a_non_object_actual_is_a_shape_mismatch() {
        let expectation = expect(r#"{ "body": { "car": { "maker": "Honda" } } }"#);
        let actual = serde_json::json!({ "car": "not an object" });
        let mismatches = evaluate(&expectation, 0, &actual);
        assert_eq!(
            mismatches,
            vec![Mismatch {
                path: "body.car".to_string(),
                expected: "an object".to_string(),
                actual: "\"not an object\"".to_string()
            }]
        );
    }

    #[test]
    fn no_expect_fields_at_all_never_produces_a_mismatch() {
        let expectation = expect("{}");
        assert_eq!(evaluate(&expectation, 999, &serde_json::json!({ "anything": true })), vec![]);
    }

    /// The design doc's own three worked cases, evaluated end to end
    /// against the exact `actual` shape their `mocks` would produce (per
    /// Point 2) — proving `evaluate` really does accept all three as
    /// written, not just the individual pieces in isolation.
    #[test]
    fn the_cars_demo_worked_examples_all_pass_against_their_expected_actuals() {
        let happy = expect(r#"{ "status": 200, "body": { "maker": "Honda", "price": 24500 } }"#);
        let happy_actual = serde_json::json!({
            "maker": "Honda", "model": "Accord", "vin": "1HGCM82633A004352", "price": 24500, "currency": "USD"
        });
        assert_eq!(evaluate(&happy, 200, &happy_actual), vec![]);

        let degraded = expect(r#"{ "status": 200, "body": { "price": null } }"#);
        let degraded_actual = serde_json::json!({ "maker": "Honda", "price": null });
        assert_eq!(evaluate(&degraded, 200, &degraded_actual), vec![]);

        let not_found = expect(r#"{ "status": 404 }"#);
        assert_eq!(
            evaluate(&not_found, 404, &serde_json::json!({ "code": 404, "name": "datasource.sql.not_found" })),
            vec![]
        );
    }
}
