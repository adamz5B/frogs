use std::collections::{HashMap, HashSet};

use axum::http::HeaderMap;
use serde_json::{Map, Value};

use crate::openapi::Operation;

/// The two fixed classification codes a validation failure can produce —
/// same "small, fixed vocabulary" posture every other failure classifier
/// in this codebase uses (`SourceErrorCause::code()`, `VerifyErrorCause::code()`).
pub const MISSING_PARAMETER: &str = "validation.missing_parameter";
pub const INVALID_TYPE: &str = "validation.invalid_type";

/// One validation failure — request validation stops and reports the
/// *first* problem found, not every problem at once, matching this
/// codebase's existing single-error-per-failure convention (a source
/// failure, a verifier failure — nothing here batches multiple errors into
/// one response).
#[derive(Debug, PartialEq)]
pub struct ValidationProblem {
    pub code: &'static str,
    pub message: String,
}

/// Checks an incoming request's path/query/header parameters and JSON body
/// against `operation`'s own OpenAPI-declared shape — required parameters
/// present, scalar parameter values parsing as their declared type, and the
/// body's required properties present with matching types, recursively
/// through nested objects and arrays. Deliberately *not* full JSON Schema:
/// `oneOf`/`anyOf` branches, `pattern`/`min`/`max`/format constraints, and
/// parameter `style`/`explode` array/object serialization are all
/// unchecked (permissive) — matching the design doc's own explicit
/// "type/required-field validation... deeper JSON Schema validation
/// explicitly deferred" scope.
pub fn validate_request(
    operation: &Operation,
    component_schemas: &Map<String, Value>,
    path_params: &HashMap<String, String>,
    query_params: &HashMap<String, String>,
    headers: &HeaderMap,
    body: &Value,
) -> Result<(), ValidationProblem> {
    for param in &operation.parameters {
        let raw = match param.location.as_str() {
            "path" => path_params.get(&param.name).cloned(),
            "query" => query_params.get(&param.name).cloned(),
            "header" => headers.get(param.name.as_str()).and_then(|v| v.to_str().ok()).map(str::to_string),
            // `cookie`, or anything OpenAPI adds in the future — this
            // project doesn't bind cookies as a parameter source at all
            // (see `ParameterInfo`'s own doc comment), so there's nothing
            // to check.
            _ => continue,
        };

        match raw {
            None if param.required => {
                return Err(ValidationProblem {
                    code: MISSING_PARAMETER,
                    message: format!("missing required {} parameter '{}'", param.location, param.name),
                });
            }
            None => {}
            Some(value) => {
                if let Some(problem) = check_scalar_type(&value, param.schema_type.as_deref(), &format!("{}.{}", param.location, param.name)) {
                    return Err(problem);
                }
            }
        }
    }

    let Some(request_body) = &operation.request_body else {
        return Ok(());
    };

    if body.is_null() {
        if request_body.required {
            return Err(ValidationProblem {
                code: MISSING_PARAMETER,
                message: "missing required request body".to_string(),
            });
        }
        return Ok(());
    }

    let mut in_progress = HashSet::new();
    validate_value(body, &request_body.schema, component_schemas, &mut in_progress, "body")
}

/// A path/query/header value is always a raw wire string — this only
/// checks it *parses* as the declared type, for the handful of types worth
/// checking that way (`"string"`/absent always passes; `array`/`object`
/// parameters aren't type-checked at all, see `ParameterInfo::schema_type`).
fn check_scalar_type(raw: &str, schema_type: Option<&str>, path: &str) -> Option<ValidationProblem> {
    let fails = match schema_type {
        Some("integer") => raw.parse::<i64>().is_err(),
        Some("number") => raw.parse::<f64>().is_err(),
        Some("boolean") => raw != "true" && raw != "false",
        _ => false,
    };
    fails.then(|| {
        let expected = schema_type.unwrap_or("?");
        let article = if matches!(expected, "integer" | "object" | "array") { "an" } else { "a" };
        ValidationProblem {
            code: INVALID_TYPE,
            message: format!("'{path}' must be {article} {expected}, got '{raw}'"),
        }
    })
}

/// Recursively checks `value` against `schema` — resolving `$ref`s against
/// `components` (with a cycle guard, the same in-progress-marking idiom
/// `openapi::schema_walk` uses for the same reason) and `allOf` by merging
/// every variant's own requirements. `oneOf`/`anyOf` fall through to the
/// permissive default below (no top-level `type` key to match on) rather
/// than getting their own branch — deliberately unchecked, per this
/// module's doc comment. `null` always passes, regardless of the declared
/// type — this project doesn't model OpenAPI's `nullable` keyword, and
/// treating every unmarked-nullable field as null-rejecting would be a
/// worse default than just not checking it.
fn validate_value(value: &Value, schema: &Value, components: &Map<String, Value>, in_progress: &mut HashSet<String>, path: &str) -> Result<(), ValidationProblem> {
    if value.is_null() {
        return Ok(());
    }
    let Some(schema_obj) = schema.as_object() else {
        return Ok(());
    };

    if let Some(ref_str) = schema_obj.get("$ref").and_then(Value::as_str) {
        let Some(name) = ref_str.strip_prefix("#/components/schemas/") else {
            return Ok(());
        };
        let Some(component_schema) = components.get(name) else {
            return Ok(());
        };
        if !in_progress.insert(name.to_string()) {
            return Ok(());
        }
        let result = validate_value(value, component_schema, components, in_progress, path);
        in_progress.remove(name);
        return result;
    }

    if let Some(variants) = schema_obj.get("allOf").and_then(Value::as_array) {
        for variant in variants {
            validate_value(value, variant, components, in_progress, path)?;
        }
        return Ok(());
    }

    match schema_obj.get("type").and_then(Value::as_str) {
        Some("object") => {
            let Some(obj) = value.as_object() else {
                return Err(type_error(path, "object"));
            };
            if let Some(required) = schema_obj.get("required").and_then(Value::as_array) {
                for name in required.iter().filter_map(Value::as_str) {
                    if !obj.contains_key(name) {
                        return Err(ValidationProblem {
                            code: MISSING_PARAMETER,
                            message: format!("'{path}.{name}' is required"),
                        });
                    }
                }
            }
            if let Some(properties) = schema_obj.get("properties").and_then(Value::as_object) {
                for (name, prop_schema) in properties {
                    if let Some(prop_value) = obj.get(name) {
                        validate_value(prop_value, prop_schema, components, in_progress, &format!("{path}.{name}"))?;
                    }
                }
            }
            Ok(())
        }
        Some("array") => {
            let Some(items_value) = value.as_array() else {
                return Err(type_error(path, "array"));
            };
            if let Some(item_schema) = schema_obj.get("items") {
                for (i, item) in items_value.iter().enumerate() {
                    validate_value(item, item_schema, components, in_progress, &format!("{path}[{i}]"))?;
                }
            }
            Ok(())
        }
        Some("string") => {
            if value.is_string() {
                Ok(())
            } else {
                Err(type_error(path, "string"))
            }
        }
        Some("integer") => {
            if is_integer(value) {
                Ok(())
            } else {
                Err(type_error(path, "integer"))
            }
        }
        Some("number") => {
            if value.is_number() {
                Ok(())
            } else {
                Err(type_error(path, "number"))
            }
        }
        Some("boolean") => {
            if value.is_boolean() {
                Ok(())
            } else {
                Err(type_error(path, "boolean"))
            }
        }
        // No `type` at all (a bare `oneOf`/`anyOf`, a free-form map, or a
        // genuinely untyped schema) or a type keyword this validator
        // doesn't model — permissive, not an error.
        _ => Ok(()),
    }
}

fn is_integer(value: &Value) -> bool {
    match value {
        Value::Number(n) => n.is_i64() || n.is_u64() || n.as_f64().is_some_and(|f| f.fract() == 0.0),
        _ => false,
    }
}

fn type_error(path: &str, expected: &str) -> ValidationProblem {
    let article = if matches!(expected, "integer" | "object" | "array") { "an" } else { "a" };
    ValidationProblem {
        code: INVALID_TYPE,
        message: format!("'{path}' must be {article} {expected}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::openapi::{ParameterInfo, RequestBodySchema};

    fn param(name: &str, location: &str, required: bool, schema_type: Option<&str>) -> ParameterInfo {
        ParameterInfo {
            name: name.to_string(),
            location: location.to_string(),
            required,
            schema_type: schema_type.map(str::to_string),
        }
    }

    fn op(parameters: Vec<ParameterInfo>, request_body: Option<RequestBodySchema>) -> Operation {
        Operation {
            path: "/test".to_string(),
            method: "post".to_string(),
            operation_id: "test".to_string(),
            response_schema: None,
            parameters,
            request_body,
            response_status_codes: vec![200],
            security: None,
        }
    }

    #[test]
    fn a_missing_required_path_parameter_fails() {
        let operation = op(vec![param("id", "path", true, None)], None);
        let err = validate_request(&operation, &Map::new(), &HashMap::new(), &HashMap::new(), &HeaderMap::new(), &Value::Null).unwrap_err();
        assert_eq!(err.code, MISSING_PARAMETER);
        assert!(err.message.contains("id"));
    }

    #[test]
    fn a_missing_optional_query_parameter_is_fine() {
        let operation = op(vec![param("limit", "query", false, Some("integer"))], None);
        assert!(validate_request(&operation, &Map::new(), &HashMap::new(), &HashMap::new(), &HeaderMap::new(), &Value::Null).is_ok());
    }

    #[test]
    fn a_present_required_parameter_of_the_right_type_passes() {
        let operation = op(vec![param("id", "path", true, Some("integer"))], None);
        let path_params = HashMap::from([("id".to_string(), "42".to_string())]);
        assert!(validate_request(&operation, &Map::new(), &path_params, &HashMap::new(), &HeaderMap::new(), &Value::Null).is_ok());
    }

    #[test]
    fn a_non_integer_value_for_an_integer_parameter_fails() {
        let operation = op(vec![param("id", "path", true, Some("integer"))], None);
        let path_params = HashMap::from([("id".to_string(), "not-a-number".to_string())]);
        let err = validate_request(&operation, &Map::new(), &path_params, &HashMap::new(), &HeaderMap::new(), &Value::Null).unwrap_err();
        assert_eq!(err.code, INVALID_TYPE);
    }

    #[test]
    fn a_string_typed_parameter_never_fails_the_type_check() {
        let operation = op(vec![param("name", "query", true, Some("string"))], None);
        let query_params = HashMap::from([("name".to_string(), "anything at all".to_string())]);
        assert!(validate_request(&operation, &Map::new(), &HashMap::new(), &query_params, &HeaderMap::new(), &Value::Null).is_ok());
    }

    #[test]
    fn a_boolean_parameter_accepts_only_true_or_false() {
        let operation = op(vec![param("active", "query", true, Some("boolean"))], None);
        let good = HashMap::from([("active".to_string(), "true".to_string())]);
        assert!(validate_request(&operation, &Map::new(), &HashMap::new(), &good, &HeaderMap::new(), &Value::Null).is_ok());

        let bad = HashMap::from([("active".to_string(), "yes".to_string())]);
        let err = validate_request(&operation, &Map::new(), &HashMap::new(), &bad, &HeaderMap::new(), &Value::Null).unwrap_err();
        assert_eq!(err.code, INVALID_TYPE);
    }

    #[test]
    fn a_header_parameter_is_read_case_insensitively() {
        let operation = op(vec![param("X-Api-Key", "header", true, None)], None);
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", "secret".parse().unwrap());
        assert!(validate_request(&operation, &Map::new(), &HashMap::new(), &HashMap::new(), &headers, &Value::Null).is_ok());
    }

    #[test]
    fn a_required_body_that_is_null_fails() {
        let operation = op(vec![], Some(RequestBodySchema { required: true, schema: serde_json::json!({ "type": "object" }) }));
        let err = validate_request(&operation, &Map::new(), &HashMap::new(), &HashMap::new(), &HeaderMap::new(), &Value::Null).unwrap_err();
        assert_eq!(err.code, MISSING_PARAMETER);
    }

    #[test]
    fn an_optional_body_that_is_null_is_fine() {
        let operation = op(vec![], Some(RequestBodySchema { required: false, schema: serde_json::json!({ "type": "object" }) }));
        assert!(validate_request(&operation, &Map::new(), &HashMap::new(), &HashMap::new(), &HeaderMap::new(), &Value::Null).is_ok());
    }

    #[test]
    fn a_body_missing_a_required_top_level_property_fails() {
        let schema = serde_json::json!({ "type": "object", "required": ["maker"], "properties": { "maker": { "type": "string" } } });
        let operation = op(vec![], Some(RequestBodySchema { required: true, schema }));
        let body = serde_json::json!({ "model": "Civic" });
        let err = validate_request(&operation, &Map::new(), &HashMap::new(), &HashMap::new(), &HeaderMap::new(), &body).unwrap_err();
        assert_eq!(err.code, MISSING_PARAMETER);
        assert!(err.message.contains("maker"));
    }

    #[test]
    fn a_body_with_a_wrong_typed_property_fails() {
        let schema = serde_json::json!({ "type": "object", "properties": { "year": { "type": "integer" } } });
        let operation = op(vec![], Some(RequestBodySchema { required: true, schema }));
        let body = serde_json::json!({ "year": "not a number" });
        let err = validate_request(&operation, &Map::new(), &HashMap::new(), &HashMap::new(), &HeaderMap::new(), &body).unwrap_err();
        assert_eq!(err.code, INVALID_TYPE);
        assert!(err.message.contains("body.year"));
    }

    #[test]
    fn a_valid_body_passes() {
        let schema = serde_json::json!({
            "type": "object",
            "required": ["maker", "year"],
            "properties": { "maker": { "type": "string" }, "year": { "type": "integer" } }
        });
        let operation = op(vec![], Some(RequestBodySchema { required: true, schema }));
        let body = serde_json::json!({ "maker": "Honda", "year": 2020 });
        assert!(validate_request(&operation, &Map::new(), &HashMap::new(), &HashMap::new(), &HeaderMap::new(), &body).is_ok());
    }

    /// Recursion into a *nested* object property — the specific case that
    /// makes this more than a flat top-level check.
    #[test]
    fn a_nested_object_propertys_own_required_field_is_checked() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "owner": {
                    "type": "object",
                    "required": ["name"],
                    "properties": { "name": { "type": "string" } }
                }
            }
        });
        let operation = op(vec![], Some(RequestBodySchema { required: true, schema }));
        let body = serde_json::json!({ "owner": {} });
        let err = validate_request(&operation, &Map::new(), &HashMap::new(), &HashMap::new(), &HeaderMap::new(), &body).unwrap_err();
        assert_eq!(err.code, MISSING_PARAMETER);
        assert!(err.message.contains("owner.name"), "path should show the full nested location: {}", err.message);
    }

    #[test]
    fn each_array_item_is_recursively_checked() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": { "type": "object", "required": ["sku"], "properties": { "sku": { "type": "string" } } }
                }
            }
        });
        let operation = op(vec![], Some(RequestBodySchema { required: true, schema }));
        let body = serde_json::json!({ "items": [{ "sku": "A1" }, {}] });
        let err = validate_request(&operation, &Map::new(), &HashMap::new(), &HashMap::new(), &HeaderMap::new(), &body).unwrap_err();
        assert_eq!(err.code, MISSING_PARAMETER);
        assert!(err.message.contains("items[1].sku"), "path should identify which array element failed: {}", err.message);
    }

    /// `$ref` resolution against the component cache, through a nested
    /// property — not just a top-level body schema that's itself a `$ref`.
    #[test]
    fn a_ref_d_nested_property_resolves_against_components() {
        let mut components = Map::new();
        components.insert(
            "Owner".to_string(),
            serde_json::json!({ "type": "object", "required": ["name"], "properties": { "name": { "type": "string" } } }),
        );
        let schema = serde_json::json!({
            "type": "object",
            "properties": { "owner": { "$ref": "#/components/schemas/Owner" } }
        });
        let operation = op(vec![], Some(RequestBodySchema { required: true, schema }));
        let body = serde_json::json!({ "owner": {} });
        let err = validate_request(&operation, &components, &HashMap::new(), &HashMap::new(), &HeaderMap::new(), &body).unwrap_err();
        assert!(err.message.contains("owner.name"));
    }

    /// A component that (directly or transitively) refs itself must never
    /// hang — same guarantee `openapi::schema_walk` gives for response
    /// schemas, now needed here too since request bodies can `$ref` just
    /// as freely.
    #[test]
    fn a_circular_ref_does_not_hang_and_is_treated_as_valid() {
        let mut components = Map::new();
        components.insert("Node".to_string(), serde_json::json!({ "type": "object", "properties": { "child": { "$ref": "#/components/schemas/Node" } } }));
        let schema = serde_json::json!({ "$ref": "#/components/schemas/Node" });
        let operation = op(vec![], Some(RequestBodySchema { required: true, schema }));
        let body = serde_json::json!({ "child": { "child": { "child": {} } } });
        assert!(validate_request(&operation, &components, &HashMap::new(), &HashMap::new(), &HeaderMap::new(), &body).is_ok());
    }

    /// `allOf` merges every variant's own requirements onto the same value
    /// — a property required by *either* variant must be present.
    #[test]
    fn all_of_checks_every_variant_against_the_same_value() {
        let schema = serde_json::json!({
            "allOf": [
                { "type": "object", "required": ["maker"] },
                { "type": "object", "required": ["model"] }
            ]
        });
        let operation = op(vec![], Some(RequestBodySchema { required: true, schema }));
        let body = serde_json::json!({ "maker": "Honda" });
        let err = validate_request(&operation, &Map::new(), &HashMap::new(), &HashMap::new(), &HeaderMap::new(), &body).unwrap_err();
        assert!(err.message.contains("model"));
    }

    /// `oneOf`/`anyOf` are deliberately not deeply validated — a body that
    /// matches neither variant's shape still passes, since there's no
    /// top-level `type` keyword for the validator to match on.
    #[test]
    fn one_of_is_not_deeply_validated() {
        let schema = serde_json::json!({
            "oneOf": [
                { "type": "object", "required": ["maker"] },
                { "type": "object", "required": ["vin"] }
            ]
        });
        let operation = op(vec![], Some(RequestBodySchema { required: true, schema }));
        let body = serde_json::json!({ "somethingElseEntirely": true });
        assert!(validate_request(&operation, &Map::new(), &HashMap::new(), &HashMap::new(), &HeaderMap::new(), &body).is_ok());
    }

    #[test]
    fn an_explicit_null_value_always_passes_type_checking() {
        let schema = serde_json::json!({ "type": "object", "properties": { "note": { "type": "string" } } });
        let operation = op(vec![], Some(RequestBodySchema { required: true, schema }));
        let body = serde_json::json!({ "note": null });
        assert!(validate_request(&operation, &Map::new(), &HashMap::new(), &HashMap::new(), &HeaderMap::new(), &body).is_ok());
    }

    #[test]
    fn a_whole_number_float_is_accepted_as_an_integer() {
        // serde_json can represent `2020` written with a decimal point as
        // an f64 internally depending on how the JSON was produced —
        // reject only genuinely fractional values, not representation.
        let schema = serde_json::json!({ "type": "object", "properties": { "year": { "type": "integer" } } });
        let operation = op(vec![], Some(RequestBodySchema { required: true, schema }));
        let body: Value = serde_json::from_str(r#"{ "year": 2020.0 }"#).unwrap();
        assert!(validate_request(&operation, &Map::new(), &HashMap::new(), &HashMap::new(), &HeaderMap::new(), &body).is_ok());
    }

    #[test]
    fn a_fractional_value_is_rejected_as_an_integer() {
        let schema = serde_json::json!({ "type": "object", "properties": { "year": { "type": "integer" } } });
        let operation = op(vec![], Some(RequestBodySchema { required: true, schema }));
        let body = serde_json::json!({ "year": 2020.5 });
        let err = validate_request(&operation, &Map::new(), &HashMap::new(), &HashMap::new(), &HeaderMap::new(), &body).unwrap_err();
        assert_eq!(err.code, INVALID_TYPE);
    }
}
