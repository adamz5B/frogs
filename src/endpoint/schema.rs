use std::collections::HashMap;

use serde::Deserialize;

/// One `datasources/endpoints/<path>/endpoint.<method>.json` file, deserialized
/// straight from disk. Mirrors the `sources` + `response` shape from
/// docs/datasource-schema-design.md — flat fields only for now, no nested
/// objects/arrays/`oneOf` (that's Phase 2's schema walk, not this file format).
#[derive(Debug, Deserialize)]
pub struct EndpointFile {
    #[serde(rename = "operationId")]
    pub operation_id: String,
    /// The name of the `security/schemes.json` scheme guarding this
    /// endpoint, if any — `None` means public, no verifier runs. A single
    /// scheme name rather than OpenAPI's full array-of-alternative-
    /// requirement-objects grammar: this project's endpoint files pick one
    /// scheme per endpoint, matching the "small vocabulary, not a
    /// language" scope cuts made elsewhere (`validIf`, `format`).
    #[serde(default)]
    pub security: Option<String>,
    /// The HTTP status a *successful* response returns — fully up to the
    /// user, no engine-side "201 for POST" guessing (validated against the
    /// operation's own declared response codes at generate time, see
    /// `openapi::Operation::validate_success_status`). `None` (the common
    /// GET case) defaults to 200 at response-building time.
    #[serde(rename = "successStatus", default)]
    pub success_status: Option<u16>,
    #[serde(default)]
    pub sources: HashMap<String, SourceDef>,
    pub response: ResponseShape,
}

/// The top-level `response` value: either the ordinary flat field map, or —
/// when the whole response *is* a list — the same array shape a `response`
/// field can also carry (see `ResponseField::Array`). `#[serde(untagged)]`
/// tries `Array` first (it requires `source`+`items`, which a field map
/// entry never has both of at the top level) and falls back to `Fields`.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum ResponseShape {
    Array(ArrayResponse),
    Fields(HashMap<String, ResponseField>),
}

/// `cardinality: "many"`'s response counterpart: `source` names the
/// many-cardinality source this array is built from (e.g. `"sources.books"`
/// — the whole resolved value, not `sources.<name>.<field>` like a scalar
/// field's `from`), and `items` maps each row's own columns into one output
/// object per row. `items`' own field paths are bare column names (`"vin"`,
/// not `"sources.books[].vin"`) since `source` already establishes which
/// row they're read from — see `resolve::build_array`. A nested `Array`
/// inside `items` (many-depends-on-many fan-out) isn't supported yet.
#[derive(Debug, Deserialize)]
pub struct ArrayResponse {
    pub source: String,
    pub items: HashMap<String, ResponseField>,
}

/// A named datasource call. `#[serde(tag = "type")]` is what makes this
/// work: serde looks at the JSON object's `"type"` key first and uses it to
/// pick which variant's fields to expect, instead of guessing from shape.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SourceDef {
    Sql {
        connection: String,
        script: String,
        #[serde(default)]
        cardinality: Cardinality,
        /// `None` (the field omitted) means "let the classified error
        /// code's registry `httpStatus` decide" — e.g. a `not_found`
        /// failure naturally returns the registry's 404. Set explicitly to
        /// make this *source's* failures always return a fixed status
        /// regardless of classification, per the design doc's "override
        /// per source if you want different behavior for a specific
        /// endpoint." `Option<T>` fields are optional automatically in
        /// serde (missing key -> `None`), so no `#[serde(default)]` needed.
        #[serde(rename = "onError")]
        on_error: Option<u16>,
        #[serde(default)]
        optional: bool,
        #[serde(default)]
        parameters: Vec<Parameter>,
    },
    Http {
        /// The `datasources/http/<request>.json` file this source executes.
        request: String,
        #[serde(default)]
        cardinality: Cardinality,
        #[serde(rename = "onError")]
        on_error: Option<u16>,
        #[serde(default)]
        optional: bool,
        #[serde(default)]
        parameters: Vec<Parameter>,
    },
}

/// `#[default]` on a variant (stable since Rust 1.62) is what lets
/// `#[derive(Default)]` work on an enum at all — otherwise the compiler has
/// no way to know which variant "default" should mean.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Cardinality {
    #[default]
    One,
    Many,
}

#[derive(Debug, Deserialize)]
pub struct Parameter {
    pub name: String,
    pub from: String,
    /// `"type": "array"` marks this parameter as array-shaped — mostly
    /// descriptive today (both the SQL and HTTP paths already fall back to
    /// JSON-encoding a resolved array/object as a single value regardless
    /// of this flag), but it's what an array-typed value's `body`
    /// passthrough form (`"body": "{{items}}"` in an HTTP datasource file)
    /// checks before treating a resolved value as real JSON worth
    /// preserving structurally rather than a scalar. See the design doc's
    /// write-operations section, point 1: "no fan-out/looping logic — the
    /// mapping declares that a parameter *is* an array, what happens to it
    /// is up to the datasource."
    #[serde(rename = "type", default)]
    pub param_type: ParameterType,
}

#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ParameterType {
    #[default]
    Scalar,
    Array,
}

/// A `response` field is a plain dot-path string, an object carrying a
/// `from` path plus formatting options, or (nested inside an object
/// response) an `Array` — a list embedded as one field among others, e.g.
/// `{"items": {"type":"array", ...}, "total": "sources.count.total"}`.
/// `#[serde(untagged)]` tries each variant in turn: a JSON string matches
/// `Plain`, an object with `source`+`items` matches `Array`, anything else
/// object-shaped matches `Detailed`.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum ResponseField {
    Array(ArrayResponse),
    Plain(String),
    Detailed(DetailedField),
}

/// The `format` field's small, fixed vocabulary (`integer`, `decimal`,
/// `boolean`, `date-time`/`date`, `string`) plus its per-format options —
/// `precision` for `decimal`, `sourceFormat` for `date-time`/`date`,
/// `trim`/`uppercase`/`lowercase` for string cleanup. Unrecognized keys are
/// silently ignored (no `deny_unknown_fields`) since this is deliberately a
/// small vocabulary, not a language, matching `validIf`/transform elsewhere
/// in the design doc.
#[derive(Debug, Deserialize)]
pub struct DetailedField {
    pub from: String,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub precision: Option<usize>,
    #[serde(rename = "sourceFormat", default)]
    pub source_format: Option<String>,
    #[serde(default)]
    pub trim: bool,
    #[serde(default)]
    pub uppercase: bool,
    #[serde(default)]
    pub lowercase: bool,
}

impl ResponseField {
    /// Callers must handle `ResponseField::Array` themselves (see
    /// `resolve::build_field`/`build_field_against_row`) before ever
    /// reaching here — an array field has no single dot-path, it has a
    /// `source` and an `items` map instead.
    pub fn from_path(&self) -> &str {
        match self {
            ResponseField::Plain(path) => path,
            ResponseField::Detailed(detail) => &detail.from,
            ResponseField::Array(_) => unreachable!("ResponseField::Array must be handled before from_path is called"),
        }
    }

    /// `None` for a `Plain` field — nothing to format, pass the resolved
    /// value straight through. Never called for `Array` — see `from_path`.
    pub fn detail(&self) -> Option<&DetailedField> {
        match self {
            ResponseField::Plain(_) => None,
            ResponseField::Detailed(detail) => Some(detail),
            ResponseField::Array(_) => unreachable!("ResponseField::Array must be handled before detail is called"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_an_endpoint_file_with_sql_and_http_sources() {
        let json = r#"{
            "operationId": "getCarByVin",
            "security": "apiKeyAuth",
            "sources": {
                "car": {
                    "type": "sql",
                    "connection": "vehicles_db",
                    "script": "get_car_by_vin.sql",
                    "cardinality": "one",
                    "onError": 500,
                    "parameters": [{ "name": "vin", "from": "path.vin" }]
                },
                "pricing": {
                    "type": "http",
                    "request": "pricing_lookup.json",
                    "cardinality": "one",
                    "onError": 502,
                    "optional": true,
                    "parameters": [{ "name": "vin", "from": "path.vin" }]
                }
            },
            "response": {
                "maker": "sources.car.maker",
                "model": "sources.car.model",
                "year": { "from": "sources.car.year", "format": "integer" },
                "vin": "sources.car.vin",
                "price": { "from": "sources.pricing.amount", "format": "decimal", "precision": 2 },
                "currency": "sources.pricing.currency",
                "listedAt": { "from": "sources.car.listed_at", "format": "date-time", "sourceFormat": "unix-seconds" }
            }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();

        assert_eq!(endpoint.operation_id, "getCarByVin");
        assert_eq!(endpoint.sources.len(), 2);
        assert!(matches!(endpoint.sources["car"], SourceDef::Sql { .. }));
        assert!(matches!(endpoint.sources["pricing"], SourceDef::Http { .. }));

        let ResponseShape::Fields(response) = &endpoint.response else {
            panic!("getCarByVin's response is an ordinary flat field map, not an array");
        };
        assert_eq!(response["vin"].from_path(), "sources.car.vin");
        assert_eq!(response["price"].from_path(), "sources.pricing.amount");

        assert_eq!(response["year"].detail().unwrap().format.as_deref(), Some("integer"));
        let price = response["price"].detail().unwrap();
        assert_eq!(price.format.as_deref(), Some("decimal"));
        assert_eq!(price.precision, Some(2));
        assert_eq!(response["listedAt"].detail().unwrap().source_format.as_deref(), Some("unix-seconds"));
    }

    #[test]
    fn omitted_on_error_defaults_to_none_letting_the_registry_decide() {
        let json = r#"{
            "operationId": "test",
            "sources": {
                "car": { "type": "sql", "connection": "db", "script": "q.sql" },
                "pricing": { "type": "http", "request": "pricing_lookup.json" }
            },
            "response": {}
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();

        let SourceDef::Sql { on_error, .. } = &endpoint.sources["car"] else {
            panic!("expected a Sql source");
        };
        assert_eq!(*on_error, None);

        let SourceDef::Http { on_error, .. } = &endpoint.sources["pricing"] else {
            panic!("expected an Http source");
        };
        assert_eq!(*on_error, None);
    }

    #[test]
    fn explicit_on_error_is_preserved() {
        let json = r#"{
            "operationId": "test",
            "sources": {
                "car": { "type": "sql", "connection": "db", "script": "q.sql", "onError": 503 }
            },
            "response": {}
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        let SourceDef::Sql { on_error, .. } = &endpoint.sources["car"] else {
            panic!("expected a Sql source");
        };
        assert_eq!(*on_error, Some(503));
    }

    #[test]
    fn a_parameter_with_no_type_defaults_to_scalar() {
        let json = r#"{
            "operationId": "test",
            "sources": {
                "car": {
                    "type": "sql", "connection": "db", "script": "q.sql",
                    "parameters": [{ "name": "vin", "from": "path.vin" }]
                }
            },
            "response": {}
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        let SourceDef::Sql { parameters, .. } = &endpoint.sources["car"] else {
            panic!("expected a Sql source");
        };
        assert_eq!(parameters[0].param_type, ParameterType::Scalar);
    }

    #[test]
    fn a_parameter_declared_type_array_parses_as_array() {
        let json = r#"{
            "operationId": "test",
            "sources": {
                "car": {
                    "type": "sql", "connection": "db", "script": "q.sql",
                    "parameters": [{ "name": "items", "from": "body.items", "type": "array" }]
                }
            },
            "response": {}
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        let SourceDef::Sql { parameters, .. } = &endpoint.sources["car"] else {
            panic!("expected a Sql source");
        };
        assert_eq!(parameters[0].param_type, ParameterType::Array);
    }

    #[test]
    fn a_top_level_array_response_parses_as_response_shape_array() {
        let json = r#"{
            "operationId": "test",
            "sources": {},
            "response": {
                "type": "array",
                "source": "sources.cars",
                "items": { "vin": "vin" }
            }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        let ResponseShape::Array(array) = &endpoint.response else {
            panic!("expected a top-level array response");
        };
        assert_eq!(array.source, "sources.cars");
        assert_eq!(array.items["vin"].from_path(), "vin");
    }

    #[test]
    fn an_array_nested_inside_a_field_map_parses_as_response_field_array() {
        let json = r#"{
            "operationId": "test",
            "sources": {},
            "response": {
                "items": { "type": "array", "source": "sources.cars", "items": { "vin": "vin" } },
                "total": "sources.count.total"
            }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        let ResponseShape::Fields(fields) = &endpoint.response else {
            panic!("expected the ordinary flat field map");
        };
        assert!(matches!(&fields["items"], ResponseField::Array(array) if array.source == "sources.cars"));
        assert_eq!(fields["total"].from_path(), "sources.count.total");
    }

    #[test]
    fn an_empty_response_object_still_parses_as_an_empty_field_map() {
        // Regression guard: untagged deserialization must try `Array`
        // first (it requires `source`+`items`, which `{}` has neither of)
        // and fall back to `Fields` — not error out or silently pick the
        // wrong variant.
        let json = r#"{ "operationId": "test", "sources": {}, "response": {} }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        assert!(matches!(&endpoint.response, ResponseShape::Fields(fields) if fields.is_empty()));
    }
}
