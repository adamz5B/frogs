use std::collections::HashMap;
use std::num::{NonZeroU64, NonZeroUsize};

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
    /// Per-endpoint overrides of the global `config/errors/` registry —
    /// `httpStatus`/`exposeDetail` for a specific code, scoped to just this
    /// endpoint, without touching the registry every other endpoint shares.
    /// Applies to *any* code this endpoint's requests can produce (a source
    /// failure, a security-verifier failure, a validation failure) — not
    /// just datasource codes, even though the design doc's own example only
    /// shows one. A source's own `onError` (see `SourceDef`) is more
    /// specific and wins over this for `httpStatus` when both apply to the
    /// same failure; `exposeDetail` has no source-level equivalent, so this
    /// is the only lever for it.
    #[serde(rename = "errorOverrides", default)]
    pub error_overrides: HashMap<String, ErrorOverride>,
    /// Per-endpoint override of the global `config/server.json`'s
    /// `debugMode` — `None` (the common case) means "use the server-wide
    /// setting." Lets one sensitive or actively-being-debugged endpoint run
    /// with verbose `detail`/discovery on (or off) without changing that
    /// behavior for every other endpoint.
    #[serde(rename = "debugMode", default)]
    pub debug_mode: Option<bool>,
    /// This endpoint's own token bucket, independent of (and in *addition*
    /// to, not a replacement for) the global `features.rateLimiting` bucket
    /// in `server.json` — a request must pass both. Only meaningful when
    /// present at all; `None` (the common case) means this endpoint is
    /// governed by the global bucket alone. Reuses `RateLimitConfig`'s
    /// shape (`requestsPerSecond`/`burst`), same defaults if only one field
    /// is set.
    #[serde(rename = "rateLimit", default)]
    pub rate_limit: Option<crate::config::RateLimitConfig>,
    /// Whether `frogs generate` wrote this file and it hasn't been hand-
    /// edited since — the generator writes `true` into every fresh stub,
    /// and never touches a file again once it exists (see [Filling In
    /// Generated Files]), so this stays `true` until a human deletes it or
    /// flips it to `false` themselves. `resolve_for_test` refuses to serve
    /// real traffic while it's `true` — see its own doc comment.
    #[serde(rename = "_generated", default)]
    pub generated: bool,
    /// The generator's own note-to-self, shown verbatim in the `501` while
    /// `generated` is `true` — not read for anything else.
    #[serde(rename = "_todo", default)]
    pub todo: Option<String>,
}

/// One entry in `errorOverrides` — either field can be set independently;
/// omitting one leaves the registry's own value for it untouched.
#[derive(Debug, Deserialize, Default)]
pub struct ErrorOverride {
    #[serde(rename = "httpStatus", default)]
    pub http_status: Option<u16>,
    #[serde(rename = "exposeDetail", default)]
    pub expose_detail: Option<bool>,
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
    /// A bare JSON `null` for the *whole* `response` key — what
    /// `frogs generate` writes for an operation with no declared response
    /// schema at all (`stub_from_descriptor(Value::Null)`, e.g. a `200`
    /// with no `content`), as opposed to a schema whose individual fields
    /// are each null (that case is `Fields` with `ResponseField::Null`
    /// entries, already handled). Without this variant, exactly that class
    /// of fresh, unedited stub fails to parse at all — the route is never
    /// registered, not even reachable to hit the `_generated: true` → `501`
    /// gate, silently 404ing instead. Treated identically to an empty
    /// `Fields` map everywhere this is matched (`resolve::build_response`,
    /// `docs_summary::response_shape_json`).
    Null,
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
        /// Many-depends-on-many array fan-out (design doc: "Many-Depends-
        /// on-Many Array Fan-Out") — `false` (the overwhelming common case)
        /// means this source resolves exactly like any other. See
        /// `resolve::resolve_nested_many` for how these four fields are
        /// used, and `validate_nested_many` for how they're enforced.
        #[serde(rename = "allowNestedMany", default)]
        allow_nested_many: bool,
        /// Required (`Some`) whenever `allow_nested_many` is true —
        /// enforced by `validate_nested_many` at startup/`frogs validate`
        /// time, not serde, since a config mistake here needs a clear
        /// message naming the source and file, not a generic serde
        /// "missing field."
        #[serde(rename = "maxConcurrency")]
        max_concurrency: Option<NonZeroUsize>,
        /// Hard ceiling on the fan-out parent's row count — same "required
        /// alongside `allowNestedMany`, enforced by validation, not serde"
        /// posture as `max_concurrency`.
        #[serde(rename = "maxRows")]
        max_rows: Option<NonZeroUsize>,
        /// `None` (the common case) defaults to
        /// `resolve::DEFAULT_NESTED_MANY_ROW_TIMEOUT_MS` (30s) at resolve
        /// time. Only meaningful alongside `allow_nested_many: true`.
        #[serde(rename = "rowTimeoutMs")]
        row_timeout_ms: Option<NonZeroU64>,
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
        #[serde(rename = "allowNestedMany", default)]
        allow_nested_many: bool,
        #[serde(rename = "maxConcurrency")]
        max_concurrency: Option<NonZeroUsize>,
        #[serde(rename = "maxRows")]
        max_rows: Option<NonZeroUsize>,
        #[serde(rename = "rowTimeoutMs")]
        row_timeout_ms: Option<NonZeroU64>,
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
    /// General-purpose numeric clamping — the safety net for a caller-
    /// controlled `limit`/`offset` reaching a script unbounded (`limit=
    /// 999999999`), but applies to any parameter, not just pagination.
    /// Absent (the common case) means this parameter is left exactly as
    /// `resolve_from` resolves it — clamping only ever kicks in when at
    /// least one of these three is actually set. See `resolve::clamp_numeric`.
    #[serde(default)]
    pub default: Option<i64>,
    #[serde(default)]
    pub min: Option<i64>,
    #[serde(default)]
    pub max: Option<i64>,
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
    /// A bare JSON `null` — exactly what `frogs generate` writes for every
    /// unmapped response field in a fresh stub (see the design doc's own
    /// worked example). Without this variant, a freshly generated file
    /// can't even be *parsed* (a bare `null` matches none of the other
    /// three shapes), which would silently keep every new stub un-routable
    /// rather than reachable-and-obviously-unfinished.
    Null,
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
    pub fn dot_path(&self) -> &str {
        match self {
            ResponseField::Plain(path) => path,
            ResponseField::Detailed(detail) => &detail.from,
            ResponseField::Array(_) => unreachable!("ResponseField::Array must be handled before dot_path is called"),
            ResponseField::Null => unreachable!("ResponseField::Null must be handled before dot_path is called"),
        }
    }

    /// `None` for a `Plain` field — nothing to format, pass the resolved
    /// value straight through. Never called for `Array`/`Null` — see `dot_path`.
    pub fn detail(&self) -> Option<&DetailedField> {
        match self {
            ResponseField::Plain(_) => None,
            ResponseField::Detailed(detail) => Some(detail),
            ResponseField::Array(_) => unreachable!("ResponseField::Array must be handled before detail is called"),
            ResponseField::Null => unreachable!("ResponseField::Null must be handled before detail is called"),
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
        assert_eq!(response["vin"].dot_path(), "sources.car.vin");
        assert_eq!(response["price"].dot_path(), "sources.pricing.amount");

        assert_eq!(response["year"].detail().unwrap().format.as_deref(), Some("integer"));
        let price = response["price"].detail().unwrap();
        assert_eq!(price.format.as_deref(), Some("decimal"));
        assert_eq!(price.precision, Some(2));
        assert_eq!(response["listedAt"].detail().unwrap().source_format.as_deref(), Some("unix-seconds"));
    }

    #[test]
    fn parses_a_per_endpoint_rate_limit_override() {
        let json = r#"{
            "operationId": "test",
            "sources": {},
            "response": {},
            "rateLimit": { "requestsPerSecond": 2, "burst": 1 }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        let rate_limit = endpoint.rate_limit.expect("rateLimit should parse");
        assert_eq!(rate_limit.requests_per_second, 2);
        assert_eq!(rate_limit.burst, 1);
    }

    #[test]
    fn a_partial_rate_limit_override_defaults_the_missing_field() {
        let json = r#"{
            "operationId": "test",
            "sources": {},
            "response": {},
            "rateLimit": { "burst": 5 }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        let rate_limit = endpoint.rate_limit.unwrap();
        assert_eq!(rate_limit.burst, 5);
        assert_eq!(
            rate_limit.requests_per_second, 20,
            "requestsPerSecond should fall back to RateLimitConfig's own default"
        );
    }

    #[test]
    fn no_rate_limit_field_at_all_is_none() {
        let json = r#"{ "operationId": "test", "sources": {}, "response": {} }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        assert!(endpoint.rate_limit.is_none());
    }

    /// Exactly `frogs generate`'s own real output shape for a fresh stub
    /// (every unmapped response field is a bare JSON `null`) — this must
    /// parse cleanly, not fail with "data did not match any variant of
    /// untagged enum ResponseShape" the way it did before `ResponseField`
    /// grew its own `Null` variant.
    #[test]
    fn a_bare_null_response_field_parses_as_a_generated_stub_would_write_it() {
        let json = r#"{
            "operationId": "getCarInfo",
            "_generated": true,
            "_todo": "fill me in",
            "sources": {},
            "response": { "maker": null, "year": null }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).expect("a fresh frogs-generate stub with null response fields must parse");
        assert!(endpoint.generated);

        let ResponseShape::Fields(response) = &endpoint.response else {
            panic!("expected the ordinary flat field map");
        };
        assert!(matches!(response["maker"], ResponseField::Null));
        assert!(matches!(response["year"], ResponseField::Null));
    }

    /// The other half of the same class of bug: an operation with *no
    /// declared response schema at all* (e.g. a `200` with no `content`)
    /// makes `frogs generate` write a bare top-level `"response": null` —
    /// distinct from the per-field-null case above, and previously unfixed:
    /// `ResponseShape`'s untagged enum had no variant a bare `null` could
    /// match at all, so this exact class of fresh stub failed to parse,
    /// silently 404ing instead of even reaching the `_generated` → `501`
    /// gate. Found live while building the docs UI's endpoint-config
    /// summary (`endpoint::docs_summary`), which hit exactly this shape.
    #[test]
    fn a_bare_null_top_level_response_parses_as_a_generated_stub_with_no_response_schema_would_write_it() {
        let json = r#"{
            "operationId": "ping",
            "_generated": true,
            "_todo": "fill me in",
            "sources": {},
            "response": null
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).expect("a fresh frogs-generate stub for a no-response-schema operation must parse");
        assert!(matches!(endpoint.response, ResponseShape::Null));
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
        assert_eq!(array.items["vin"].dot_path(), "vin");
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
        assert_eq!(fields["total"].dot_path(), "sources.count.total");
    }

    #[test]
    fn allow_nested_many_and_its_three_companion_fields_parse_on_a_sql_source() {
        let json = r#"{
            "operationId": "test",
            "sources": {
                "pricing": {
                    "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "many",
                    "allowNestedMany": true, "maxConcurrency": 3, "maxRows": 100, "rowTimeoutMs": 5000,
                    "parameters": [{ "name": "vin", "from": "sources.cars[].vin" }]
                }
            },
            "response": {}
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        let SourceDef::Sql {
            allow_nested_many,
            max_concurrency,
            max_rows,
            row_timeout_ms,
            ..
        } = &endpoint.sources["pricing"]
        else {
            panic!("expected a Sql source");
        };
        assert!(*allow_nested_many);
        assert_eq!(max_concurrency.map(|n| n.get()), Some(3));
        assert_eq!(max_rows.map(|n| n.get()), Some(100));
        assert_eq!(row_timeout_ms.map(|n| n.get()), Some(5000));
    }

    #[test]
    fn allow_nested_many_and_its_three_companion_fields_parse_on_an_http_source() {
        let json = r#"{
            "operationId": "test",
            "sources": {
                "pricing": {
                    "type": "http", "request": "pricing.json",
                    "allowNestedMany": true, "maxConcurrency": 2, "maxRows": 50, "rowTimeoutMs": 15000,
                    "parameters": [{ "name": "vin", "from": "sources.cars[].vin" }]
                }
            },
            "response": {}
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        let SourceDef::Http {
            allow_nested_many,
            max_concurrency,
            max_rows,
            row_timeout_ms,
            ..
        } = &endpoint.sources["pricing"]
        else {
            panic!("expected an Http source");
        };
        assert!(*allow_nested_many);
        assert_eq!(max_concurrency.map(|n| n.get()), Some(2));
        assert_eq!(max_rows.map(|n| n.get()), Some(50));
        assert_eq!(row_timeout_ms.map(|n| n.get()), Some(15000));
    }

    #[test]
    fn allow_nested_many_defaults_to_false_and_its_companion_fields_to_none_when_omitted() {
        let json = r#"{
            "operationId": "test",
            "sources": {
                "car": { "type": "sql", "connection": "db", "script": "q.sql" }
            },
            "response": {}
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        let SourceDef::Sql {
            allow_nested_many,
            max_concurrency,
            max_rows,
            row_timeout_ms,
            ..
        } = &endpoint.sources["car"]
        else {
            panic!("expected a Sql source");
        };
        assert!(
            !*allow_nested_many,
            "allowNestedMany omitted must default to false, matching the overwhelming common case"
        );
        assert_eq!(*max_concurrency, None);
        assert_eq!(*max_rows, None);
        assert_eq!(
            *row_timeout_ms, None,
            "rowTimeoutMs omitted must parse as None — resolve::resolve_nested_many is what applies the 30s default downstream, not serde"
        );
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
