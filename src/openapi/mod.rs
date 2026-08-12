mod change_detection;
mod schema_walk;

use std::collections::HashMap;
use std::fmt;
use std::path::Path;

use serde_json::{Map, Value};

pub use change_detection::{content_hash, referenced_component_names};
pub use schema_walk::{merge_stub_response, stub_from_descriptor, walk_response_schema, SchemaWalker};

/// The HTTP methods OpenAPI's Path Item Object recognizes as operations —
/// any other key under a path (`parameters`, `summary`, ...) is ignored.
const HTTP_METHODS: &[&str] = &["get", "put", "post", "delete", "options", "head", "patch", "trace"];

/// One `in: query|path|header|cookie` parameter declared on an operation.
/// `cookie` is parsed (so it isn't silently dropped) but not surfaced in
/// the reference file yet — the doc's own reference-file examples only
/// ever show `query`/`path`/`header`.
#[derive(Debug, Clone, PartialEq)]
pub struct ParameterInfo {
    pub name: String,
    pub location: String,
}

/// One operation from `openapi.yaml`'s `paths`. `response_schema` is the
/// first `2xx` response's `application/json` schema, if any — this project
/// only tracks one response shape per operation for now (matching the
/// design doc's own examples, which always focus on the success case);
/// non-2xx responses and non-JSON bodies aren't tracked yet. Likewise,
/// `requestBody` isn't tracked — every reference file's `request.body` is
/// `null` for now, matching write support (Phase 4) not existing yet.
#[derive(Debug, Clone, PartialEq)]
pub struct Operation {
    pub path: String,
    pub method: String,
    pub operation_id: String,
    pub response_schema: Option<Value>,
    pub parameters: Vec<ParameterInfo>,
    /// Every numeric response code this operation declares in `openapi.yaml`
    /// (`responses`' own keys — `default` and pattern keys like `4XX` are
    /// skipped, since `successStatus` is validated against literal codes
    /// only, matching the design doc's own example).
    pub response_status_codes: Vec<u16>,
    /// The single security scheme name guarding this operation, if any —
    /// resolved from its own `security:` (falling back to the document's
    /// top-level default if the operation doesn't declare one at all; an
    /// explicit empty `security: []` opts out of that default rather than
    /// inheriting it, per the OpenAPI spec). Collapsed to the first scheme
    /// name of the first non-empty requirement object — OpenAPI's fuller
    /// grammar (multiple alternative requirement objects as OR, multiple
    /// scheme keys within one object as AND) is out of scope for v1,
    /// matching `EndpointFile.security`'s own single-scheme simplification.
    pub security: Option<String>,
}

impl Operation {
    /// Resolves this operation's response schema against an already-built
    /// component cache (`OpenApiDocument::resolve_components`) — Phase 1 of
    /// the design doc's two-phase generation algorithm. `None` if this
    /// operation has no JSON success-response schema to walk.
    pub fn resolve_response(&self, cache: &HashMap<String, Value>) -> Option<Value> {
        self.response_schema.as_ref().map(|schema| walk_response_schema(schema, cache))
    }

    /// A cheap fingerprint of this operation's *own* raw response schema
    /// (before resolution) — a `$ref`'s target name is part of this hash,
    /// but not that component's own content, since that's tracked
    /// separately via `referenced_components`. Empty-string hash for an
    /// operation with no response schema at all.
    pub fn response_schema_hash(&self) -> String {
        content_hash(self.response_schema.as_ref().unwrap_or(&Value::Null))
    }

    /// Every named component this operation's response schema references,
    /// directly or nested (inside `properties`/`items`/`allOf`/`oneOf`/
    /// `anyOf`) — cheap to compute (no descriptor building) so drift
    /// detection can check "does this endpoint depend on a component that
    /// changed" without first walking the whole schema.
    pub fn referenced_components(&self) -> std::collections::HashSet<String> {
        self.response_schema.as_ref().map(referenced_component_names).unwrap_or_default()
    }

    /// Checks a hand-authored endpoint file's `successStatus` (if it
    /// declares one at all — fully optional, no engine-side convention)
    /// against this operation's own declared response codes. `Ok(())` if
    /// there's nothing to check or the status matches one of them.
    pub fn validate_success_status(&self, endpoint_file: &Value) -> Result<(), String> {
        let Some(success_status) = endpoint_file.get("successStatus").and_then(Value::as_u64) else {
            return Ok(());
        };
        if self.response_status_codes.is_empty() || self.response_status_codes.contains(&(success_status as u16)) {
            return Ok(());
        }
        Err(format!(
            "{} {}: successStatus {success_status} is not among the response codes declared in openapi.yaml ({})",
            self.method.to_uppercase(),
            self.path,
            self.response_status_codes.iter().map(u16::to_string).collect::<Vec<_>>().join(", ")
        ))
    }

    fn parameter_names(&self, location: &str) -> Vec<String> {
        self.parameters.iter().filter(|p| p.location == location).map(|p| p.name.clone()).collect()
    }

    /// The reference file's `request` object: which parameter names are
    /// available at each location.
    pub fn request_sources(&self) -> Value {
        serde_json::json!({
            "query": self.parameter_names("query"),
            "path": self.parameter_names("path"),
            "header": self.parameter_names("header"),
            "body": Value::Null,
        })
    }

    /// The reference file's `availableParameterSources` — every parameter,
    /// as a dot-path, in `query`/`path`/`header` order (matching the design
    /// doc's own examples, which always list `query.*` before `path.*`
    /// before `header.*`, regardless of the spec's own parameter order).
    pub fn available_parameter_sources(&self) -> Vec<String> {
        ["query", "path", "header"]
            .iter()
            .flat_map(|location| self.parameter_names(location).into_iter().map(move |name| format!("{location}.{name}")))
            .collect()
    }
}

/// Extracts `name`/`in` from an operation's `parameters` array.
fn extract_parameters(operation: &Map<String, Value>) -> Vec<ParameterInfo> {
    let Some(parameters) = operation.get("parameters").and_then(Value::as_array) else {
        return Vec::new();
    };
    parameters
        .iter()
        .filter_map(|param| {
            let name = param.get("name")?.as_str()?;
            let location = param.get("in")?.as_str()?;
            Some(ParameterInfo {
                name: name.to_string(),
                location: location.to_string(),
            })
        })
        .collect()
}

/// Every numeric key of an operation's `responses` object — `default` and
/// pattern keys (`4XX`) are silently skipped, not treated as parse errors,
/// since they're valid OpenAPI but not something `successStatus` (a single
/// literal code) could ever match anyway.
fn declared_response_codes(operation: &Map<String, Value>) -> Vec<u16> {
    let Some(responses) = operation.get("responses").and_then(Value::as_object) else {
        return Vec::new();
    };
    responses.keys().filter_map(|status| status.parse().ok()).collect()
}

/// Resolves which security scheme (if any) guards one operation: its own
/// `security:` if it declares one at all (even an explicit empty array,
/// which per the OpenAPI spec means "no security" and deliberately opts
/// out of any document-level default rather than inheriting it), otherwise
/// the document's top-level default.
fn operation_security(operation: &Map<String, Value>, document_default: Option<&Value>) -> Option<String> {
    let security = operation.get("security").or(document_default)?;
    first_scheme_name(security)
}

/// The first scheme name of the first non-empty requirement object in a
/// `security:` array — see `Operation::security`'s doc comment for why
/// this collapses OpenAPI's fuller OR/AND grammar down to a single name.
fn first_scheme_name(security: &Value) -> Option<String> {
    security.as_array()?.iter().find_map(|requirement| requirement.as_object().and_then(|obj| obj.keys().next().cloned()))
}

/// The first `2xx` response's `application/json` schema on an operation
/// object, e.g. `paths./cars.get`. A `2xx` response with no `content` at
/// all (e.g. cars-demo's `404`, which is never a match here anyway since
/// it isn't `2xx` — but the same would apply to a bodyless `204`) is
/// skipped in favor of the next candidate, not treated as "nothing found."
fn success_response_schema(operation: &Map<String, Value>) -> Option<Value> {
    let responses = operation.get("responses")?.as_object()?;
    for (status, response) in responses {
        if !status.starts_with('2') {
            continue;
        }
        let schema =
            response.get("content").and_then(|content| content.get("application/json")).and_then(|json| json.get("schema"));
        if let Some(schema) = schema {
            return Some(schema.clone());
        }
    }
    None
}

#[derive(Debug)]
pub struct OpenApiDocument {
    pub operations: Vec<Operation>,
    /// The raw `components/schemas` object — kept generic (not pre-walked)
    /// since resolving it is a distinct step (`resolve_components`) a
    /// caller may or may not need yet.
    pub component_schemas: Map<String, Value>,
}

impl OpenApiDocument {
    /// Resolves every named component in `components/schemas` into one
    /// type descriptor each — Phase 0 of the design doc's two-phase
    /// generation algorithm. See `SchemaWalker` for how each descriptor is
    /// produced.
    pub fn resolve_components(&self) -> HashMap<String, Value> {
        SchemaWalker::new(&self.component_schemas).resolve_components()
    }
}

#[derive(Debug)]
pub enum OpenApiError {
    Io(std::io::Error),
    Parse(serde_yaml::Error),
    /// The design doc stores `operationId` inside each generated endpoint
    /// file for logging/traceability — it has to actually exist in the spec
    /// for that to be possible, so a missing one is a spec error, not
    /// something to silently paper over with a synthesized id.
    MissingOperationId { path: String, method: String },
}

impl fmt::Display for OpenApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpenApiError::Io(e) => write!(f, "failed to read openapi.yaml: {e}"),
            OpenApiError::Parse(e) => write!(f, "failed to parse openapi.yaml: {e}"),
            OpenApiError::MissingOperationId { path, method } => {
                write!(f, "{} {path} has no operationId", method.to_uppercase())
            }
        }
    }
}

impl std::error::Error for OpenApiError {}

/// Parses `openapi.yaml` and enumerates every operation under `paths`.
/// Deliberately generic (`serde_json::Value`, the same type response
/// mapping already uses) rather than a fully-typed OpenAPI model — the
/// design doc's recursive schema walk (`$ref`/`allOf`/`oneOf`/arrays/free-
/// form maps) is naturally a walk over a loosely-typed schema tree, which a
/// generic `Value` fits more directly than a rigid struct hierarchy would.
pub fn load(path: &Path) -> Result<OpenApiDocument, OpenApiError> {
    let contents = std::fs::read_to_string(path).map_err(OpenApiError::Io)?;
    let doc: Value = serde_yaml::from_str(&contents).map_err(OpenApiError::Parse)?;

    let document_security = doc.get("security");

    let mut operations = Vec::new();
    if let Some(paths) = doc.get("paths").and_then(Value::as_object) {
        for (path, item) in paths {
            let Some(item) = item.as_object() else { continue };
            for method in HTTP_METHODS {
                let Some(operation_obj) = item.get(*method).and_then(Value::as_object) else { continue };
                let operation_id =
                    operation_obj.get("operationId").and_then(Value::as_str).ok_or_else(|| {
                        OpenApiError::MissingOperationId {
                            path: path.clone(),
                            method: method.to_string(),
                        }
                    })?;
                operations.push(Operation {
                    path: path.clone(),
                    method: method.to_string(),
                    operation_id: operation_id.to_string(),
                    response_schema: success_response_schema(operation_obj),
                    parameters: extract_parameters(operation_obj),
                    response_status_codes: declared_response_codes(operation_obj),
                    security: operation_security(operation_obj, document_security),
                });
            }
        }
    }

    let component_schemas = doc
        .get("components")
        .and_then(|components| components.get("schemas"))
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    Ok(OpenApiDocument { operations, component_schemas })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumerates_a_specs_operations() {
        let dir = std::env::temp_dir().join(format!(
            "frogs-openapi-test3-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let spec_path = dir.join("openapi.yaml");
        std::fs::write(
            &spec_path,
            "openapi: 3.0.3\n\
             info: { title: Cars Demo API, version: 0.1.0 }\n\
             paths:\n\
             \x20\x20/cars:\n\
             \x20\x20\x20\x20get:\n\
             \x20\x20\x20\x20\x20\x20operationId: getCarInfo\n\
             \x20\x20\x20\x20\x20\x20parameters:\n\
             \x20\x20\x20\x20\x20\x20\x20\x20- { name: maker, in: query, required: true, schema: { type: string } }\n\
             \x20\x20\x20\x20\x20\x20\x20\x20- { name: model, in: query, required: true, schema: { type: string } }\n\
             \x20\x20\x20\x20\x20\x20responses:\n\
             \x20\x20\x20\x20\x20\x20\x20\x20'200':\n\
             \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20description: A matching car\n\
             \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20content:\n\
             \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20application/json:\n\
             \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20schema: { $ref: '#/components/schemas/CarWithPrice' }\n\
             \x20\x20\x20\x20post:\n\
             \x20\x20\x20\x20\x20\x20operationId: createCar\n\
             \x20\x20\x20\x20\x20\x20responses:\n\
             \x20\x20\x20\x20\x20\x20\x20\x20'201':\n\
             \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20description: The newly created car\n\
             \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20content:\n\
             \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20application/json:\n\
             \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20schema: { $ref: '#/components/schemas/CarWithPrice' }\n\
             \x20\x20/cars/{vin}:\n\
             \x20\x20\x20\x20get:\n\
             \x20\x20\x20\x20\x20\x20operationId: getCarByVin\n\
             \x20\x20\x20\x20\x20\x20security:\n\
             \x20\x20\x20\x20\x20\x20\x20\x20- apiKeyAuth: []\n\
             \x20\x20\x20\x20\x20\x20parameters:\n\
             \x20\x20\x20\x20\x20\x20\x20\x20- { name: vin, in: path, required: true, schema: { type: string } }\n\
             \x20\x20\x20\x20\x20\x20responses:\n\
             \x20\x20\x20\x20\x20\x20\x20\x20'200':\n\
             \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20description: The car with this VIN\n\
             \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20content:\n\
             \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20application/json:\n\
             \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20schema: { $ref: '#/components/schemas/CarWithPrice' }\n\
             \x20\x20\x20\x20\x20\x20\x20\x20'404':\n\
             \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20description: No car with this VIN\n\
             components:\n\
             \x20\x20securitySchemes:\n\
             \x20\x20\x20\x20apiKeyAuth: { type: apiKey, in: header, name: X-Api-Key }\n\
             \x20\x20schemas:\n\
             \x20\x20\x20\x20CarWithPrice:\n\
             \x20\x20\x20\x20\x20\x20type: object\n\
             \x20\x20\x20\x20\x20\x20required: [maker, model, year, vin]\n\
             \x20\x20\x20\x20\x20\x20properties:\n\
             \x20\x20\x20\x20\x20\x20\x20\x20maker: { type: string }\n\
             \x20\x20\x20\x20\x20\x20\x20\x20model: { type: string }\n\
             \x20\x20\x20\x20\x20\x20\x20\x20year: { type: integer }\n\
             \x20\x20\x20\x20\x20\x20\x20\x20vin: { type: string }\n",
        )
        .unwrap();

        let doc = load(&spec_path).expect("fixture should parse cleanly");
        let _ = std::fs::remove_dir_all(&dir);

        let car_with_price_ref = Some(serde_json::json!({ "$ref": "#/components/schemas/CarWithPrice" }));
        assert_eq!(
            doc.operations,
            vec![
                Operation {
                    path: "/cars".to_string(),
                    method: "get".to_string(),
                    operation_id: "getCarInfo".to_string(),
                    response_schema: car_with_price_ref.clone(),
                    parameters: vec![
                        ParameterInfo { name: "maker".to_string(), location: "query".to_string() },
                        ParameterInfo { name: "model".to_string(), location: "query".to_string() },
                    ],
                    response_status_codes: vec![200],
                    security: None,
                },
                Operation {
                    path: "/cars".to_string(),
                    method: "post".to_string(),
                    operation_id: "createCar".to_string(),
                    response_schema: car_with_price_ref.clone(),
                    parameters: vec![],
                    response_status_codes: vec![201],
                    security: None,
                },
                Operation {
                    path: "/cars/{vin}".to_string(),
                    method: "get".to_string(),
                    operation_id: "getCarByVin".to_string(),
                    response_schema: car_with_price_ref,
                    parameters: vec![ParameterInfo { name: "vin".to_string(), location: "path".to_string() }],
                    response_status_codes: vec![200, 404],
                    security: Some("apiKeyAuth".to_string()),
                },
            ]
        );
    }

    #[test]
    fn request_sources_and_available_parameter_sources_follow_query_path_header_order() {
        let op = Operation {
            path: "/things/{id}".to_string(),
            method: "get".to_string(),
            operation_id: "test".to_string(),
            response_schema: None,
            parameters: vec![
                ParameterInfo { name: "id".to_string(), location: "path".to_string() },
                ParameterInfo { name: "limit".to_string(), location: "query".to_string() },
                ParameterInfo { name: "Authorization".to_string(), location: "header".to_string() },
            ],
            response_status_codes: vec![200],
            security: None,
        };

        assert_eq!(
            op.request_sources(),
            serde_json::json!({ "query": ["limit"], "path": ["id"], "header": ["Authorization"], "body": null })
        );
        assert_eq!(op.available_parameter_sources(), vec!["query.limit", "path.id", "header.Authorization"]);
    }

    #[test]
    fn missing_operation_id_is_a_clear_error() {
        let dir = std::env::temp_dir().join(format!(
            "frogs-openapi-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let spec_path = dir.join("openapi.yaml");
        std::fs::write(
            &spec_path,
            "paths:\n  /ping:\n    get:\n      responses:\n        '200':\n          description: ok\n",
        )
        .unwrap();

        let err = load(&spec_path).expect_err("a path with no operationId should fail to load");
        assert!(matches!(err, OpenApiError::MissingOperationId { .. }));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn malformed_yaml_is_a_clear_parse_error() {
        let dir = std::env::temp_dir().join(format!(
            "frogs-openapi-test2-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let spec_path = dir.join("openapi.yaml");
        std::fs::write(&spec_path, "paths: [this, is, not, a, map").unwrap();

        let err = load(&spec_path).expect_err("malformed YAML should fail to parse");
        assert!(matches!(err, OpenApiError::Parse(_)));

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn op_with_codes(codes: Vec<u16>) -> Operation {
        Operation {
            path: "/cars".to_string(),
            method: "post".to_string(),
            operation_id: "createCar".to_string(),
            response_schema: None,
            parameters: Vec::new(),
            response_status_codes: codes,
            security: None,
        }
    }

    #[test]
    fn success_status_matching_a_declared_code_is_valid() {
        let op = op_with_codes(vec![201]);
        assert!(op.validate_success_status(&serde_json::json!({ "successStatus": 201 })).is_ok());
    }

    #[test]
    fn success_status_not_among_declared_codes_is_an_error() {
        let op = op_with_codes(vec![201]);
        let err = op
            .validate_success_status(&serde_json::json!({ "successStatus": 200 }))
            .expect_err("200 isn't declared for this operation");
        assert!(err.contains("200"), "error should mention the bad status: {err}");
        assert!(err.contains("201"), "error should mention what was actually declared: {err}");
    }

    #[test]
    fn no_success_status_declared_is_never_an_error() {
        let op = op_with_codes(vec![201]);
        assert!(op.validate_success_status(&serde_json::json!({ "sources": {} })).is_ok());
    }

    #[test]
    fn an_operation_with_no_security_and_no_document_default_is_public() {
        let operation = serde_json::json!({ "operationId": "test" });
        assert_eq!(operation_security(operation.as_object().unwrap(), None), None);
    }

    #[test]
    fn an_operations_own_security_scheme_is_used() {
        let operation = serde_json::json!({ "security": [{ "apiKeyAuth": [] }] });
        assert_eq!(
            operation_security(operation.as_object().unwrap(), None),
            Some("apiKeyAuth".to_string())
        );
    }

    #[test]
    fn an_operation_with_no_security_of_its_own_inherits_the_document_default() {
        let document_default = serde_json::json!([{ "bearerAuth": [] }]);
        let operation = serde_json::json!({ "operationId": "test" });
        assert_eq!(
            operation_security(operation.as_object().unwrap(), Some(&document_default)),
            Some("bearerAuth".to_string())
        );
    }

    #[test]
    fn an_operations_own_security_overrides_the_document_default() {
        let document_default = serde_json::json!([{ "bearerAuth": [] }]);
        let operation = serde_json::json!({ "security": [{ "apiKeyAuth": [] }] });
        assert_eq!(
            operation_security(operation.as_object().unwrap(), Some(&document_default)),
            Some("apiKeyAuth".to_string())
        );
    }

    #[test]
    fn an_explicit_empty_security_array_opts_out_of_the_document_default() {
        let document_default = serde_json::json!([{ "bearerAuth": [] }]);
        let operation = serde_json::json!({ "security": [] });
        assert_eq!(operation_security(operation.as_object().unwrap(), Some(&document_default)), None);
    }

    #[test]
    fn multiple_alternative_requirement_objects_collapse_to_the_first() {
        // OpenAPI's own OR semantics: either scheme would satisfy this
        // operation. v1 collapses that down to just the first alternative.
        let operation = serde_json::json!({ "security": [{ "apiKeyAuth": [] }, { "bearerAuth": [] }] });
        assert_eq!(
            operation_security(operation.as_object().unwrap(), None),
            Some("apiKeyAuth".to_string())
        );
    }

    #[test]
    fn multiple_schemes_required_together_collapse_to_the_first_key() {
        // OpenAPI's own AND semantics: both schemes are required together.
        // v1 collapses that down to just the first key of the object —
        // deterministic here because this crate enables serde_json's
        // `preserve_order` feature, so the object's key order matches the
        // order it was written in.
        let operation = serde_json::json!({ "security": [{ "apiKeyAuth": [], "bearerAuth": [] }] });
        assert_eq!(
            operation_security(operation.as_object().unwrap(), None),
            Some("apiKeyAuth".to_string())
        );
    }
}
