mod change_detection;
pub mod dir_index;
#[cfg(test)]
mod fs_os_tests;
pub mod path_rules;
mod schema_walk;

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::path::Path;

use serde_json::{Map, Value};

pub use change_detection::{content_hash, referenced_component_names};
pub use path_rules::{PortabilityPolicy, untrusted};
pub use schema_walk::{SchemaWalker, merge_stub_response, stub_from_descriptor, walk_response_schema};

/// The HTTP methods OpenAPI's Path Item Object recognizes as operations —
/// any other key under a path (`parameters`, `summary`, ...) is ignored.
pub(crate) const HTTP_METHODS: &[&str] = &["get", "put", "post", "delete", "options", "head", "patch", "trace"];

/// One `in: query|path|header|cookie` parameter declared on an operation.
/// `cookie` is parsed (so it isn't silently dropped) but not surfaced in
/// the reference file yet — the doc's own reference-file examples only
/// ever show `query`/`path`/`header`.
#[derive(Debug, Clone, PartialEq)]
pub struct ParameterInfo {
    pub name: String,
    pub location: String,
    /// `required: true` in the spec — request validation's own concern
    /// (`endpoint::request_validation`), unused by the reference-file/
    /// generation machinery this struct originally existed for.
    pub required: bool,
    /// The raw OpenAPI `schema.type` string (`"string"`/`"integer"`/...),
    /// if the parameter declares one at all. Only meaningful for request
    /// validation's type check — a bare scalar, since path/query/header
    /// values are always plain strings on the wire; array/object-typed
    /// parameters (rare, and dependent on `style`/`explode` serialization
    /// this project doesn't otherwise model) get presence-checked only,
    /// never type-checked.
    pub schema_type: Option<String>,
}

/// A `requestBody`'s `application/json` schema, if the operation declares
/// one — `required` per the spec's own `requestBody.required` (default
/// `false` when omitted, same as the spec itself).
#[derive(Debug, Clone, PartialEq)]
pub struct RequestBodySchema {
    pub required: bool,
    pub schema: Value,
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
    /// This operation's `requestBody`'s `application/json` schema, if it
    /// declares one — request validation's own concern, resolved (`$ref`s
    /// included) against `OpenApiDocument::component_schemas` at validation
    /// time, not eagerly here.
    pub request_body: Option<RequestBodySchema>,
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

/// Extracts `name`/`in`/`required`/`schema.type` from an operation's
/// `parameters` array.
fn extract_parameters(operation: &Map<String, Value>) -> Vec<ParameterInfo> {
    let Some(parameters) = operation.get("parameters").and_then(Value::as_array) else {
        return Vec::new();
    };
    parameters
        .iter()
        .filter_map(|param| {
            let name = param.get("name")?.as_str()?;
            let location = param.get("in")?.as_str()?;
            let required = param.get("required").and_then(Value::as_bool).unwrap_or(false);
            let schema_type = param.get("schema").and_then(|s| s.get("type")).and_then(Value::as_str).map(str::to_string);
            Some(ParameterInfo {
                name: name.to_string(),
                location: location.to_string(),
                required,
                schema_type,
            })
        })
        .collect()
}

/// This operation's `requestBody.content.application/json.schema`, if it
/// declares one at all — `None` for an operation with no `requestBody`, or
/// one that declares a body but not a JSON content type (nothing else is
/// validated).
fn extract_request_body(operation: &Map<String, Value>) -> Option<RequestBodySchema> {
    let request_body = operation.get("requestBody")?.as_object()?;
    let schema = request_body.get("content")?.get("application/json")?.get("schema")?.clone();
    let required = request_body.get("required").and_then(Value::as_bool).unwrap_or(false);
    Some(RequestBodySchema { required, schema })
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
    security
        .as_array()?
        .iter()
        .find_map(|requirement| requirement.as_object().and_then(|obj| obj.keys().next().cloned()))
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
        let schema = response
            .get("content")
            .and_then(|content| content.get("application/json"))
            .and_then(|json| json.get("schema"));
        if let Some(schema) = schema {
            return Some(schema.clone());
        }
    }
    None
}

/// What the top-level `openapi:` field says, classified without regexes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SpecVersion {
    V3_0,
    V3_1,
    V3_2,
    /// A well-formed 3.x/4.x version newer than the newest one frogs knows.
    Newer(String),
    Unrecognized(String),
    #[default]
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Warning,
    /// Part of the spec was dropped (or would have been unsafe to use).
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueKind {
    VersionMissing,
    VersionUnrecognized,
    Swagger2,
    VersionNewer,
    /// Interim: `query`/`additionalOperations` are loaded but not served yet.
    NotServed,
    UnsafePath,
    WindowsPortability,
    CaseOnlyPathCollision,
    TrailingSlashNormalised,
    TrailingSlashCollision,
    UnsafeComponentName,
}

impl IssueKind {
    /// Whether `strictOpenApi: true` turns this kind into a refusal.
    pub fn is_strict_error(&self) -> bool {
        !matches!(self, IssueKind::NotServed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadIssue {
    pub kind: IssueKind,
    pub severity: Severity,
    pub message: String,
}

impl LoadIssue {
    fn new(kind: IssueKind, severity: Severity, message: String) -> Self {
        LoadIssue { kind, severity, message }
    }
}

#[derive(Debug, Default)]
pub struct OpenApiDocument {
    pub operations: Vec<Operation>,
    /// The raw `components/schemas` object — kept generic (not pre-walked)
    /// since resolving it is a distinct step (`resolve_components`) a
    /// caller may or may not need yet.
    pub component_schemas: Map<String, Value>,
    /// `components/securitySchemes/<name>/type` for every declared scheme
    /// (`apiKey`, `http`, `mutualTLS`, ...) — how `generate` and `validate`
    /// recognize a `mutualTLS` scheme, which OpenAPI 3.1 defines but 3.0
    /// documents may still use as a free-form name.
    pub security_scheme_types: HashMap<String, String>,
    #[allow(dead_code)] // Later milestones branch on it; exercised by tests.
    pub spec_version: SpecVersion,
    /// Everything notable the loader found, in spec order.
    pub issues: Vec<LoadIssue>,
    /// Normalised paths skipped because they differ from another only by
    /// letter case.
    pub ambiguous: BTreeSet<String>,
    /// Those paths' operations — kept out of `operations` so generate never
    /// writes for them, but request validation still finds them.
    pub ambiguous_operations: Vec<Operation>,
    /// Raw `paths` keys skipped as unsafe. Only ever compared as strings,
    /// never used to build a filesystem path.
    pub skipped_paths: BTreeSet<String>,
    /// `components/schemas` names that can't safely be a cache file name.
    pub unwritable_components: BTreeSet<String>,
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
    MissingOperationId {
        path: String,
        method: String,
    },
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
    load_with_policy(path, PortabilityPolicy::for_host())
}

fn classify_version(raw: &str) -> SpecVersion {
    let mut parts = raw.splitn(3, '.');
    let (Some(major), Some(minor)) = (parts.next(), parts.next()) else {
        return SpecVersion::Unrecognized(raw.to_string());
    };
    let plain_number = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && (s == "0" || !s.starts_with('0'));
    if !plain_number(major) || !plain_number(minor) {
        return SpecVersion::Unrecognized(raw.to_string());
    }
    let (Ok(major_n), Ok(minor_n)) = (major.parse::<u64>(), minor.parse::<u64>()) else {
        return SpecVersion::Unrecognized(raw.to_string());
    };
    match (major_n, minor_n) {
        (3, 0) => SpecVersion::V3_0,
        (3, 1) => SpecVersion::V3_1,
        (3, 2) => SpecVersion::V3_2,
        (3, _) => SpecVersion::Newer(raw.to_string()),
        (n, _) if n >= 4 => SpecVersion::Newer(raw.to_string()),
        _ => SpecVersion::Unrecognized(raw.to_string()),
    }
}

fn detect_version(doc: &Value, issues: &mut Vec<LoadIssue>) -> SpecVersion {
    let has_swagger = doc.get("swagger").is_some();
    if has_swagger {
        issues.push(LoadIssue::new(
            IssueKind::Swagger2,
            Severity::Warning,
            "Swagger 2.0 is not supported; generation will be incomplete".to_string(),
        ));
    }
    let version = match doc.get("openapi") {
        None => {
            if !has_swagger {
                issues.push(LoadIssue::new(
                    IssueKind::VersionMissing,
                    Severity::Warning,
                    "openapi.yaml has no `openapi:` version field; treating it as 3.x".to_string(),
                ));
            }
            return SpecVersion::Missing;
        }
        Some(Value::String(s)) => classify_version(s),
        Some(Value::Number(n)) => classify_version(&n.to_string()),
        Some(other) => SpecVersion::Unrecognized(other.to_string()),
    };
    match &version {
        SpecVersion::Newer(v) => issues.push(LoadIssue::new(
            IssueKind::VersionNewer,
            Severity::Warning,
            format!(
                "openapi {} is newer than the newest version frogs knows (3.2); fields frogs does not know are ignored",
                untrusted(v)
            ),
        )),
        SpecVersion::Unrecognized(v) => issues.push(LoadIssue::new(
            IssueKind::VersionUnrecognized,
            Severity::Warning,
            format!("openapi version {} is not recognized; treating it as 3.x", untrusted(v)),
        )),
        _ => {}
    }
    version
}

fn parse_operations(path: &str, item: &Map<String, Value>, document_security: Option<&Value>) -> Result<Vec<Operation>, OpenApiError> {
    let mut operations = Vec::new();
    for method in HTTP_METHODS {
        let Some(operation_obj) = item.get(*method).and_then(Value::as_object) else {
            continue;
        };
        let operation_id = operation_obj
            .get("operationId")
            .and_then(Value::as_str)
            .ok_or_else(|| OpenApiError::MissingOperationId {
                path: path.to_string(),
                method: method.to_string(),
            })?;
        operations.push(Operation {
            path: path.to_string(),
            method: method.to_string(),
            operation_id: operation_id.to_string(),
            response_schema: success_response_schema(operation_obj),
            parameters: extract_parameters(operation_obj),
            request_body: extract_request_body(operation_obj),
            response_status_codes: declared_response_codes(operation_obj),
            security: operation_security(operation_obj, document_security),
        });
    }
    Ok(operations)
}

fn not_served_issue(method: &str, path: &str, operation: &Value) -> LoadIssue {
    let operation_id = operation
        .get("operationId")
        .and_then(Value::as_str)
        .map(untrusted)
        .unwrap_or_else(|| "<none>".to_string());
    LoadIssue::new(
        IssueKind::NotServed,
        Severity::Warning,
        format!(
            "{} {} (operationId {operation_id}) is not served by this version of frogs",
            untrusted(method),
            untrusted(path)
        ),
    )
}

fn not_served_issues(path: &str, item: &Map<String, Value>, issues: &mut Vec<LoadIssue>) {
    if let Some(query) = item.get("query") {
        issues.push(not_served_issue("QUERY", path, query));
    }
    match item.get("additionalOperations") {
        None => {}
        Some(Value::Object(additional)) => {
            for (name, operation) in additional {
                issues.push(not_served_issue(name, path, operation));
            }
        }
        Some(_) => issues.push(LoadIssue::new(
            IssueKind::NotServed,
            Severity::Warning,
            format!("additionalOperations on {} is not a map and is not served by this version of frogs", untrusted(path)),
        )),
    }
}

pub(crate) fn load_with_policy(path: &Path, policy: PortabilityPolicy) -> Result<OpenApiDocument, OpenApiError> {
    let contents = std::fs::read_to_string(path).map_err(OpenApiError::Io)?;
    let doc: Value = serde_yaml::from_str(&contents).map_err(OpenApiError::Parse)?;

    let mut issues = Vec::new();
    let spec_version = detect_version(&doc, &mut issues);
    let document_security = doc.get("security");

    let mut skipped_paths = BTreeSet::new();
    let mut accepted: Vec<(String, &Map<String, Value>)> = Vec::new();
    if let Some(paths) = doc.get("paths").and_then(Value::as_object) {
        let mut checked = Vec::new();
        for (raw, item) in paths {
            match path_rules::validate_path(raw, policy) {
                Ok(check) => checked.push((raw, item, check)),
                Err((kind, message)) => {
                    issues.push(LoadIssue::new(kind, Severity::Error, message));
                    skipped_paths.insert(raw.clone());
                }
            }
        }

        let canonical: BTreeSet<&str> = checked
            .iter()
            .filter(|(raw, _, check)| raw.as_str() == check.normalized)
            .map(|(raw, _, _)| raw.as_str())
            .collect();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for (raw, item, check) in checked {
            if raw.as_str() != check.normalized && (canonical.contains(check.normalized.as_str()) || seen.contains(&check.normalized)) {
                issues.push(LoadIssue::new(
                    IssueKind::TrailingSlashCollision,
                    Severity::Error,
                    format!(
                        "path '{}' normalises to '{}', which another path already provides — skipped",
                        untrusted(raw),
                        untrusted(&check.normalized)
                    ),
                ));
                skipped_paths.insert(raw.clone());
                continue;
            }
            for (kind, severity, message) in check.issues {
                issues.push(LoadIssue::new(kind, severity, message));
            }
            seen.insert(check.normalized.clone());
            let Some(item) = item.as_object() else { continue };
            accepted.push((check.normalized, item));
        }
    }

    let mut groups: Vec<(String, Vec<usize>)> = Vec::new();
    for (i, (normalized, _)) in accepted.iter().enumerate() {
        let folded = dir_index::fold(normalized);
        match groups.iter_mut().find(|(key, _)| *key == folded) {
            Some((_, members)) => members.push(i),
            None => groups.push((folded, vec![i])),
        }
    }
    let mut ambiguous = BTreeSet::new();
    let mut ambiguous_indexes = BTreeSet::new();
    for (_, members) in &groups {
        if members.len() < 2 {
            continue;
        }
        let names: Vec<String> = members.iter().map(|&i| format!("'{}'", untrusted(&accepted[i].0))).collect();
        issues.push(LoadIssue::new(
            IssueKind::CaseOnlyPathCollision,
            Severity::Error,
            format!(
                "paths differ only by letter case and would share one folder on a case-insensitive filesystem: {} — all skipped",
                names.join(", ")
            ),
        ));
        for &i in members {
            ambiguous.insert(accepted[i].0.clone());
            ambiguous_indexes.insert(i);
        }
    }

    let mut operations = Vec::new();
    let mut ambiguous_operations = Vec::new();
    for (i, (normalized, item)) in accepted.iter().enumerate() {
        let parsed = parse_operations(normalized, item, document_security)?;
        not_served_issues(normalized, item, &mut issues);
        if ambiguous_indexes.contains(&i) {
            ambiguous_operations.extend(parsed);
        } else {
            operations.extend(parsed);
        }
    }

    let component_schemas = doc
        .get("components")
        .and_then(|components| components.get("schemas"))
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    let mut unwritable_components = BTreeSet::new();
    for name in component_schemas.keys() {
        match path_rules::validate_file_name(&format!("{name}.json"), policy) {
            Ok(rule_issues) => {
                for (kind, severity, message) in rule_issues {
                    issues.push(LoadIssue::new(kind, severity, message));
                }
            }
            Err((kind, message)) => {
                issues.push(LoadIssue::new(kind, Severity::Error, message));
                unwritable_components.insert(name.clone());
            }
        }
    }

    let security_scheme_types = doc
        .get("components")
        .and_then(|components| components.get("securitySchemes"))
        .and_then(Value::as_object)
        .map(|schemes| {
            schemes
                .iter()
                .filter_map(|(name, scheme)| Some((name.clone(), scheme.get("type")?.as_str()?.to_string())))
                .collect()
        })
        .unwrap_or_default();

    Ok(OpenApiDocument {
        operations,
        component_schemas,
        security_scheme_types,
        spec_version,
        issues,
        ambiguous,
        ambiguous_operations,
        skipped_paths,
        unwritable_components,
    })
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
                        ParameterInfo {
                            name: "maker".to_string(),
                            location: "query".to_string(),
                            required: true,
                            schema_type: Some("string".to_string()),
                        },
                        ParameterInfo {
                            name: "model".to_string(),
                            location: "query".to_string(),
                            required: true,
                            schema_type: Some("string".to_string()),
                        },
                    ],
                    request_body: None,
                    response_status_codes: vec![200],
                    security: None,
                },
                Operation {
                    path: "/cars".to_string(),
                    method: "post".to_string(),
                    operation_id: "createCar".to_string(),
                    response_schema: car_with_price_ref.clone(),
                    parameters: vec![],
                    request_body: None,
                    response_status_codes: vec![201],
                    security: None,
                },
                Operation {
                    path: "/cars/{vin}".to_string(),
                    method: "get".to_string(),
                    operation_id: "getCarByVin".to_string(),
                    response_schema: car_with_price_ref,
                    parameters: vec![ParameterInfo {
                        name: "vin".to_string(),
                        location: "path".to_string(),
                        required: true,
                        schema_type: Some("string".to_string()),
                    }],
                    request_body: None,
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
                ParameterInfo {
                    name: "id".to_string(),
                    location: "path".to_string(),
                    required: true,
                    schema_type: Some("string".to_string()),
                },
                ParameterInfo {
                    name: "limit".to_string(),
                    location: "query".to_string(),
                    required: false,
                    schema_type: Some("integer".to_string()),
                },
                ParameterInfo {
                    name: "Authorization".to_string(),
                    location: "header".to_string(),
                    required: true,
                    schema_type: Some("string".to_string()),
                },
            ],
            request_body: None,
            response_status_codes: vec![200],
            security: None,
        };

        assert_eq!(
            op.request_sources(),
            serde_json::json!({ "query": ["limit"], "path": ["id"], "header": ["Authorization"], "body": null })
        );
        assert_eq!(op.available_parameter_sources(), vec!["query.limit", "path.id", "header.Authorization"]);
    }

    /// `extract_parameters`/`extract_request_body` — the raw `required`/
    /// `schema.type`/`requestBody` data request validation needs, which
    /// used to be parsed and immediately discarded.
    #[test]
    fn extracts_required_and_schema_type_for_parameters() {
        let operation = serde_json::json!({
            "parameters": [
                { "name": "id", "in": "path", "required": true, "schema": { "type": "integer" } },
                { "name": "limit", "in": "query", "schema": { "type": "integer" } },
                { "name": "note", "in": "query" }
            ]
        });
        let params = extract_parameters(operation.as_object().unwrap());
        assert_eq!(
            params,
            vec![
                ParameterInfo {
                    name: "id".to_string(),
                    location: "path".to_string(),
                    required: true,
                    schema_type: Some("integer".to_string()),
                },
                ParameterInfo {
                    name: "limit".to_string(),
                    location: "query".to_string(),
                    required: false,
                    schema_type: Some("integer".to_string()),
                },
                ParameterInfo {
                    name: "note".to_string(),
                    location: "query".to_string(),
                    required: false,
                    schema_type: None,
                },
            ]
        );
    }

    #[test]
    fn extracts_the_json_request_body_schema() {
        let operation = serde_json::json!({
            "requestBody": {
                "required": true,
                "content": { "application/json": { "schema": { "type": "object", "required": ["maker"] } } }
            }
        });
        let body = extract_request_body(operation.as_object().unwrap()).expect("a declared JSON request body should be found");
        assert!(body.required);
        assert_eq!(body.schema, serde_json::json!({ "type": "object", "required": ["maker"] }));
    }

    #[test]
    fn a_request_body_omitting_required_defaults_to_false() {
        let operation = serde_json::json!({
            "requestBody": { "content": { "application/json": { "schema": { "type": "object" } } } }
        });
        let body = extract_request_body(operation.as_object().unwrap()).unwrap();
        assert!(!body.required);
    }

    #[test]
    fn no_request_body_at_all_is_none() {
        let operation = serde_json::json!({ "operationId": "test" });
        assert_eq!(extract_request_body(operation.as_object().unwrap()), None);
    }

    #[test]
    fn a_request_body_with_no_json_content_is_none() {
        let operation = serde_json::json!({
            "requestBody": { "content": { "text/plain": { "schema": { "type": "string" } } } }
        });
        assert_eq!(extract_request_body(operation.as_object().unwrap()), None);
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
            request_body: None,
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
        assert_eq!(operation_security(operation.as_object().unwrap(), None), Some("apiKeyAuth".to_string()));
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
        assert_eq!(operation_security(operation.as_object().unwrap(), None), Some("apiKeyAuth".to_string()));
    }

    #[test]
    fn multiple_schemes_required_together_collapse_to_the_first_key() {
        // OpenAPI's own AND semantics: both schemes are required together.
        // v1 collapses that down to just the first key of the object —
        // deterministic here because this crate enables serde_json's
        // `preserve_order` feature, so the object's key order matches the
        // order it was written in.
        let operation = serde_json::json!({ "security": [{ "apiKeyAuth": [], "bearerAuth": [] }] });
        assert_eq!(operation_security(operation.as_object().unwrap(), None), Some("apiKeyAuth".to_string()));
    }
}

#[cfg(test)]
mod load_hardening_tests {
    use super::*;

    fn tempdir() -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "frogs-openapi-m1-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn load_yaml_with(yaml: &str, policy: PortabilityPolicy) -> Result<OpenApiDocument, OpenApiError> {
        let dir = tempdir();
        let path = dir.join("openapi.yaml");
        std::fs::write(&path, yaml).unwrap();
        let result = load_with_policy(&path, policy);
        let _ = std::fs::remove_dir_all(&dir);
        result
    }

    fn load_yaml(yaml: &str) -> OpenApiDocument {
        load_yaml_with(yaml, PortabilityPolicy::Warn).unwrap()
    }

    /// A spec with the given version line (`None` omits it) and one valid
    /// `/ping` operation.
    fn spec_with_version(version_line: Option<&str>) -> String {
        let mut yaml = String::new();
        if let Some(line) = version_line {
            yaml.push_str(line);
            yaml.push('\n');
        }
        yaml.push_str("info: { title: t, version: 1 }\npaths:\n  /ping:\n    get:\n      operationId: ping\n      responses:\n        '200': { description: ok }\n");
        yaml
    }

    fn spec_with_paths(paths: &[&str]) -> String {
        let mut yaml = "openapi: 3.1.0\ninfo: { title: t, version: 1 }\npaths:\n".to_string();
        for (i, p) in paths.iter().enumerate() {
            yaml.push_str(&format!("  '{p}':\n    get:\n      operationId: op{i}\n      responses:\n        '200': {{ description: ok }}\n"));
        }
        yaml
    }

    fn kinds(doc: &OpenApiDocument) -> Vec<IssueKind> {
        doc.issues.iter().map(|i| i.kind).collect()
    }

    #[test]
    fn every_openapi_version_string_is_classified_as_documented() {
        let cases: &[(&str, SpecVersion)] = &[
            ("openapi: 3.0.0", SpecVersion::V3_0),
            ("openapi: 3.0.3", SpecVersion::V3_0),
            ("openapi: 3.0", SpecVersion::V3_0),
            ("openapi: 3.1", SpecVersion::V3_1),
            ("openapi: 3.1.0", SpecVersion::V3_1),
            ("openapi: 3.1.0-rc1", SpecVersion::V3_1),
            ("openapi: 3.2.0", SpecVersion::V3_2),
            ("openapi: 3.3.0", SpecVersion::Newer("3.3.0".into())),
            ("openapi: 4.0", SpecVersion::Newer("4.0".into())),
            ("openapi: '3.10'", SpecVersion::Newer("3.10".into())),
            ("openapi: '3'", SpecVersion::Unrecognized("3".into())),
            ("openapi: '3.01'", SpecVersion::Unrecognized("3.01".into())),
            ("openapi: '2.0'", SpecVersion::Unrecognized("2.0".into())),
            ("openapi: abc", SpecVersion::Unrecognized("abc".into())),
            ("openapi: ''", SpecVersion::Unrecognized("".into())),
            ("openapi: true", SpecVersion::Unrecognized("true".into())),
        ];
        for (line, expected) in cases {
            let doc = load_yaml(&spec_with_version(Some(line)));
            assert_eq!(&doc.spec_version, expected, "{line}");
        }
    }

    #[test]
    fn known_versions_raise_no_issue_and_a_missing_version_raises_exactly_one_warning() {
        for line in ["openapi: 3.0.3", "openapi: 3.1.0", "openapi: 3.2.0"] {
            assert!(load_yaml(&spec_with_version(Some(line))).issues.is_empty(), "{line}");
        }
        let doc = load_yaml(&spec_with_version(None));
        assert_eq!(doc.spec_version, SpecVersion::Missing);
        assert_eq!(kinds(&doc), vec![IssueKind::VersionMissing]);
        assert_eq!(doc.issues[0].severity, Severity::Warning);
        assert_eq!(doc.operations.len(), 1, "a missing version still loads the spec");
    }

    #[test]
    fn newer_and_unrecognized_versions_warn_but_still_load_their_operations() {
        let newer = load_yaml(&spec_with_version(Some("openapi: 3.3.0")));
        assert_eq!(kinds(&newer), vec![IssueKind::VersionNewer]);
        assert_eq!(newer.operations.len(), 1);
        let weird = load_yaml(&spec_with_version(Some("openapi: abc")));
        assert_eq!(kinds(&weird), vec![IssueKind::VersionUnrecognized]);
        assert_eq!(weird.operations.len(), 1);
        assert!(weird.issues.iter().all(|i| i.severity == Severity::Warning));
    }

    #[test]
    fn a_swagger_2_document_gets_one_swagger_issue_and_no_missing_version_issue() {
        let doc = load_yaml(&spec_with_version(Some("swagger: '2.0'")));
        assert_eq!(kinds(&doc), vec![IssueKind::Swagger2]);
        assert_eq!(doc.spec_version, SpecVersion::Missing);
    }

    #[test]
    fn the_version_issue_message_escapes_hostile_version_text() {
        let doc = load_yaml(&spec_with_version(Some("openapi: \"x\\e[2Jy\"")));
        assert_eq!(kinds(&doc), vec![IssueKind::VersionUnrecognized]);
        assert!(!doc.issues[0].message.chars().any(char::is_control));
    }

    #[test]
    fn strict_error_classification_covers_everything_except_not_served() {
        assert!(!IssueKind::NotServed.is_strict_error());
        for kind in [
            IssueKind::VersionMissing,
            IssueKind::VersionUnrecognized,
            IssueKind::Swagger2,
            IssueKind::VersionNewer,
            IssueKind::UnsafePath,
            IssueKind::WindowsPortability,
            IssueKind::CaseOnlyPathCollision,
            IssueKind::TrailingSlashNormalised,
            IssueKind::TrailingSlashCollision,
            IssueKind::UnsafeComponentName,
        ] {
            assert!(kind.is_strict_error(), "{kind:?}");
        }
    }

    const TWIN_PATHS_HEAD: &str = "paths:
  /cars:
    get:
      operationId: listCars
      parameters:
        - { name: q, in: query, schema: { type: string } }
";
    const TWIN_PATHS_TAIL: &str = "      responses:
        '200':
          description: ok
          content:
            application/json:
              schema: { $ref: '#/components/schemas/Car' }
";

    #[test]
    fn a_3_2_spec_with_3_2_only_constructs_loads_like_its_3_1_twin_with_no_issues() {
        let v32 = format!(
            "openapi: 3.2.0
info: {{ title: t, version: 1, summary: s }}
{TWIN_PATHS_HEAD}        - {{ name: raw, in: querystring, content: {{ application/x-www-form-urlencoded: {{ schema: {{ type: object }} }} }} }}
{TWIN_PATHS_TAIL}components:
  schemas:
    Car:
      type: object
      discriminator: {{ propertyName: kind, defaultMapping: Car }}
      xml: {{ nodeType: element }}
      properties: {{ kind: {{ type: string }} }}
"
        );
        let v31 = format!("openapi: 3.1.0
info: {{ title: t, version: 1 }}
{TWIN_PATHS_HEAD}{TWIN_PATHS_TAIL}components:
  schemas:
    Car:
      type: object
      properties: {{ kind: {{ type: string }} }}
");
        let a = load_yaml(&v32);
        let b = load_yaml(&v31);
        assert!(a.issues.is_empty(), "{:?}", a.issues);
        assert!(b.issues.is_empty(), "{:?}", b.issues);
        assert_eq!(a.operations.len(), b.operations.len());
        assert_eq!(a.operations[0].response_schema, b.operations[0].response_schema);
        let served = |doc: &OpenApiDocument| -> Vec<String> {
            doc.operations[0]
                .parameters
                .iter()
                .filter(|p| matches!(p.location.as_str(), "query" | "path" | "header"))
                .map(|p| p.name.clone())
                .collect()
        };
        assert_eq!(served(&a), served(&b));
        assert!(a.operations[0].parameters.iter().any(|p| p.location == "querystring"), "querystring params are still collected");
        assert_eq!(a.operations[0].response_schema_hash(), b.operations[0].response_schema_hash());
    }

    #[test]
    fn query_and_additional_operations_are_loaded_as_not_served_warnings_only() {
        let yaml = "openapi: 3.2.0\ninfo: { title: t, version: 1 }\npaths:\n  /search:\n    get:\n      operationId: s\n      responses: { '200': { description: ok } }\n    query:\n      operationId: q\n      responses: { '200': { description: ok } }\n    additionalOperations:\n      PURGE:\n        operationId: purge\n        responses: { '200': { description: ok } }\n      LINK:\n        responses: { '200': { description: ok } }\n";
        let doc = load_yaml(yaml);
        assert_eq!(doc.operations.len(), 1, "only the get is a served operation");
        let not_served: Vec<&LoadIssue> = doc.issues.iter().filter(|i| i.kind == IssueKind::NotServed).collect();
        assert_eq!(not_served.len(), 3, "{:?}", doc.issues);
        assert!(not_served.iter().all(|i| i.severity == Severity::Warning));
        assert!(not_served.iter().any(|i| i.message.starts_with("QUERY /search (operationId q)")));
        assert!(not_served.iter().any(|i| i.message.starts_with("PURGE /search (operationId purge)")));
        assert!(not_served.iter().any(|i| i.message.starts_with("LINK /search (operationId <none>)")));
        assert_eq!(doc.issues.len(), 3);
    }

    #[test]
    fn a_non_map_additional_operations_value_is_one_generic_not_served_warning() {
        let yaml = "openapi: 3.2.0\ninfo: { title: t, version: 1 }\npaths:\n  /x:\n    additionalOperations: [1, 2]\n    get:\n      operationId: x\n      responses: { '200': { description: ok } }\n";
        let doc = load_yaml(yaml);
        assert_eq!(kinds(&doc), vec![IssueKind::NotServed]);
    }

    #[test]
    fn paths_differing_only_by_case_are_all_skipped_into_the_ambiguous_set() {
        let doc = load_yaml(&spec_with_paths(&["/Cars", "/cars", "/other"]));
        assert_eq!(doc.operations.iter().map(|o| o.path.as_str()).collect::<Vec<_>>(), vec!["/other"]);
        assert_eq!(doc.ambiguous.iter().cloned().collect::<Vec<_>>(), vec!["/Cars".to_string(), "/cars".to_string()]);
        let mut ambiguous_paths: Vec<&str> = doc.ambiguous_operations.iter().map(|o| o.path.as_str()).collect();
        ambiguous_paths.sort();
        assert_eq!(ambiguous_paths, vec!["/Cars", "/cars"]);
        let collisions: Vec<&LoadIssue> = doc.issues.iter().filter(|i| i.kind == IssueKind::CaseOnlyPathCollision).collect();
        assert_eq!(collisions.len(), 1);
        assert_eq!(collisions[0].severity, Severity::Error);
        assert!(collisions[0].message.contains("/Cars") && collisions[0].message.contains("/cars"));
    }

    #[test]
    fn a_three_way_case_collision_skips_all_three_with_one_issue() {
        let doc = load_yaml(&spec_with_paths(&["/cars", "/Cars", "/CARS"]));
        assert!(doc.operations.is_empty());
        assert_eq!(doc.ambiguous.len(), 3);
        assert_eq!(doc.ambiguous_operations.len(), 3);
        assert_eq!(kinds(&doc), vec![IssueKind::CaseOnlyPathCollision]);
    }

    #[test]
    fn sharp_s_and_double_s_paths_collide_even_though_they_are_not_ascii_case_variants() {
        let doc = load_yaml(&spec_with_paths(&["/Straße", "/STRASSE"]));
        assert_eq!(doc.ambiguous.len(), 2);
        assert!(doc.operations.is_empty());
    }

    #[test]
    fn a_trailing_slash_duplicate_is_skipped_and_the_canonical_form_wins_in_either_spec_order() {
        for order in [["/cars", "/cars/"], ["/cars/", "/cars"]] {
            let doc = load_yaml(&spec_with_paths(&order));
            assert_eq!(doc.operations.len(), 1, "{order:?}");
            assert_eq!(doc.operations[0].path, "/cars");
            assert!(doc.skipped_paths.contains("/cars/"));
            let collisions = doc.issues.iter().filter(|i| i.kind == IssueKind::TrailingSlashCollision).count();
            assert_eq!(collisions, 1, "{order:?}");
            assert!(doc.issues.iter().filter(|i| i.kind == IssueKind::TrailingSlashCollision).all(|i| i.severity == Severity::Error));
            assert!(doc.ambiguous.is_empty());
        }
    }

    #[test]
    fn a_lone_trailing_slash_path_is_normalised_to_its_canonical_form_with_a_warning() {
        let doc = load_yaml(&spec_with_paths(&["/cars/"]));
        assert_eq!(doc.operations.len(), 1);
        assert_eq!(doc.operations[0].path, "/cars");
        assert_eq!(kinds(&doc), vec![IssueKind::TrailingSlashNormalised]);
        assert_eq!(doc.issues[0].severity, Severity::Warning);
    }

    #[test]
    fn two_non_canonical_forms_of_one_path_keep_the_first_in_spec_order() {
        let doc = load_yaml(&spec_with_paths(&["cars/", "cars"]));
        // "cars/" and "cars" both normalise to "/cars"; neither is canonical.
        assert_eq!(doc.operations.len(), 1);
        assert_eq!(doc.operations[0].path, "/cars");
        assert!(doc.skipped_paths.contains("cars"));
        assert!(!doc.skipped_paths.contains("cars/"));
    }

    #[test]
    fn unsafe_paths_are_skipped_with_error_issues_and_never_become_operations() {
        let doc = load_yaml(&spec_with_paths(&["/ok", "/a/../../escape", "/x/_backups", "/a//b"]));
        assert_eq!(doc.operations.iter().map(|o| o.path.as_str()).collect::<Vec<_>>(), vec!["/ok"]);
        assert_eq!(doc.skipped_paths.len(), 3);
        assert_eq!(doc.issues.iter().filter(|i| i.kind == IssueKind::UnsafePath && i.severity == Severity::Error).count(), 3);
    }

    #[test]
    fn a_skipped_path_item_without_an_operation_id_does_not_fail_the_load() {
        let yaml = "openapi: 3.1.0\ninfo: { title: t, version: 1 }\npaths:\n  /a/../b:\n    get:\n      responses: { '200': { description: ok } }\n  /fine:\n    get:\n      operationId: fine\n      responses: { '200': { description: ok } }\n";
        let doc = load_yaml(yaml);
        assert_eq!(doc.operations.len(), 1);
        assert_eq!(doc.skipped_paths.len(), 1);
    }

    #[test]
    fn a_missing_operation_id_in_a_kept_path_is_still_a_load_error() {
        let yaml = "openapi: 3.1.0\ninfo: { title: t, version: 1 }\npaths:\n  /fine:\n    get:\n      responses: { '200': { description: ok } }\n";
        assert!(matches!(
            load_yaml_with(yaml, PortabilityPolicy::Warn),
            Err(OpenApiError::MissingOperationId { .. })
        ));
    }

    #[test]
    fn a_drive_letter_path_is_skipped_under_skip_and_kept_with_a_warning_under_warn() {
        let yaml = spec_with_paths(&["/C:/x"]);
        let skip = load_yaml_with(&yaml, PortabilityPolicy::Skip).unwrap();
        assert!(skip.operations.is_empty());
        assert!(skip.issues.iter().any(|i| i.kind == IssueKind::WindowsPortability && i.severity == Severity::Error));
        let warn = load_yaml_with(&yaml, PortabilityPolicy::Warn).unwrap();
        assert_eq!(warn.operations.len(), 1);
        assert!(warn.issues.iter().any(|i| i.kind == IssueKind::WindowsPortability && i.severity == Severity::Warning));
    }

    #[test]
    fn an_unsafe_component_name_stays_resolvable_but_is_marked_unwritable() {
        let yaml = "openapi: 3.1.0\ninfo: { title: t, version: 1 }\npaths: {}\ncomponents:\n  schemas:\n    '../../x':\n      type: object\n    Fine:\n      type: object\n";
        let doc = load_yaml(yaml);
        assert!(doc.component_schemas.contains_key("../../x"));
        assert!(doc.component_schemas.contains_key("Fine"));
        assert_eq!(doc.unwritable_components.iter().cloned().collect::<Vec<_>>(), vec!["../../x".to_string()]);
        assert!(doc.issues.iter().any(|i| i.kind == IssueKind::UnsafeComponentName && i.severity == Severity::Error));
        assert!(!doc.unwritable_components.contains("Fine"));
    }

    #[test]
    fn an_empty_document_loads_with_a_missing_version_issue_only() {
        let doc = load_yaml("info: { title: t, version: 1 }\n");
        assert!(doc.operations.is_empty());
        assert_eq!(kinds(&doc), vec![IssueKind::VersionMissing]);
    }

    #[test]
    fn malformed_yaml_and_a_missing_file_are_load_errors() {
        assert!(matches!(load_yaml_with("paths: [unclosed", PortabilityPolicy::Warn), Err(OpenApiError::Parse(_))));
        let dir = tempdir();
        assert!(matches!(load(&dir.join("nope.yaml")), Err(OpenApiError::Io(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn issue_order_follows_the_spec_order_deterministically() {
        let yaml = spec_with_paths(&["/b/", "/a/"]);
        let first = load_yaml(&yaml);
        let second = load_yaml(&yaml);
        assert_eq!(first.issues, second.issues);
        assert!(first.issues[0].message.contains("/b"));
        assert!(first.issues[1].message.contains("/a"));
    }
}
