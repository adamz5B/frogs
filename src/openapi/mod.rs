mod change_detection;
pub mod dir_index;
#[cfg(test)]
mod fs_os_tests;
pub mod method_token;
pub mod path_rules;
mod schema_walk;

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;
use std::path::Path;

use serde_json::{Map, Value};

pub use change_detection::{content_hash, referenced_component_names};
pub use path_rules::{PortabilityPolicy, untrusted};
pub use schema_walk::{SchemaWalker, merge_stub_response, stub_from_descriptor, walk_response_schema};

use method_token::FIXED_FIELDS;

/// Caller-supplied loader settings (the loader itself never reads config).
#[derive(Debug, Clone, Copy, Default)]
pub struct LoadOptions {
    #[allow(dead_code)] // M4: additionalOperations classification
    pub case_sensitive_methods: bool,
}

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
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Operation {
    pub path: String,
    /// The file token (`get`, `query`, ...) — what names the endpoint file.
    pub method: String,
    /// The method sent on the wire (`GET`, `QUERY`, ...). Always taken from the
    /// constant field table, never from spec text.
    pub http_method: String,
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
    /// Every scheme name any requirement object of this operation's
    /// effective `security:` mentions (after reference resolution), deduped,
    /// in spec order — `security` above is only the first of these.
    pub declared_security_schemes: Vec<String>,
    /// One inner list per requirement object of the effective `security:`
    /// (spec order, keys resolved), so route/stub agreement can be checked
    /// against what the spec actually allows rather than the collapsed first
    /// name. Empty outer list: no security required.
    pub security_alternatives: Vec<Vec<String>>,
    /// Streaming is detected but not served: the endpoint is still one JSON
    /// response, this just records what the spec asked for.
    pub response_mode: ResponseMode,
    pub request_stream: Option<StreamSpec>,
    /// Why the `application/json` request body schema couldn't be resolved,
    /// in which case `request_body` holds a permissive `{}` schema (so
    /// `required` is still enforced) and shape validation is effectively off.
    pub request_body_unresolved: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub enum ResponseMode {
    #[default]
    Single,
    Stream(StreamSpec),
}

#[derive(Debug, Clone, PartialEq)]
pub struct StreamSpec {
    /// `Some` for a response stream, `None` for a request stream.
    pub status: Option<u16>,
    pub media_type: String,
    pub item_schema: Option<Value>,
    pub item_encoding: Option<Value>,
}

impl StreamSpec {
    fn raw_json(&self) -> Value {
        let mut obj = Map::new();
        if let Some(status) = self.status {
            obj.insert("status".to_string(), Value::from(status));
        }
        obj.insert("mediaType".to_string(), Value::String(self.media_type.clone()));
        obj.insert("itemSchema".to_string(), self.item_schema.clone().unwrap_or(Value::Null));
        obj.insert("itemEncoding".to_string(), self.item_encoding.clone().unwrap_or(Value::Null));
        Value::Object(obj)
    }
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
        if self.response_mode == ResponseMode::Single && self.request_stream.is_none() {
            return content_hash(self.response_schema.as_ref().unwrap_or(&Value::Null));
        }
        let response_mode = match &self.response_mode {
            ResponseMode::Single => Value::Null,
            ResponseMode::Stream(spec) => spec.raw_json(),
        };
        content_hash(&serde_json::json!({
            "responseSchema": self.response_schema.clone().unwrap_or(Value::Null),
            "responseMode": response_mode,
            "requestMode": self.request_stream.as_ref().map_or(Value::Null, StreamSpec::raw_json),
        }))
    }

    /// Every named component this operation's response schema references,
    /// directly or nested (inside `properties`/`items`/`allOf`/`oneOf`/
    /// `anyOf`) — cheap to compute (no descriptor building) so drift
    /// detection can check "does this endpoint depend on a component that
    /// changed" without first walking the whole schema.
    pub fn referenced_components(&self) -> std::collections::HashSet<String> {
        let mut names: HashSet<String> = self.response_schema.as_ref().map(referenced_component_names).unwrap_or_default();
        let streams = [
            match &self.response_mode {
                ResponseMode::Single => None,
                ResponseMode::Stream(spec) => Some(spec),
            },
            self.request_stream.as_ref(),
        ];
        for item_schema in streams.into_iter().flatten().filter_map(|spec| spec.item_schema.as_ref()) {
            names.extend(referenced_component_names(item_schema));
        }
        names
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
            self.http_method,
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

const MAX_MEDIA_TYPE_REF_HOPS: usize = 8;
const MEDIA_TYPE_REF_PREFIX: &str = "#/components/mediaTypes/";
const SCHEMA_REF_PREFIX: &str = "#/components/schemas/";
const SECURITY_SCHEME_REF_PREFIX: &str = "#/components/securitySchemes/";

#[derive(Debug, PartialEq, Eq)]
enum MediaRefError {
    Cycle,
    TooLong,
    UnknownName(String),
    WrongKind,
    Unsupported(String),
    NonStringRef,
    NotAnObject,
}

impl fmt::Display for MediaRefError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MediaRefError::Cycle => write!(f, "cycle"),
            MediaRefError::TooLong => write!(f, "chain longer than {MAX_MEDIA_TYPE_REF_HOPS} hops"),
            MediaRefError::UnknownName(name) => write!(f, "unknown media type '{}'", untrusted(name)),
            MediaRefError::WrongKind => write!(f, "a #/components/schemas/ reference where a media type belongs"),
            MediaRefError::Unsupported(r) => write!(f, "unsupported reference form '{}' (external references are never fetched)", untrusted(r)),
            MediaRefError::NonStringRef => write!(f, "$ref is not a string"),
            MediaRefError::NotAnObject => write!(f, "reference target is not an object"),
        }
    }
}

/// Follows a Media Type Object's `$ref` chain through `components.mediaTypes`
/// only — never the filesystem or network. A non-object entry is `Ok(None)`
/// (nothing to read, nothing to report), matching how such an entry was
/// already ignored before references were supported.
fn resolve_media_type<'a>(entry: &'a Value, media_types: &'a Map<String, Value>) -> Result<Option<&'a Map<String, Value>>, MediaRefError> {
    let mut current = entry;
    let mut hops = 0usize;
    let mut visited: HashSet<&str> = HashSet::new();
    loop {
        let Some(obj) = current.as_object() else {
            return if hops == 0 { Ok(None) } else { Err(MediaRefError::NotAnObject) };
        };
        let Some(reference) = obj.get("$ref") else {
            return Ok(Some(obj));
        };
        let Some(reference) = reference.as_str() else {
            return Err(MediaRefError::NonStringRef);
        };
        if reference.starts_with(SCHEMA_REF_PREFIX) {
            return Err(MediaRefError::WrongKind);
        }
        let Some(name) = reference.strip_prefix(MEDIA_TYPE_REF_PREFIX) else {
            return Err(MediaRefError::Unsupported(reference.to_string()));
        };
        if !visited.insert(name) {
            return Err(MediaRefError::Cycle);
        }
        hops += 1;
        if hops > MAX_MEDIA_TYPE_REF_HOPS {
            return Err(MediaRefError::TooLong);
        }
        current = media_types.get(name).ok_or_else(|| MediaRefError::UnknownName(name.to_string()))?;
    }
}

type ResolvedSecurity = (Option<String>, Vec<String>, Vec<Vec<String>>);

struct OpCtx<'a> {
    media_types: &'a Map<String, Value>,
    scheme_names: &'a Map<String, Value>,
    document_security: Option<&'a ResolvedSecurity>,
}

fn media_ref_issue(message: String) -> LoadIssue {
    LoadIssue::new(IssueKind::MediaTypeRefUnresolved, Severity::Error, message)
}

/// Extracts `name`/`in`/`required`/`schema.type` from an operation's
/// `parameters` array. A parameter with no `schema` but exactly one `content`
/// entry takes its type from that entry's schema.
fn extract_parameters(operation: &Map<String, Value>, ctx: &OpCtx, label: &str, issues: &mut Vec<LoadIssue>) -> Vec<ParameterInfo> {
    let Some(parameters) = operation.get("parameters").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for param in parameters {
        let (Some(name), Some(location)) = (param.get("name").and_then(Value::as_str), param.get("in").and_then(Value::as_str)) else {
            continue;
        };
        let required = param.get("required").and_then(Value::as_bool).unwrap_or(false);
        let schema_type = match param.get("schema") {
            Some(schema) => schema.get("type").and_then(Value::as_str).map(str::to_string),
            None => match param.get("content").and_then(Value::as_object) {
                Some(content) if content.len() == 1 => {
                    let (media, entry) = content.iter().next().expect("len checked");
                    match resolve_media_type(entry, ctx.media_types) {
                        Ok(Some(obj)) => obj.get("schema").and_then(|s| s.get("type")).and_then(Value::as_str).map(str::to_string),
                        Ok(None) => None,
                        Err(e) => {
                            issues.push(media_ref_issue(format!(
                                "{label}: parameter '{}' content '{}': media type $ref unresolved ({e}) — type check skipped",
                                untrusted(name),
                                untrusted(media)
                            )));
                            None
                        }
                    }
                }
                _ => None,
            },
        };
        out.push(ParameterInfo {
            name: name.to_string(),
            location: location.to_string(),
            required,
            schema_type,
        });
    }
    out
}

fn is_streaming_entry(media_key: &str, entry: &Map<String, Value>) -> bool {
    let key = media_key.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    matches!(
        key.as_str(),
        "text/event-stream" | "application/jsonl" | "application/x-ndjson" | "application/json-seq"
    ) || key.ends_with("+json-seq")
        || (key.starts_with("multipart/") && ["itemSchema", "itemEncoding", "prefixEncoding"].iter().any(|k| entry.contains_key(*k)))
        || entry.contains_key("itemSchema")
}

fn stream_spec(status: Option<u16>, media_key: &str, entry: &Map<String, Value>) -> StreamSpec {
    StreamSpec {
        status,
        media_type: media_key.to_string(),
        item_schema: entry.get("itemSchema").cloned(),
        item_encoding: entry.get("itemEncoding").cloned(),
    }
}

/// This operation's `requestBody.content.application/json.schema`, plus the
/// reasons it may be unusable: an unresolvable `application/json` entry keeps
/// a permissive `{}` schema (so `required: true` is still enforced) and
/// records why; a body with no JSON entry is either a streaming request
/// (W2) or just non-JSON (W3).
fn extract_request_body(
    operation: &Map<String, Value>,
    ctx: &OpCtx,
    label: &str,
    issues: &mut Vec<LoadIssue>,
) -> (Option<RequestBodySchema>, Option<String>, Option<StreamSpec>) {
    let Some(request_body) = operation.get("requestBody").and_then(Value::as_object) else {
        return (None, None, None);
    };
    let Some(content) = request_body.get("content").and_then(Value::as_object) else {
        return (None, None, None);
    };
    let required = request_body.get("required").and_then(Value::as_bool).unwrap_or(false);

    if let Some(entry) = content.get("application/json") {
        return match resolve_media_type(entry, ctx.media_types) {
            Ok(Some(obj)) => (obj.get("schema").cloned().map(|schema| RequestBodySchema { required, schema }), None, None),
            Ok(None) => (None, None, None),
            Err(e) => {
                issues.push(media_ref_issue(format!(
                    "{label}: request body schema unresolved ({e}) — body validation skipped for this route"
                )));
                (
                    Some(RequestBodySchema {
                        required,
                        schema: Value::Object(Map::new()),
                    }),
                    Some(e.to_string()),
                    None,
                )
            }
        };
    }

    for (media, entry) in content {
        match resolve_media_type(entry, ctx.media_types) {
            Ok(Some(obj)) if is_streaming_entry(media, obj) => {
                issues.push(LoadIssue::new(
                    IssueKind::StreamingDeclared,
                    Severity::Warning,
                    format!(
                        "{label} declares a streaming request body ({}); frogs only reads a single JSON request body — body validation is skipped for this route",
                        untrusted(media)
                    ),
                ));
                return (None, None, Some(stream_spec(None, media, obj)));
            }
            Ok(_) => {}
            Err(e) => issues.push(media_ref_issue(format!(
                "{label}: request body content '{}': media type $ref unresolved ({e}) — entry ignored",
                untrusted(media)
            ))),
        }
    }

    if !content.is_empty() {
        let mut keys: Vec<String> = content.keys().take(5).map(|k| untrusted(k)).collect();
        if content.len() > 5 {
            keys.push("…".to_string());
        }
        issues.push(LoadIssue::new(
            IssueKind::NonJsonRequestBody,
            Severity::Warning,
            format!(
                "{label} declares a request body with only non-JSON content ({}); frogs only reads application/json bodies — the body is not validated and sources see it as null",
                keys.join(", ")
            ),
        ));
    }
    (None, None, None)
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

/// The first `2xx` response's `application/json` schema (media-type `$ref`s
/// followed), or — when no `2xx` has one — the first streaming `2xx` content
/// entry, which frogs still serves as a single JSON response. A `2xx` with no
/// `content` at all (e.g. a bodyless `204`) is skipped in favor of the next
/// candidate, not treated as "nothing found."
fn extract_response(operation: &Map<String, Value>, ctx: &OpCtx, label: &str, issues: &mut Vec<LoadIssue>) -> (Option<Value>, ResponseMode) {
    let Some(responses) = operation.get("responses").and_then(Value::as_object) else {
        return (None, ResponseMode::Single);
    };
    let success = || responses.iter().filter(|(status, _)| status.starts_with('2'));

    for (status, response) in success() {
        let Some(entry) = response.get("content").and_then(|c| c.get("application/json")) else {
            continue;
        };
        match resolve_media_type(entry, ctx.media_types) {
            Ok(Some(obj)) => {
                if let Some(schema) = obj.get("schema") {
                    return (Some(schema.clone()), ResponseMode::Single);
                }
            }
            Ok(None) => {}
            Err(e) => issues.push(media_ref_issue(format!(
                "{label}: response {} content 'application/json': media type $ref unresolved ({e}) — treated as having no schema",
                untrusted(status)
            ))),
        }
    }

    for (status, response) in success() {
        let Some(content) = response.get("content").and_then(Value::as_object) else {
            continue;
        };
        for (media, entry) in content {
            match resolve_media_type(entry, ctx.media_types) {
                Ok(Some(obj)) if is_streaming_entry(media, obj) => {
                    issues.push(LoadIssue::new(
                        IssueKind::StreamingDeclared,
                        Severity::Warning,
                        format!(
                            "{label} declares a streaming response ({}); frogs does not serve streaming responses — this endpoint will be generated as a single JSON response",
                            untrusted(media)
                        ),
                    ));
                    let code = status.parse::<u16>().ok().or(Some(200));
                    return (None, ResponseMode::Stream(stream_spec(code, media, obj)));
                }
                Ok(_) => {}
                Err(e) if media != "application/json" => issues.push(media_ref_issue(format!(
                    "{label}: response {} content '{}': media type $ref unresolved ({e}) — treated as having no schema",
                    untrusted(status),
                    untrusted(media)
                ))),
                Err(_) => {}
            }
        }
    }
    (None, ResponseMode::Single)
}

/// Maps one `security:` requirement key to a `securitySchemes` name. `None`
/// means the key can never name a scheme (a URI, a non-matching pointer) and
/// is kept verbatim by the caller with a warning — it then fails closed at
/// route registration since no verifier can carry that name.
fn resolve_scheme_key(key: &str, scheme_names: &Map<String, Value>) -> Option<String> {
    if scheme_names.contains_key(key) {
        return Some(key.to_string());
    }
    if let Some(name) = key.strip_prefix(SECURITY_SCHEME_REF_PREFIX) {
        return scheme_names.contains_key(name).then(|| name.to_string());
    }
    schema_walk::is_name_shaped(key).then(|| key.to_string())
}

/// `(first, all)` for a `security:` value: `first` is the first key of the
/// first non-empty requirement object (see `Operation::security` for why it
/// collapses to one name); `all` is every key of every requirement, deduped.
fn resolve_security(value: &Value, scheme_names: &Map<String, Value>, context: &str, issues: &mut Vec<LoadIssue>) -> ResolvedSecurity {
    let mut first = None;
    let mut all: Vec<String> = Vec::new();
    let mut alternatives: Vec<Vec<String>> = Vec::new();
    let Some(requirements) = value.as_array() else {
        return (None, all, alternatives);
    };
    for requirement in requirements {
        let Some(obj) = requirement.as_object() else { continue };
        let mut alternative: Vec<String> = Vec::new();
        for key in obj.keys() {
            let resolved = resolve_scheme_key(key, scheme_names).unwrap_or_else(|| {
                issues.push(LoadIssue::new(
                    IssueKind::SecurityRequirementUnresolved,
                    Severity::Warning,
                    format!(
                        "{context}: security requirement {} is not a securitySchemes name or a resolvable #/components/securitySchemes/<Name> reference — kept verbatim; the route stays refused unless security/schemes.json defines exactly that name",
                        untrusted(key)
                    ),
                ));
                key.clone()
            });
            if first.is_none() {
                first = Some(resolved.clone());
            }
            if !all.contains(&resolved) {
                all.push(resolved.clone());
            }
            alternative.push(resolved);
        }
        if alternative.len() > 1 {
            issues.push(LoadIssue::new(
                IssueKind::SecurityRequirementCollapsed,
                Severity::Warning,
                format!(
                    "{context}: security requirement combines schemes ({}); frogs enforces only '{}'",
                    alternative.iter().map(|k| format!("'{}'", untrusted(k))).collect::<Vec<_>>().join(", "),
                    untrusted(&alternative[0])
                ),
            ));
        }
        alternatives.push(alternative);
    }
    (first, all, alternatives)
}

const MAX_DEFAULT_MAPPING_SCAN_DEPTH: usize = 32;

/// Flags `discriminator.defaultMapping` values that name nothing frogs can
/// resolve. Never follows `$ref`s, so it is linear in the schema's own size.
fn scan_default_mappings(schema: &Value, components: &Map<String, Value>, label: &str, issues: &mut Vec<LoadIssue>, depth: usize) {
    if depth > MAX_DEFAULT_MAPPING_SCAN_DEPTH {
        return;
    }
    let Some(obj) = schema.as_object() else { return };
    if let schema_walk::DefaultMapping::Unresolved(reason) = schema_walk::default_mapping_target(obj, |n| components.contains_key(n)) {
        let value = obj
            .get("discriminator")
            .and_then(|d| d.get("defaultMapping"))
            .map(|v| v.as_str().map(untrusted).unwrap_or_else(|| untrusted(&v.to_string())))
            .unwrap_or_default();
        issues.push(LoadIssue::new(
            IssueKind::DefaultMappingUnresolved,
            Severity::Warning,
            format!("{label}: discriminator.defaultMapping {value} {reason} — the oneOf is left unresolved"),
        ));
    }
    if let Some(props) = obj.get("properties").and_then(Value::as_object) {
        for prop in props.values() {
            scan_default_mappings(prop, components, label, issues, depth + 1);
        }
    }
    if let Some(items) = obj.get("items") {
        scan_default_mappings(items, components, label, issues, depth + 1);
    }
    for key in ["allOf", "oneOf", "anyOf"] {
        if let Some(variants) = obj.get(key).and_then(Value::as_array) {
            for variant in variants {
                scan_default_mappings(variant, components, label, issues, depth + 1);
            }
        }
    }
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
    /// Interim: `additionalOperations` is loaded but not served yet.
    NotServed,
    /// A 3.0/3.1 document uses an operation field introduced in 3.2.
    OperationNeedsNewerVersion,
    UnsafePath,
    WindowsPortability,
    CaseOnlyPathCollision,
    TrailingSlashNormalised,
    TrailingSlashCollision,
    UnsafeComponentName,
    MediaTypeRefUnresolved,
    DefaultMappingUnresolved,
    SecurityRequirementUnresolved,
    StreamingDeclared,
    NonJsonRequestBody,
    DeprecatedSecurityScheme,
    SecurityRequirementCollapsed,
}

impl IssueKind {
    /// Whether `strictOpenApi: true` turns this kind into a refusal.
    pub fn is_strict_error(&self) -> bool {
        match self {
            IssueKind::NotServed
            | IssueKind::StreamingDeclared
            | IssueKind::NonJsonRequestBody
            | IssueKind::DeprecatedSecurityScheme
            | IssueKind::SecurityRequirementCollapsed => false,
            IssueKind::VersionMissing
            | IssueKind::VersionUnrecognized
            | IssueKind::Swagger2
            | IssueKind::VersionNewer
            | IssueKind::OperationNeedsNewerVersion
            | IssueKind::UnsafePath
            | IssueKind::WindowsPortability
            | IssueKind::CaseOnlyPathCollision
            | IssueKind::TrailingSlashNormalised
            | IssueKind::TrailingSlashCollision
            | IssueKind::UnsafeComponentName
            | IssueKind::MediaTypeRefUnresolved
            | IssueKind::DefaultMappingUnresolved
            | IssueKind::SecurityRequirementUnresolved => true,
        }
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
    /// `components/securitySchemes` names whose `deprecated` is JSON `true`.
    pub deprecated_security_schemes: HashSet<String>,
}

impl OpenApiDocument {
    /// One message per deprecated scheme some operation (served or ambiguous)
    /// still uses, sorted by scheme name. Informational only — never affects
    /// routing.
    pub fn deprecated_scheme_warnings(&self) -> Vec<String> {
        let mut names: Vec<&String> = self.deprecated_security_schemes.iter().collect();
        names.sort();
        let mut out = Vec::new();
        for name in names {
            let mut users: Vec<String> = Vec::new();
            for op in self.operations.iter().chain(&self.ambiguous_operations) {
                if op.declared_security_schemes.contains(name) {
                    let user = format!("{} {}", op.http_method, untrusted(&op.path));
                    if !users.contains(&user) {
                        users.push(user);
                    }
                }
            }
            if !users.is_empty() {
                out.push(format!(
                    "security scheme '{}' is marked deprecated in openapi.yaml (used by: {})",
                    untrusted(name),
                    users.join(", ")
                ));
            }
        }
        out
    }

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
                write!(f, "{} {} has no operationId", method_token::display_token(method), untrusted(path))
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
pub fn load(path: &Path, options: LoadOptions) -> Result<OpenApiDocument, OpenApiError> {
    load_with_policy(path, PortabilityPolicy::for_host(), options)
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

fn parse_operations(path: &str, item: &Map<String, Value>, ctx: &OpCtx, spec_version: &SpecVersion, issues: &mut Vec<LoadIssue>) -> Result<Vec<Operation>, OpenApiError> {
    let mut operations = Vec::new();
    for method in FIXED_FIELDS {
        let Some(operation_obj) = item.get(method).and_then(Value::as_object) else {
            continue;
        };
        let operation_id = operation_obj
            .get("operationId")
            .and_then(Value::as_str)
            .ok_or_else(|| OpenApiError::MissingOperationId {
                path: path.to_string(),
                method: method.to_string(),
            })?;
        let http_method = method.to_ascii_uppercase();
        let label = format!("{http_method} {}", untrusted(path));
        if method == "query" && matches!(spec_version, SpecVersion::V3_0 | SpecVersion::V3_1) {
            let declared = match spec_version {
                SpecVersion::V3_0 => "3.0",
                _ => "3.1",
            };
            issues.push(LoadIssue::new(
                IssueKind::OperationNeedsNewerVersion,
                Severity::Warning,
                format!(
                    "QUERY {} (operationId {}) uses the `query` operation field from OpenAPI 3.2, but this document declares openapi {} — served anyway; declare openapi: 3.2.0",
                    untrusted(path),
                    untrusted(operation_id),
                    declared
                ),
            ));
        }
        let parameters = extract_parameters(operation_obj, ctx, &label, issues);
        let (request_body, request_body_unresolved, request_stream) = extract_request_body(operation_obj, ctx, &label, issues);
        let (response_schema, response_mode) = extract_response(operation_obj, ctx, &label, issues);
        let (security, declared_security_schemes, security_alternatives) = match operation_obj.get("security") {
            Some(value) => resolve_security(value, ctx.scheme_names, &label, issues),
            None => ctx.document_security.cloned().unwrap_or_default(),
        };
        operations.push(Operation {
            path: path.to_string(),
            method: method.to_string(),
            http_method,
            operation_id: operation_id.to_string(),
            response_schema,
            parameters,
            request_body,
            response_status_codes: declared_response_codes(operation_obj),
            security,
            declared_security_schemes,
            security_alternatives,
            response_mode,
            request_stream,
            request_body_unresolved,
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

pub(crate) fn load_with_policy(path: &Path, policy: PortabilityPolicy, _options: LoadOptions) -> Result<OpenApiDocument, OpenApiError> {
    let contents = std::fs::read_to_string(path).map_err(OpenApiError::Io)?;
    let doc: Value = serde_yaml::from_str(&contents).map_err(OpenApiError::Parse)?;

    let mut issues = Vec::new();
    let spec_version = detect_version(&doc, &mut issues);
    let empty = Map::new();
    let components_obj = doc.get("components");
    let media_types = components_obj.and_then(|c| c.get("mediaTypes")).and_then(Value::as_object).unwrap_or(&empty);
    let scheme_names = components_obj.and_then(|c| c.get("securitySchemes")).and_then(Value::as_object).unwrap_or(&empty);
    let document_security = doc
        .get("security")
        .map(|value| resolve_security(value, scheme_names, "top-level security", &mut issues));
    let ctx = OpCtx {
        media_types,
        scheme_names,
        document_security: document_security.as_ref(),
    };

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
        let parsed = parse_operations(normalized, item, &ctx, &spec_version, &mut issues)?;
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

    let security_scheme_types = scheme_names
        .iter()
        .filter_map(|(name, scheme)| Some((name.clone(), scheme.get("type")?.as_str()?.to_string())))
        .collect();
    let deprecated_security_schemes = scheme_names
        .iter()
        .filter(|(_, scheme)| scheme.get("deprecated") == Some(&Value::Bool(true)))
        .map(|(name, _)| name.clone())
        .collect();

    let mut document = OpenApiDocument {
        operations,
        component_schemas,
        security_scheme_types,
        spec_version,
        issues,
        ambiguous,
        ambiguous_operations,
        skipped_paths,
        unwritable_components,
        deprecated_security_schemes,
    };

    let mut mapping_issues = Vec::new();
    for (name, schema) in &document.component_schemas {
        scan_default_mappings(
            schema,
            &document.component_schemas,
            &format!("components/schemas/{}", untrusted(name)),
            &mut mapping_issues,
            0,
        );
    }
    for op in document.operations.iter().chain(&document.ambiguous_operations) {
        let label = format!("{} {}", op.http_method, untrusted(&op.path));
        let response_stream = match &op.response_mode {
            ResponseMode::Single => None,
            ResponseMode::Stream(spec) => spec.item_schema.as_ref(),
        };
        let scans: [(&str, Option<&Value>); 4] = [
            ("response", op.response_schema.as_ref()),
            ("request body", op.request_body.as_ref().map(|b| &b.schema)),
            ("response stream item schema", response_stream),
            ("request stream item schema", op.request_stream.as_ref().and_then(|spec| spec.item_schema.as_ref())),
        ];
        for (what, schema) in scans {
            if let Some(schema) = schema {
                scan_default_mappings(schema, &document.component_schemas, &format!("{label} {what}"), &mut mapping_issues, 0);
            }
        }
    }
    document.issues.extend(mapping_issues);

    for message in document.deprecated_scheme_warnings() {
        document.issues.push(LoadIssue::new(IssueKind::DeprecatedSecurityScheme, Severity::Warning, message));
    }
    Ok(document)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extract_parameters(operation: &Map<String, Value>) -> Vec<ParameterInfo> {
        let empty = Map::new();
        let ctx = OpCtx {
            media_types: &empty,
            scheme_names: &empty,
            document_security: None,
        };
        super::extract_parameters(operation, &ctx, "test", &mut Vec::new())
    }

    fn extract_request_body(operation: &Map<String, Value>) -> Option<RequestBodySchema> {
        let empty = Map::new();
        let ctx = OpCtx {
            media_types: &empty,
            scheme_names: &empty,
            document_security: None,
        };
        super::extract_request_body(operation, &ctx, "test", &mut Vec::new()).0
    }

    fn operation_security(operation: &Map<String, Value>, document_default: Option<&Value>) -> Option<String> {
        let empty = Map::new();
        operation
            .get("security")
            .or(document_default)
            .and_then(|value| resolve_security(value, &empty, "test", &mut Vec::new()).0)
    }

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

        let doc = load(&spec_path, LoadOptions::default()).expect("fixture should parse cleanly");
        let _ = std::fs::remove_dir_all(&dir);

        let car_with_price_ref = Some(serde_json::json!({ "$ref": "#/components/schemas/CarWithPrice" }));
        assert_eq!(
            doc.operations,
            vec![
                Operation {
                    path: "/cars".to_string(),
                    method: "get".to_string(),
                    http_method: "GET".to_string(),
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
                    ..Default::default()
                },
                Operation {
                    path: "/cars".to_string(),
                    method: "post".to_string(),
                    http_method: "POST".to_string(),
                    operation_id: "createCar".to_string(),
                    response_schema: car_with_price_ref.clone(),
                    parameters: vec![],
                    request_body: None,
                    response_status_codes: vec![201],
                    security: None,
                    ..Default::default()
                },
                Operation {
                    path: "/cars/{vin}".to_string(),
                    method: "get".to_string(),
                    http_method: "GET".to_string(),
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
                    declared_security_schemes: vec!["apiKeyAuth".to_string()],
                    security_alternatives: vec![vec!["apiKeyAuth".to_string()]],
                    ..Default::default()
                },
            ]
        );
    }

    #[test]
    fn request_sources_and_available_parameter_sources_follow_query_path_header_order() {
        let op = Operation {
            path: "/things/{id}".to_string(),
            method: "get".to_string(),
            http_method: "GET".to_string(),
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
            ..Default::default()
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

        let err = load(&spec_path, LoadOptions::default()).expect_err("a path with no operationId should fail to load");
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

        let err = load(&spec_path, LoadOptions::default()).expect_err("malformed YAML should fail to parse");
        assert!(matches!(err, OpenApiError::Parse(_)));

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn op_with_codes(codes: Vec<u16>) -> Operation {
        Operation {
            path: "/cars".to_string(),
            method: "post".to_string(),
            http_method: "POST".to_string(),
            operation_id: "createCar".to_string(),
            response_schema: None,
            parameters: Vec::new(),
            request_body: None,
            response_status_codes: codes,
            ..Default::default()
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
        let result = load_with_policy(&path, policy, LoadOptions::default());
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
            yaml.push_str(&format!(
                "  '{p}':\n    get:\n      operationId: op{i}\n      responses:\n        '200': {{ description: ok }}\n"
            ));
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
        let v31 = format!(
            "openapi: 3.1.0
info: {{ title: t, version: 1 }}
{TWIN_PATHS_HEAD}{TWIN_PATHS_TAIL}components:
  schemas:
    Car:
      type: object
      properties: {{ kind: {{ type: string }} }}
"
        );
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
        assert!(
            a.operations[0].parameters.iter().any(|p| p.location == "querystring"),
            "querystring params are still collected"
        );
        assert_eq!(a.operations[0].response_schema_hash(), b.operations[0].response_schema_hash());
    }

    #[test]
    fn additional_operations_are_loaded_as_not_served_warnings_only_and_query_is_served() {
        let yaml = "openapi: 3.2.0\ninfo: { title: t, version: 1 }\npaths:\n  /search:\n    get:\n      operationId: s\n      responses: { '200': { description: ok } }\n    query:\n      operationId: q\n      responses: { '200': { description: ok } }\n    additionalOperations:\n      PURGE:\n        operationId: purge\n        responses: { '200': { description: ok } }\n      LINK:\n        responses: { '200': { description: ok } }\n";
        let doc = load_yaml(yaml);
        assert_eq!(doc.operations.len(), 2, "the get and the query are served operations");
        let not_served: Vec<&LoadIssue> = doc.issues.iter().filter(|i| i.kind == IssueKind::NotServed).collect();
        assert_eq!(not_served.len(), 2, "{:?}", doc.issues);
        assert!(not_served.iter().all(|i| i.severity == Severity::Warning));
        assert!(not_served.iter().any(|i| i.message.starts_with("PURGE /search (operationId purge)")));
        assert!(not_served.iter().any(|i| i.message.starts_with("LINK /search (operationId <none>)")));
        assert_eq!(doc.issues.len(), 2);
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
            assert!(
                doc.issues
                    .iter()
                    .filter(|i| i.kind == IssueKind::TrailingSlashCollision)
                    .all(|i| i.severity == Severity::Error)
            );
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
        assert_eq!(
            doc.issues.iter().filter(|i| i.kind == IssueKind::UnsafePath && i.severity == Severity::Error).count(),
            3
        );
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
        assert!(matches!(load_yaml_with(yaml, PortabilityPolicy::Warn), Err(OpenApiError::MissingOperationId { .. })));
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
        let yaml =
            "openapi: 3.1.0\ninfo: { title: t, version: 1 }\npaths: {}\ncomponents:\n  schemas:\n    '../../x':\n      type: object\n    Fine:\n      type: object\n";
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
        assert!(matches!(load(&dir.join("nope.yaml"), LoadOptions::default()), Err(OpenApiError::Io(_))));
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

#[cfg(test)]
mod m2_schema_and_security_tests {
    use super::*;

    fn tempdir() -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "frogs-openapi-m2-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn load_yaml(yaml: &str) -> OpenApiDocument {
        let dir = tempdir();
        let path = dir.join("openapi.yaml");
        std::fs::write(&path, yaml).unwrap();
        let result = load_with_policy(&path, PortabilityPolicy::Warn, LoadOptions::default()).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        result
    }

    /// Builds a 3.2 spec: `components_yaml` is spliced under `components:`,
    /// `paths_yaml` under `paths:` (both must be pre-indented by 2 spaces).
    fn spec(components_yaml: &str, paths_yaml: &str) -> String {
        format!("openapi: 3.2.0\ninfo: {{ title: t, version: 1 }}\ncomponents:\n{components_yaml}\npaths:\n{paths_yaml}\n")
    }

    fn get_with_200_content(content: &str) -> String {
        format!("  /a:\n    get:\n      operationId: a\n      responses:\n        '200':\n          description: ok\n          content:\n{content}\n")
    }

    fn issues_of(doc: &OpenApiDocument, kind: IssueKind) -> Vec<&LoadIssue> {
        doc.issues.iter().filter(|i| i.kind == kind).collect()
    }

    const JSON_SCHEMA_STRING: &str = "{ schema: { type: string } }";

    fn media_chain(len: usize) -> String {
        // entry -> M0 -> ... -> M{len} (the last is the real object): len + 1 $ref hops.
        let mut s = String::from("  mediaTypes:\n");
        for i in 0..len {
            s.push_str(&format!("    M{i}: {{ $ref: '#/components/mediaTypes/M{}' }}\n", i + 1));
        }
        s.push_str(&format!("    M{len}: {JSON_SCHEMA_STRING}\n"));
        s
    }

    // ---------------------------------------------------------------- S9

    #[test]
    fn a_direct_media_type_ref_in_a_response_supplies_the_response_schema() {
        let doc = load_yaml(&spec(
            "  mediaTypes:\n    Car: { schema: { type: object, properties: { vin: { type: string } } } }",
            &get_with_200_content("            application/json: { $ref: '#/components/mediaTypes/Car' }"),
        ));
        assert!(doc.issues.is_empty(), "{:?}", doc.issues);
        assert_eq!(doc.operations[0].response_schema.as_ref().unwrap()["properties"]["vin"]["type"], "string");
    }

    #[test]
    fn a_two_hop_media_type_ref_chain_resolves() {
        let doc = load_yaml(&spec(
            &media_chain(2),
            &get_with_200_content("            application/json: { $ref: '#/components/mediaTypes/M0' }"),
        ));
        assert!(doc.issues.is_empty(), "{:?}", doc.issues);
        assert!(doc.operations[0].response_schema.is_some());
    }

    #[test]
    fn a_media_type_chain_of_exactly_eight_hops_resolves_and_nine_is_rejected() {
        let ok = load_yaml(&spec(
            &media_chain(7),
            &get_with_200_content("            application/json: { $ref: '#/components/mediaTypes/M0' }"),
        ));
        assert!(ok.issues.is_empty(), "{:?}", ok.issues);
        assert!(ok.operations[0].response_schema.is_some());

        let too_long = load_yaml(&spec(
            &media_chain(8),
            &get_with_200_content("            application/json: { $ref: '#/components/mediaTypes/M0' }"),
        ));
        let s9 = issues_of(&too_long, IssueKind::MediaTypeRefUnresolved);
        assert_eq!(s9.len(), 1, "{:?}", too_long.issues);
        assert_eq!(s9[0].severity, Severity::Error);
        assert!(s9[0].message.contains("chain longer than 8 hops"), "{}", s9[0].message);
        assert!(too_long.operations[0].response_schema.is_none());
    }

    #[test]
    fn self_referencing_and_mutually_referencing_media_types_report_a_cycle_without_hanging() {
        let selfref = load_yaml(&spec(
            "  mediaTypes:\n    A: { $ref: '#/components/mediaTypes/A' }",
            &get_with_200_content("            application/json: { $ref: '#/components/mediaTypes/A' }"),
        ));
        let s9 = issues_of(&selfref, IssueKind::MediaTypeRefUnresolved);
        assert_eq!(s9.len(), 1);
        assert!(s9[0].message.contains("cycle"), "{}", s9[0].message);

        let pair = load_yaml(&spec(
            "  mediaTypes:\n    A: { $ref: '#/components/mediaTypes/B' }\n    B: { $ref: '#/components/mediaTypes/A' }",
            &get_with_200_content("            application/json: { $ref: '#/components/mediaTypes/A' }"),
        ));
        let s9 = issues_of(&pair, IssueKind::MediaTypeRefUnresolved);
        assert_eq!(s9.len(), 1);
        assert!(s9[0].message.contains("cycle"), "{}", s9[0].message);
    }

    #[test]
    fn each_unresolvable_media_type_ref_form_is_an_s9_error_and_leaves_no_response_schema() {
        let cases: &[(&str, &str)] = &[
            ("'#/components/mediaTypes/Missing'", "unknown media type 'Missing'"),
            ("./x.yaml", "unsupported reference form"),
            ("'https://h/x#/components/mediaTypes/A'", "unsupported reference form"),
            ("'#/components/schemas/Car'", "a #/components/schemas/ reference where a media type belongs"),
            ("42", "$ref is not a string"),
        ];
        for (reference, expected) in cases {
            let doc = load_yaml(&spec(
                "  mediaTypes:\n    A: { schema: { type: string } }\n  schemas:\n    Car: { type: object }",
                &get_with_200_content(&format!("            application/json: {{ $ref: {reference} }}")),
            ));
            let s9 = issues_of(&doc, IssueKind::MediaTypeRefUnresolved);
            assert_eq!(s9.len(), 1, "{reference}: {:?}", doc.issues);
            assert_eq!(s9[0].severity, Severity::Error, "{reference}");
            assert!(s9[0].message.contains(expected), "{reference}: {}", s9[0].message);
            assert!(s9[0].message.contains("treated as having no schema"), "{reference}: {}", s9[0].message);
            assert!(doc.operations[0].response_schema.is_none(), "{reference}");
        }
    }

    #[test]
    fn a_media_type_ref_whose_target_is_not_an_object_is_reported() {
        let doc = load_yaml(&spec(
            "  mediaTypes:\n    A: 5",
            &get_with_200_content("            application/json: { $ref: '#/components/mediaTypes/A' }"),
        ));
        let s9 = issues_of(&doc, IssueKind::MediaTypeRefUnresolved);
        assert_eq!(s9.len(), 1);
        assert!(s9[0].message.contains("reference target is not an object"), "{}", s9[0].message);
    }

    #[test]
    fn a_media_type_ref_with_a_sibling_schema_uses_the_ref_target_not_the_sibling() {
        let doc = load_yaml(&spec(
            "  mediaTypes:\n    A: { schema: { type: integer } }",
            &get_with_200_content("            application/json: { $ref: '#/components/mediaTypes/A', schema: { type: string } }"),
        ));
        assert_eq!(doc.operations[0].response_schema.as_ref().unwrap()["type"], "integer");
    }

    #[test]
    fn an_unresolvable_200_json_entry_is_reported_once_and_a_good_201_supplies_the_schema() {
        let paths = "  /a:\n    post:\n      operationId: a\n      responses:\n        '200':\n          description: ok\n          content:\n            application/json: { $ref: '#/components/mediaTypes/Missing' }\n        '201':\n          description: created\n          content:\n            application/json: { schema: { type: integer } }\n";
        let doc = load_yaml(&spec("  mediaTypes:\n    A: { schema: { type: string } }", paths));
        assert_eq!(issues_of(&doc, IssueKind::MediaTypeRefUnresolved).len(), 1, "{:?}", doc.issues);
        assert_eq!(doc.operations[0].response_schema.as_ref().unwrap()["type"], "integer");
    }

    #[test]
    fn an_unresolvable_non_json_entry_next_to_a_good_json_entry_is_never_dereferenced() {
        let doc = load_yaml(&spec(
            "  mediaTypes:\n    A: { schema: { type: string } }",
            &get_with_200_content(
                "            application/json: { $ref: '#/components/mediaTypes/A' }\n            application/xml: { $ref: '#/components/mediaTypes/Missing' }",
            ),
        ));
        assert!(doc.issues.is_empty(), "{:?}", doc.issues);
    }

    #[test]
    fn a_broken_media_type_in_a_non_2xx_response_or_unused_component_is_never_reported() {
        let paths = "  /a:\n    get:\n      operationId: a\n      responses:\n        '200': { description: ok }\n        '404':\n          description: no\n          content:\n            application/json: { $ref: '#/components/mediaTypes/Missing' }\n";
        let doc = load_yaml(&spec("  mediaTypes:\n    Unused: { $ref: '#/components/mediaTypes/Nope' }", paths));
        assert!(doc.issues.is_empty(), "{:?}", doc.issues);
    }

    #[test]
    fn a_request_body_media_type_ref_populates_request_body() {
        let paths = "  /a:\n    post:\n      operationId: a\n      requestBody:\n        required: true\n        content:\n          application/json: { $ref: '#/components/mediaTypes/B' }\n      responses:\n        '200': { description: ok }\n";
        let doc = load_yaml(&spec("  mediaTypes:\n    B: { schema: { type: object, required: [x] } }", paths));
        let body = doc.operations[0].request_body.as_ref().unwrap();
        assert!(body.required);
        assert_eq!(body.schema["type"], "object");
        assert!(doc.operations[0].request_body_unresolved.is_none());
        assert!(doc.issues.is_empty(), "{:?}", doc.issues);
    }

    #[test]
    fn an_unresolved_request_body_keeps_a_permissive_schema_so_required_is_still_enforced_and_reports_s9() {
        let paths = "  /a:\n    post:\n      operationId: a\n      requestBody:\n        required: true\n        content:\n          application/json: { $ref: '#/components/mediaTypes/Missing' }\n      responses:\n        '200': { description: ok }\n";
        let doc = load_yaml(&spec("  mediaTypes:\n    B: { schema: { type: object } }", paths));
        let op = &doc.operations[0];
        let body = op.request_body.as_ref().expect("amended A15: Some");
        assert!(body.required);
        assert_eq!(body.schema, serde_json::json!({}));
        assert!(op.request_body_unresolved.is_some());
        let s9 = issues_of(&doc, IssueKind::MediaTypeRefUnresolved);
        assert_eq!(s9.len(), 1, "{:?}", doc.issues);
        assert_eq!(s9[0].severity, Severity::Error);
        assert_eq!(
            s9[0].message,
            format!(
                "POST /a: request body schema unresolved ({}) — body validation skipped for this route",
                op.request_body_unresolved.as_ref().unwrap()
            )
        );
        assert!(s9[0].message.contains("unknown media type 'Missing'"));
    }

    #[test]
    fn a_request_body_json_entry_without_a_schema_gives_no_request_body() {
        let paths = "  /a:\n    post:\n      operationId: a\n      requestBody:\n        content:\n          application/json: {}\n      responses:\n        '200': { description: ok }\n";
        let doc = load_yaml(&spec("  schemas: {}", paths));
        assert!(doc.operations[0].request_body.is_none());
    }

    #[test]
    fn parameter_content_by_ref_and_inline_both_supply_schema_type() {
        let paths = "  /a:\n    get:\n      operationId: a\n      parameters:\n        - { name: n, in: query, content: { application/json: { $ref: '#/components/mediaTypes/I' } } }\n        - { name: m, in: query, content: { application/json: { schema: { type: boolean } } } }\n      responses:\n        '200': { description: ok }\n";
        let doc = load_yaml(&spec("  mediaTypes:\n    I: { schema: { type: integer } }", paths));
        assert!(doc.issues.is_empty(), "{:?}", doc.issues);
        let ps = &doc.operations[0].parameters;
        assert_eq!(ps[0].schema_type.as_deref(), Some("integer"));
        assert_eq!(ps[1].schema_type.as_deref(), Some("boolean"));
    }

    #[test]
    fn parameter_content_with_zero_or_two_entries_or_an_explicit_schema_is_handled_without_issue() {
        let paths = "  /a:\n    get:\n      operationId: a\n      parameters:\n        - { name: zero, in: query, content: {} }\n        - { name: two, in: query, content: { application/json: { schema: { type: integer } }, text/plain: { schema: { type: string } } } }\n        - { name: both, in: query, schema: { type: string }, content: { application/json: { schema: { type: integer } } } }\n      responses:\n        '200': { description: ok }\n";
        let doc = load_yaml(&spec("  schemas: {}", paths));
        assert!(doc.issues.is_empty(), "{:?}", doc.issues);
        let ps = &doc.operations[0].parameters;
        assert_eq!(ps[0].schema_type, None);
        assert_eq!(ps[1].schema_type, None);
        assert_eq!(ps[2].schema_type.as_deref(), Some("string"));
    }

    #[test]
    fn an_unresolvable_parameter_content_ref_reports_s9_and_skips_the_type() {
        let paths = "  /a:\n    get:\n      operationId: a\n      parameters:\n        - { name: n, in: query, content: { application/json: { $ref: '#/components/mediaTypes/Missing' } } }\n      responses:\n        '200': { description: ok }\n";
        let doc = load_yaml(&spec("  schemas: {}", paths));
        let s9 = issues_of(&doc, IssueKind::MediaTypeRefUnresolved);
        assert_eq!(s9.len(), 1, "{:?}", doc.issues);
        assert!(s9[0].message.contains("parameter 'n'"), "{}", s9[0].message);
        assert!(s9[0].message.contains("type check skipped"), "{}", s9[0].message);
        assert_eq!(doc.operations[0].parameters[0].schema_type, None);
    }

    #[test]
    fn control_characters_in_a_media_type_ref_are_escaped_in_the_issue_message() {
        let doc = load_yaml(&spec(
            "  schemas: {}",
            &get_with_200_content("            application/json: { $ref: \"evil\\e[31mred\\nline\" }"),
        ));
        let s9 = issues_of(&doc, IssueKind::MediaTypeRefUnresolved);
        assert_eq!(s9.len(), 1);
        assert!(!s9[0].message.contains('\u{1b}'));
        assert!(!s9[0].message.contains('\n'));
    }

    #[test]
    fn the_response_hash_changes_when_the_referenced_media_type_schema_changes() {
        let build = |ty: &str| {
            load_yaml(&spec(
                &format!("  mediaTypes:\n    Car: {{ schema: {{ type: {ty} }} }}"),
                &get_with_200_content("            application/json: { $ref: '#/components/mediaTypes/Car' }"),
            ))
        };
        assert_ne!(
            build("string").operations[0].response_schema_hash(),
            build("integer").operations[0].response_schema_hash()
        );
    }

    // ---------------------------------------------------------- Streaming

    fn response_stream_doc(media_line: &str) -> OpenApiDocument {
        load_yaml(&spec("  schemas: {}", &get_with_200_content(&format!("            {media_line}"))))
    }

    #[test]
    fn each_streaming_media_type_is_detected_with_a_w2_warning_and_no_response_schema() {
        for media in [
            "text/event-stream",
            "application/jsonl",
            "application/x-ndjson",
            "application/json-seq",
            "application/geo+json-seq",
        ] {
            let doc = response_stream_doc(&format!("{media}: {{ itemSchema: {{ type: string }} }}"));
            let op = &doc.operations[0];
            match &op.response_mode {
                ResponseMode::Stream(spec) => {
                    assert_eq!(spec.media_type, media);
                    assert_eq!(spec.status, Some(200));
                    assert_eq!(spec.item_schema, Some(serde_json::json!({ "type": "string" })));
                }
                ResponseMode::Single => panic!("{media} not detected"),
            }
            let w2 = issues_of(&doc, IssueKind::StreamingDeclared);
            assert_eq!(w2.len(), 1, "{media}");
            assert_eq!(w2[0].severity, Severity::Warning);
            assert!(w2[0].message.starts_with("GET /a declares a streaming response ("), "{}", w2[0].message);
            assert!(
                w2[0].message.contains("served") || w2[0].message.contains("single JSON response"),
                "{}",
                w2[0].message
            );
        }
    }

    #[test]
    fn a_streaming_entry_with_no_item_schema_still_records_none_for_it() {
        let doc = response_stream_doc("text/event-stream: {}");
        let ResponseMode::Stream(spec) = &doc.operations[0].response_mode else {
            panic!("expected stream")
        };
        assert_eq!(spec.item_schema, None);
        assert_eq!(spec.item_encoding, None);
    }

    #[test]
    fn multipart_is_streaming_only_with_an_item_schema_item_encoding_or_prefix_encoding() {
        for key in ["itemSchema: { type: string }", "itemEncoding: { contentType: text/plain }", "prefixEncoding: []"] {
            let doc = response_stream_doc(&format!("multipart/mixed: {{ {key} }}"));
            assert!(matches!(doc.operations[0].response_mode, ResponseMode::Stream(_)), "{key}");
        }
        let doc = response_stream_doc("multipart/mixed: { schema: { type: object } }");
        assert!(matches!(doc.operations[0].response_mode, ResponseMode::Single));
        assert!(issues_of(&doc, IssueKind::StreamingDeclared).is_empty());
    }

    #[test]
    fn a_bare_item_schema_on_any_media_type_makes_it_streaming() {
        let doc = response_stream_doc("application/octet-stream: { itemSchema: { type: string } }");
        assert!(matches!(doc.operations[0].response_mode, ResponseMode::Stream(_)));
    }

    #[test]
    fn streaming_media_keys_are_matched_case_insensitively_ignoring_parameters() {
        let doc = response_stream_doc("'Text/Event-Stream; charset=utf-8': {}");
        let ResponseMode::Stream(spec) = &doc.operations[0].response_mode else {
            panic!("expected stream")
        };
        assert_eq!(spec.media_type, "Text/Event-Stream; charset=utf-8", "media type is kept verbatim");
    }

    #[test]
    fn a_json_success_response_beats_a_streaming_one_and_raises_no_w2() {
        let paths = "  /a:\n    get:\n      operationId: a\n      responses:\n        '200':\n          description: ok\n          content:\n            application/json: { schema: { type: string } }\n        '206':\n          description: part\n          content:\n            text/event-stream: {}\n";
        let doc = load_yaml(&spec("  schemas: {}", paths));
        assert!(matches!(doc.operations[0].response_mode, ResponseMode::Single));
        assert!(doc.operations[0].response_schema.is_some());
        assert!(issues_of(&doc, IssueKind::StreamingDeclared).is_empty());
    }

    #[test]
    fn a_pattern_success_key_streaming_response_reports_status_200() {
        let paths =
            "  /a:\n    get:\n      operationId: a\n      responses:\n        2XX:\n          description: ok\n          content:\n            text/event-stream: {}\n";
        let doc = load_yaml(&spec("  schemas: {}", paths));
        let ResponseMode::Stream(spec) = &doc.operations[0].response_mode else {
            panic!("expected stream")
        };
        assert_eq!(spec.status, Some(200));
    }

    fn request_body_doc(content: &str) -> OpenApiDocument {
        let paths =
            format!("  /a:\n    post:\n      operationId: a\n      requestBody:\n        content:\n{content}\n      responses:\n        '200': {{ description: ok }}\n");
        load_yaml(&spec("  schemas: {}", &paths))
    }

    #[test]
    fn a_jsonl_request_body_is_a_request_stream_with_w2_and_without_w3() {
        let doc = request_body_doc("          application/jsonl: { itemSchema: { type: object } }");
        let op = &doc.operations[0];
        let spec = op.request_stream.as_ref().expect("request stream");
        assert_eq!(spec.status, None);
        assert_eq!(spec.media_type, "application/jsonl");
        assert!(op.request_body.is_none());
        let w2 = issues_of(&doc, IssueKind::StreamingDeclared);
        assert_eq!(w2.len(), 1);
        assert!(
            w2[0].message.starts_with("POST /a declares a streaming request body (application/jsonl)"),
            "{}",
            w2[0].message
        );
        assert!(issues_of(&doc, IssueKind::NonJsonRequestBody).is_empty());
    }

    #[test]
    fn a_non_streaming_non_json_request_body_raises_w3_with_the_documented_text() {
        let doc = request_body_doc("          multipart/form-data: { schema: { type: object } }");
        assert!(doc.operations[0].request_stream.is_none());
        let w3 = issues_of(&doc, IssueKind::NonJsonRequestBody);
        assert_eq!(w3.len(), 1);
        assert_eq!(w3[0].severity, Severity::Warning);
        assert_eq!(
            w3[0].message,
            "POST /a declares a request body with only non-JSON content (multipart/form-data); frogs only reads application/json bodies — the body is not validated and sources see it as null"
        );
        assert!(issues_of(&doc, IssueKind::StreamingDeclared).is_empty());
    }

    #[test]
    fn w3_lists_at_most_five_media_types_then_an_ellipsis() {
        let doc = request_body_doc("          a/1: {}\n          a/2: {}\n          a/3: {}\n          a/4: {}\n          a/5: {}\n          a/6: {}");
        let w3 = issues_of(&doc, IssueKind::NonJsonRequestBody);
        assert_eq!(w3.len(), 1);
        assert!(w3[0].message.contains("a/1, a/2, a/3, a/4, a/5, …"), "{}", w3[0].message);
        assert!(!w3[0].message.contains("a/6"));
    }

    #[test]
    fn a_request_body_with_json_plus_jsonl_is_neither_stream_nor_non_json() {
        let doc = request_body_doc("          application/json: { schema: { type: object } }\n          application/jsonl: { itemSchema: { type: object } }");
        assert!(doc.operations[0].request_stream.is_none());
        assert!(doc.operations[0].request_body.is_some());
        assert!(doc.issues.is_empty(), "{:?}", doc.issues);
    }

    #[test]
    fn a_plus_json_media_type_is_not_treated_as_json() {
        let doc = request_body_doc("          application/vnd.api+json: { schema: { type: object } }");
        assert!(doc.operations[0].request_body.is_none());
        assert_eq!(issues_of(&doc, IssueKind::NonJsonRequestBody).len(), 1);
    }

    #[test]
    fn the_hash_of_a_single_response_is_the_plain_schema_hash_and_changes_with_stream_item_schema() {
        let single = load_yaml(&spec(
            "  schemas: {}",
            &get_with_200_content("            application/json: { schema: { type: string } }"),
        ));
        assert_eq!(single.operations[0].response_schema_hash(), content_hash(&serde_json::json!({ "type": "string" })));

        let none = load_yaml(&spec(
            "  schemas: {}",
            "  /a:\n    get:\n      operationId: a\n      responses:\n        '200': { description: ok }\n",
        ));
        assert_eq!(none.operations[0].response_schema_hash(), content_hash(&Value::Null));

        let h = |item: &str| response_stream_doc(&format!("text/event-stream: {{ itemSchema: {{ type: {item} }} }}")).operations[0].response_schema_hash();
        assert_ne!(h("string"), h("integer"));
        assert_ne!(h("string"), single.operations[0].response_schema_hash());
    }

    #[test]
    fn referenced_components_includes_refs_inside_stream_item_schemas() {
        let doc = load_yaml(&spec(
            "  schemas:\n    Evt: { type: object }\n    In: { type: object }",
            "  /a:\n    post:\n      operationId: a\n      requestBody:\n        content:\n          application/jsonl: { itemSchema: { $ref: '#/components/schemas/In' } }\n      responses:\n        '200':\n          description: ok\n          content:\n            text/event-stream: { itemSchema: { $ref: '#/components/schemas/Evt' } }\n",
        ));
        let refs = doc.operations[0].referenced_components();
        assert!(refs.contains("Evt") && refs.contains("In"), "{refs:?}");
    }

    // ----------------------------------------------------------------- S10

    #[test]
    fn s10_fires_for_unknown_and_foreign_default_mapping_targets_and_not_for_resolvable_ones() {
        let one_of = |dm: &str| format!("    V: {{ oneOf: [ {{ type: string }} ], discriminator: {{ propertyName: k, defaultMapping: {dm} }} }}");
        let components = |dm: &str| format!("  schemas:\n    Car: {{ type: object }}\n{}", one_of(dm));
        for bad in ["Nope", "'#/components/schemas/Nope'", "'https://x/y'", "'../other.yaml#/Car'", "5"] {
            let doc = load_yaml(&spec(
                &components(bad),
                "  /a:\n    get:\n      operationId: a\n      responses:\n        '200': { description: ok }\n",
            ));
            let s10 = issues_of(&doc, IssueKind::DefaultMappingUnresolved);
            assert_eq!(s10.len(), 1, "{bad}: {:?}", doc.issues);
            assert_eq!(s10[0].severity, Severity::Warning);
            assert!(s10[0].message.contains("components/schemas/V"), "{}", s10[0].message);
            assert!(s10[0].message.contains("the oneOf is left unresolved"), "{}", s10[0].message);
        }
        for good in ["Car", "'#/components/schemas/Car'"] {
            let doc = load_yaml(&spec(
                &components(good),
                "  /a:\n    get:\n      operationId: a\n      responses:\n        '200': { description: ok }\n",
            ));
            assert!(doc.issues.is_empty(), "{good}: {:?}", doc.issues);
        }
    }

    #[test]
    fn s10_also_scans_operation_response_schemas_and_ignores_default_mapping_without_one_of() {
        let paths = get_with_200_content(
            "            application/json:\n              schema: { oneOf: [ { type: string } ], discriminator: { propertyName: k, defaultMapping: Nope } }",
        );
        let doc = load_yaml(&spec("  schemas: {}", &paths));
        assert_eq!(issues_of(&doc, IssueKind::DefaultMappingUnresolved).len(), 1, "{:?}", doc.issues);

        let paths =
            get_with_200_content("            application/json:\n              schema: { type: object, discriminator: { propertyName: k, defaultMapping: Nope } }");
        let doc = load_yaml(&spec("  schemas: {}", &paths));
        assert!(doc.issues.is_empty(), "{:?}", doc.issues);
    }

    // ----------------------------------------------------------- Strictness

    #[test]
    fn strict_error_classification_covers_the_m2_kinds() {
        assert!(IssueKind::MediaTypeRefUnresolved.is_strict_error());
        assert!(IssueKind::DefaultMappingUnresolved.is_strict_error());
        assert!(IssueKind::SecurityRequirementUnresolved.is_strict_error());
        assert!(!IssueKind::StreamingDeclared.is_strict_error());
        assert!(!IssueKind::NonJsonRequestBody.is_strict_error());
        assert!(!IssueKind::DeprecatedSecurityScheme.is_strict_error());
        assert!(!IssueKind::NotServed.is_strict_error());
    }

    // ------------------------------------------------------------------ W4

    fn security_doc(schemes_yaml: &str, paths_yaml: &str, top_level: &str) -> OpenApiDocument {
        let yaml = format!("openapi: 3.2.0\ninfo: {{ title: t, version: 1 }}\n{top_level}components:\n  securitySchemes:\n{schemes_yaml}\npaths:\n{paths_yaml}\n");
        load_yaml(&yaml)
    }

    fn op_with_security(path: &str, id: &str, security: &str) -> String {
        format!("  {path}:\n    get:\n      operationId: {id}\n      security: {security}\n      responses:\n        '200': {{ description: ok }}\n")
    }

    #[test]
    fn a_deprecated_scheme_in_use_raises_w4_with_the_exact_text_and_deduped_users() {
        let paths = format!(
            "{}{}",
            op_with_security("/b", "b", "[ { old: [] }, { old: [] } ]"),
            op_with_security("/a", "a", "[ { old: [] } ]")
        );
        let doc = security_doc("    old: { type: apiKey, in: header, name: k, deprecated: true }", &paths, "");
        let w4 = issues_of(&doc, IssueKind::DeprecatedSecurityScheme);
        assert_eq!(w4.len(), 1);
        assert_eq!(w4[0].severity, Severity::Warning);
        assert_eq!(w4[0].message, "security scheme 'old' is marked deprecated in openapi.yaml (used by: GET /b, GET /a)");
        assert_eq!(doc.deprecated_security_schemes, HashSet::from(["old".to_string()]));
    }

    #[test]
    fn deprecated_scheme_warnings_are_sorted_by_scheme_name() {
        let paths = format!(
            "{}{}",
            op_with_security("/a", "a", "[ { zed: [] } ]"),
            op_with_security("/b", "b", "[ { alpha: [] } ]")
        );
        let doc = security_doc(
            "    zed: { type: apiKey, in: header, name: k, deprecated: true }\n    alpha: { type: apiKey, in: header, name: k, deprecated: true }",
            &paths,
            "",
        );
        let msgs = doc.deprecated_scheme_warnings();
        assert_eq!(msgs.len(), 2);
        assert!(msgs[0].contains("'alpha'") && msgs[1].contains("'zed'"), "{msgs:?}");
    }

    #[test]
    fn a_deprecated_scheme_nobody_uses_or_a_string_true_raises_nothing() {
        let paths = op_with_security("/a", "a", "[ { other: [] } ]");
        let doc = security_doc(
            "    unused: { type: apiKey, in: header, name: k, deprecated: true }\n    other: { type: apiKey, in: header, name: k, deprecated: 'true' }",
            &paths,
            "",
        );
        assert!(issues_of(&doc, IssueKind::DeprecatedSecurityScheme).is_empty(), "{:?}", doc.issues);
        assert!(!doc.deprecated_security_schemes.contains("other"));
    }

    #[test]
    fn a_deprecated_scheme_used_only_as_the_second_key_of_an_and_requirement_is_still_reported() {
        let paths = op_with_security("/a", "a", "[ { fresh: [], old: [] } ]");
        let doc = security_doc(
            "    fresh: { type: apiKey, in: header, name: k }\n    old: { type: apiKey, in: header, name: k, deprecated: true }",
            &paths,
            "",
        );
        let w4 = issues_of(&doc, IssueKind::DeprecatedSecurityScheme);
        assert_eq!(w4.len(), 1, "{:?}", doc.issues);
        assert!(w4[0].message.contains("'old'"));
        assert_eq!(doc.operations[0].security.as_deref(), Some("fresh"));
        assert_eq!(doc.operations[0].declared_security_schemes, vec!["fresh".to_string(), "old".to_string()]);
    }

    #[test]
    fn a_deprecated_scheme_inherited_from_top_level_security_is_reported_for_the_inheriting_operation() {
        let paths = "  /a:\n    get:\n      operationId: a\n      responses:\n        '200': { description: ok }\n";
        let doc = security_doc(
            "    old: { type: apiKey, in: header, name: k, deprecated: true }",
            paths,
            "security: [ { old: [] } ]\n",
        );
        let w4 = issues_of(&doc, IssueKind::DeprecatedSecurityScheme);
        assert_eq!(w4.len(), 1, "{:?}", doc.issues);
        assert!(w4[0].message.contains("GET /a"));
    }

    // ------------------------------------------------------------------ S11

    const KEYS_SCHEME: &str = "    keyA: { type: apiKey, in: header, name: k }";

    #[test]
    fn security_requirement_names_resolve_exact_ref_and_plain_undeclared_forms_without_issues() {
        let paths = format!(
            "{}{}{}",
            op_with_security("/a", "a", "[ { keyA: [] } ]"),
            op_with_security("/b", "b", "[ { '#/components/securitySchemes/keyA': [] } ]"),
            op_with_security("/c", "c", "[ { undeclaredPlain: [] } ]"),
        );
        let doc = security_doc(KEYS_SCHEME, &paths, "");
        assert!(doc.issues.is_empty(), "{:?}", doc.issues);
        let sec = |p: &str| doc.operations.iter().find(|o| o.path == p).unwrap().security.clone();
        assert_eq!(sec("/a").as_deref(), Some("keyA"));
        assert_eq!(sec("/b").as_deref(), Some("keyA"));
        assert_eq!(sec("/c").as_deref(), Some("undeclaredPlain"));
    }

    #[test]
    fn an_unknown_scheme_ref_or_a_uri_is_kept_verbatim_with_an_s11_warning() {
        let paths = format!(
            "{}{}",
            op_with_security("/a", "a", "[ { '#/components/securitySchemes/Nope': [] } ]"),
            op_with_security("/b", "b", "[ { 'https://x/y': [] } ]"),
        );
        let doc = security_doc(KEYS_SCHEME, &paths, "");
        let s11 = issues_of(&doc, IssueKind::SecurityRequirementUnresolved);
        assert_eq!(s11.len(), 2, "{:?}", doc.issues);
        assert!(s11.iter().all(|i| i.severity == Severity::Warning));
        assert!(s11[0].message.starts_with("GET /a: security requirement "), "{}", s11[0].message);
        assert!(s11[0].message.contains("kept verbatim"));
        let sec = |p: &str| doc.operations.iter().find(|o| o.path == p).unwrap().security.clone();
        assert_eq!(sec("/a").as_deref(), Some("#/components/securitySchemes/Nope"));
        assert_eq!(sec("/b").as_deref(), Some("https://x/y"));
    }

    #[test]
    fn a_bad_top_level_security_inherited_by_three_operations_raises_exactly_one_s11() {
        let no_security = |path: &str, id: &str| {
            format!(
                "  {path}:
    get:
      operationId: {id}
      responses:
        '200': {{ description: ok }}
"
            )
        };
        let paths = format!("{}{}{}", no_security("/a", "a"), no_security("/b", "b"), no_security("/c", "c"));
        let doc = security_doc(KEYS_SCHEME, &paths, "security: [ { 'https://x/y': [] } ]\n");
        assert_eq!(doc.operations.len(), 3);
        let s11 = issues_of(&doc, IssueKind::SecurityRequirementUnresolved);
        assert_eq!(s11.len(), 1, "{:?}", doc.issues);
        assert!(s11[0].message.starts_with("top-level security: "), "{}", s11[0].message);
        assert!(doc.operations.iter().all(|o| o.security.as_deref() == Some("https://x/y")));
    }

    #[test]
    fn an_explicit_empty_security_list_opts_out_of_the_top_level_default() {
        let paths = op_with_security("/a", "a", "[]");
        let doc = security_doc(KEYS_SCHEME, &paths, "security: [ { keyA: [] } ]\n");
        assert_eq!(doc.operations[0].security, None);
        assert!(doc.operations[0].declared_security_schemes.is_empty());
    }

    #[test]
    fn security_scheme_names_with_control_characters_are_escaped_in_the_s11_message() {
        let paths = op_with_security("/a", "a", "[ { \"bad\\u001b[31m name\": [] } ]");
        let doc = security_doc(KEYS_SCHEME, &paths, "");
        let s11 = issues_of(&doc, IssueKind::SecurityRequirementUnresolved);
        assert_eq!(s11.len(), 1, "{:?}", doc.issues);
        assert!(!s11[0].message.contains('\u{1b}'));
    }
}

#[cfg(test)]
mod m2_7_security_alternatives_tests {
    use super::*;

    fn load_yaml(yaml: &str) -> OpenApiDocument {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "frogs-openapi-m27-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("openapi.yaml");
        std::fs::write(&path, yaml).unwrap();
        let doc = load_with_policy(&path, PortabilityPolicy::Warn, LoadOptions::default()).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        doc
    }

    fn doc_with(top: &str, op_security_line: &str) -> OpenApiDocument {
        load_yaml(&format!(
            "openapi: 3.2.0\ninfo: {{ title: t, version: 1 }}\n{top}components:\n  securitySchemes:\n    a: {{ type: apiKey, in: header, name: k }}\n    b: {{ type: apiKey, in: header, name: k2 }}\n    c: {{ type: apiKey, in: header, name: k3 }}\npaths:\n  /p:\n    get:\n      operationId: p\n{op_security_line}      responses:\n        '200': {{ description: ok }}\n"
        ))
    }

    fn alts(doc: &OpenApiDocument) -> Vec<Vec<String>> {
        doc.operations[0].security_alternatives.clone()
    }

    fn v(items: &[&[&str]]) -> Vec<Vec<String>> {
        items.iter().map(|alt| alt.iter().map(|s| s.to_string()).collect()).collect()
    }

    fn collapsed(doc: &OpenApiDocument) -> Vec<&LoadIssue> {
        doc.issues.iter().filter(|i| i.kind == IssueKind::SecurityRequirementCollapsed).collect()
    }

    #[test]
    fn an_operations_own_requirement_objects_become_one_inner_list_each_in_spec_order() {
        let doc = doc_with("", "      security: [ { a: [] }, { c: [], b: [] } ]\n");
        assert_eq!(alts(&doc), v(&[&["a"], &["c", "b"]]));
        assert_eq!(doc.operations[0].security.as_deref(), Some("a"));
    }

    #[test]
    fn an_operation_without_security_inherits_the_document_default() {
        let doc = doc_with("security: [ { b: [] } ]\n", "");
        assert_eq!(alts(&doc), v(&[&["b"]]));
    }

    #[test]
    fn an_explicit_empty_security_list_gives_no_alternatives_even_with_a_document_default() {
        let doc = doc_with("security: [ { b: [] } ]\n", "      security: []\n");
        assert!(alts(&doc).is_empty());
    }

    #[test]
    fn an_empty_requirement_object_is_an_empty_inner_list() {
        let doc = doc_with("", "      security: [ {}, { a: [] } ]\n");
        assert_eq!(alts(&doc), v(&[&[], &["a"]]));
    }

    #[test]
    fn scheme_ref_keys_are_resolved_to_names_and_unresolvable_ones_kept_verbatim_with_s11() {
        let doc = doc_with("", "      security: [ { '#/components/securitySchemes/a': [] }, { 'https://x/y': [] } ]\n");
        assert_eq!(alts(&doc), v(&[&["a"], &["https://x/y"]]));
        assert_eq!(doc.issues.iter().filter(|i| i.kind == IssueKind::SecurityRequirementUnresolved).count(), 1);
    }

    #[test]
    fn a_multi_key_requirement_object_raises_one_non_strict_collapse_warning_naming_the_enforced_scheme() {
        let doc = doc_with("", "      security: [ { a: [], b: [] }, { c: [] } ]\n");
        let issues = collapsed(&doc);
        assert_eq!(issues.len(), 1, "{:?}", doc.issues);
        assert_eq!(issues[0].severity, Severity::Warning);
        assert!(!issues[0].kind.is_strict_error());
        assert_eq!(issues[0].message, "GET /p: security requirement combines schemes ('a', 'b'); frogs enforces only 'a'");
    }

    #[test]
    fn two_multi_key_objects_raise_two_warnings_and_single_key_objects_none() {
        let doc = doc_with("", "      security: [ { a: [], b: [] }, { b: [], c: [] }, { a: [] } ]\n");
        assert_eq!(collapsed(&doc).len(), 2);
        let doc = doc_with("", "      security: [ { a: [] }, { b: [] } ]\n");
        assert!(collapsed(&doc).is_empty());
    }

    #[test]
    fn a_collapsed_document_default_is_reported_once_as_top_level_security_however_many_ops_inherit_it() {
        let yaml = "openapi: 3.2.0\ninfo: { title: t, version: 1 }\nsecurity: [ { a: [], b: [] } ]\ncomponents:\n  securitySchemes:\n    a: { type: apiKey, in: header, name: k }\n    b: { type: apiKey, in: header, name: k2 }\npaths:\n  /p:\n    get:\n      operationId: p\n      responses:\n        '200': { description: ok }\n  /q:\n    get:\n      operationId: q\n      responses:\n        '200': { description: ok }\n";
        let doc = load_yaml(yaml);
        let issues = collapsed(&doc);
        assert_eq!(issues.len(), 1, "{:?}", doc.issues);
        assert!(issues[0].message.starts_with("top-level security: "), "{}", issues[0].message);
        assert!(doc.operations.iter().all(|o| o.security_alternatives == v(&[&["a", "b"]])));
    }
}

#[cfg(test)]
mod m3_query_tests {
    use super::*;

    fn tempdir() -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "frogs-openapi-m3-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn load_yaml(yaml: &str) -> Result<OpenApiDocument, OpenApiError> {
        let dir = tempdir();
        let path = dir.join("openapi.yaml");
        std::fs::write(&path, yaml).unwrap();
        let result = load(&path, LoadOptions::default());
        let _ = std::fs::remove_dir_all(&dir);
        result
    }

    fn spec(version_line: &str) -> String {
        format!(
            "{version_line}info: {{ title: t, version: '1' }}\npaths:\n  /things:\n    get:\n      operationId: getThings\n      responses: {{ '200': {{ description: ok }} }}\n    query:\n      operationId: queryThings\n      responses: {{ '200': {{ description: ok }} }}\n"
        )
    }

    fn newer_version_issues(doc: &OpenApiDocument) -> Vec<&LoadIssue> {
        doc.issues.iter().filter(|i| i.kind == IssueKind::OperationNeedsNewerVersion).collect()
    }

    #[test]
    fn a_3_2_spec_loads_a_query_operation_with_token_and_wire_method_and_no_issue() {
        let doc = load_yaml(&spec("openapi: 3.2.0\n")).unwrap();
        let q = doc.operations.iter().find(|o| o.operation_id == "queryThings").unwrap();
        assert_eq!(q.method, "query");
        assert_eq!(q.http_method, "QUERY");
        let g = doc.operations.iter().find(|o| o.operation_id == "getThings").unwrap();
        assert_eq!((g.method.as_str(), g.http_method.as_str()), ("get", "GET"));
        assert!(doc.issues.is_empty(), "{:?}", doc.issues);
    }

    #[test]
    fn query_on_a_3_0_or_3_1_document_raises_exactly_one_strict_warning_each() {
        for version in ["3.0.3", "3.1.0"] {
            let doc = load_yaml(&spec(&format!("openapi: {version}\n"))).unwrap();
            assert!(doc.operations.iter().any(|o| o.http_method == "QUERY"), "still served: {version}");
            let found = newer_version_issues(&doc);
            assert_eq!(found.len(), 1, "{version}: {:?}", doc.issues);
            assert_eq!(found[0].severity, Severity::Warning);
            assert!(found[0].kind.is_strict_error());
            assert!(found[0].message.contains("QUERY /things (operationId queryThings)"), "{}", found[0].message);
            assert!(found[0].message.contains(&format!("openapi {}", &version[..3])), "{}", found[0].message);
        }
    }

    #[test]
    fn a_missing_version_gets_only_the_missing_version_issue_not_the_query_one() {
        let doc = load_yaml(&spec("")).unwrap();
        assert!(newer_version_issues(&doc).is_empty(), "{:?}", doc.issues);
        assert!(doc.issues.iter().any(|i| i.kind == IssueKind::VersionMissing));
    }

    #[test]
    fn a_query_operation_without_an_operation_id_is_the_same_hard_error_as_any_other_method() {
        let yaml = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths:\n  /things:\n    query:\n      responses: { '200': { description: ok } }\n";
        match load_yaml(yaml) {
            Err(OpenApiError::MissingOperationId { path, method }) => {
                assert_eq!(path, "/things");
                assert_eq!(method, "query");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn query_is_no_longer_reported_as_not_served_but_additional_operations_still_are() {
        let yaml = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths:\n  /things:\n    query:\n      operationId: q\n      responses: { '200': { description: ok } }\n    additionalOperations:\n      PURGE:\n        operationId: p\n        responses: { '200': { description: ok } }\n";
        let doc = load_yaml(yaml).unwrap();
        let not_served: Vec<_> = doc.issues.iter().filter(|i| i.kind == IssueKind::NotServed).collect();
        assert_eq!(not_served.len(), 1, "{:?}", doc.issues);
        assert!(!not_served[0].message.to_lowercase().contains("query"), "{}", not_served[0].message);
    }

    #[test]
    fn operation_order_for_a_spec_without_query_follows_the_historical_field_order() {
        let yaml = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths:\n  /a:\n    patch: { operationId: pa, responses: { '200': { description: ok } } }\n    delete: { operationId: de, responses: { '200': { description: ok } } }\n    post: { operationId: po, responses: { '200': { description: ok } } }\n    get: { operationId: ge, responses: { '200': { description: ok } } }\n    put: { operationId: pu, responses: { '200': { description: ok } } }\n";
        let doc = load_yaml(yaml).unwrap();
        let order: Vec<_> = doc.operations.iter().map(|o| o.method.as_str()).collect();
        assert_eq!(order, ["get", "put", "post", "delete", "patch"]);
    }

    #[test]
    fn the_http_method_of_every_operation_comes_from_the_constant_table() {
        let yaml = "openapi: 3.2.0\ninfo: { title: t, version: '1' }\npaths:\n  /a:\n    get: { operationId: g, responses: { '200': { description: ok } } }\n    trace: { operationId: t, responses: { '200': { description: ok } } }\n    head: { operationId: h, responses: { '200': { description: ok } } }\n";
        let doc = load_yaml(yaml).unwrap();
        for op in &doc.operations {
            assert_eq!(op.http_method, op.method.to_ascii_uppercase());
        }
    }
}
