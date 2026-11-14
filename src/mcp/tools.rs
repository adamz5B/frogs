//! The tool table: which endpoints become MCP tools, their JSON-Schema input, and how a
//! `tools/call` argument object is split back into the path/query/body an endpoint expects.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use serde_json::value::RawValue;
use serde_json::{Map, Value, json};

use super::auth::cache_scope;
use super::protocol::ProtoError;
use super::settings::AuthSettings;
use crate::config::{DEFAULT_MCP_LIST_TTL_MS, McpConfig};
use crate::endpoint::{EndpointFile, find_operation, match_key};
use crate::openapi::json_schema::{InlineBudget, contains_number_type, inline_component_refs};
use crate::openapi::route_syntax::axum_style;
use crate::openapi::{OpenApiDocument, Operation, ParameterInfo, untrusted};

const MAX_MCP_TOOLS_LIST_BYTES: usize = 1024 * 1024;
const MAX_TOOL_NAME_BYTES: usize = 128;
const VERBATIM_NOTE: &str = "The raw HTTP value is passed through verbatim.";
const NUMBERS_NOTE: &str = "Numbers in `body` are processed as IEEE-754 doubles.";
const BODY_ARGUMENT: &str = "body";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArgLoc {
    Path,
    Query,
    Body,
}

/// One endpoint file considered for exposure; built from either a pre-bind decision or a route
/// the router actually registered.
pub(crate) struct Candidate<'a> {
    pub url_path: &'a str,
    pub token: &'a str,
    pub file: &'a Path,
    pub endpoint: &'a EndpointFile,
}

pub(crate) struct McpBlock {
    pub expose: bool,
    name: Option<String>,
    description: Option<String>,
}

impl McpBlock {
    pub(crate) fn name_or(&self, fallback: &str) -> String {
        self.name.clone().unwrap_or_else(|| fallback.to_string())
    }
}

/// Interprets an endpoint file's lenient `mcp` value. A typo in a key is a problem, not a silent
/// "not exposed".
pub(crate) fn parse_block(value: &Value) -> Result<McpBlock, String> {
    let Value::Object(map) = value else {
        return Err("\"mcp\" must be an object".to_string());
    };
    if let Some(key) = map.keys().find(|key| !matches!(key.as_str(), "expose" | "name" | "description")) {
        return Err(format!("\"mcp\" has an unknown key '{}' (allowed: expose, name, description)", untrusted(key)));
    }
    let Some(Value::Bool(expose)) = map.get("expose") else {
        return Err("\"mcp.expose\" must be true or false".to_string());
    };
    let text = |key: &str| match map.get(key) {
        None => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(format!("\"mcp.{key}\" must be a string")),
    };
    Ok(McpBlock {
        expose: *expose,
        name: text("name")?,
        description: text("description")?,
    })
}

pub(crate) struct ToolSpec {
    pub name: String,
    /// Index into the candidate slice the plan was built from.
    pub index: usize,
    pub args: HashMap<String, ArgLoc>,
    pub path_params: Vec<String>,
    /// The endpoint file's `securityScopes`, which the 403 challenge names.
    pub security_scopes: Vec<String>,
    definition: Value,
}

pub(crate) struct ToolPlan {
    pub tools: Vec<ToolSpec>,
    pub list_modern: Box<RawValue>,
    pub list_legacy: Box<RawValue>,
}

#[derive(Default)]
pub(crate) struct Planned {
    pub plan: Option<ToolPlan>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

fn is_valid_tool_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_TOOL_NAME_BYTES && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

fn type_names(schema: &Value) -> Vec<&str> {
    match schema.get("type") {
        Some(Value::String(name)) => vec![name.as_str()],
        Some(Value::Array(names)) => names.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
}

fn template_params(url_path: &str) -> Vec<String> {
    url_path.split('/').filter_map(|segment| segment.strip_prefix(':')).map(str::to_string).collect()
}

struct BuiltTool {
    name: String,
    definition: Value,
    args: HashMap<String, ArgLoc>,
    path_params: Vec<String>,
}

fn annotations_for(op: &Operation) -> Value {
    match op.http_method.to_ascii_uppercase().as_str() {
        "GET" | "QUERY" => json!({ "readOnlyHint": true, "idempotentHint": true, "openWorldHint": false }),
        "DELETE" => json!({ "readOnlyHint": false, "destructiveHint": true, "idempotentHint": true, "openWorldHint": false }),
        "PUT" => json!({ "readOnlyHint": false, "idempotentHint": true, "openWorldHint": false }),
        _ => json!({ "readOnlyHint": false, "openWorldHint": false }),
    }
}

fn parameter_schema(param: &ParameterInfo, components: &Map<String, Value>, budget: &mut InlineBudget) -> Result<Value, String> {
    let mut schema = match &param.schema {
        Some(raw) => inline_component_refs(raw, components, budget).map_err(|_| format!("parameter '{}' is over the schema size budget", untrusted(&param.name)))?,
        None => json!({}),
    };
    if !schema.is_object() {
        schema = json!({});
    }
    let non_scalar = param.from_content || type_names(&schema).iter().any(|name| matches!(*name, "array" | "object"));
    let mut description = schema
        .get("description")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| param.description.clone());
    if non_scalar {
        schema = json!({ "type": "string" });
        description = Some(match description {
            Some(text) => format!("{text} {VERBATIM_NOTE}"),
            None => VERBATIM_NOTE.to_string(),
        });
    }
    if let Some(text) = description {
        schema["description"] = Value::String(text);
    }
    Ok(schema)
}

fn build_tool(candidate: &Candidate, block: &McpBlock, doc: Option<&OpenApiDocument>) -> Result<BuiltTool, Vec<String>> {
    let Some(doc) = doc else {
        return Err(vec![
            "is exposed over MCP but openapi.yaml could not be loaded, so there is no operation to describe — fix the spec load error".to_string(),
        ]);
    };
    let Some(op) = find_operation(doc, candidate.url_path, candidate.token) else {
        let fallback = doc
            .operations
            .iter()
            .chain(&doc.ambiguous_operations)
            .find(|op| op.method == candidate.token && match_key(&axum_style(&op.path)) == match_key(candidate.url_path));
        return Err(vec![match fallback {
            Some(op) => format!(
                "is exposed over MCP but its folder does not match the spec path template exactly — rename the folder to '{}' (the spec's own parameter names and letter case)",
                untrusted(&op.path)
            ),
            None => "is exposed over MCP but openapi.yaml has no operation for this path and method".to_string(),
        }]);
    };

    let mut problems = Vec::new();
    let name = match &block.name {
        Some(name) => name.clone(),
        None => op.operation_id.clone(),
    };
    if block.name.is_none() && name.trim().is_empty() {
        problems.push("is exposed over MCP but the operation has an empty operationId — set \"mcp.name\"".to_string());
    } else if !is_valid_tool_name(&name) {
        problems.push(format!(
            "tool name '{}' is not valid (1-{MAX_TOOL_NAME_BYTES} characters from A-Z a-z 0-9 _ . -) — set \"mcp.name\"",
            untrusted(&name)
        ));
    }

    let template = template_params(candidate.url_path);
    let path_declared: Vec<&ParameterInfo> = op.parameters.iter().filter(|p| p.location == "path").collect();
    for placeholder in &template {
        if !path_declared.iter().any(|p| &p.name == placeholder) {
            problems.push(format!(
                "route template parameter '{}' is not declared as a path parameter in openapi.yaml",
                untrusted(placeholder)
            ));
        }
    }
    let mut args: HashMap<String, ArgLoc> = HashMap::new();
    let mut ordered: Vec<(&ParameterInfo, ArgLoc)> = Vec::new();
    for placeholder in &template {
        if let Some(param) = path_declared.iter().find(|p| &p.name == placeholder) {
            ordered.push((param, ArgLoc::Path));
        }
    }
    for param in op.parameters.iter().filter(|p| p.location == "query") {
        if ordered.iter().any(|(existing, _)| existing.name == param.name) {
            problems.push(format!("path and query parameters share the name '{}'", untrusted(&param.name)));
            continue;
        }
        ordered.push((param, ArgLoc::Query));
    }
    if op.request_body.is_some() && ordered.iter().any(|(param, _)| param.name == BODY_ARGUMENT) {
        problems.push("has a parameter named 'body' while the operation also has a request body — the argument name would be ambiguous".to_string());
    }
    if !problems.is_empty() {
        return Err(problems);
    }

    let mut budget = InlineBudget::new();
    let mut properties = Map::new();
    let mut required: Vec<Value> = Vec::new();
    for (param, location) in &ordered {
        let schema = parameter_schema(param, &doc.component_schemas, &mut budget).map_err(|message| vec![message])?;
        properties.insert(param.name.clone(), schema);
        args.insert(param.name.clone(), *location);
        if *location == ArgLoc::Path || param.required {
            required.push(Value::String(param.name.clone()));
        }
    }
    let mut numbers_in_body = false;
    if let Some(body) = &op.request_body {
        let schema =
            inline_component_refs(&body.schema, &doc.component_schemas, &mut budget).map_err(|_| vec!["request body is over the schema size budget".to_string()])?;
        numbers_in_body = contains_number_type(&schema);
        properties.insert(BODY_ARGUMENT.to_string(), schema);
        args.insert(BODY_ARGUMENT.to_string(), ArgLoc::Body);
        if body.required {
            required.push(Value::String(BODY_ARGUMENT.to_string()));
        }
    }

    let mut input_schema = Map::new();
    input_schema.insert("type".to_string(), json!("object"));
    input_schema.insert("properties".to_string(), Value::Object(properties));
    if !required.is_empty() {
        input_schema.insert("required".to_string(), Value::Array(required));
    }
    input_schema.insert("additionalProperties".to_string(), json!(false));

    let mut description = block
        .description
        .clone()
        .or_else(|| op.summary.clone())
        .or_else(|| op.description.clone())
        .unwrap_or_default();
    if numbers_in_body {
        if !description.is_empty() {
            description.push(' ');
        }
        description.push_str(NUMBERS_NOTE);
    }
    let mut definition = Map::new();
    definition.insert("name".to_string(), Value::String(name.clone()));
    if let Some(title) = &op.summary {
        definition.insert("title".to_string(), Value::String(title.clone()));
    }
    if !description.is_empty() {
        definition.insert("description".to_string(), Value::String(description));
    }
    definition.insert("inputSchema".to_string(), Value::Object(input_schema));
    definition.insert("annotations".to_string(), annotations_for(op));

    Ok(BuiltTool {
        name,
        definition: Value::Object(definition),
        args,
        path_params: template,
    })
}

fn largest_tools(tools: &[ToolSpec]) -> String {
    let mut sizes: Vec<(usize, &str)> = tools.iter().map(|tool| (tool.definition.to_string().len(), tool.name.as_str())).collect();
    sizes.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(b.1)));
    sizes
        .iter()
        .take(3)
        .map(|(size, name)| format!("'{}' ({size} bytes)", untrusted(name)))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Decides every tool from the accepted routes: the single place FR12-13 live. `plan` is `Some`
/// exactly when `errors` is empty.
pub(crate) fn plan_tools(candidates: &[Candidate], doc: Option<&OpenApiDocument>, settings: &McpConfig, auth: &AuthSettings) -> Planned {
    let mut planned = Planned::default();
    let mut tools: Vec<ToolSpec> = Vec::new();
    let mut owners: HashMap<String, String> = HashMap::new();
    for (index, candidate) in candidates.iter().enumerate() {
        let Some(value) = &candidate.endpoint.mcp else { continue };
        let file = untrusted(&candidate.file.display().to_string());
        let block = match parse_block(value) {
            Ok(block) => block,
            Err(message) => {
                planned.errors.push(format!("{file}: {message}"));
                continue;
            }
        };
        if !block.expose {
            continue;
        }
        match build_tool(candidate, &block, doc) {
            Ok(built) => {
                if let Some(first) = owners.get(&built.name) {
                    planned.errors.push(format!(
                        "{file}: tool name '{}' is already used by {first} — set a distinct \"mcp.name\"",
                        untrusted(&built.name)
                    ));
                    continue;
                }
                owners.insert(built.name.clone(), file.clone());
                if candidate.endpoint.generated {
                    planned.warnings.push(format!(
                        "{file}: is exposed over MCP but is still a generated stub (\"_generated\": true) — calls answer 501"
                    ));
                }
                if let Some(protected) = &auth.protected
                    && !candidate.endpoint.security_scopes.is_empty()
                {
                    let outside: Vec<&String> = candidate
                        .endpoint
                        .security_scopes
                        .iter()
                        .filter(|scope| !protected.scopes_supported.contains(scope))
                        .collect();
                    if !outside.is_empty() {
                        planned.warnings.push(format!(
                            "{file}: tool '{}' requires scope(s) {} that are not listed in mcp.protectedResource.scopesSupported",
                            untrusted(&built.name),
                            outside.iter().map(|scope| untrusted(scope)).collect::<Vec<_>>().join(", ")
                        ));
                    }
                }
                if auth.access_scheme.is_none()
                    && let Some(scheme) = &candidate.endpoint.security
                {
                    planned.warnings.push(format!(
                        "{file}: tool '{}' is listed to anyone who can reach /mcp (tools/list is not authenticated); calls still require security scheme '{}'",
                        untrusted(&built.name),
                        untrusted(scheme)
                    ));
                }
                tools.push(ToolSpec {
                    name: built.name,
                    index,
                    args: built.args,
                    path_params: built.path_params,
                    security_scopes: candidate.endpoint.security_scopes.clone(),
                    definition: built.definition,
                });
            }
            Err(problems) => planned.errors.extend(problems.into_iter().map(|problem| format!("{file}: {problem}"))),
        }
    }
    if !planned.errors.is_empty() {
        return planned;
    }
    tools.sort_by(|a, b| a.name.cmp(&b.name));
    if auth.protected.as_ref().is_some_and(|protected| protected.scopes_supported.is_empty()) && !tools.is_empty() {
        planned
            .warnings
            .push("mcp.protectedResource.scopesSupported is empty: clients get no scope hint in the metadata or the WWW-Authenticate challenge".to_string());
    }

    let definitions: Vec<&Value> = tools.iter().map(|tool| &tool.definition).collect();
    let ttl = settings.list_ttl_ms.unwrap_or(DEFAULT_MCP_LIST_TTL_MS);
    let modern = json!({ "tools": definitions, "ttlMs": ttl, "cacheScope": cache_scope(auth), "resultType": "complete" });
    let legacy = json!({ "tools": definitions });
    let (Ok(list_modern), Ok(list_legacy)) = (serde_json::value::to_raw_value(&modern), serde_json::value::to_raw_value(&legacy)) else {
        planned.errors.push("the tools/list result could not be serialised".to_string());
        return planned;
    };
    for (variant, raw) in [("modern", &list_modern), ("legacy", &list_legacy)] {
        if raw.get().len() > MAX_MCP_TOOLS_LIST_BYTES {
            planned.errors.push(format!(
                "the {variant} tools/list result is {} bytes, over the {MAX_MCP_TOOLS_LIST_BYTES}-byte limit — shrink or unexpose tools; largest: {}",
                raw.get().len(),
                largest_tools(&tools)
            ));
        }
    }
    if planned.errors.is_empty() {
        planned.plan = Some(ToolPlan { tools, list_modern, list_legacy });
    }
    planned
}

/// The path and query maps and body `execute` takes, built from a `tools/call` argument object.
pub(crate) struct SplitArgs {
    pub path: HashMap<String, String>,
    pub query: HashMap<String, String>,
    pub body: Value,
}

/// FR14 steps 3-4. Strings are JSON-unescaped, numbers keep their raw token text, booleans become
/// `true`/`false`, `null` means absent; an array or object for a path/query parameter, an unknown
/// name, a missing template parameter and an unparseable `body` are all `-32602`. The values only
/// ever become map entries that SQL binds and HTTP sources percent-encode, exactly as for a
/// real HTTP request; nothing here joins them into a path or URL.
pub(crate) fn split_arguments(args: &HashMap<String, ArgLoc>, path_params: &[String], arguments: Option<&RawValue>) -> Result<SplitArgs, ProtoError> {
    let supplied: BTreeMap<String, Box<RawValue>> = match arguments {
        None => BTreeMap::new(),
        Some(raw) => serde_json::from_str(raw.get()).map_err(|_| ProtoError::invalid_params())?,
    };
    let mut split = SplitArgs {
        path: HashMap::new(),
        query: HashMap::new(),
        body: Value::Null,
    };
    for (name, raw) in supplied {
        let Some(location) = args.get(&name) else {
            return Err(ProtoError::invalid_params());
        };
        let text = raw.get();
        if *location == ArgLoc::Body {
            split.body = serde_json::from_str::<Value>(text).map_err(|_| ProtoError::invalid_params())?;
            continue;
        }
        let value = match text.as_bytes().first() {
            Some(b'"') => serde_json::from_str::<String>(text).map_err(|_| ProtoError::invalid_params())?,
            Some(b'n') => continue,
            Some(b'[' | b'{') => return Err(ProtoError::invalid_params()),
            _ => text.to_string(),
        };
        match location {
            ArgLoc::Path => split.path.insert(name, value),
            _ => split.query.insert(name, value),
        };
    }
    if path_params.iter().any(|name| split.path.get(name).is_none_or(String::is_empty)) {
        return Err(ProtoError::invalid_params());
    }
    Ok(split)
}
