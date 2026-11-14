//! The runtime MCP server: a stateless `POST <apiRoot>/mcp` that exposes opted-in endpoints as
//! tools and runs every call through the very same `RouteState::execute` an HTTP request uses.
//! See `docs/frogs-mcp.md` and `docs/frogs-mcp-m1-plan.md`.

mod auth;
pub(crate) mod authoring;
mod metadata;
mod protocol;
mod settings;
mod tools;
mod transport;

#[cfg(test)]
mod auth_gate_tests;
#[cfg(test)]
mod auth_tests;
#[cfg(test)]
mod metadata_tests;
#[cfg(test)]
mod protocol_stdio_tests;
#[cfg(test)]
mod protocol_tests;
#[cfg(test)]
mod settings_tests;
#[cfg(test)]
mod tools_tests;
#[cfg(test)]
mod transport_tests;

use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Request as HttpRequest, State};
use axum::http::request::Parts;
use axum::response::Response;
use axum::routing::any;
use serde_json::value::RawValue;
use serde_json::{Value, json};

use crate::config::{ConnectionConfig, DEFAULT_MCP_LIST_TTL_MS, McpConfig, ServerConfig};
use crate::endpoint::mock::{SOURCE_NOT_MOCKED, VERIFIER_MOCK_KEY};
use crate::endpoint::{AcceptedRoute, MockOutcome, OwnedAuthContext, RouteDecision, RouteState, accept_routes, authorize};
use crate::openapi::endpoint_tree::EndpointTree;
use crate::openapi::method_token::MethodCase;
use crate::openapi::{OpenApiDocument, untrusted};
use crate::security::{ClientCertIdentity, SecurityConfig};
use crate::server::{RateLimiter, RequestId};
use protocol::{Era, ProtoError};
pub(crate) use settings::{AuthSettings, final_path, is_scope_token, parse_auth_settings};
use tools::{Candidate, Planned, ToolPlan};

/// The apiRoot-relative path of the endpoint.
pub(crate) const MCP_PATH: &str = "/mcp";

const MAX_MCP_DISCOVER_BYTES: usize = 64 * 1024;
const DEFAULT_SERVER_NAME: &str = "frogs-api";
const UNVERSIONED: &str = "unversioned";
const HTTP_STATUS_META: &str = "frogs/httpStatus";
const RETRY_AFTER_META: &str = "frogs/retryAfterSeconds";

struct Tool {
    args: HashMap<String, tools::ArgLoc>,
    path_params: Vec<String>,
    route: Arc<RouteState>,
    limiter: Option<Arc<RateLimiter>>,
}

/// The `accessScheme` gate: runs the shared `authorize` for `tools/list` and `tools/call` before
/// anything about the request is looked at.
struct Gate {
    scheme: String,
    ctx: OwnedAuthContext,
    /// Empty under `frogs run`, always: only a `MockProvider` can put anything here.
    mocks: HashMap<String, MockOutcome>,
}

/// What `build_router` needs to build the gate. `mock` is `None` under `frogs run` (the real
/// verifier runs) and `Some(file value)` under `frogs test`.
pub(crate) struct GateParts {
    pub ctx: OwnedAuthContext,
    pub mock: Option<Option<MockOutcome>>,
}

struct McpState {
    guard: transport::Guard,
    gate: Option<Gate>,
    challenges: Option<auth::Challenges>,
    tools: HashMap<String, Tool>,
    discover: Box<RawValue>,
    initialize: HashMap<&'static str, Box<RawValue>>,
    list_modern: Box<RawValue>,
    list_legacy: Box<RawValue>,
}

struct StaticResults {
    discover: Box<RawValue>,
    initialize: HashMap<&'static str, Box<RawValue>>,
}

fn server_info(doc: Option<&OpenApiDocument>, settings: &McpConfig) -> Value {
    let name = settings
        .server_name
        .clone()
        .or_else(|| doc.and_then(|doc| doc.info_title.clone()))
        .unwrap_or_else(|| DEFAULT_SERVER_NAME.to_string());
    // Never the frogs binary version: that would tell an anonymous caller exactly which build is running.
    let version = doc.and_then(|doc| doc.info_version.clone()).unwrap_or_else(|| UNVERSIONED.to_string());
    json!({ "name": name, "version": version })
}

fn static_results(doc: Option<&OpenApiDocument>, settings: &McpConfig) -> Result<StaticResults, String> {
    let info = server_info(doc, settings);
    let ttl = settings.list_ttl_ms.unwrap_or(DEFAULT_MCP_LIST_TTL_MS);
    let discover = json!({
        "supportedVersions": protocol::supported_versions(),
        "capabilities": { "tools": {} },
        "_meta": { protocol::META_SERVER_INFO_KEY: info },
        "ttlMs": ttl,
        "cacheScope": "public",
        "resultType": "complete",
    });
    let to_raw = |what: &str, value: &Value| {
        let raw = serde_json::value::to_raw_value(value).map_err(|_| format!("the MCP {what} result could not be serialised"))?;
        if raw.get().len() > MAX_MCP_DISCOVER_BYTES {
            return Err(format!(
                "the MCP {what} result is {} bytes, over the {MAX_MCP_DISCOVER_BYTES}-byte limit — shorten mcp.serverName or info.title/info.version",
                raw.get().len()
            ));
        }
        Ok(raw)
    };
    let mut initialize = HashMap::new();
    for version in protocol::LEGACY_VERSIONS {
        let result = json!({ "protocolVersion": version, "capabilities": { "tools": { "listChanged": false } }, "serverInfo": info });
        initialize.insert(version, to_raw("initialize", &result)?);
    }
    Ok(StaticResults {
        discover: to_raw("server/discover", &discover)?,
        initialize,
    })
}

/// Builds the `/mcp` router from the tool plan and the routes the HTTP router actually
/// registered. The router sets no fallback of its own (axum refuses to merge two that do).
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_router(
    planned: ToolPlan,
    accepted: &[AcceptedRoute],
    doc: Option<&OpenApiDocument>,
    settings: &McpConfig,
    auth: &AuthSettings,
    gate: GateParts,
    final_path: &str,
) -> io::Result<Router> {
    let invalid = |message: String| io::Error::new(io::ErrorKind::InvalidData, message);
    let challenges = match &auth.protected {
        Some(protected) => {
            Some(auth::Challenges::build(protected, planned.tools.iter().map(|tool| (tool.name.as_str(), tool.security_scopes.as_slice()))).map_err(invalid)?)
        }
        None => None,
    };
    let gate = match &auth.access_scheme {
        Some(scheme) => {
            let mut mocks = HashMap::new();
            if let Some(file_value) = gate.mock
                && gate.ctx.security.verifiers.get(scheme).is_some_and(|verifier| verifier.mtls.is_none())
            {
                mocks.insert(
                    VERIFIER_MOCK_KEY.to_string(),
                    file_value.unwrap_or_else(|| MockOutcome::Fail(SOURCE_NOT_MOCKED.to_string())),
                );
            }
            Some(Gate {
                scheme: scheme.clone(),
                ctx: gate.ctx,
                mocks,
            })
        }
        None => None,
    };
    let statics = static_results(doc, settings).map_err(invalid)?;
    let mut tools = HashMap::new();
    for spec in planned.tools {
        let Some(route) = accepted.get(spec.index) else {
            return Err(invalid(format!("MCP tool '{}' has no registered route — refusing to start", untrusted(&spec.name))));
        };
        tools.insert(
            spec.name,
            Tool {
                args: spec.args,
                path_params: spec.path_params,
                route: route.state.clone(),
                limiter: route.rate_limiter.clone(),
            },
        );
    }
    let state = Arc::new(McpState {
        guard: match &auth.protected {
            Some(protected) => transport::Guard::new(settings).with_resource_host(&protected.host),
            None => transport::Guard::new(settings),
        },
        gate,
        challenges,
        tools,
        discover: statics.discover,
        initialize: statics.initialize,
        list_modern: planned.list_modern,
        list_legacy: planned.list_legacy,
    });
    Ok(Router::new().route(final_path, any(handle)).with_state(state))
}

/// The candidates and plan for the routes the router registered (the second line of defence
/// behind `check`); the caller refuses startup on any returned problem.
pub(crate) fn plan_for_router(accepted: &[AcceptedRoute], doc: Option<&OpenApiDocument>, settings: &McpConfig, auth: &AuthSettings) -> Planned {
    let candidates: Vec<Candidate> = accepted
        .iter()
        .map(|route| Candidate {
            url_path: &route.url_path,
            token: &route.token,
            file: &route.file,
            endpoint: &route.state.endpoint,
        })
        .collect();
    tools::plan_tools(&candidates, doc, settings, auth)
}

/// The RFC 9728 metadata route, `None` unless `protectedResource` is configured and valid.
pub(crate) fn metadata_router(auth: &AuthSettings) -> io::Result<Option<Router>> {
    auth.protected.as_ref().map(metadata::router).transpose()
}

async fn handle(State(state): State<Arc<McpState>>, request: HttpRequest) -> Response {
    let (parts, body) = request.into_parts();
    if let Err(reject) = transport::check_parts(&parts, &state.guard) {
        return reject.into_response();
    }
    let bytes = match transport::read_body_capped(body).await {
        Ok(bytes) => bytes,
        Err(reject) => return reject.into_response(),
    };
    dispatch(&state, &parts, &bytes).await
}

async fn dispatch(state: &McpState, parts: &Parts, bytes: &[u8]) -> Response {
    let provisional = protocol::provisional_era(&parts.headers);
    let request = match protocol::parse_envelope(bytes) {
        // Never dispatched, whatever the method: a notification can't run a tool or touch a verifier.
        Ok(protocol::Parsed::Notification) => return protocol::accepted_no_content(),
        Ok(protocol::Parsed::Request(request)) => request,
        Err(error) => return error.into_response(provisional, None),
    };
    let id: &RawValue = &request.id;
    let params = match protocol::parse_params(request.params.as_deref()) {
        Ok(params) => params,
        Err(error) => return error.into_response(provisional, Some(id)),
    };
    let era = match protocol::negotiate_for(protocol::Transport::Http(&parts.headers), &request, &params) {
        Ok(era) => era,
        Err(error) => return error.into_response(provisional, Some(id)),
    };
    match (era, request.method.as_str()) {
        (Era::Legacy, "initialize") => {
            let requested = params.protocol_version.as_ref().and_then(Value::as_str);
            let version = protocol::LEGACY_VERSIONS
                .iter()
                .copied()
                .find(|v| Some(*v) == requested)
                .unwrap_or(protocol::LEGACY_VERSIONS[0]);
            match state.initialize.get(version) {
                Some(result) => protocol::rpc_result(id, result),
                None => ProtoError::method_not_found().into_response(era, Some(id)),
            }
        }
        (Era::Legacy, "ping") => protocol::rpc_result_value(id, &json!({})),
        (Era::Modern, "server/discover") => protocol::rpc_result(id, &state.discover),
        (_, "tools/list") => {
            if let Some(response) = run_gate(state, parts, era, id, false).await {
                return response;
            }
            protocol::rpc_result(id, if era == Era::Modern { &state.list_modern } else { &state.list_legacy })
        }
        (_, "tools/call") => {
            if let Some(response) = run_gate(state, parts, era, id, true).await {
                return response;
            }
            call_tool(state, parts, era, id, &params).await
        }
        _ => ProtoError::method_not_found().into_response(era, Some(id)),
    }
}

/// `Some(response)` when the gate refuses. Built from the failure kind alone: the verifier's own
/// text goes to the debug log, never to the caller, and no registry or override is consulted.
async fn run_gate(state: &McpState, parts: &Parts, era: Era, id: &RawValue, is_call: bool) -> Option<Response> {
    let gate = state.gate.as_ref()?;
    let client_cert = parts.extensions.get::<Arc<ClientCertIdentity>>().cloned();
    let failure = authorize(&gate.ctx.borrow(), &gate.scheme, &[], &parts.headers, client_cert.as_deref(), &gate.mocks)
        .await
        .err()?;
    tracing::debug!(code = %failure.code, detail = %failure.message, "MCP accessScheme gate refused a request");
    Some(match auth::gate_outcome(failure.kind) {
        auth::GateOutcome::Deny { challenge } => {
            let header = if challenge {
                state.challenges.as_ref().map(auth::Challenges::gate_401)
            } else {
                None
            };
            auth::gate_denied(id, header)
        }
        auth::GateOutcome::Outage if is_call => protocol::rpc_result_value(id, &call_result(era, 500, &auth::gate_call_outage_body())),
        auth::GateOutcome::Outage => auth::gate_list_outage(era, id),
    })
}

fn status_block(status: u16) -> String {
    let reason = axum::http::StatusCode::from_u16(status).ok().and_then(|code| code.canonical_reason()).unwrap_or("");
    format!("HTTP {status} {reason}").trim_end().to_string()
}

fn text_block(text: String) -> Value {
    json!({ "type": "text", "text": text })
}

fn call_result(era: Era, status: u16, body: &Value) -> Value {
    let mut result = if (200..300).contains(&status) {
        let mut content = Vec::new();
        if status != 200 {
            content.push(text_block(status_block(status)));
        }
        if status != 204 {
            content.push(text_block(body.to_string()));
        }
        json!({ "content": content })
    } else {
        json!({ "content": [text_block(body.to_string())], "isError": true })
    };
    result["_meta"] = json!({ HTTP_STATUS_META: status });
    if era == Era::Modern {
        result["resultType"] = json!("complete");
    }
    result
}

async fn call_tool(state: &McpState, parts: &Parts, era: Era, id: &RawValue, params: &protocol::ParamsView) -> Response {
    let Some((tool_name, tool)) = params
        .name
        .as_ref()
        .and_then(Value::as_str)
        .and_then(|name| state.tools.get(name).map(|tool| (name, tool)))
    else {
        return ProtoError::invalid_params().into_response(era, Some(id));
    };
    // Spent before the arguments are looked at, exactly as the HTTP route's limiter layer runs before extraction.
    if let Some(limiter) = &tool.limiter
        && let Err(exceeded) = limiter.try_acquire()
    {
        let mut result = call_result(era, 429, &crate::server::rate_limited_body());
        result["_meta"][RETRY_AFTER_META] = json!(exceeded.retry_after_secs);
        return protocol::rpc_result_value(id, &result);
    }
    let split = match tools::split_arguments(&tool.args, &tool.path_params, params.arguments.as_deref()) {
        Ok(split) => split,
        Err(error) => return error.into_response(era, Some(id)),
    };
    // Same sources as an HTTP request: the connection's verified identity and the request id, never anything from the arguments.
    let transaction_id = parts.extensions.get::<RequestId>().map(|request_id| request_id.0.clone()).unwrap_or_default();
    let client_cert = parts.extensions.get::<Arc<ClientCertIdentity>>().cloned();
    let (status, body) = tool
        .route
        .execute(&parts.headers, client_cert.as_deref(), &split.path, &split.query, &split.body, &transaction_id)
        .await;
    let code = body.get("name").and_then(Value::as_str).unwrap_or("");
    tracing::debug!(status, code, "MCP tool call finished");
    if let Some(http) = auth::transport_auth_status(code, status) {
        let message = if http == axum::http::StatusCode::UNAUTHORIZED {
            "Unauthorized"
        } else {
            "Forbidden"
        };
        let challenge = state.challenges.as_ref().and_then(|challenges| challenges.challenge_for(code, status, tool_name));
        return auth::with_challenge(protocol::rpc_error_with_status(http, id, protocol::INVALID_REQUEST, message, body), challenge);
    }
    protocol::rpc_result_value(id, &call_result(era, status, &body))
}

/// What `check` and `validate_findings` look at; `client_identity_available` is whether this
/// process can ever hand a handler a client certificate (so a cert-dependent tool is servable).
pub(crate) struct StartupInputs<'a> {
    pub server: &'a ServerConfig,
    pub security: &'a SecurityConfig,
    pub connections: &'a HashMap<String, ConnectionConfig>,
    pub tree: &'a EndpointTree,
    pub doc: Option<&'a OpenApiDocument>,
    pub client_identity_available: bool,
    pub web_role: bool,
    /// `webserve.json`'s `allowDotPaths` (empty without a web role).
    pub web_allow_dot_paths: &'a [String],
}

#[derive(Default)]
struct Analysis {
    tool_count: usize,
    errors: Vec<String>,
    warnings: Vec<String>,
    /// Exposed endpoints that are not served: logged and tolerated at startup, a problem for `frogs validate`.
    unavailable: Vec<String>,
}

fn exposed_name(endpoint: &crate::endpoint::EndpointFile) -> Option<String> {
    let block = endpoint.mcp.as_ref().and_then(|value| tools::parse_block(value).ok())?;
    block.expose.then(|| block.name_or(&endpoint.operation_id))
}

fn analyse(inputs: &StartupInputs, on: bool) -> Analysis {
    let settings = inputs.server.mcp_settings();
    let mode = MethodCase::from_case_sensitive(inputs.server.case_sensitive_methods());
    let decisions = accept_routes(inputs.tree, mode, inputs.security, inputs.connections, inputs.client_identity_available);
    let mut analysis = Analysis::default();

    let final_mcp_path = final_path(inputs.server);
    let (auth, auth_errors) = parse_auth_settings(&settings, &final_mcp_path);
    analysis.errors.extend(transport::settings_errors(&settings));
    analysis.errors.extend(auth_errors);
    analysis.warnings.extend(transport::settings_warnings(&settings));
    if !on && (settings.access_scheme.is_some() || settings.protected_resource.is_some()) {
        analysis
            .warnings
            .push("mcp.accessScheme/mcp.protectedResource are set, but features.mcp is off — they have no effect".to_string());
    }
    if on {
        let problems = access_scheme_problems(inputs, &auth, &mut analysis.warnings);
        analysis.errors.extend(problems);
    }
    if on && settings.allowed_hosts.is_empty() && auth.protected.is_none() {
        analysis.warnings.push(
            "mcp.allowedHosts is empty, so only loopback host names (localhost, 127.0.0.1, ::1) are accepted: clients reaching this server by another name or IP will get 403 — \
             set mcp.allowedHosts (a DNS-rebinding defence, not network access control)"
                .to_string(),
        );
    }

    let mut candidates: Vec<Candidate> = Vec::new();
    for decision in &decisions {
        match decision {
            RouteDecision::Accepted { entry, endpoint, .. } => {
                if !on && endpoint.mcp.is_some() {
                    analysis.warnings.push(format!(
                        "{}: has an \"mcp\" block, but features.mcp is off — it has no effect",
                        untrusted(&entry.file.display().to_string())
                    ));
                }
                candidates.push(Candidate {
                    url_path: &entry.url_path,
                    token: &entry.token,
                    file: &entry.file,
                    endpoint,
                });
            }
            RouteDecision::Unavailable { entry, reason, endpoint } => {
                let file = untrusted(&entry.file.display().to_string());
                if let Some(endpoint) = endpoint {
                    if !on && endpoint.mcp.is_some() {
                        analysis
                            .warnings
                            .push(format!("{file}: has an \"mcp\" block, but features.mcp is off — it has no effect"));
                    }
                    if let Some(name) = exposed_name(endpoint) {
                        analysis
                            .unavailable
                            .push(format!("tool '{}' not available: {} ({file})", untrusted(&name), untrusted(reason)));
                    }
                }
            }
            RouteDecision::Skipped { .. } => {}
        }
    }

    if let Some(doc) = inputs.doc
        && (doc.operations.iter().chain(&doc.ambiguous_operations).any(|op| op.path == MCP_PATH)
            || doc.dropped_operations.iter().any(|dropped| dropped.path == MCP_PATH)
            || doc.unresolved_path_items.contains(MCP_PATH))
    {
        analysis.errors.push(
            "openapi.yaml declares an operation at /mcp (relative to apiRoot), which the MCP endpoint owns — move the operation or set a different apiRoot".to_string(),
        );
    }

    let Planned { plan, errors, warnings } = tools::plan_tools(&candidates, inputs.doc, &settings, &auth);
    analysis.errors.extend(errors);
    analysis.warnings.extend(warnings);
    if let Some(plan) = &plan {
        analysis.tool_count = plan.tools.len();
        for tool in &plan.tools {
            let endpoint = candidates[tool.index].endpoint;
            for code in auth::CALLER_AUTH_CODES {
                if let Some(status) = endpoint.error_overrides.get(code).and_then(|o| o.http_status)
                    && !matches!(status, 401 | 403)
                {
                    analysis.warnings.push(format!(
                        "tool '{}': errorOverrides re-maps {code} to {status}, so a failed authentication is a tool error rather than HTTP 401/403 over MCP",
                        untrusted(&tool.name)
                    ));
                }
            }
        }
        if on && let Some(protected) = &auth.protected {
            if let Err(message) = auth::Challenges::build(protected, plan.tools.iter().map(|tool| (tool.name.as_str(), tool.security_scopes.as_slice()))) {
                analysis.errors.push(message);
            }
            analysis.errors.extend(passthrough_problems(inputs, &auth, plan, &candidates));
            analysis.warnings.extend(audience_and_oracle_warnings(&auth, plan, &candidates));
            if inputs.web_role && dot_path_shadows(inputs.web_allow_dot_paths, &protected.metadata_path) {
                analysis.warnings.push(format!(
                    "webserve.json allowDotPaths covers {}, which the protected-resource metadata route answers instead — the static file there is shadowed",
                    protected.metadata_path
                ));
            }
        }
        if on && plan.tools.is_empty() {
            analysis
                .warnings
                .push("features.mcp is on but no endpoint is exposed (set \"mcp\": {\"expose\": true} in an endpoint file) — tools/list will be empty".to_string());
        }
    }
    if analysis.errors.is_empty()
        && let Err(message) = static_results(inputs.doc, &settings)
    {
        analysis.errors.push(message);
    }

    if on && inputs.server.api_root.trim().trim_matches('/').is_empty() {
        let shadowed_param_post = decisions.iter().any(|decision| match decision {
            RouteDecision::Accepted { entry, .. } | RouteDecision::Unavailable { entry, .. } => {
                entry.wire == "POST" && entry.url_path.strip_prefix('/').is_some_and(|rest| rest.starts_with(':') && !rest.contains('/'))
            }
            RouteDecision::Skipped { .. } => false,
        });
        if shadowed_param_post {
            analysis
                .warnings
                .push("a root-level {param} POST endpoint exists while apiRoot is empty: POST /mcp now reaches the MCP endpoint instead of it".to_string());
        }
        if inputs.web_role {
            analysis
                .warnings
                .push("apiRoot is empty while static content is served: /mcp takes precedence over the static catch-all, so a project-root file or folder named \"mcp\" is shadowed".to_string());
        }
    }
    analysis
}

const ALWAYS_CREDENTIAL_HEADERS: [&str; 3] = ["authorization", "proxy-authorization", "cookie"];

fn access_scheme_problems(inputs: &StartupInputs, auth: &AuthSettings, warnings: &mut Vec<String>) -> Vec<String> {
    let Some(scheme) = &auth.access_scheme else { return Vec::new() };
    let Some(verifier) = inputs.security.verifiers.get(scheme) else {
        return vec![format!("mcp.accessScheme '{}' is not a scheme in security/schemes.json", untrusted(scheme))];
    };
    if verifier.requires_client_cert() && !inputs.client_identity_available {
        return vec![format!(
            "mcp.accessScheme '{}' needs a client certificate, but this server's TLS listener doesn't request one (set tls.mode to \"manual\" and enable tls.clientAuth in config/server.json)",
            untrusted(scheme)
        )];
    }
    if verifier.mtls.is_none() && verifier.def.cache_ttl_seconds().is_none() {
        warnings.push(format!(
            "mcp.accessScheme '{}': its verifier has no cacheTtlSeconds, so every tools/list and tools/call runs the verifier against its datasource",
            untrusted(scheme)
        ));
    }
    Vec::new()
}

fn verifier_headers(inputs: &StartupInputs, scheme: Option<&String>, out: &mut std::collections::HashSet<String>) {
    let Some(verifier) = scheme.and_then(|name| inputs.security.verifiers.get(name)) else {
        return;
    };
    for param in verifier.def.parameters() {
        if let Some(name) = param.from.strip_prefix("header.") {
            out.insert(name.to_ascii_lowercase());
        }
    }
}

fn plain_relative(path: &str) -> bool {
    use std::path::Component;
    !path.is_empty() && !path.contains('\\') && std::path::Path::new(path).components().all(|component| matches!(component, Component::Normal(_)))
}

/// FR32 (best effort): an exposed endpoint must not hand the caller's own credential to an upstream.
fn passthrough_problems(inputs: &StartupInputs, auth: &AuthSettings, plan: &ToolPlan, candidates: &[Candidate]) -> Vec<String> {
    let http_root = inputs.tree.endpoints_root().parent().map(|datasources| datasources.join("http"));
    let mut problems = Vec::new();
    for tool in &plan.tools {
        let endpoint = candidates[tool.index].endpoint;
        let file = untrusted(&candidates[tool.index].file.display().to_string());
        let mut guarded: std::collections::HashSet<String> = ALWAYS_CREDENTIAL_HEADERS.iter().map(|name| (*name).to_string()).collect();
        verifier_headers(inputs, endpoint.security.as_ref(), &mut guarded);
        verifier_headers(inputs, auth.access_scheme.as_ref(), &mut guarded);
        let mut names: Vec<&String> = endpoint.sources.keys().collect();
        names.sort();
        for name in names {
            let (parameters, request) = match &endpoint.sources[name] {
                crate::endpoint::SourceDef::Sql { parameters, .. } => (parameters, None),
                crate::endpoint::SourceDef::Http { parameters, request, .. } => (parameters, Some(request)),
            };
            for parameter in parameters {
                if let Some(header) = parameter.from.strip_prefix("header.")
                    && guarded.contains(&header.to_ascii_lowercase())
                {
                    problems.push(format!(
                        "{file}: source '{}' binds the caller's '{}' header, which would pass the caller's credential to an upstream (token passthrough, refused while mcp.protectedResource is set; this check is best effort)",
                        untrusted(name),
                        untrusted(header)
                    ));
                }
            }
            let Some(request) = request else { continue };
            let parsed = http_root
                .as_ref()
                .filter(|_| plain_relative(request))
                .and_then(|root| std::fs::read_to_string(root.join(request)).ok())
                .and_then(|text| serde_json::from_str::<crate::http::HttpRequestFile>(&text).ok());
            match parsed {
                None => problems.push(format!(
                    "{file}: source '{}': the HTTP request file '{}' could not be read, so frogs cannot prove it does not forward the caller's credential — refusing while mcp.protectedResource is set",
                    untrusted(name),
                    untrusted(request)
                )),
                Some(request_file) => {
                    if let Some(crate::http::HttpAuth::Forward { header }) = &request_file.auth
                        && guarded.contains(&header.to_ascii_lowercase())
                    {
                        problems.push(format!(
                            "{file}: source '{}' forwards the caller's '{}' header to an upstream (token passthrough, refused while mcp.protectedResource is set; this check is best effort)",
                            untrusted(name),
                            untrusted(header)
                        ));
                    }
                }
            }
        }
    }
    problems
}

fn audience_and_oracle_warnings(auth: &AuthSettings, plan: &ToolPlan, candidates: &[Candidate]) -> Vec<String> {
    let Some(protected) = &auth.protected else { return Vec::new() };
    let mut schemes: Vec<&String> = auth.access_scheme.iter().collect();
    let mut any_secured = false;
    for tool in &plan.tools {
        if let Some(scheme) = &candidates[tool.index].endpoint.security {
            any_secured = true;
            if !schemes.contains(&scheme) {
                schemes.push(scheme);
            }
        }
    }
    let mut warnings: Vec<String> = schemes
        .iter()
        .map(|scheme| {
            format!(
                "frogs does not check token audience: the verifier for scheme '{}' must reject tokens not issued for {}",
                untrusted(scheme),
                untrusted(&protected.resource)
            )
        })
        .collect();
    if auth.access_scheme.is_none() {
        let mut message = "mcp.protectedResource is set without mcp.accessScheme: tools/list is anonymous and tool names are enumerable anyway (an unknown tool gets -32602, a known secured tool 401 with a challenge) — set mcp.accessScheme to gate both".to_string();
        if !any_secured {
            message.push_str("; also, OAuth metadata is advertised while no exposed tool declares security, so nothing on /mcp requires a token");
        }
        warnings.push(message);
    }
    warnings
}

/// Whether an `allowDotPaths` entry covers the metadata path (compared case-insensitively, so a mismatch errs toward warning).
fn dot_path_shadows(entries: &[String], metadata_path: &str) -> bool {
    let target = metadata_path.trim_matches('/').to_ascii_lowercase();
    entries.iter().any(|entry| {
        let entry = entry.trim_matches('/').to_ascii_lowercase();
        !entry.is_empty() && (target == entry || target.starts_with(&format!("{entry}/")))
    })
}

/// Startup refusal for MCP (FR13), run right after the spec is loaded and before any connection,
/// bind or pidfile. Returns the number of tools. Does nothing when `features.mcp` is off.
pub(crate) fn check(inputs: &StartupInputs, refusal_hint: &str) -> io::Result<usize> {
    if !inputs.server.features.mcp {
        return Ok(0);
    }
    let analysis = analyse(inputs, true);
    for message in &analysis.warnings {
        tracing::warn!("MCP: {message}");
    }
    for message in &analysis.unavailable {
        tracing::error!("{message}");
    }
    if analysis.errors.is_empty() {
        return Ok(analysis.tool_count);
    }
    for message in &analysis.errors {
        eprintln!("error: {message}");
        tracing::error!("{message}");
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "{} MCP problem(s) found — refusing to start; fix them, then run frogs validate{refusal_hint}",
            analysis.errors.len()
        ),
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Severity {
    Error,
    Warning,
}

pub(crate) struct ValidateReport {
    pub tools: usize,
    pub findings: Vec<(Severity, String)>,
}

/// The `mcp:` section of `frogs validate`: errors when `features.mcp` is on, the same findings as
/// warnings when it is off. `None` when MCP is off and no endpoint has an `mcp` block.
pub(crate) fn validate_findings(inputs: &StartupInputs) -> Option<ValidateReport> {
    let on = inputs.server.features.mcp;
    let analysis = analyse(inputs, on);
    if !on && analysis.warnings.is_empty() && analysis.errors.is_empty() && analysis.tool_count == 0 {
        return None;
    }
    let problem_severity = if on { Severity::Error } else { Severity::Warning };
    let mut findings: Vec<(Severity, String)> = Vec::new();
    findings.extend(analysis.errors.into_iter().map(|message| (problem_severity, message)));
    findings.extend(analysis.unavailable.into_iter().map(|message| (problem_severity, message)));
    findings.extend(analysis.warnings.into_iter().map(|message| (Severity::Warning, message)));
    Some(ValidateReport {
        tools: analysis.tool_count,
        findings,
    })
}
