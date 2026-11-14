//! JSON-RPC envelope handling and MCP protocol-version negotiation. Every protocol detail that
//! was read from the MCP `2026-07-28` pages but never checked against a real client lives here.

use std::cell::Cell;
use std::collections::HashSet;
use std::fmt;

use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use serde::Deserialize;
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::value::RawValue;
use serde_json::{Map, Value};

pub(crate) const MODERN_VERSIONS: [&str; 1] = ["2026-07-28"];
pub(crate) const LEGACY_VERSIONS: [&str; 2] = ["2025-11-25", "2025-06-18"];
pub(crate) const META_VERSION_KEY: &str = "io.modelcontextprotocol/protocolVersion";
const META_CAPABILITIES_KEY: &str = "io.modelcontextprotocol/clientCapabilities";
pub(crate) const META_SERVER_INFO_KEY: &str = "io.modelcontextprotocol/serverInfo";

const HEADER_VERSION: &str = "mcp-protocol-version";
const HEADER_METHOD: &str = "mcp-method";
const HEADER_NAME: &str = "mcp-name";
const BASE64_SENTINEL_PREFIX: &str = "=?base64?";
const BASE64_SENTINEL_SUFFIX: &str = "?=";
const MAX_HEADER_VALUE_BYTES: usize = 1024;
const MAX_DECODED_NAME_BYTES: usize = 768;
const MAX_REQUESTED_VERSION_BYTES: usize = 64;

pub(crate) const PARSE_ERROR: i32 = -32700;
pub(crate) const INVALID_REQUEST: i32 = -32600;
pub(crate) const METHOD_NOT_FOUND: i32 = -32601;
pub(crate) const INVALID_PARAMS: i32 = -32602;
pub(crate) const INTERNAL_ERROR: i32 = -32603;
pub(crate) const HEADER_MISMATCH: i32 = -32020;
pub(crate) const UNSUPPORTED_VERSION: i32 = -32022;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Era {
    Modern,
    Legacy,
}

/// A JSON-RPC error before it is turned into a response (the HTTP status depends on the era).
#[derive(Debug)]
pub(crate) struct ProtoError {
    pub code: i32,
    pub message: &'static str,
    pub data: Option<Value>,
}

impl ProtoError {
    pub(crate) fn new(code: i32, message: &'static str) -> Self {
        ProtoError { code, message, data: None }
    }

    pub(crate) fn invalid_params() -> Self {
        ProtoError::new(INVALID_PARAMS, "Invalid params")
    }

    pub(crate) fn method_not_found() -> Self {
        ProtoError::new(METHOD_NOT_FOUND, "Method not found")
    }

    pub(crate) fn internal_error() -> Self {
        ProtoError::new(INTERNAL_ERROR, "Internal error")
    }

    fn status(&self, era: Era) -> StatusCode {
        match (self.code, era) {
            (HEADER_MISMATCH | UNSUPPORTED_VERSION, _) => StatusCode::BAD_REQUEST,
            (METHOD_NOT_FOUND, Era::Modern) => StatusCode::NOT_FOUND,
            (INTERNAL_ERROR, Era::Modern) => StatusCode::INTERNAL_SERVER_ERROR,
            (_, Era::Modern) => StatusCode::BAD_REQUEST,
            (_, Era::Legacy) => StatusCode::OK,
        }
    }

    fn error_value(self) -> Value {
        let mut error = serde_json::json!({ "code": self.code, "message": self.message });
        if let Some(data) = self.data {
            error["data"] = data;
        }
        error
    }

    pub(crate) fn into_response(self, era: Era, id: Option<&RawValue>) -> Response {
        let status = self.status(era);
        error_response(status, id, self.error_value())
    }

    /// One compact JSON-RPC error line (no trailing newline) for a transport with no HTTP status.
    pub(crate) fn into_line(self, id: Option<&RawValue>) -> String {
        error_line(id, self.error_value())
    }
}

#[derive(serde::Serialize)]
struct ResultBody<'a> {
    jsonrpc: &'static str,
    id: &'a RawValue,
    result: &'a RawValue,
}

#[derive(serde::Serialize)]
struct ErrorBody<'a> {
    jsonrpc: &'static str,
    id: Option<&'a RawValue>,
    error: Value,
}

fn json_response(status: StatusCode, body: Result<String, serde_json::Error>) -> Response {
    let Ok(body) = body else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

fn error_body(id: Option<&RawValue>, error: Value) -> Result<String, serde_json::Error> {
    serde_json::to_string(&ErrorBody { jsonrpc: "2.0", id, error })
}

fn error_response(status: StatusCode, id: Option<&RawValue>, error: Value) -> Response {
    json_response(status, error_body(id, error))
}

/// The stdio form of an error body; if serialising ever fails, a fixed internal-error line still goes out.
pub(crate) fn error_line(id: Option<&RawValue>, error: Value) -> String {
    error_body(id, error).unwrap_or_else(|_| r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"Internal error"}}"#.to_string())
}

fn result_body(id: &RawValue, result: &RawValue) -> Result<String, serde_json::Error> {
    serde_json::to_string(&ResultBody { jsonrpc: "2.0", id, result })
}

/// One compact JSON-RPC result line (no trailing newline).
pub(crate) fn result_line(id: &RawValue, result: &RawValue) -> Option<String> {
    result_body(id, result).ok()
}

/// `{"jsonrpc","id","result"}` around a result serialised once at startup (or built per call), so
/// a pre-built value tree is never walked again per request.
pub(crate) fn rpc_result(id: &RawValue, result: &RawValue) -> Response {
    json_response(StatusCode::OK, result_body(id, result))
}

pub(crate) fn rpc_result_value(id: &RawValue, result: &Value) -> Response {
    match serde_json::value::to_raw_value(result) {
        Ok(raw) => rpc_result(id, &raw),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// A transport-level JSON-RPC error with a chosen HTTP status (the caller-auth 401/403 case).
pub(crate) fn rpc_error_with_status(status: StatusCode, id: &RawValue, code: i32, message: &'static str, data: Value) -> Response {
    error_response(status, Some(id), serde_json::json!({ "code": code, "message": message, "data": data }))
}

/// A transport-level JSON-RPC error whose body is only `code` and `message` — never a `data`
/// member (the `accessScheme` gate's fixed denial: nothing may be learned from it).
pub(crate) fn rpc_error_fixed(status: StatusCode, id: &RawValue, code: i32, message: &'static str) -> Response {
    error_response(status, Some(id), serde_json::json!({ "code": code, "message": message }))
}

/// The body of a refusal that happens before any JSON is read: id `null`, a fixed message, nothing echoed.
pub(crate) fn generic_error(status: StatusCode, message: &'static str) -> Response {
    error_response(status, None, serde_json::json!({ "code": INVALID_REQUEST, "message": message }))
}

pub(crate) fn accepted_no_content() -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::ACCEPTED;
    response
}

pub(crate) fn supported_versions() -> Vec<&'static str> {
    MODERN_VERSIONS.iter().chain(LEGACY_VERSIONS.iter()).copied().collect()
}

fn is_supported(version: &str) -> bool {
    MODERN_VERSIONS.contains(&version) || LEGACY_VERSIONS.contains(&version)
}

fn truncate_requested(text: &str) -> String {
    let mut end = text.len().min(MAX_REQUESTED_VERSION_BYTES);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

fn unsupported_version(requested: &str) -> ProtoError {
    ProtoError {
        code: UNSUPPORTED_VERSION,
        message: "Unsupported protocol version",
        data: Some(serde_json::json!({ "supported": supported_versions(), "requested": truncate_requested(requested) })),
    }
}

fn header_text(headers: &HeaderMap, name: &str) -> Option<Result<String, ()>> {
    headers.get(name).map(|value| value.to_str().map(str::to_string).map_err(|_| ()))
}

/// The era used for errors raised before negotiation completes (parse errors, a bad `params`).
pub(crate) fn provisional_era(headers: &HeaderMap) -> Era {
    match header_text(headers, HEADER_VERSION) {
        Some(Ok(version)) if MODERN_VERSIONS.contains(&version.as_str()) => Era::Modern,
        _ => Era::Legacy,
    }
}

#[derive(Debug, Clone, Copy)]
enum DuplicateAt {
    TopLevel,
    Params,
}

/// Walks the whole document and fails on any object that repeats a key (compared decoded), at
/// every depth, so no later reader can see a value chosen by first-wins or last-wins. Nesting
/// beyond serde_json's own 128-level limit is a syntax error here, so it surfaces as `-32700`.
struct Walk<'a> {
    found: &'a Cell<Option<DuplicateAt>>,
    depth: usize,
    in_params: bool,
}

impl<'de> DeserializeSeed<'de> for Walk<'_> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Walk<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq
            .next_element_seed(Walk {
                found: self.found,
                depth: self.depth + 1,
                in_params: self.in_params,
            })?
            .is_some()
        {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut seen: HashSet<String> = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            let child_in_params = self.in_params || (self.depth == 0 && key == "params");
            if !seen.insert(key) {
                self.found.set(Some(if self.in_params { DuplicateAt::Params } else { DuplicateAt::TopLevel }));
                return Err(serde::de::Error::custom("duplicate key"));
            }
            map.next_value_seed(Walk {
                found: self.found,
                depth: self.depth + 1,
                in_params: child_in_params,
            })?;
        }
        Ok(())
    }
}

fn reject_duplicate_keys(bytes: &[u8]) -> Result<(), ProtoError> {
    let found = Cell::new(None);
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let outcome = DeserializeSeed::deserialize(
        Walk {
            found: &found,
            depth: 0,
            in_params: false,
        },
        &mut deserializer,
    )
    .and_then(|()| deserializer.end());
    match (found.get(), outcome) {
        (Some(DuplicateAt::TopLevel), _) => Err(ProtoError::new(INVALID_REQUEST, "Invalid Request")),
        (Some(DuplicateAt::Params), _) => Err(ProtoError::invalid_params()),
        (None, Ok(())) => Ok(()),
        // serde's own message can echo request content, so it is never forwarded.
        (None, Err(_)) => Err(ProtoError::new(PARSE_ERROR, "Parse error")),
    }
}

fn present<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<Box<RawValue>>, D::Error> {
    Box::<RawValue>::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
struct RawEnvelope {
    jsonrpc: Option<Value>,
    // `present` so an explicit `"id": null` is distinguishable from a missing `id` (a notification).
    #[serde(default, deserialize_with = "present")]
    id: Option<Box<RawValue>>,
    method: Option<Value>,
    params: Option<Box<RawValue>>,
}

pub(crate) struct Request {
    pub id: Box<RawValue>,
    pub method: String,
    pub params: Option<Box<RawValue>>,
}

pub(crate) enum Parsed {
    Notification,
    Request(Request),
}

/// Duplicate-key pre-pass, then the typed envelope. A batch, a non-object, a wrong `jsonrpc`, a
/// non-string `method` and `id: null` are all `-32600`; a missing `id` is a notification.
pub(crate) fn parse_envelope(bytes: &[u8]) -> Result<Parsed, ProtoError> {
    reject_duplicate_keys(bytes)?;
    let invalid = || ProtoError::new(INVALID_REQUEST, "Invalid Request");
    if bytes.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'[') {
        return Err(invalid());
    }
    let raw: RawEnvelope = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    if raw.jsonrpc.as_ref().and_then(Value::as_str) != Some("2.0") {
        return Err(invalid());
    }
    let Some(Value::String(method)) = raw.method else {
        return Err(invalid());
    };
    let Some(id) = raw.id else {
        return Ok(Parsed::Notification);
    };
    match serde_json::from_str::<Value>(id.get()) {
        Ok(Value::String(_) | Value::Number(_)) => {}
        _ => return Err(invalid()),
    }
    Ok(Parsed::Request(Request { id, method, params: raw.params }))
}

/// The members of `params` the protocol layer and `tools/call` read; everything else is ignored.
#[derive(Deserialize, Default)]
pub(crate) struct ParamsView {
    #[serde(rename = "_meta", default)]
    meta: Option<Map<String, Value>>,
    #[serde(default)]
    pub name: Option<Value>,
    #[serde(default)]
    pub arguments: Option<Box<RawValue>>,
    #[serde(rename = "protocolVersion", default)]
    pub protocol_version: Option<Value>,
}

pub(crate) fn parse_params(raw: Option<&RawValue>) -> Result<ParamsView, ProtoError> {
    match raw {
        None => Ok(ParamsView::default()),
        Some(raw) => serde_json::from_str(raw.get()).map_err(|_| ProtoError::invalid_params()),
    }
}

/// `Mcp-Name`/`Mcp-Method` value: plain text, or `=?base64?<standard base64>?=` for anything a
/// header can't carry. Over-long input is refused without decoding.
fn decode_header_value(raw: &str) -> Option<String> {
    if raw.len() > MAX_HEADER_VALUE_BYTES {
        return None;
    }
    let Some(encoded) = raw.strip_prefix(BASE64_SENTINEL_PREFIX).and_then(|rest| rest.strip_suffix(BASE64_SENTINEL_SUFFIX)) else {
        return Some(raw.to_string());
    };
    let decoded = base64::engine::general_purpose::STANDARD.decode(encoded).ok()?;
    if decoded.len() > MAX_DECODED_NAME_BYTES {
        return None;
    }
    String::from_utf8(decoded).ok()
}

fn mismatch() -> ProtoError {
    ProtoError::new(HEADER_MISMATCH, "Header mismatch")
}

fn header_value_decoded(headers: &HeaderMap, name: &str) -> Option<String> {
    match header_text(headers, name) {
        Some(Ok(text)) => decode_header_value(&text),
        _ => None,
    }
}

/// The HTTP form of `negotiate_for`.
#[cfg(test)]
pub(crate) fn negotiate(headers: &HeaderMap, request: &Request, params: &ParamsView) -> Result<Era, ProtoError> {
    negotiate_for(Transport::Http(headers), request, params)
}

/// Where a request came from: HTTP carries the `MCP-*` headers the modern era must keep consistent with the body; stdio has none.
#[derive(Clone, Copy)]
pub(crate) enum Transport<'a> {
    Http(&'a HeaderMap),
    Stdio,
}

/// Chooses the era for this request alone (nothing is remembered between requests) and, for a
/// modern request, validates the headers against the body before any dispatch.
pub(crate) fn negotiate_for(transport: Transport, request: &Request, params: &ParamsView) -> Result<Era, ProtoError> {
    let header_version = match transport {
        Transport::Stdio => None,
        Transport::Http(headers) => match header_text(headers, HEADER_VERSION) {
            None => None,
            Some(Ok(version)) => Some(version),
            Some(Err(())) => return Err(unsupported_version("")),
        },
    };
    if let Some(version) = &header_version
        && !is_supported(version)
    {
        return Err(unsupported_version(version));
    }
    let is_initialize = request.method == "initialize";
    let meta_version = match params.meta.as_ref().and_then(|meta| meta.get(META_VERSION_KEY)) {
        None => None,
        Some(Value::String(version)) => Some(version.as_str()),
        Some(_) => return Err(ProtoError::invalid_params()),
    };
    if !is_initialize
        && let Some(version) = meta_version
        && !is_supported(version)
    {
        return Err(unsupported_version(version));
    }

    let modern =
        !is_initialize && (meta_version.is_some_and(|v| MODERN_VERSIONS.contains(&v)) || header_version.as_deref().is_some_and(|v| MODERN_VERSIONS.contains(&v)));
    if !modern {
        return Ok(Era::Legacy);
    }

    let Transport::Http(headers) = transport else {
        let capabilities_ok = params.meta.as_ref().and_then(|meta| meta.get(META_CAPABILITIES_KEY)).is_some_and(Value::is_object);
        return if capabilities_ok { Ok(Era::Modern) } else { Err(ProtoError::invalid_params()) };
    };
    if let Some(version) = meta_version
        && header_version.as_deref() != Some(version)
    {
        return Err(mismatch());
    }
    let capabilities_ok = params.meta.as_ref().and_then(|meta| meta.get(META_CAPABILITIES_KEY)).is_some_and(Value::is_object);
    if meta_version.is_none() || !capabilities_ok {
        return Err(ProtoError::invalid_params());
    }
    if header_value_decoded(headers, HEADER_METHOD).as_deref() != Some(request.method.as_str()) {
        return Err(mismatch());
    }
    if request.method == "tools/call" {
        let name_header = header_value_decoded(headers, HEADER_NAME);
        let body_name = params.name.as_ref().and_then(Value::as_str);
        if name_header.is_none() || name_header.as_deref() != body_name {
            return Err(mismatch());
        }
    }
    Ok(Era::Modern)
}
