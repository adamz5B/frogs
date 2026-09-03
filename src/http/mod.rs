use std::collections::{HashMap, HashSet};
use std::time::Duration;

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde::Deserialize;
use serde_json::Value;

use crate::sql::{SqlValue, sql_value_to_json};

/// RFC 3986 "unreserved" characters (`ALPHA / DIGIT / "-" / "." / "_" / "~"`)
/// are the only bytes left unescaped when substituting a value into a URL
/// template — every other byte, including URL metacharacters like `&`, `=`,
/// `#`, `?`, `/`, is percent-encoded. This is what makes it safe to splice a
/// caller-controlled value (a request header, an API key) into a URL: the
/// value can never be interpreted as introducing a new query parameter,
/// path segment, or fragment.
const URL_COMPONENT: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'.').remove(b'_').remove(b'~');

/// One `datasources/http/<file>.json` file, deserialized straight from
/// disk — mirrors the shape from docs/datasource-schema-design.md's HTTP
/// datasource section.
#[derive(Debug, Deserialize)]
pub struct HttpRequestFile {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub body: Option<Value>,
    #[serde(default)]
    pub auth: Option<HttpAuth>,
    #[serde(rename = "timeoutMs", default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(rename = "responsePath", default)]
    pub response_path: Option<String>,
}

fn default_timeout_ms() -> u64 {
    5000
}

/// Every way executing an HTTP source can fail, kept as a structured type
/// (rather than a flattened `String`) specifically so the caller can
/// classify a failure into one of the design doc's canonical error codes
/// without pattern-matching message text.
#[derive(Debug)]
pub enum HttpError {
    InvalidMethod(String),
    /// The request itself couldn't complete — network/DNS/timeout, as
    /// opposed to completing with a non-2xx status.
    Request(String),
    UpstreamStatus(u16),
    InvalidJson(String),
    ResponsePathNotFound(String),
    Auth(String),
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::InvalidMethod(m) => write!(f, "invalid HTTP method '{m}'"),
            HttpError::Request(m) => write!(f, "request failed: {m}"),
            HttpError::UpstreamStatus(status) => write!(f, "upstream returned {status}"),
            HttpError::InvalidJson(m) => write!(f, "invalid JSON response: {m}"),
            HttpError::ResponsePathNotFound(path) => write!(f, "responsePath '{path}' not found in response"),
            HttpError::Auth(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for HttpError {}

/// A structured block instead of a raw header, since these are the common,
/// nameable cases — secrets are always referenced via `*Env`, never
/// inlined, so datasource files stay safe to commit.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum HttpAuth {
    Bearer {
        #[serde(rename = "tokenEnv")]
        token_env: String,
    },
    ApiKey {
        #[serde(rename = "headerName")]
        header_name: String,
        #[serde(rename = "valueEnv")]
        value_env: String,
    },
    Basic {
        #[serde(rename = "userEnv")]
        user_env: String,
        #[serde(rename = "passwordEnv")]
        password_env: String,
    },
    /// Passes the *caller's own* auth header through unchanged — the one
    /// case a raw env-based secret can't cover. Parses so a datasource file
    /// that declares one doesn't fail to load, but isn't executable yet:
    /// it needs the incoming request's own headers threaded all the way
    /// down to here, which nothing in the resolver does yet (the same gap
    /// noted for `header.`/`body.`/`sources.` parameter prefixes).
    Forward {
        #[allow(dead_code)]
        header: String,
    },
}

/// Executes one HTTP source: substitutes `{{param}}` templates into the
/// URL and body, applies auth, sends the request, and unwraps `responsePath`
/// if present. Returns the (already-unwrapped) JSON body on success.
///
/// `array_params` names every bound parameter the *endpoint file* declared
/// `"type": "array"` — used only to decide whether a bare `"body":
/// "{{name}}"` template should reconstitute `name`'s real JSON shape (see
/// `whole_value_passthrough`) rather than substitute it as a string like
/// every other template position does.
pub async fn execute(
    client: &reqwest::Client,
    request: &HttpRequestFile,
    params: &HashMap<String, SqlValue>,
    array_params: &HashSet<String>,
) -> Result<Value, HttpError> {
    let url = substitute_string(&request.url, params);
    let method = reqwest::Method::from_bytes(request.method.as_bytes()).map_err(|e| HttpError::InvalidMethod(format!("{}: {e}", request.method)))?;

    let mut builder = client.request(method, &url).timeout(Duration::from_millis(request.timeout_ms));

    if let Some(body) = &request.body {
        let substituted = whole_value_passthrough(body, params, array_params).unwrap_or_else(|| substitute_value(body, params));
        builder = builder.json(&substituted);
    }

    if let Some(auth) = &request.auth {
        builder = apply_auth(builder, auth)?;
    }

    let response = builder.send().await.map_err(|e| HttpError::Request(e.to_string()))?;
    let status = response.status();
    if !status.is_success() {
        return Err(HttpError::UpstreamStatus(status.as_u16()));
    }

    let body: Value = response.json().await.map_err(|e| HttpError::InvalidJson(e.to_string()))?;

    match &request.response_path {
        Some(path) => navigate(&body, path).cloned().ok_or_else(|| HttpError::ResponsePathNotFound(path.clone())),
        None => Ok(body),
    }
}

fn apply_auth(builder: reqwest::RequestBuilder, auth: &HttpAuth) -> Result<reqwest::RequestBuilder, HttpError> {
    match auth {
        HttpAuth::Bearer { token_env } => {
            let token = std::env::var(token_env).map_err(|_| HttpError::Auth(format!("env var '{token_env}' not set for bearer auth")))?;
            Ok(builder.bearer_auth(token))
        }
        HttpAuth::ApiKey { header_name, value_env } => {
            let value = std::env::var(value_env).map_err(|_| HttpError::Auth(format!("env var '{value_env}' not set for apiKey auth")))?;
            Ok(builder.header(header_name, value))
        }
        HttpAuth::Basic { user_env, password_env } => {
            let user = std::env::var(user_env).map_err(|_| HttpError::Auth(format!("env var '{user_env}' not set for basic auth")))?;
            let password = std::env::var(password_env).map_err(|_| HttpError::Auth(format!("env var '{password_env}' not set for basic auth")))?;
            Ok(builder.basic_auth(user, Some(password)))
        }
        HttpAuth::Forward { .. } => Err(HttpError::Auth(
            "auth type 'forward' isn't supported yet (needs the caller's own request headers threaded through, \
             which the resolver doesn't do yet)"
                .to_string(),
        )),
    }
}

fn sql_value_to_string(value: &SqlValue) -> String {
    match value {
        SqlValue::Null => String::new(),
        SqlValue::Bool(b) => b.to_string(),
        SqlValue::Int(n) => n.to_string(),
        SqlValue::Float(f) => f.to_string(),
        SqlValue::Text(s) => s.clone(),
        SqlValue::Timestamp(ts) => ts.to_rfc3339(),
    }
}

/// Walks `template`, replacing every `{{name}}` with `encode`'s transform
/// of the matching parameter's string form (an unresolvable name
/// substitutes an empty string either way — the same "say so via a failed
/// request, don't crash" posture used elsewhere). `encode` sees the
/// placeholder's own name alongside its value, so a caller can vary the
/// transform per-placeholder (see `substitute_string`'s `services.`
/// carve-out) rather than only per-template. Static template text outside
/// `{{...}}` is never touched, only the substituted values are — shared by
/// `substitute_string` (URL context, percent-encoded) and
/// `substitute_literal` (JSON body context, verbatim) below.
fn substitute_template(template: &str, params: &HashMap<String, SqlValue>, encode: impl Fn(&str, &str) -> String) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        rest = &rest[start + 2..];
        match rest.find("}}") {
            Some(end) => {
                let name = rest[..end].trim();
                let raw = sql_value_to_string(params.get(name).unwrap_or(&SqlValue::Null));
                out.push_str(&encode(name, &raw));
                rest = &rest[end + 2..];
            }
            None => {
                out.push_str("{{");
                break;
            }
        }
    }
    out.push_str(rest);
    out
}

/// The reserved namespace `run_http_source` (`endpoint::resolve`) seeds
/// `bound` with for the service registry (`config/services.json`) — a
/// server-operator-authored base URL, not caller input, so (unlike every
/// other substituted value) it must reach the URL verbatim: percent-encoding
/// it would mangle its own `://` and `:<port>` into something reqwest can't
/// parse at all.
const SERVICE_REGISTRY_PREFIX: &str = "services.";

/// Substitutes `{{param}}` into a URL template, percent-encoding each
/// substituted value (see `URL_COMPONENT`) — critical when the value came
/// from a caller-controlled source, like a security verifier binding a
/// request header directly into a token-introspection URL. Without this, a
/// crafted header value could inject its own `&extra=param` and change
/// which query parameters the receiving server sees. The one exception is a
/// `services.<name>` placeholder (see `SERVICE_REGISTRY_PREFIX`), passed
/// through unencoded since it's a trusted base URL, not a value a caller
/// could have influenced.
fn substitute_string(template: &str, params: &HashMap<String, SqlValue>) -> String {
    substitute_template(template, params, |name, v| {
        if name.starts_with(SERVICE_REGISTRY_PREFIX) {
            v.to_string()
        } else {
            utf8_percent_encode(v, URL_COMPONENT).to_string()
        }
    })
}

/// Substitutes `{{param}}` verbatim — no percent-encoding — for JSON body
/// templates, where a substituted value is a body *value*, not a URL
/// component, so encoding it would corrupt rather than protect it.
fn substitute_literal(template: &str, params: &HashMap<String, SqlValue>) -> String {
    substitute_template(template, params, |_name, v| v.to_string())
}

/// Walks a JSON body template, substituting `{{param}}` into every string
/// leaf — this is what makes `"body": { "vin": "{{vin}}" }` work the same
/// way as the bare `url` template. Uses `substitute_literal`, not
/// `substitute_string`: these values are going into a JSON body, not a URL,
/// so percent-encoding them would corrupt the value instead of protecting
/// anything.
fn substitute_value(value: &Value, params: &HashMap<String, SqlValue>) -> Value {
    match value {
        Value::String(s) => Value::String(substitute_literal(s, params)),
        Value::Array(items) => Value::Array(items.iter().map(|v| substitute_value(v, params)).collect()),
        Value::Object(map) => Value::Object(map.iter().map(|(k, v)| (k.clone(), substitute_value(v, params))).collect()),
        other => other.clone(),
    }
}

/// The design doc's array-passthrough form: `"body": "{{items}}"`, the
/// *whole* body being exactly one array-typed parameter's value, preserving
/// its real JSON shape — the target API receives the array (or object) as
/// itself, not as a quoted string containing array-looking text the way
/// `substitute_value`'s normal templating would produce. `None` whenever
/// this form doesn't apply (not a bare `"{{name}}"` string, or `name` isn't
/// one of `array_params`) — the caller falls back to normal templating.
///
/// Gated on `array_params` rather than just trying to parse every bound
/// `SqlValue::Text` as JSON: an ordinary scalar parameter can coincidentally
/// hold a string that *looks* like JSON array/object syntax (e.g. a body
/// field whose value is literally the text `"[1,2,3]"`), and reparsing that
/// unconditionally would silently reinterpret it as a real array. Only a
/// parameter the endpoint file actually declared `"type": "array"` gets
/// that treatment.
fn whole_value_passthrough(body: &Value, params: &HashMap<String, SqlValue>, array_params: &HashSet<String>) -> Option<Value> {
    let Value::String(s) = body else { return None };
    let name = s.strip_prefix("{{")?.strip_suffix("}}")?.trim();
    if name.is_empty() || name.contains("{{") || name.contains("}}") || !array_params.contains(name) {
        return None;
    }

    let value = params.get(name)?;
    Some(match value {
        // Array/object values always travel through `SqlValue` as
        // JSON-encoded text (see `sql::json_value_to_sql_value`) — this is
        // the one place that's deliberately reconstituted into real JSON,
        // rather than left as a stringified blob. A parse failure (the
        // declared `"type": "array"` didn't actually match what `from`
        // resolved to) falls back to a plain string rather than erroring.
        SqlValue::Text(text) => serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.clone())),
        other => sql_value_to_json(other),
    })
}

fn navigate<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for part in path.split('.') {
        current = current.get(part)?;
    }
    Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;
    use axum::http::HeaderMap;
    use axum::routing::get;
    use axum::{Json, Router};
    use std::sync::Arc;
    use tokio::net::TcpListener;

    #[test]
    fn substitutes_a_single_placeholder() {
        let mut params = HashMap::new();
        params.insert("vin".to_string(), SqlValue::Text("1HGCM82633A004352".to_string()));
        assert_eq!(
            substitute_string("https://example.com/vehicles/{{vin}}/price", &params),
            "https://example.com/vehicles/1HGCM82633A004352/price"
        );
    }

    #[test]
    fn unresolvable_placeholder_becomes_empty_string() {
        let params = HashMap::new();
        assert_eq!(substitute_string("https://example.com/{{missing}}", &params), "https://example.com/");
    }

    #[test]
    fn navigate_unwraps_a_nested_envelope() {
        let body = serde_json::json!({ "data": { "amount": 100 } });
        assert_eq!(navigate(&body, "data").unwrap(), &serde_json::json!({ "amount": 100 }));
    }

    /// A real end-to-end test against a real local HTTP server (spun up on
    /// an ephemeral port for the duration of the test) rather than a mocked
    /// transport — same "verify against the real thing" approach used for
    /// SQLite's `:memory:` tests.
    #[tokio::test]
    async fn executes_a_real_request_with_auth_templating_and_response_unwrapping() {
        async fn pricing_handler(State(expected_token): State<Arc<String>>, headers: HeaderMap) -> Json<Value> {
            let auth = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
            assert_eq!(auth, format!("Bearer {expected_token}"));
            Json(serde_json::json!({ "data": { "amount": 24500, "currency": "USD" } }))
        }

        // SAFETY: this test doesn't run concurrently with anything else
        // that reads/writes this specific env var.
        unsafe {
            std::env::set_var("FROGS_TEST_PRICING_TOKEN", "test-token-123");
        }
        let app = Router::new()
            .route("/vehicles/:vin/price", get(pricing_handler))
            .with_state(Arc::new("test-token-123".to_string()));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let request_file = HttpRequestFile {
            method: "GET".to_string(),
            url: format!("http://{addr}/vehicles/{{{{vin}}}}/price"),
            body: None,
            auth: Some(HttpAuth::Bearer {
                token_env: "FROGS_TEST_PRICING_TOKEN".to_string(),
            }),
            timeout_ms: 3000,
            response_path: Some("data".to_string()),
        };

        let mut params = HashMap::new();
        params.insert("vin".to_string(), SqlValue::Text("1HGCM82633A004352".to_string()));

        let client = reqwest::Client::new();
        let result = execute(&client, &request_file, &params, &HashSet::new()).await.expect("request should succeed");

        assert_eq!(result, serde_json::json!({ "amount": 24500, "currency": "USD" }));
    }

    fn request_file(url: String) -> HttpRequestFile {
        HttpRequestFile {
            method: "GET".to_string(),
            url,
            body: None,
            auth: None,
            timeout_ms: 3000,
            response_path: None,
        }
    }

    #[tokio::test]
    async fn a_non_2xx_status_becomes_upstream_status() {
        let app = Router::new().route("/broken", get(|| async { (axum::http::StatusCode::NOT_FOUND, "nope") }));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = reqwest::Client::new();
        let err = execute(&client, &request_file(format!("http://{addr}/broken")), &HashMap::new(), &HashSet::new())
            .await
            .expect_err("a 404 upstream response must not be treated as success");

        assert!(matches!(err, HttpError::UpstreamStatus(404)));
    }

    #[tokio::test]
    async fn a_non_json_body_becomes_invalid_json() {
        let app = Router::new().route("/text", get(|| async { "not json at all" }));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = reqwest::Client::new();
        let err = execute(&client, &request_file(format!("http://{addr}/text")), &HashMap::new(), &HashSet::new())
            .await
            .expect_err("a non-JSON body must not parse as a JSON response");

        assert!(matches!(err, HttpError::InvalidJson(_)));
    }

    #[tokio::test]
    async fn a_response_path_missing_from_the_body_is_reported_not_defaulted() {
        let app = Router::new().route("/price", get(|| async { Json(serde_json::json!({ "amount": 100 })) }));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let mut request = request_file(format!("http://{addr}/price"));
        request.response_path = Some("data".to_string());

        let client = reqwest::Client::new();
        let err = execute(&client, &request, &HashMap::new(), &HashSet::new())
            .await
            .expect_err("a responsePath absent from the body must be an error, not null");

        assert!(matches!(err, HttpError::ResponsePathNotFound(path) if path == "data"));
    }

    #[tokio::test]
    async fn a_connection_that_cannot_be_reached_becomes_a_request_error() {
        // Bind then immediately drop the listener: the port is guaranteed
        // free but nothing is listening on it, so the connection is refused
        // deterministically instead of relying on a hardcoded, possibly-in-use port.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let client = reqwest::Client::new();
        let err = execute(&client, &request_file(format!("http://{addr}/anything")), &HashMap::new(), &HashSet::new())
            .await
            .expect_err("nothing listening on this port must fail the request, not hang or panic");

        assert!(matches!(err, HttpError::Request(_)));
    }

    #[tokio::test]
    async fn an_invalid_http_method_is_reported_before_any_request_is_sent() {
        let mut request = request_file("http://127.0.0.1:1/unreachable".to_string());
        request.method = "IN VALID".to_string();

        let err = execute(&reqwest::Client::new(), &request, &HashMap::new(), &HashSet::new())
            .await
            .expect_err("a method containing a space isn't a valid HTTP token");

        assert!(matches!(err, HttpError::InvalidMethod(_)));
    }

    #[tokio::test]
    async fn bearer_auth_with_an_unset_env_var_fails_before_sending() {
        let mut request = request_file("http://127.0.0.1:1/unreachable".to_string());
        request.auth = Some(HttpAuth::Bearer {
            token_env: "FROGS_TEST_DEFINITELY_UNSET_TOKEN_VAR".to_string(),
        });

        let err = execute(&reqwest::Client::new(), &request, &HashMap::new(), &HashSet::new())
            .await
            .expect_err("a missing env var for bearer auth must fail, not send an empty token");

        assert!(matches!(err, HttpError::Auth(_)));
    }

    #[tokio::test]
    async fn forward_auth_is_not_executable_yet() {
        let mut request = request_file("http://127.0.0.1:1/unreachable".to_string());
        request.auth = Some(HttpAuth::Forward {
            header: "Authorization".to_string(),
        });

        let err = execute(&reqwest::Client::new(), &request, &HashMap::new(), &HashSet::new())
            .await
            .expect_err("forward auth has no caller-header plumbing yet, so it must fail rather than silently skip auth");

        assert!(matches!(err, HttpError::Auth(_)));
    }

    /// A parameter value containing URL metacharacters (`&`, `#`, `=`) is
    /// percent-encoded before it's spliced into a URL, so it can't inject
    /// additional query parameters. See the matching end-to-end test in
    /// `security::verify` for why this matters most in the HTTP-verifier
    /// path, where the substituted value *is* the credential being checked.
    #[test]
    fn a_parameter_value_with_url_metacharacters_is_percent_encoded() {
        let mut params = HashMap::new();
        params.insert("token".to_string(), SqlValue::Text("good-token&admin=true".to_string()));

        let url = substitute_string("https://auth.example.com/introspect?token={{token}}", &params);

        assert_eq!(url, "https://auth.example.com/introspect?token=good-token%26admin%3Dtrue");
    }

    #[test]
    fn whole_value_passthrough_reconstitutes_a_json_encoded_array() {
        let mut params = HashMap::new();
        params.insert("items".to_string(), SqlValue::Text("[1,2,3]".to_string()));
        let array_params = HashSet::from(["items".to_string()]);

        let body = Value::String("{{items}}".to_string());
        assert_eq!(whole_value_passthrough(&body, &params, &array_params), Some(serde_json::json!([1, 2, 3])));
    }

    #[test]
    fn whole_value_passthrough_ignores_a_parameter_not_declared_array_typed() {
        // Same coincidentally-array-looking text, but `items` was never
        // declared `"type": "array"` — must not be reinterpreted as JSON.
        let mut params = HashMap::new();
        params.insert("items".to_string(), SqlValue::Text("[1,2,3]".to_string()));

        let body = Value::String("{{items}}".to_string());
        assert_eq!(whole_value_passthrough(&body, &params, &HashSet::new()), None);
    }

    #[test]
    fn whole_value_passthrough_ignores_a_template_with_surrounding_text() {
        let mut params = HashMap::new();
        params.insert("items".to_string(), SqlValue::Text("[1,2,3]".to_string()));
        let array_params = HashSet::from(["items".to_string()]);

        let body = Value::String("prefix {{items}}".to_string());
        assert_eq!(whole_value_passthrough(&body, &params, &array_params), None);
    }

    #[test]
    fn whole_value_passthrough_ignores_a_non_string_body() {
        let array_params = HashSet::from(["items".to_string()]);
        let body = serde_json::json!({ "items": "{{items}}" });
        assert_eq!(whole_value_passthrough(&body, &HashMap::new(), &array_params), None);
    }

    #[test]
    fn whole_value_passthrough_falls_back_to_a_plain_string_when_the_value_is_not_actually_json() {
        // Declared array-typed, but whatever `from` resolved to wasn't
        // valid JSON — falls back gracefully instead of erroring.
        let mut params = HashMap::new();
        params.insert("items".to_string(), SqlValue::Text("not json".to_string()));
        let array_params = HashSet::from(["items".to_string()]);

        let body = Value::String("{{items}}".to_string());
        assert_eq!(whole_value_passthrough(&body, &params, &array_params), Some(Value::String("not json".to_string())));
    }

    /// The design doc's own array-passthrough example, proven against a
    /// real local server: the target API receives the array as itself
    /// (real JSON structure), not a JSON string containing array-looking
    /// text — the gap `substitute_value`'s normal per-leaf templating would
    /// otherwise leave.
    #[tokio::test]
    async fn a_real_request_passes_an_array_typed_parameter_through_as_the_whole_body() {
        async fn echo(Json(body): Json<Value>) -> Json<Value> {
            Json(body)
        }

        let app = Router::new().route("/items", axum::routing::post(echo));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let request = HttpRequestFile {
            method: "POST".to_string(),
            url: format!("http://{addr}/items"),
            body: Some(Value::String("{{items}}".to_string())),
            auth: None,
            timeout_ms: 3000,
            response_path: None,
        };

        let mut params = HashMap::new();
        params.insert("items".to_string(), SqlValue::Text(r#"[{"maker":"Honda"},{"maker":"Ford"}]"#.to_string()));
        let array_params = HashSet::from(["items".to_string()]);

        let client = reqwest::Client::new();
        let result = execute(&client, &request, &params, &array_params).await.expect("request should succeed");

        assert_eq!(result, serde_json::json!([{ "maker": "Honda" }, { "maker": "Ford" }]));
    }
}
