use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use super::error::SourceErrorCause;
use super::schema::{
    ArrayResponse, Cardinality, EndpointFile, Parameter, ParameterType, ResponseField, ResponseShape, SourceDef,
};
use crate::sql::{json_value_to_sql_value, sql_value_to_json, SqlDriver, SqlValue};

/// One resolved source's result, as plain JSON — a `Value::Object` whether
/// it came from a SQL row (converted once here) or an HTTP response body
/// (already JSON natively). `None` means the source failed and every
/// response field that reads from it should render as `null` — the design
/// doc's `optional` semantics. A non-optional failure never reaches this
/// map at all: it short-circuits the whole request via `Err(SourceFailure)`
/// below.
type ResolvedSources = HashMap<String, Option<Value>>;

#[derive(Debug)]
pub struct SourceFailure {
    /// The source's own `onError` override, if it set one — `None` means
    /// "let the classified error code's registry `httpStatus` decide,"
    /// resolved later by whoever builds the actual HTTP response.
    pub on_error: Option<u16>,
    pub source_name: String,
    pub cause: SourceErrorCause,
}

/// What one source's *execution* should do instead of actually running —
/// the testing framework's mock-substitution mechanic (design doc,
/// "Testing"). `mocks` swaps source *execution*, not source *definition*:
/// a mocked source's `type`/`parameters`/everything in `endpoint.sources`
/// is untouched, only whether `resolve_sources` calls out to a real
/// SQL/HTTP call is affected. `Fail` classifies to
/// `SourceErrorCause::Mocked`, which flows through the exact same
/// `onError`/`optional`/registry-lookup path a real failure would — the
/// point is exercising the *real* error-handling logic against an
/// injected code, not reimplementing it here.
#[derive(Debug, Clone, PartialEq)]
pub enum MockOutcome {
    Success(Value),
    Fail(String),
}

/// A mock is `{"fail": "<code>"}` if — and only if — it's a JSON object
/// with exactly that one key and a string value; anything else (including
/// an object that happens to have other fields alongside a `fail` key) is
/// a literal success value. Avoids the ambiguity a generic
/// `#[serde(untagged)]` enum would have picking between the two shapes.
/// Lives here (not in `testing::schema`, where the rest of the test-file
/// parsing types live) because this *is* the type `resolve_sources` itself
/// consumes — one definition, not a parsed copy converted into an
/// execution-time one.
impl<'de> Deserialize<'de> for MockOutcome {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        if let Value::Object(map) = &value {
            if map.len() == 1 {
                if let Some(Value::String(code)) = map.get("fail") {
                    return Ok(MockOutcome::Fail(code.clone()));
                }
            }
        }
        Ok(MockOutcome::Success(value))
    }
}

/// The exact inverse of the `Deserialize` impl above — `frogs test record`
/// (Point 6) constructs `Success` values from a real run and needs them to
/// write back out in the same shape a hand-authored mock would use: a
/// success value serializes as itself (not wrapped), and `Fail` serializes
/// as the `{"fail": "<code>"}` object form.
impl Serialize for MockOutcome {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            MockOutcome::Success(value) => value.serialize(serializer),
            MockOutcome::Fail(code) => {
                let mut map = Map::new();
                map.insert("fail".to_string(), Value::String(code.clone()));
                Value::Object(map).serialize(serializer)
            }
        }
    }
}

/// Runs every source in `endpoint.sources` (in map-iteration order — fine
/// while no source depends on another's output; real dependency ordering
/// is future work once `sources.<name>.` chaining is wired up) and collects
/// each result. Returns `Err` immediately if a non-optional source fails,
/// since there's no point building a response the client can't use.
///
/// `mocks` is keyed by source name; a source with no entry runs for real.
/// The real (non-test) request path always passes an empty map — same
/// "empty means nothing special" convention `transaction_id: ""` uses.
#[allow(clippy::too_many_arguments)]
pub async fn resolve_sources(
    endpoint: &EndpointFile,
    drivers: &HashMap<String, Box<dyn SqlDriver>>,
    sql_root: &Path,
    http_root: &Path,
    http_client: &reqwest::Client,
    path_params: &HashMap<String, String>,
    query_params: &HashMap<String, String>,
    body: &Value,
    transaction_id: &str,
    mocks: &HashMap<String, MockOutcome>,
) -> Result<ResolvedSources, SourceFailure> {
    let mut resolved: ResolvedSources = HashMap::new();

    for (name, source) in &endpoint.sources {
        let (on_error, optional) = match source {
            SourceDef::Sql { on_error, optional, .. } => (*on_error, *optional),
            SourceDef::Http { on_error, optional, .. } => (*on_error, *optional),
        };

        let outcome = match mocks.get(name) {
            Some(MockOutcome::Success(value)) => Ok(value.clone()),
            Some(MockOutcome::Fail(code)) => Err(SourceErrorCause::Mocked(code.clone())),
            None => match source {
                SourceDef::Sql { connection, script, cardinality, parameters, .. } => {
                    run_sql_source(
                        drivers,
                        sql_root,
                        connection,
                        script,
                        *cardinality,
                        parameters,
                        path_params,
                        query_params,
                        body,
                        transaction_id,
                    )
                    .await
                }
                SourceDef::Http { request, cardinality, parameters, .. } => {
                    run_http_source(
                        http_root,
                        http_client,
                        request,
                        *cardinality,
                        parameters,
                        path_params,
                        query_params,
                        body,
                        transaction_id,
                    )
                    .await
                }
            },
        };

        match outcome {
            Ok(value) => {
                resolved.insert(name.clone(), Some(value));
            }
            Err(cause) => {
                if optional {
                    resolved.insert(name.clone(), None);
                } else {
                    return Err(SourceFailure {
                        on_error,
                        source_name: name.clone(),
                        cause,
                    });
                }
            }
        }
    }

    Ok(resolved)
}

#[allow(clippy::too_many_arguments)]
async fn run_sql_source(
    drivers: &HashMap<String, Box<dyn SqlDriver>>,
    sql_root: &Path,
    connection: &str,
    script: &str,
    cardinality: Cardinality,
    parameters: &[Parameter],
    path_params: &HashMap<String, String>,
    query_params: &HashMap<String, String>,
    body: &Value,
    transaction_id: &str,
) -> Result<Value, SourceErrorCause> {
    let driver = drivers
        .get(connection)
        .ok_or_else(|| SourceErrorCause::Config(format!("no connection named '{connection}'")))?;

    let script_path = sql_root.join(connection).join(script);
    let script_contents = std::fs::read_to_string(&script_path)
        .map_err(|e| SourceErrorCause::Config(format!("failed to read {}: {e}", script_path.display())))?;

    let mut bound = HashMap::new();
    for param in parameters {
        bound.insert(param.name.clone(), resolve_from(&param.from, path_params, query_params, body, transaction_id));
    }

    let rows = driver.query(&script_contents, &bound).await.map_err(SourceErrorCause::Sql)?;

    match cardinality {
        Cardinality::One => rows
            .into_iter()
            .next()
            .map(|row| Value::Object(row.iter().map(|(k, v)| (k.clone(), sql_value_to_json(v))).collect()))
            .ok_or(SourceErrorCause::NotFound),
        // Zero rows is a legitimate, non-error result for a list — an empty
        // array, not `SourceErrorCause::NotFound` (that's a "one" concept:
        // no such single row).
        Cardinality::Many => Ok(Value::Array(
            rows.into_iter()
                .map(|row| Value::Object(row.iter().map(|(k, v)| (k.clone(), sql_value_to_json(v))).collect()))
                .collect(),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_http_source(
    http_root: &Path,
    client: &reqwest::Client,
    request: &str,
    cardinality: Cardinality,
    parameters: &[Parameter],
    path_params: &HashMap<String, String>,
    query_params: &HashMap<String, String>,
    body: &Value,
    transaction_id: &str,
) -> Result<Value, SourceErrorCause> {
    if cardinality == Cardinality::Many {
        // SQL's `many` is wired into response assembly (see `run_sql_source`
        // and `resolve::build_array`) — an HTTP source returning a list is a
        // separate, not-yet-designed question (does the upstream paginate?
        // is the array the whole body or nested in an envelope?), so this
        // stays a clear, deliberate error rather than a guess.
        return Err(SourceErrorCause::Config("cardinality 'many' isn't supported for http sources yet".to_string()));
    }

    let request_path = http_root.join(request);
    let contents = std::fs::read_to_string(&request_path)
        .map_err(|e| SourceErrorCause::Config(format!("failed to read {}: {e}", request_path.display())))?;
    let request_file: crate::http::HttpRequestFile = serde_json::from_str(&contents)
        .map_err(|e| SourceErrorCause::Config(format!("invalid JSON in {}: {e}", request_path.display())))?;

    let mut bound = HashMap::new();
    let mut array_params = HashSet::new();
    for param in parameters {
        bound.insert(param.name.clone(), resolve_from(&param.from, path_params, query_params, body, transaction_id));
        if param.param_type == ParameterType::Array {
            array_params.insert(param.name.clone());
        }
    }

    crate::http::execute(client, &request_file, &bound, &array_params).await.map_err(SourceErrorCause::Http)
}

/// `path.`/`query.` look up the URL; `body.<field>` walks the parsed
/// request body's dot-path, and bare `body` binds the *whole* body as one
/// parameter (JSON-encoded as text if it isn't already a scalar — a
/// reasonable fallback until array-typed parameters get native handling,
/// see the design doc's write-operations section, point 1). `context.
/// transactionId` binds the same per-request correlation ID every log line
/// for this request is already tagged with (see `server::RequestId`) — a
/// shared identifier every source in a request can use for its own
/// coordination, per the design doc's multi-source write atomicity section;
/// the engine itself does no distributed-transaction/rollback logic. `header.`/
/// `sources.` still aren't wired up (no caller-header passthrough, no
/// source chaining yet). An unresolvable `from` becomes `SqlValue::Null`
/// rather than an error: a script author who references a parameter that
/// isn't available (or a body sent with a GET) gets a null bound value,
/// not a crash.
fn resolve_from(
    from: &str,
    path_params: &HashMap<String, String>,
    query_params: &HashMap<String, String>,
    body: &Value,
    transaction_id: &str,
) -> SqlValue {
    if let Some(name) = from.strip_prefix("path.") {
        return path_params.get(name).map(|v| SqlValue::Text(v.clone())).unwrap_or(SqlValue::Null);
    }
    if let Some(name) = from.strip_prefix("query.") {
        return query_params.get(name).map(|v| SqlValue::Text(v.clone())).unwrap_or(SqlValue::Null);
    }
    if from == "context.transactionId" {
        return SqlValue::Text(transaction_id.to_string());
    }
    if from == "body" {
        return json_value_to_sql_value(body);
    }
    if let Some(path) = from.strip_prefix("body.") {
        let mut current = body;
        for segment in path.split('.') {
            match current.get(segment) {
                Some(next) => current = next,
                None => return SqlValue::Null,
            }
        }
        return json_value_to_sql_value(current);
    }
    SqlValue::Null
}

/// Builds the JSON response body from resolved sources, per the endpoint's
/// `response` mapping — either the ordinary flat field map, or a top-level
/// array (see `ResponseShape`).
pub fn build_response(endpoint: &EndpointFile, resolved: &ResolvedSources) -> Value {
    match &endpoint.response {
        ResponseShape::Fields(fields) => build_fields(fields, resolved),
        ResponseShape::Array(array) => build_array(array, resolved),
    }
}

/// The ordinary case: each field is independently resolved against
/// `resolved` (every field's `from` is its own full `sources.<name>.<field>`
/// path) and formatted if it declares a `format`.
fn build_fields(fields: &HashMap<String, ResponseField>, resolved: &ResolvedSources) -> Value {
    let mut out = Map::new();
    for (field, mapping) in fields {
        out.insert(field.clone(), build_field(mapping, resolved));
    }
    Value::Object(out)
}

fn build_field(mapping: &ResponseField, resolved: &ResolvedSources) -> Value {
    match mapping {
        ResponseField::Array(array) => build_array(array, resolved),
        ResponseField::Plain(_) | ResponseField::Detailed(_) => {
            let value = lookup(mapping.from_path(), resolved);
            match mapping.detail() {
                Some(detail) => super::format::apply(value, detail),
                None => value,
            }
        }
    }
}

/// `array.source` names a `cardinality: "many"` source's *whole* resolved
/// value (e.g. `"sources.books"` — not `sources.books.<field>`, since there
/// is no single object to pull one field from). Each row in that array gets
/// `array.items` applied against it independently, producing one output
/// object per row — a source that isn't actually an array (never resolved,
/// optional-and-failed, or a `cardinality: "one"` source used here by
/// mistake) yields an empty list rather than an error, matching this
/// project's general "a missing value renders as absent, not a crash"
/// posture for response assembly.
fn build_array(array: &ArrayResponse, resolved: &ResolvedSources) -> Value {
    let Value::Array(rows) = lookup_source(&array.source, resolved) else {
        return Value::Array(Vec::new());
    };
    Value::Array(rows.iter().map(|row| build_fields_against_row(&array.items, row)).collect())
}

/// `items`' own field paths are bare column names, not
/// `sources.<name>.<field>` — `array.source` already established which
/// row-shaped value they're read from, so each field is looked up directly
/// against that one row (dot-separated for a nested field, same traversal
/// `resolve_from`'s `body.*` handling already uses).
fn build_fields_against_row(fields: &HashMap<String, ResponseField>, row: &Value) -> Value {
    let mut out = Map::new();
    for (field, mapping) in fields {
        out.insert(field.clone(), build_field_against_row(mapping, row));
    }
    Value::Object(out)
}

fn build_field_against_row(mapping: &ResponseField, row: &Value) -> Value {
    match mapping {
        // Many-depends-on-many fan-out isn't supported yet — same scope
        // boundary as HTTP `cardinality: "many"` (see `run_http_source`).
        ResponseField::Array(_) => Value::Null,
        ResponseField::Plain(path) => lookup_in_row(path, row),
        ResponseField::Detailed(detail) => super::format::apply(lookup_in_row(&detail.from, row), detail),
    }
}

fn lookup_in_row(path: &str, row: &Value) -> Value {
    let mut current = row;
    for segment in path.split('.') {
        match current.get(segment) {
            Some(next) => current = next,
            None => return Value::Null,
        }
    }
    current.clone()
}

fn lookup(from: &str, resolved: &ResolvedSources) -> Value {
    let mut parts = from.split('.');
    let (Some("sources"), Some(source_name), Some(field_name)) = (parts.next(), parts.next(), parts.next()) else {
        return Value::Null;
    };

    match resolved.get(source_name) {
        Some(Some(value)) => value.get(field_name).cloned().unwrap_or(Value::Null),
        _ => Value::Null,
    }
}

/// Like `lookup`, but returns a source's *entire* resolved value —
/// `array.source` is `"sources.<name>"`, exactly two parts, unlike a scalar
/// field's `"sources.<name>.<field>"`.
fn lookup_source(from: &str, resolved: &ResolvedSources) -> Value {
    let mut parts = from.split('.');
    let (Some("sources"), Some(source_name), None) = (parts.next(), parts.next(), parts.next()) else {
        return Value::Null;
    };

    match resolved.get(source_name) {
        Some(Some(value)) => value.clone(),
        _ => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql::SqlError;
    use std::path::PathBuf;

    #[test]
    fn a_fail_object_parses_as_a_fail_mock() {
        let mock: MockOutcome = serde_json::from_str(r#"{ "fail": "datasource.sql.not_found" }"#).unwrap();
        assert_eq!(mock, MockOutcome::Fail("datasource.sql.not_found".to_string()));
    }

    #[test]
    fn a_success_object_with_other_fields_alongside_fail_is_not_reinterpreted() {
        let mock: MockOutcome = serde_json::from_str(r#"{ "fail": "not a code", "other": 1 }"#).unwrap();
        assert_eq!(mock, MockOutcome::Success(serde_json::json!({ "fail": "not a code", "other": 1 })));
    }

    /// A fake `SqlDriver` so these tests exercise the resolution logic
    /// (cardinality, optional-failure-to-null, response mapping) without a
    /// real Postgres instance — the same "swap what a source returns, not
    /// how it runs" principle the design doc's own testing section
    /// describes for the eventual `.test.json` mock runner.
    #[derive(Debug)]
    struct FakeDriver {
        rows: Vec<HashMap<String, SqlValue>>,
        fail: bool,
    }

    #[async_trait::async_trait]
    impl SqlDriver for FakeDriver {
        async fn query(&self, _script: &str, _params: &HashMap<String, SqlValue>) -> Result<Vec<HashMap<String, SqlValue>>, SqlError> {
            if self.fail {
                Err(SqlError::QueryFailed("simulated failure".to_string()))
            } else {
                Ok(self.rows.clone())
            }
        }
    }

    fn row(pairs: &[(&str, SqlValue)]) -> HashMap<String, SqlValue> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
    }

    /// `run_sql_source`/`run_http_source` read their config from disk before
    /// doing anything else — this scratch dir gives both a real place to
    /// read from: `db/q.sql` for the fake driver's tests (which ignore the
    /// script's *contents* but still need the file to exist), `http/` is
    /// created for parity even though most tests here don't use it.
    fn temp_project_root() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "frogs-resolve-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("db")).unwrap();
        std::fs::create_dir_all(root.join("http")).unwrap();
        std::fs::write(root.join("db/q.sql"), "SELECT 1;").unwrap();
        root
    }

    fn endpoint_with_one_sql_source(name: &str, optional: bool) -> EndpointFile {
        let json = format!(
            r#"{{
                "operationId": "test",
                "sources": {{
                    "{name}": {{
                        "type": "sql",
                        "connection": "db",
                        "script": "q.sql",
                        "cardinality": "one",
                        "onError": 500,
                        "optional": {optional},
                        "parameters": [{{ "name": "vin", "from": "path.vin" }}]
                    }}
                }},
                "response": {{ "vin": "sources.{name}.vin" }}
            }}"#
        );
        serde_json::from_str(&json).unwrap()
    }

    #[tokio::test]
    async fn resolves_a_row_and_maps_it_into_the_response() {
        let endpoint = endpoint_with_one_sql_source("car", false);
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert(
            "db".to_string(),
            Box::new(FakeDriver {
                rows: vec![row(&[("vin", SqlValue::Text("1HGCM82633A004352".to_string()))])],
                fail: false,
            }),
        );

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let path_params = HashMap::from([("vin".to_string(), "1HGCM82633A004352".to_string())]);
        let resolved = resolve_sources(
            &endpoint,
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &path_params,
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
        )
        .await
        .expect("non-optional source with a row should resolve");

        let body = build_response(&endpoint, &resolved);
        assert_eq!(body["vin"], "1HGCM82633A004352");
    }

    #[tokio::test]
    async fn optional_source_failure_becomes_null_not_an_error() {
        let endpoint = endpoint_with_one_sql_source("pricing", true);
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(FakeDriver { rows: vec![], fail: true }));

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let resolved = resolve_sources(
            &endpoint,
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
        )
        .await
        .expect("an optional source's failure must not fail the whole request");

        let body = build_response(&endpoint, &resolved);
        assert_eq!(body["vin"], Value::Null);
    }

    #[tokio::test]
    async fn non_optional_source_failure_returns_its_on_error_status() {
        let endpoint = endpoint_with_one_sql_source("car", false);
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(FakeDriver { rows: vec![], fail: true }));

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let failure = resolve_sources(
            &endpoint,
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
        )
        .await
        .expect_err("a non-optional source's failure must fail the request");

        assert_eq!(failure.on_error, Some(500));
        assert_eq!(failure.source_name, "car");
        assert_eq!(failure.cause.code(), "datasource.sql.query_failed");
    }

    #[tokio::test]
    async fn omitted_on_error_carries_through_as_none() {
        let json = r#"{
            "operationId": "test",
            "sources": {
                "car": {
                    "type": "sql",
                    "connection": "db",
                    "script": "q.sql",
                    "parameters": [{ "name": "vin", "from": "path.vin" }]
                }
            },
            "response": { "vin": "sources.car.vin" }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();

        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(FakeDriver { rows: vec![], fail: true }));

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let failure = resolve_sources(
            &endpoint,
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
        )
        .await
        .expect_err("a non-optional source's failure must fail the request");

        assert_eq!(failure.on_error, None);
    }

    #[tokio::test]
    async fn cardinality_one_with_no_rows_is_treated_as_a_failure() {
        let endpoint = endpoint_with_one_sql_source("car", false);
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(FakeDriver { rows: vec![], fail: false }));

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let failure = resolve_sources(
            &endpoint,
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
        )
        .await
        .expect_err("zero rows for cardinality 'one' should be treated as not found");

        assert_eq!(failure.source_name, "car");
        assert_eq!(failure.cause.code(), "datasource.sql.not_found");
    }

    /// A real HTTP source, executed against a real local server, wired all
    /// the way through `resolve_sources` and the `sources.pricing.amount`
    /// dot-path lookup — not just `http::execute` in isolation.
    #[tokio::test]
    async fn resolves_a_real_http_source_and_maps_it_into_the_response() {
        use axum::routing::get;
        use axum::{Json, Router};

        let app = Router::new().route(
            "/price",
            get(|| async { Json(serde_json::json!({ "amount": 24500, "currency": "USD" })) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let root = temp_project_root();
        std::fs::write(
            root.join("http/pricing.json"),
            format!(r#"{{ "method": "GET", "url": "http://{addr}/price" }}"#),
        )
        .unwrap();

        let json = r#"{
            "operationId": "test",
            "sources": {
                "pricing": {
                    "type": "http",
                    "request": "pricing.json",
                    "onError": 502,
                    "optional": false
                }
            },
            "response": { "price": "sources.pricing.amount" }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();

        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        let client = reqwest::Client::new();
        let resolved = resolve_sources(
            &endpoint,
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
        )
        .await
        .expect("the real HTTP source should resolve");

        let body = build_response(&endpoint, &resolved);
        assert_eq!(body["price"], 24500);
    }

    #[tokio::test]
    async fn sql_cardinality_many_resolves_to_an_array_of_rows() {
        let json = r#"{
            "operationId": "test",
            "sources": {
                "cars": { "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "many" }
            },
            "response": {}
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert(
            "db".to_string(),
            Box::new(FakeDriver {
                rows: vec![
                    row(&[("vin", SqlValue::Text("AAA".to_string()))]),
                    row(&[("vin", SqlValue::Text("BBB".to_string()))]),
                ],
                fail: false,
            }),
        );

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let resolved =
            resolve_sources(&endpoint, &drivers, &root, &root.join("http"), &client, &HashMap::new(), &HashMap::new(), &Value::Null, "", &HashMap::new())
                .await
                .expect("a many-cardinality source with rows should resolve");

        let Some(Value::Array(rows)) = resolved.get("cars").cloned().flatten() else {
            panic!("expected sources.cars to resolve to a JSON array");
        };
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["vin"], "AAA");
        assert_eq!(rows[1]["vin"], "BBB");
    }

    #[tokio::test]
    async fn sql_cardinality_many_with_zero_rows_is_an_empty_array_not_an_error() {
        let json = r#"{
            "operationId": "test",
            "sources": {
                "cars": { "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "many" }
            },
            "response": {}
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(FakeDriver { rows: vec![], fail: false }));

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let resolved =
            resolve_sources(&endpoint, &drivers, &root, &root.join("http"), &client, &HashMap::new(), &HashMap::new(), &Value::Null, "", &HashMap::new())
                .await
                .expect("zero rows is a valid result for a list, not a failure");

        assert_eq!(resolved.get("cars").cloned().flatten(), Some(Value::Array(Vec::new())));
    }

    #[tokio::test]
    async fn build_response_maps_a_many_source_into_a_top_level_array() {
        let json = r#"{
            "operationId": "test",
            "sources": {
                "cars": { "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "many" }
            },
            "response": {
                "type": "array",
                "source": "sources.cars",
                "items": { "vin": "vin", "year": { "from": "year", "format": "integer" } }
            }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert(
            "db".to_string(),
            Box::new(FakeDriver {
                rows: vec![row(&[("vin", SqlValue::Text("AAA".to_string())), ("year", SqlValue::Int(2020))])],
                fail: false,
            }),
        );

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let resolved =
            resolve_sources(&endpoint, &drivers, &root, &root.join("http"), &client, &HashMap::new(), &HashMap::new(), &Value::Null, "", &HashMap::new())
                .await
                .unwrap();

        let body = build_response(&endpoint, &resolved);
        assert_eq!(body, serde_json::json!([{ "vin": "AAA", "year": 2020 }]));
    }

    #[tokio::test]
    async fn build_response_maps_a_many_source_into_a_nested_array_field() {
        let json = r#"{
            "operationId": "test",
            "sources": {
                "cars": { "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "many" }
            },
            "response": {
                "items": {
                    "type": "array",
                    "source": "sources.cars",
                    "items": { "vin": "vin" }
                },
                "total": "sources.cars.doesNotExist"
            }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert(
            "db".to_string(),
            Box::new(FakeDriver {
                rows: vec![
                    row(&[("vin", SqlValue::Text("AAA".to_string()))]),
                    row(&[("vin", SqlValue::Text("BBB".to_string()))]),
                ],
                fail: false,
            }),
        );

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let resolved =
            resolve_sources(&endpoint, &drivers, &root, &root.join("http"), &client, &HashMap::new(), &HashMap::new(), &Value::Null, "", &HashMap::new())
                .await
                .unwrap();

        let body = build_response(&endpoint, &resolved);
        assert_eq!(body["items"], serde_json::json!([{ "vin": "AAA" }, { "vin": "BBB" }]));
        // `sources.cars` is an array, not an object with a `doesNotExist`
        // field — a mismatched lookup renders as null, same "absent, not a
        // crash" posture as every other unresolved response field.
        assert_eq!(body["total"], Value::Null);
    }

    #[tokio::test]
    async fn a_source_that_is_not_actually_an_array_yields_an_empty_list() {
        let endpoint = endpoint_with_one_sql_source("car", false);
        let mut endpoint = endpoint;
        endpoint.response = serde_json::from_str(r#"{ "type": "array", "source": "sources.car", "items": {} }"#).unwrap();

        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert(
            "db".to_string(),
            Box::new(FakeDriver { rows: vec![row(&[("vin", SqlValue::Text("AAA".to_string()))])], fail: false }),
        );

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let path_params = HashMap::from([("vin".to_string(), "AAA".to_string())]);
        let resolved = resolve_sources(
            &endpoint,
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &path_params,
            &HashMap::new(),
            &Value::Null,
            "",
            &HashMap::new(),
        )
        .await
        .unwrap();

        let body = build_response(&endpoint, &resolved);
        assert_eq!(body, serde_json::json!([]));
    }

    #[tokio::test]
    async fn http_cardinality_many_is_a_config_failure_not_wired_up_yet() {
        let json = r#"{
            "operationId": "test",
            "sources": {
                "pricing": { "type": "http", "request": "pricing.json", "cardinality": "many" }
            },
            "response": {}
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let failure =
            resolve_sources(&endpoint, &drivers, &root, &root.join("http"), &client, &HashMap::new(), &HashMap::new(), &Value::Null, "", &HashMap::new())
            .await
            .expect_err("cardinality 'many' has no response-assembly support yet, even before the request file is read");

        assert_eq!(failure.cause.code(), "unexpected.error");
    }

    #[tokio::test]
    async fn referencing_an_unknown_connection_name_is_a_config_failure() {
        let endpoint = endpoint_with_one_sql_source("car", false);
        // No "db" connection registered at all — a typo'd or removed entry
        // in connections.json, distinct from the driver itself failing.
        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let failure =
            resolve_sources(&endpoint, &drivers, &root, &root.join("http"), &client, &HashMap::new(), &HashMap::new(), &Value::Null, "", &HashMap::new())
            .await
            .expect_err("a source referencing a connection that isn't configured must fail clearly");

        assert_eq!(failure.source_name, "car");
        assert_eq!(failure.cause.code(), "unexpected.error");
    }

    #[tokio::test]
    async fn a_missing_sql_script_file_is_a_config_failure() {
        let json = r#"{
            "operationId": "test",
            "sources": {
                "car": { "type": "sql", "connection": "db", "script": "does_not_exist.sql" }
            },
            "response": {}
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(FakeDriver { rows: vec![], fail: false }));

        let root = temp_project_root(); // only creates db/q.sql, not does_not_exist.sql
        let client = reqwest::Client::new();
        let failure =
            resolve_sources(&endpoint, &drivers, &root, &root.join("http"), &client, &HashMap::new(), &HashMap::new(), &Value::Null, "", &HashMap::new())
            .await
            .expect_err("a script file that isn't on disk must fail before ever reaching the driver");

        assert_eq!(failure.cause.code(), "unexpected.error");
    }

    #[tokio::test]
    async fn a_failing_non_optional_http_source_fails_the_whole_request() {
        use axum::routing::get;
        use axum::{Json, Router};

        let app = Router::new().route(
            "/price",
            get(|| async { (axum::http::StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({}))) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let root = temp_project_root();
        std::fs::write(
            root.join("http/pricing.json"),
            format!(r#"{{ "method": "GET", "url": "http://{addr}/price" }}"#),
        )
        .unwrap();

        let json = r#"{
            "operationId": "test",
            "sources": {
                "pricing": { "type": "http", "request": "pricing.json", "onError": 502, "optional": false }
            },
            "response": { "price": "sources.pricing.amount" }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();
        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();

        let root_http = root.join("http");
        let client = reqwest::Client::new();
        let failure =
            resolve_sources(&endpoint, &drivers, &root, &root_http, &client, &HashMap::new(), &HashMap::new(), &Value::Null, "", &HashMap::new())
            .await
            .expect_err("a non-optional http source returning a server error must fail the request");

        assert_eq!(failure.on_error, Some(502));
        assert_eq!(failure.cause.code(), "datasource.http.upstream_error");
    }

    /// Mirrors `cars-demo`'s real shape: a `sql` source and an `http` source
    /// resolving side by side (not chained — parameter chaining isn't wired
    /// up yet, see the module doc comment) and both landing in one response.
    #[tokio::test]
    async fn a_sql_source_and_an_http_source_together_both_populate_the_response() {
        use axum::routing::get;
        use axum::{Json, Router};

        let app = Router::new().route(
            "/price",
            get(|| async { Json(serde_json::json!({ "amount": 24500, "currency": "USD" })) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let root = temp_project_root();
        std::fs::write(
            root.join("http/pricing.json"),
            format!(r#"{{ "method": "GET", "url": "http://{addr}/price" }}"#),
        )
        .unwrap();

        let json = r#"{
            "operationId": "getCarByVin",
            "sources": {
                "car": {
                    "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "one",
                    "parameters": [{ "name": "vin", "from": "path.vin" }]
                },
                "pricing": {
                    "type": "http", "request": "pricing.json", "optional": true
                }
            },
            "response": {
                "vin": "sources.car.vin",
                "maker": "sources.car.maker",
                "price": "sources.pricing.amount",
                "currency": "sources.pricing.currency"
            }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();

        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert(
            "db".to_string(),
            Box::new(FakeDriver {
                rows: vec![row(&[
                    ("vin", SqlValue::Text("1HGCM82633A004352".to_string())),
                    ("maker", SqlValue::Text("Honda".to_string())),
                ])],
                fail: false,
            }),
        );

        let path_params = HashMap::from([("vin".to_string(), "1HGCM82633A004352".to_string())]);
        let client = reqwest::Client::new();
        let resolved =
            resolve_sources(&endpoint, &drivers, &root, &root.join("http"), &client, &path_params, &HashMap::new(), &Value::Null, "", &HashMap::new())
            .await
            .expect("both sources should resolve independently");

        let body = build_response(&endpoint, &resolved);
        assert_eq!(body["vin"], "1HGCM82633A004352");
        assert_eq!(body["maker"], "Honda");
        assert_eq!(body["price"], 24500);
        assert_eq!(body["currency"], "USD");
    }

    #[test]
    fn resolve_from_reads_a_top_level_body_field() {
        let body = serde_json::json!({ "maker": "Honda" });
        assert_eq!(resolve_from("body.maker", &HashMap::new(), &HashMap::new(), &body, ""), SqlValue::Text("Honda".to_string()));
    }

    #[test]
    fn resolve_from_reads_a_nested_body_field() {
        let body = serde_json::json!({ "car": { "maker": "Honda" } });
        assert_eq!(
            resolve_from("body.car.maker", &HashMap::new(), &HashMap::new(), &body, ""),
            SqlValue::Text("Honda".to_string())
        );
    }

    #[test]
    fn resolve_from_a_missing_body_field_is_null_not_an_error() {
        let body = serde_json::json!({ "maker": "Honda" });
        assert_eq!(resolve_from("body.model", &HashMap::new(), &HashMap::new(), &body, ""), SqlValue::Null);
    }

    #[test]
    fn resolve_from_bare_body_binds_the_whole_value_json_encoded() {
        let body = serde_json::json!({ "maker": "Honda" });
        assert_eq!(
            resolve_from("body", &HashMap::new(), &HashMap::new(), &body, ""),
            SqlValue::Text(r#"{"maker":"Honda"}"#.to_string())
        );
    }

    #[test]
    fn resolve_from_bare_body_as_a_scalar_binds_the_scalar_directly() {
        let body = serde_json::json!(42);
        assert_eq!(resolve_from("body", &HashMap::new(), &HashMap::new(), &body, ""), SqlValue::Int(42));
    }

    #[test]
    fn resolve_from_with_no_body_sent_is_null() {
        assert_eq!(resolve_from("body.maker", &HashMap::new(), &HashMap::new(), &Value::Null, ""), SqlValue::Null);
    }

    #[test]
    fn resolve_from_binds_the_transaction_id() {
        assert_eq!(
            resolve_from("context.transactionId", &HashMap::new(), &HashMap::new(), &Value::Null, "txn-123"),
            SqlValue::Text("txn-123".to_string())
        );
    }

    /// A shared coordination ID, not a per-source secret — every source in
    /// the same request must see the exact same value, so two sources
    /// resolved side by side (mirroring `resolve_sources`' own real usage,
    /// not just a direct `resolve_from` call) both end up with it.
    #[tokio::test]
    async fn every_source_in_a_request_receives_the_same_transaction_id() {
        #[derive(Debug)]
        struct RecordingDriver {
            received: std::sync::Arc<std::sync::Mutex<Vec<HashMap<String, SqlValue>>>>,
        }

        #[async_trait::async_trait]
        impl SqlDriver for RecordingDriver {
            async fn query(
                &self,
                _script: &str,
                params: &HashMap<String, SqlValue>,
            ) -> Result<Vec<HashMap<String, SqlValue>>, SqlError> {
                self.received.lock().unwrap().push(params.clone());
                Ok(vec![row(&[("id", SqlValue::Int(1))])])
            }
        }

        let json = r#"{
            "operationId": "createCar",
            "sources": {
                "a": {
                    "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "one",
                    "parameters": [{ "name": "txId", "from": "context.transactionId" }]
                },
                "b": {
                    "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "one",
                    "parameters": [{ "name": "txId", "from": "context.transactionId" }]
                }
            },
            "response": {}
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();

        let received = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(RecordingDriver { received: received.clone() }));

        let root = temp_project_root();
        let client = reqwest::Client::new();
        resolve_sources(
            &endpoint,
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "shared-txn-id",
            &HashMap::new(),
        )
        .await
        .expect("both sources should resolve");

        let calls = received.lock().unwrap();
        assert_eq!(calls.len(), 2);
        for call in calls.iter() {
            assert_eq!(call.get("txId"), Some(&SqlValue::Text("shared-txn-id".to_string())));
        }
    }

    /// The parity gap flagged in review: the test above only proves
    /// `context.transactionId` for two *SQL* sources — `run_http_source`
    /// calls the exact same `resolve_from` function, but that path had no
    /// test of its own. Proven here via a real local HTTP server that
    /// records the raw query string it actually received, the same
    /// "capture what a fake server got" technique used in
    /// `security::verify`'s injection test.
    #[tokio::test]
    async fn an_http_source_also_receives_the_shared_transaction_id() {
        use axum::extract::{RawQuery, State};
        use axum::routing::get;
        use axum::{Json, Router};
        use std::sync::{Arc, Mutex};

        async fn record(State(received): State<Arc<Mutex<Option<String>>>>, RawQuery(query): RawQuery) -> Json<Value> {
            *received.lock().unwrap() = query;
            Json(serde_json::json!({ "ok": true }))
        }

        let received_query: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let app = Router::new().route("/ping", get(record)).with_state(received_query.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let root = temp_project_root();
        std::fs::write(
            root.join("http/ping.json"),
            format!(r#"{{ "method": "GET", "url": "http://{addr}/ping?txId={{{{txId}}}}" }}"#),
        )
        .unwrap();

        let json = r#"{
            "operationId": "test",
            "sources": {
                "ping": {
                    "type": "http",
                    "request": "ping.json",
                    "parameters": [{ "name": "txId", "from": "context.transactionId" }]
                }
            },
            "response": {}
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();

        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        let client = reqwest::Client::new();
        resolve_sources(
            &endpoint,
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "shared-txn-id",
            &HashMap::new(),
        )
        .await
        .expect("the http source should resolve");

        assert_eq!(
            received_query.lock().unwrap().as_deref(),
            Some("txId=shared-txn-id"),
            "an HTTP source's context.transactionId parameter must receive the same transaction id a SQL source would"
        );
    }

    /// The point-2 exit criterion, proven through the real `resolve_sources`
    /// path (not just the `resolve_from` unit tests above): a SQL source's
    /// `"from": "body.maker"` parameter actually receives the request
    /// body's `maker` field, recorded here by a driver that captures
    /// exactly what it was bound — the same "swap what a source returns"
    /// principle as `FakeDriver`, but recording inbound params instead of
    /// controlling outbound rows.
    #[tokio::test]
    async fn a_sql_source_reads_a_parameter_from_the_request_body() {
        #[derive(Debug)]
        struct RecordingDriver {
            received: std::sync::Arc<std::sync::Mutex<Option<HashMap<String, SqlValue>>>>,
        }

        #[async_trait::async_trait]
        impl SqlDriver for RecordingDriver {
            async fn query(
                &self,
                _script: &str,
                params: &HashMap<String, SqlValue>,
            ) -> Result<Vec<HashMap<String, SqlValue>>, SqlError> {
                *self.received.lock().unwrap() = Some(params.clone());
                Ok(vec![row(&[("id", SqlValue::Int(1))])])
            }
        }

        let json = r#"{
            "operationId": "createCar",
            "sources": {
                "car": {
                    "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "one",
                    "parameters": [{ "name": "maker", "from": "body.maker" }]
                }
            },
            "response": { "id": "sources.car.id" }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();

        let received = std::sync::Arc::new(std::sync::Mutex::new(None));
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(RecordingDriver { received: received.clone() }));

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let body = serde_json::json!({ "maker": "Honda" });
        let resolved =
            resolve_sources(&endpoint, &drivers, &root, &root.join("http"), &client, &HashMap::new(), &HashMap::new(), &body, "", &HashMap::new())
                .await
                .expect("the sql source should resolve using the body-derived parameter");

        let response = build_response(&endpoint, &resolved);
        assert_eq!(response["id"], 1);

        let received_params = received.lock().unwrap().clone().unwrap();
        assert_eq!(received_params.get("maker"), Some(&SqlValue::Text("Honda".to_string())));
    }

    /// Point 3's SQL-side behavior, per the design doc: "an array-typed
    /// parameter is passed to the script as a single value ... JSON-encoded
    /// text" where a native driver array type isn't wired up. No SQL-side
    /// code change was actually needed for this — `json_value_to_sql_value`
    /// already JSON-encodes arrays generically — so this test exists to
    /// prove that fallback holds end to end for a real array-typed
    /// `parameters[]` entry, not just as an isolated unit test.
    #[tokio::test]
    async fn a_sql_source_receives_an_array_typed_body_field_as_json_encoded_text() {
        #[derive(Debug)]
        struct RecordingDriver {
            received: std::sync::Arc<std::sync::Mutex<Option<HashMap<String, SqlValue>>>>,
        }

        #[async_trait::async_trait]
        impl SqlDriver for RecordingDriver {
            async fn query(
                &self,
                _script: &str,
                params: &HashMap<String, SqlValue>,
            ) -> Result<Vec<HashMap<String, SqlValue>>, SqlError> {
                *self.received.lock().unwrap() = Some(params.clone());
                Ok(vec![row(&[("count", SqlValue::Int(2))])])
            }
        }

        let json = r#"{
            "operationId": "createCarBatch",
            "sources": {
                "batch": {
                    "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "one",
                    "parameters": [{ "name": "items", "from": "body.items", "type": "array" }]
                }
            },
            "response": { "count": "sources.batch.count" }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();

        let received = std::sync::Arc::new(std::sync::Mutex::new(None));
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(RecordingDriver { received: received.clone() }));

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let body = serde_json::json!({ "items": [{ "maker": "Honda" }, { "maker": "Ford" }] });
        resolve_sources(&endpoint, &drivers, &root, &root.join("http"), &client, &HashMap::new(), &HashMap::new(), &body, "", &HashMap::new())
            .await
            .expect("the sql source should resolve using the array-typed body parameter");

        let received_params = received.lock().unwrap().clone().unwrap();
        assert_eq!(
            received_params.get("items"),
            Some(&SqlValue::Text(r#"[{"maker":"Honda"},{"maker":"Ford"}]"#.to_string()))
        );
    }

    /// A driver that panics if it's ever actually queried — the strongest
    /// possible proof a mocked source bypasses real execution entirely,
    /// not just "the mocked value happened to win."
    #[derive(Debug)]
    struct PanicsIfCalledDriver;

    #[async_trait::async_trait]
    impl SqlDriver for PanicsIfCalledDriver {
        async fn query(&self, _script: &str, _params: &HashMap<String, SqlValue>) -> Result<Vec<HashMap<String, SqlValue>>, SqlError> {
            panic!("a mocked source must never reach the real driver");
        }
    }

    #[tokio::test]
    async fn a_mocked_source_success_bypasses_real_execution_entirely() {
        let endpoint = endpoint_with_one_sql_source("car", false);
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert("db".to_string(), Box::new(PanicsIfCalledDriver));

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let mut mocks = HashMap::new();
        mocks.insert(
            "car".to_string(),
            MockOutcome::Success(serde_json::json!({ "vin": "MOCKED-VIN" })),
        );

        let resolved = resolve_sources(
            &endpoint,
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &mocks,
        )
        .await
        .expect("a mocked source should resolve without touching the real driver");

        let body = build_response(&endpoint, &resolved);
        assert_eq!(body["vin"], "MOCKED-VIN");
    }

    #[tokio::test]
    async fn a_mocked_source_failure_is_classified_by_its_injected_code_and_respects_on_error() {
        let endpoint = endpoint_with_one_sql_source("car", false);
        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new(); // no "db" connection at all — proves the mock never needs one

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let mut mocks = HashMap::new();
        mocks.insert("car".to_string(), MockOutcome::Fail("datasource.sql.connection_failed".to_string()));

        let failure = resolve_sources(
            &endpoint,
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &mocks,
        )
        .await
        .expect_err("a mocked failure on a non-optional source must fail the request");

        // `endpoint_with_one_sql_source` sets `"onError": 500` on the source itself.
        assert_eq!(failure.on_error, Some(500));
        assert_eq!(failure.cause.code(), "datasource.sql.connection_failed");
    }

    #[tokio::test]
    async fn a_mocked_failure_on_an_optional_source_degrades_to_null_like_a_real_one_would() {
        let endpoint = endpoint_with_one_sql_source("pricing", true);
        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let mut mocks = HashMap::new();
        mocks.insert("pricing".to_string(), MockOutcome::Fail("datasource.http.timeout".to_string()));

        let resolved = resolve_sources(
            &endpoint,
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &mocks,
        )
        .await
        .expect("an optional source's mocked failure must not fail the whole request");

        let body = build_response(&endpoint, &resolved);
        assert_eq!(body["vin"], Value::Null);
    }

    /// The design doc's "hybrid" case: `mocks` can cover some sources and
    /// not others in the same file format — one mocked, one real, both
    /// landing in the same response.
    #[tokio::test]
    async fn a_partially_mocked_request_runs_the_unmocked_source_for_real() {
        let json = r#"{
            "operationId": "getCarByVin",
            "sources": {
                "car": {
                    "type": "sql", "connection": "db", "script": "q.sql", "cardinality": "one",
                    "parameters": [{ "name": "vin", "from": "path.vin" }]
                },
                "pricing": { "type": "http", "request": "pricing.json" }
            },
            "response": {
                "vin": "sources.car.vin",
                "price": "sources.pricing.amount"
            }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();

        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert(
            "db".to_string(),
            Box::new(FakeDriver {
                rows: vec![row(&[("vin", SqlValue::Text("1HGCM82633A004352".to_string()))])],
                fail: false,
            }),
        );

        let root = temp_project_root();
        let client = reqwest::Client::new();
        let path_params = HashMap::from([("vin".to_string(), "1HGCM82633A004352".to_string())]);
        let mut mocks = HashMap::new();
        mocks.insert("pricing".to_string(), MockOutcome::Success(serde_json::json!({ "amount": 24500 })));

        let resolved = resolve_sources(
            &endpoint,
            &drivers,
            &root,
            &root.join("http"), // never actually read — the http source is mocked
            &client,
            &path_params,
            &HashMap::new(),
            &Value::Null,
            "",
            &mocks,
        )
        .await
        .expect("the real sql source and the mocked http source should both resolve");

        let body = build_response(&endpoint, &resolved);
        assert_eq!(body["vin"], "1HGCM82633A004352", "the unmocked source ran for real");
        assert_eq!(body["price"], 24500, "the mocked source used its substituted value");
    }

    #[tokio::test]
    async fn an_http_source_can_be_mocked_bypassing_the_real_request_entirely() {
        let json = r#"{
            "operationId": "test",
            "sources": {
                "pricing": { "type": "http", "request": "does_not_exist.json" }
            },
            "response": { "price": "sources.pricing.amount" }
        }"#;
        let endpoint: EndpointFile = serde_json::from_str(json).unwrap();

        // No http/does_not_exist.json on disk at all — if the mock didn't
        // bypass real execution, this would fail trying to read the file.
        let root = temp_project_root();
        let drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        let client = reqwest::Client::new();
        let mut mocks = HashMap::new();
        mocks.insert("pricing".to_string(), MockOutcome::Success(serde_json::json!({ "amount": 100 })));

        let resolved = resolve_sources(
            &endpoint,
            &drivers,
            &root,
            &root.join("http"),
            &client,
            &HashMap::new(),
            &HashMap::new(),
            &Value::Null,
            "",
            &mocks,
        )
        .await
        .expect("a mocked http source must resolve without ever reading its request file");

        let body = build_response(&endpoint, &resolved);
        assert_eq!(body["price"], 100);
    }
}
