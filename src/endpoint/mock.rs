use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use axum::http::HeaderMap;
use serde_json::Value;

use super::resolve::MockOutcome;
use super::schema::{EndpointFile, SourceDef};

/// The harness-owned error codes `frogs test` inserts into the loaded
/// registry at startup (only if the project hasn't defined them itself —
/// see `ErrorRegistry::insert_if_absent`), so they classify like any other
/// code and never land in `errors.discovered.json`.
pub const SOURCE_NOT_MOCKED: &str = "test.source_not_mocked";
pub const NO_MATCHING_CASE: &str = "test.no_matching_case";
pub const UNKNOWN_SCENARIO: &str = "test.unknown_scenario";

/// The reserved `mocks` key that stands in for an endpoint's security
/// verifier rather than one of its data sources (see `resolve_request`).
pub const VERIFIER_MOCK_KEY: &str = "verifier";

/// One registered route, in the OpenAPI-style `{name}` path form a
/// `.test.json` file's folder already uses (`/cars/{vin}`), never axum's
/// `:name` form. `method` is lowercase, matching `endpoint.<method>.json`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RouteKey {
    pub method: String,
    pub path: String,
}

/// The parts of an inbound request a case's `request` block can constrain.
pub struct InboundRequest<'a> {
    pub path_params: &'a HashMap<String, String>,
    pub query_params: &'a HashMap<String, String>,
    pub headers: &'a HeaderMap,
    pub body: &'a Value,
}

/// Which of the three selection mechanisms (plus the untagged baseline)
/// decided the active scenario for one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScenarioSource {
    Header,
    ControlPlane,
    Flag,
    Baseline,
}

impl ScenarioSource {
    pub fn label(self) -> &'static str {
        match self {
            ScenarioSource::Header => "header",
            ScenarioSource::ControlPlane => "control-plane",
            ScenarioSource::Flag => "flag",
            ScenarioSource::Baseline => "baseline",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioChoice {
    pub name: Option<String>,
    pub source: ScenarioSource,
}

/// The case a request matched: its name, its index in the file's `cases`
/// array, and the file's project-relative display path (e.g.
/// `/cars/{vin}/endpoint.get.test.json`) — never an absolute path, since
/// this ends up in a served error `detail`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseRef {
    pub name: String,
    pub index: usize,
    pub file: PathBuf,
}

/// What a `MockProvider` decided for one request. `Case { case: None }` is
/// a route with no `.test.json` file at all — it still runs through
/// `enforce_no_real_infrastructure`, so a route with sources fails 501
/// rather than dialing out, and a source-less one serves normally.
#[derive(Debug, Clone)]
pub enum MockSelection {
    Case {
        case: Option<CaseRef>,
        mocks: HashMap<String, MockOutcome>,
        scenario: ScenarioChoice,
    },
    NoMatch {
        scenario: ScenarioChoice,
        detail: String,
    },
    Reject {
        code: &'static str,
        detail: String,
        scenario: ScenarioChoice,
    },
}

impl MockSelection {
    pub fn scenario(&self) -> &ScenarioChoice {
        match self {
            MockSelection::Case { scenario, .. } | MockSelection::NoMatch { scenario, .. } | MockSelection::Reject { scenario, .. } => scenario,
        }
    }
}

/// A source (or the reserved `verifier`) the enforcer had to fill in
/// because the matched case didn't mock it. `optional` mirrors the
/// source's own flag — an optional one degrades to null exactly as a real
/// failure would, so it's reported but doesn't change the verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unmocked {
    pub name: String,
    pub optional: bool,
}

/// What the route actually served, handed back to the provider after the
/// fact so it can evaluate `expect` and record the request.
pub struct Served<'a> {
    pub status: u16,
    pub body: &'a Value,
    pub unmocked: &'a [Unmocked],
    pub request_id: &'a str,
    pub elapsed: Duration,
}

/// The seam `frogs test` plugs into `RouteState`: `select` picks the mocks
/// for one inbound request, `observe` sees what was served. `frogs run`
/// never installs one (`RouteState::mock_provider` stays `None`), which is
/// what keeps the `X-Frogs-Scenario` header inert there.
pub trait MockProvider: Send + Sync {
    fn select(&self, route: &RouteKey, request: &InboundRequest<'_>) -> MockSelection;
    fn observe(&self, route: &RouteKey, selection: &MockSelection, served: &Served<'_>);
}

/// The no-real-infrastructure guarantee: every `endpoint.sources` key
/// absent from `mocks` gets a `Fail(test.source_not_mocked)` entry, and so
/// does the reserved `verifier` key when the endpoint declares `security`
/// — `resolve::resolve_one` and the security check in `resolve_request`
/// only ever dial a real driver/HTTP/verifier when their lookup is `None`,
/// so a map covering every name is a structural guarantee nothing is
/// contacted. Returns what was filled in, with each source's `optional`
/// flag (the verifier is never optional).
pub fn enforce_no_real_infrastructure(endpoint: &EndpointFile, mocks: &mut HashMap<String, MockOutcome>) -> Vec<Unmocked> {
    let mut filled = Vec::new();
    let mut names: Vec<&String> = endpoint.sources.keys().collect();
    names.sort();
    for name in names {
        if mocks.contains_key(name) {
            continue;
        }
        let optional = match &endpoint.sources[name] {
            SourceDef::Sql { optional, .. } | SourceDef::Http { optional, .. } => *optional,
        };
        mocks.insert(name.clone(), MockOutcome::Fail(SOURCE_NOT_MOCKED.to_string()));
        filled.push(Unmocked { name: name.clone(), optional });
    }
    if endpoint.security.is_some() && !mocks.contains_key(VERIFIER_MOCK_KEY) {
        mocks.insert(VERIFIER_MOCK_KEY.to_string(), MockOutcome::Fail(SOURCE_NOT_MOCKED.to_string()));
        filled.push(Unmocked {
            name: VERIFIER_MOCK_KEY.to_string(),
            optional: false,
        });
    }
    filled
}

/// `:name` -> `{name}`, segment by segment — the inverse of
/// `endpoint::axum_style_path`, so a registered axum route can be keyed
/// the same way a `.test.json` file's own folder path reads.
pub fn openapi_style_path(axum_path: &str) -> String {
    axum_path
        .split('/')
        .map(|segment| match segment.strip_prefix(':') {
            Some(name) => format!("{{{name}}}"),
            None => segment.to_string(),
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(json: &str) -> EndpointFile {
        serde_json::from_str(json).expect("endpoint fixture JSON should parse")
    }

    const TWO_SOURCES_AND_SECURITY: &str = r#"{
        "operationId": "getCar",
        "security": "apiKeyAuth",
        "sources": {
            "car": { "type": "sql", "connection": "db", "script": "car.sql" },
            "pricing": { "type": "http", "request": "pricing.json", "optional": true }
        },
        "response": {}
    }"#;

    #[test]
    fn every_unmocked_source_and_the_verifier_get_a_source_not_mocked_failure_filled_in() {
        let endpoint = endpoint(TWO_SOURCES_AND_SECURITY);
        let mut mocks = HashMap::new();

        let filled = enforce_no_real_infrastructure(&endpoint, &mut mocks);

        assert_eq!(mocks.get("car"), Some(&MockOutcome::Fail(SOURCE_NOT_MOCKED.to_string())));
        assert_eq!(mocks.get("pricing"), Some(&MockOutcome::Fail(SOURCE_NOT_MOCKED.to_string())));
        assert_eq!(mocks.get(VERIFIER_MOCK_KEY), Some(&MockOutcome::Fail(SOURCE_NOT_MOCKED.to_string())));
        assert_eq!(
            mocks.len(),
            3,
            "exactly one entry per source plus the verifier — nothing left for a real lookup to miss"
        );
        assert_eq!(
            filled,
            vec![
                Unmocked {
                    name: "car".to_string(),
                    optional: false
                },
                Unmocked {
                    name: "pricing".to_string(),
                    optional: true
                },
                Unmocked {
                    name: VERIFIER_MOCK_KEY.to_string(),
                    optional: false
                },
            ],
            "sources in sorted name order, each with its own optional flag, then the never-optional verifier"
        );
    }

    #[test]
    fn a_source_the_case_already_mocks_is_left_untouched() {
        let endpoint = endpoint(TWO_SOURCES_AND_SECURITY);
        let mut mocks = HashMap::from([
            ("car".to_string(), MockOutcome::Success(serde_json::json!({ "maker": "Honda" }))),
            (VERIFIER_MOCK_KEY.to_string(), MockOutcome::Success(serde_json::json!({ "active": true }))),
        ]);

        let filled = enforce_no_real_infrastructure(&endpoint, &mut mocks);

        assert_eq!(mocks.get("car"), Some(&MockOutcome::Success(serde_json::json!({ "maker": "Honda" }))));
        assert_eq!(mocks.get(VERIFIER_MOCK_KEY), Some(&MockOutcome::Success(serde_json::json!({ "active": true }))));
        assert_eq!(filled.iter().map(|u| u.name.as_str()).collect::<Vec<_>>(), ["pricing"]);
    }

    #[test]
    fn no_verifier_entry_is_added_for_an_endpoint_without_security() {
        let endpoint = endpoint(r#"{ "operationId": "ping", "sources": {}, "response": {} }"#);
        let mut mocks = HashMap::new();
        let filled = enforce_no_real_infrastructure(&endpoint, &mut mocks);
        assert!(mocks.is_empty());
        assert!(filled.is_empty());
    }

    #[test]
    fn openapi_style_path_turns_every_colon_segment_into_braces() {
        assert_eq!(openapi_style_path("/cars/:vin/parts/:partId"), "/cars/{vin}/parts/{partId}");
        assert_eq!(openapi_style_path("/cars"), "/cars");
        assert_eq!(openapi_style_path("/"), "/");
    }

    #[test]
    fn openapi_style_path_is_the_inverse_of_the_router_side_translation() {
        let axum_path = super::super::axum_style_path("/cars/{vin}");
        assert_eq!(openapi_style_path(&axum_path), "/cars/{vin}");
    }
}
