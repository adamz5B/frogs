use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, mpsc};

use axum::http::HeaderMap;
use chrono::Utc;

use super::memory::Memory;
use super::report::{self, Entry, Report, ReportFormat, Summary, Verdict};
use super::schema::{Expectation, TestFile};
use super::select::select_case;
use crate::endpoint::mock::{CaseRef, InboundRequest, MockProvider, MockSelection, RouteKey, ScenarioChoice, ScenarioSource, Served, UNKNOWN_SCENARIO};
use crate::endpoint::{EndpointFile, MockOutcome};

/// The request header that picks a scenario for one request only — read
/// solely by `MockSession::current_scenario`, which only ever runs under
/// `frogs test` (see `endpoint::handle_request`'s `mock_provider` branch).
pub const SCENARIO_HEADER: &str = "x-frogs-scenario";

/// One `endpoint.<method>.test.json` file, loaded at startup, keyed by the
/// route it sits next to. `endpoint` is the sibling `endpoint.<method>.json`
/// (`None` if it's missing or unparseable — a corpus-validation warning,
/// not a startup failure).
pub struct LoadedTestFile {
    pub route: RouteKey,
    pub path: PathBuf,
    pub file: TestFile,
    pub endpoint: Option<EndpointFile>,
}

#[derive(Debug, Clone)]
pub struct ReportConfig {
    pub format: ReportFormat,
    pub file: Option<PathBuf>,
}

/// Everything mutable about one mock-server session, behind a single
/// mutex that is only ever held for synchronous work — never across an
/// `.await`, and never while doing file I/O (report writes go through
/// `ReportWriter`'s own thread).
struct SessionState {
    override_scenario: Option<String>,
    memory: Memory,
    report: Report,
}

/// A dedicated OS thread that rewrites the report file after every
/// request, fed the full rendered content over a channel — coalescing to
/// the newest pending content whenever it falls behind. Joined by
/// `MockSession::finish`, which then writes the final content itself.
struct ReportWriter {
    sender: mpsc::Sender<String>,
    handle: std::thread::JoinHandle<()>,
}

/// The `MockProvider` `frogs test` installs into every route: owns the
/// loaded test corpus, the active-scenario override, the process-lifetime
/// `Memory`, and the session report.
pub struct MockSession {
    files: HashMap<RouteKey, LoadedTestFile>,
    known_scenarios: Vec<String>,
    scenario_flag: Option<String>,
    report_config: ReportConfig,
    state: Mutex<SessionState>,
    writer: Mutex<Option<ReportWriter>>,
}

impl MockSession {
    /// Fails (with a message meant for `eprintln!` + exit 1) when the
    /// `--scenario` flag names a scenario no case carries, or the report
    /// file can't be created up front — both are startup-time mistakes
    /// that must surface before a port is ever bound.
    pub fn new(files: Vec<LoadedTestFile>, scenario_flag: Option<String>, report_config: ReportConfig) -> Result<Arc<Self>, String> {
        let mut known_scenarios: Vec<String> = files
            .iter()
            .flat_map(|f| f.file.cases.iter().filter_map(|c| c.scenario.clone()))
            .filter(|name| !name.is_empty())
            .collect();
        known_scenarios.sort();
        known_scenarios.dedup();

        if let Some(flag) = &scenario_flag
            && !known_scenarios.contains(flag)
        {
            return Err(format!("unknown scenario '{flag}' — {}", known_list(&known_scenarios)));
        }

        let files: HashMap<RouteKey, LoadedTestFile> = files.into_iter().map(|f| (f.route.clone(), f)).collect();
        let report = Report {
            started_at: Utc::now(),
            scenario_flag: scenario_flag.clone(),
            entries: Vec::new(),
        };

        let writer = match &report_config.file {
            Some(path) => {
                let initial = render_content(&report, report_config.format);
                report::write_atomic(path, &initial).map_err(|e| format!("cannot write report file {}: {e}", path.display()))?;
                Some(spawn_writer(path.clone()))
            }
            None => None,
        };

        Ok(Arc::new(MockSession {
            files,
            known_scenarios,
            scenario_flag,
            report_config,
            state: Mutex::new(SessionState {
                override_scenario: None,
                memory: Memory::new(),
                report,
            }),
            writer: Mutex::new(writer),
        }))
    }

    pub fn known_scenarios(&self) -> &[String] {
        &self.known_scenarios
    }

    pub fn scenario_flag(&self) -> Option<&str> {
        self.scenario_flag.as_deref()
    }

    /// The control-plane override — `None` clears it. An unknown name is
    /// refused (the caller maps that to a 400) rather than stored.
    pub fn set_override(&self, name: Option<String>) -> Result<(), String> {
        if let Some(name) = &name
            && !self.known_scenarios.contains(name)
        {
            return Err(format!("unknown scenario '{name}' — {}", known_list(&self.known_scenarios)));
        }
        self.state.lock().unwrap().override_scenario = name;
        Ok(())
    }

    /// Header > control-plane override > `--scenario` flag > baseline.
    /// `Err` carries the unknown name a header asked for.
    pub fn current_scenario(&self, headers: &HeaderMap) -> Result<ScenarioChoice, String> {
        if let Some(value) = headers.get(SCENARIO_HEADER) {
            let name = value.to_str().unwrap_or_default().to_string();
            return if self.known_scenarios.contains(&name) {
                Ok(ScenarioChoice {
                    name: Some(name),
                    source: ScenarioSource::Header,
                })
            } else {
                Err(name)
            };
        }
        let override_scenario = self.state.lock().unwrap().override_scenario.clone();
        if let Some(name) = override_scenario {
            return Ok(ScenarioChoice {
                name: Some(name),
                source: ScenarioSource::ControlPlane,
            });
        }
        if let Some(name) = &self.scenario_flag {
            return Ok(ScenarioChoice {
                name: Some(name.clone()),
                source: ScenarioSource::Flag,
            });
        }
        Ok(ScenarioChoice {
            name: None,
            source: ScenarioSource::Baseline,
        })
    }

    pub fn summary(&self) -> Summary {
        report::summary(&self.state.lock().unwrap().report.entries)
    }

    /// Stops the background writer and writes the final report content
    /// synchronously — called once, at shutdown. Returns the summary the
    /// caller prints and derives the exit code from.
    pub fn finish(&self) -> Summary {
        if let Some(writer) = self.writer.lock().unwrap().take() {
            drop(writer.sender);
            let _ = writer.handle.join();
        }
        let content = {
            let state = self.state.lock().unwrap();
            self.report_config.file.as_ref().map(|_| render_content(&state.report, self.report_config.format))
        };
        if let (Some(path), Some(content)) = (&self.report_config.file, content)
            && let Err(e) = report::write_atomic(path, &content)
        {
            tracing::warn!("failed to write report file {}: {e}", path.display());
        }
        self.summary()
    }
}

/// The project-relative display form of a route's test file
/// (`/cars/{vin}/endpoint.get.test.json`) — what served error details and
/// startup warnings name, never an absolute path.
pub(crate) fn test_file_display(route: &RouteKey) -> String {
    let dir = if route.path == "/" { "" } else { route.path.as_str() };
    format!("{dir}/endpoint.{}.test.json", route.method)
}

impl MockProvider for MockSession {
    fn select(&self, route: &RouteKey, request: &InboundRequest<'_>) -> MockSelection {
        let scenario = match self.current_scenario(request.headers) {
            Ok(choice) => choice,
            Err(unknown) => {
                return MockSelection::Reject {
                    code: UNKNOWN_SCENARIO,
                    detail: format!("unknown scenario '{unknown}' — {}", known_list(&self.known_scenarios)),
                    scenario: ScenarioChoice {
                        name: Some(unknown),
                        source: ScenarioSource::Header,
                    },
                };
            }
        };

        let Some(loaded) = self.files.get(route) else {
            return MockSelection::Case {
                case: None,
                mocks: HashMap::new(),
                scenario,
            };
        };

        let state = self.state.lock().unwrap();
        match select_case(&loaded.file.cases, scenario.name.as_deref(), request, &state.memory) {
            Some((index, case)) => {
                let mocks = case
                    .mocks
                    .iter()
                    .map(|(name, outcome)| {
                        let substituted = match outcome {
                            MockOutcome::Success(v) => MockOutcome::Success(state.memory.substitute(v)),
                            MockOutcome::Fail(code) => MockOutcome::Fail(code.clone()),
                        };
                        (name.clone(), substituted)
                    })
                    .collect();
                MockSelection::Case {
                    case: Some(CaseRef {
                        name: case.name.clone(),
                        index,
                        file: PathBuf::from(test_file_display(route)),
                    }),
                    mocks,
                    scenario,
                }
            }
            None => {
                let considered = loaded
                    .file
                    .cases
                    .iter()
                    .filter(|c| c.scenario.is_none() || c.scenario.as_deref() == scenario.name.as_deref())
                    .count();
                let detail = format!(
                    "no case in {} matched {} {} under scenario {} ({considered} case(s) considered)",
                    test_file_display(route),
                    route.method.to_uppercase(),
                    route.path,
                    scenario.name.as_deref().unwrap_or("<baseline>")
                );
                MockSelection::NoMatch { scenario, detail }
            }
        }
    }

    fn observe(&self, route: &RouteKey, selection: &MockSelection, served: &Served<'_>) {
        let required_unmocked: Vec<String> = served.unmocked.iter().filter(|u| !u.optional).map(|u| u.name.clone()).collect();

        let (line, content) = {
            let mut state = self.state.lock().unwrap();
            let scenario = selection.scenario();
            let mut entry = Entry {
                sequence: state.report.entries.len() as u64 + 1,
                timestamp: Utc::now(),
                method: route.method.clone(),
                path: route.path.clone(),
                request_id: served.request_id.to_string(),
                scenario: scenario.name.clone(),
                scenario_source: scenario.source,
                case_name: None,
                case_file: None,
                status: served.status,
                body: report::cap_body(served.body),
                verdict: Verdict::Served,
                unmatched_reason: None,
                unmocked: served.unmocked.to_vec(),
                elapsed_ms: served.elapsed.as_millis() as u64,
            };

            match selection {
                MockSelection::Reject { detail, .. } => {
                    entry.verdict = Verdict::Unmatched;
                    entry.unmatched_reason = Some(detail.clone());
                }
                MockSelection::NoMatch { .. } => {
                    entry.verdict = Verdict::Unmatched;
                    entry.unmatched_reason = Some("no matching case".to_string());
                }
                MockSelection::Case { case: None, .. } => {
                    if !required_unmocked.is_empty() {
                        entry.verdict = Verdict::NotMocked(required_unmocked);
                    }
                }
                MockSelection::Case { case: Some(case_ref), .. } => {
                    entry.case_name = Some(case_ref.name.clone());
                    entry.case_file = Some(case_ref.file.display().to_string());
                    let case = self.files.get(route).and_then(|f| f.file.cases.get(case_ref.index));
                    if !required_unmocked.is_empty() {
                        entry.verdict = Verdict::NotMocked(required_unmocked);
                    } else if let Some(case) = case {
                        let expect = Expectation {
                            status: case.expect.status,
                            body: case.expect.body.as_ref().map(|b| state.memory.substitute(b)),
                        };
                        if expect.status.is_some() || expect.body.is_some() {
                            let mismatches = super::expect::evaluate(&expect, served.status, served.body);
                            entry.verdict = if mismatches.is_empty() { Verdict::Pass } else { Verdict::Fail(mismatches) };
                        }
                    }
                    if let Some(case) = case
                        && !case.save.is_empty()
                    {
                        state.memory.save(&case.save, served.status, served.body);
                    }
                }
            }

            let line = matches!(self.report_config.format, ReportFormat::Text).then(|| report::render_text_line(&entry));
            state.report.entries.push(entry);
            let content = self.report_config.file.as_ref().map(|_| render_content(&state.report, self.report_config.format));
            (line, content)
        };

        if let Some(line) = line {
            println!("{line}");
        }
        if let Some(content) = content
            && let Some(writer) = self.writer.lock().unwrap().as_ref()
        {
            let _ = writer.sender.send(content);
        }
    }
}

fn known_list(known: &[String]) -> String {
    if known.is_empty() {
        "no case in this project declares a scenario".to_string()
    } else {
        format!("known scenarios: {}", known.join(", "))
    }
}

fn render_content(report: &Report, format: ReportFormat) -> String {
    match format {
        ReportFormat::Text => report::render_text(report),
        ReportFormat::Json => report::render_json(report, Utc::now()),
        ReportFormat::Junit => report::render_junit(report),
    }
}

fn spawn_writer(path: PathBuf) -> ReportWriter {
    let (sender, receiver) = mpsc::channel::<String>();
    let handle = std::thread::spawn(move || {
        while let Ok(mut content) = receiver.recv() {
            while let Ok(newer) = receiver.try_recv() {
                content = newer;
            }
            if let Err(e) = report::write_atomic(&path, &content) {
                tracing::warn!("failed to write report file {}: {e}", path.display());
            }
        }
    });
    ReportWriter { sender, handle }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::mock::Unmocked;
    use crate::testing::schema::TestFile;
    use serde_json::json;
    use std::time::Duration;

    fn route(method: &str, path: &str) -> RouteKey {
        RouteKey {
            method: method.to_string(),
            path: path.to_string(),
        }
    }

    fn loaded(method: &str, path: &str, cases_json: &str) -> LoadedTestFile {
        let file: TestFile = serde_json::from_str(cases_json).expect("test-file fixture JSON should parse");
        LoadedTestFile {
            route: route(method, path),
            path: PathBuf::from("unused"),
            file,
            endpoint: None,
        }
    }

    fn text_report() -> ReportConfig {
        ReportConfig {
            format: ReportFormat::Text,
            file: None,
        }
    }

    const TWO_SCENARIOS: &str = r#"{ "cases": [
        { "name": "baseline", "request": {}, "mocks": { "car": { "maker": "Honda" } }, "expect": { "status": 200 } },
        { "name": "pricing down", "scenario": "pricing-down", "request": {}, "mocks": { "car": { "maker": "Honda" } }, "expect": {} },
        { "name": "db down", "scenario": "db-down", "request": {}, "mocks": { "car": { "fail": "x" } }, "expect": {} }
    ] }"#;

    fn session_with_flag(flag: Option<&str>) -> Arc<MockSession> {
        MockSession::new(vec![loaded("get", "/cars/{vin}", TWO_SCENARIOS)], flag.map(str::to_string), text_report()).expect("known flag")
    }

    fn header(name: &'static str, value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(name, value.parse().unwrap());
        headers
    }

    struct Inbound {
        path: HashMap<String, String>,
        query: HashMap<String, String>,
        headers: HeaderMap,
        body: serde_json::Value,
    }

    impl Inbound {
        fn new(headers: HeaderMap) -> Self {
            Inbound {
                path: HashMap::new(),
                query: HashMap::new(),
                headers,
                body: serde_json::Value::Null,
            }
        }

        fn as_request(&self) -> InboundRequest<'_> {
            InboundRequest {
                path_params: &self.path,
                query_params: &self.query,
                headers: &self.headers,
                body: &self.body,
            }
        }
    }

    #[test]
    fn known_scenarios_are_collected_across_files_sorted_and_deduplicated_ignoring_empty_tags() {
        let session = MockSession::new(
            vec![
                loaded("get", "/cars/{vin}", TWO_SCENARIOS),
                loaded(
                    "get",
                    "/cars",
                    r#"{ "cases": [
                        { "name": "a", "scenario": "pricing-down", "expect": {} },
                        { "name": "b", "scenario": "", "expect": {} },
                        { "name": "c", "scenario": "aaa-first", "expect": {} }
                    ] }"#,
                ),
            ],
            None,
            text_report(),
        )
        .unwrap();
        assert_eq!(session.known_scenarios(), ["aaa-first", "db-down", "pricing-down"]);
    }

    #[test]
    fn a_scenario_flag_naming_no_tagged_case_is_a_startup_error() {
        let err = MockSession::new(vec![loaded("get", "/cars/{vin}", TWO_SCENARIOS)], Some("nope".to_string()), text_report())
            .err()
            .expect("an unknown --scenario must be refused before a port is bound");
        assert!(err.contains("unknown scenario 'nope'"), "{err}");
        assert!(err.contains("known scenarios: db-down, pricing-down"), "{err}");
    }

    #[test]
    fn a_scenario_flag_with_no_tagged_case_anywhere_says_so() {
        let err = MockSession::new(
            vec![loaded("get", "/ping", r#"{ "cases": [ { "name": "only", "expect": {} } ] }"#)],
            Some("x".to_string()),
            text_report(),
        )
        .err()
        .unwrap();
        assert!(err.contains("no case in this project declares a scenario"), "{err}");
    }

    #[test]
    fn with_nothing_set_the_baseline_is_active() {
        let session = session_with_flag(None);
        let choice = session.current_scenario(&HeaderMap::new()).unwrap();
        assert_eq!(
            choice,
            ScenarioChoice {
                name: None,
                source: ScenarioSource::Baseline
            }
        );
    }

    #[test]
    fn the_flag_applies_when_neither_a_header_nor_an_override_is_present() {
        let session = session_with_flag(Some("db-down"));
        assert_eq!(session.scenario_flag(), Some("db-down"));
        let choice = session.current_scenario(&HeaderMap::new()).unwrap();
        assert_eq!(choice.name.as_deref(), Some("db-down"));
        assert_eq!(choice.source, ScenarioSource::Flag);
    }

    #[test]
    fn the_control_plane_override_beats_the_flag() {
        let session = session_with_flag(Some("db-down"));
        session.set_override(Some("pricing-down".to_string())).unwrap();
        let choice = session.current_scenario(&HeaderMap::new()).unwrap();
        assert_eq!(choice.name.as_deref(), Some("pricing-down"));
        assert_eq!(choice.source, ScenarioSource::ControlPlane);
    }

    #[test]
    fn the_request_header_beats_the_control_plane_override_and_the_flag() {
        let session = session_with_flag(Some("db-down"));
        session.set_override(Some("pricing-down".to_string())).unwrap();
        let choice = session.current_scenario(&header(SCENARIO_HEADER, "db-down")).unwrap();
        assert_eq!(choice.name.as_deref(), Some("db-down"));
        assert_eq!(choice.source, ScenarioSource::Header);
    }

    #[test]
    fn the_scenario_header_name_matches_case_insensitively() {
        let session = session_with_flag(None);
        let choice = session.current_scenario(&header("X-Frogs-Scenario", "pricing-down")).unwrap();
        assert_eq!(choice.source, ScenarioSource::Header);
    }

    #[test]
    fn a_header_naming_an_unknown_scenario_is_an_error_carrying_that_name() {
        let session = session_with_flag(None);
        assert_eq!(session.current_scenario(&header(SCENARIO_HEADER, "made-up")), Err("made-up".to_string()));
    }

    #[test]
    fn clearing_the_override_falls_back_to_the_flag_then_the_baseline() {
        let session = session_with_flag(Some("db-down"));
        session.set_override(Some("pricing-down".to_string())).unwrap();
        session.set_override(None).unwrap();
        assert_eq!(session.current_scenario(&HeaderMap::new()).unwrap().source, ScenarioSource::Flag);

        let unflagged = session_with_flag(None);
        unflagged.set_override(Some("pricing-down".to_string())).unwrap();
        unflagged.set_override(None).unwrap();
        assert_eq!(unflagged.current_scenario(&HeaderMap::new()).unwrap().source, ScenarioSource::Baseline);
    }

    #[test]
    fn setting_an_unknown_override_is_refused_and_leaves_the_previous_override_in_place() {
        let session = session_with_flag(None);
        session.set_override(Some("pricing-down".to_string())).unwrap();
        let err = session.set_override(Some("made-up".to_string())).expect_err("unknown name must be refused");
        assert!(err.contains("unknown scenario 'made-up'"), "{err}");
        assert_eq!(session.current_scenario(&HeaderMap::new()).unwrap().name.as_deref(), Some("pricing-down"));
    }

    #[test]
    fn test_file_display_is_project_relative_and_handles_the_root_route() {
        assert_eq!(test_file_display(&route("get", "/cars/{vin}")), "/cars/{vin}/endpoint.get.test.json");
        assert_eq!(test_file_display(&route("post", "/")), "/endpoint.post.test.json");
    }

    #[test]
    fn select_on_a_route_with_no_test_file_yields_a_case_selection_with_no_case_and_no_mocks() {
        let session = session_with_flag(None);
        let inbound = Inbound::new(HeaderMap::new());
        match session.select(&route("get", "/ping"), &inbound.as_request()) {
            MockSelection::Case { case, mocks, scenario } => {
                assert!(case.is_none());
                assert!(mocks.is_empty());
                assert_eq!(scenario.source, ScenarioSource::Baseline);
            }
            other => panic!("expected Case {{ case: None }}, got {other:?}"),
        }
    }

    #[test]
    fn select_rejects_an_unknown_header_scenario_before_looking_at_any_case() {
        let session = session_with_flag(None);
        let inbound = Inbound::new(header(SCENARIO_HEADER, "made-up"));
        match session.select(&route("get", "/cars/{vin}"), &inbound.as_request()) {
            MockSelection::Reject { code, detail, scenario } => {
                assert_eq!(code, UNKNOWN_SCENARIO);
                assert!(detail.contains("unknown scenario 'made-up'"), "{detail}");
                assert_eq!(scenario.name.as_deref(), Some("made-up"));
                assert_eq!(scenario.source, ScenarioSource::Header);
            }
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    #[test]
    fn select_reports_no_match_with_the_file_route_and_scenario_named_in_the_detail() {
        let session = MockSession::new(
            vec![loaded(
                "get",
                "/cars/{vin}",
                r#"{ "cases": [ { "name": "only AAA", "request": { "path": { "vin": "AAA" } }, "expect": {} } ] }"#,
            )],
            None,
            text_report(),
        )
        .unwrap();
        let inbound = Inbound::new(HeaderMap::new());
        match session.select(&route("get", "/cars/{vin}"), &inbound.as_request()) {
            MockSelection::NoMatch { detail, .. } => {
                assert!(detail.contains("/cars/{vin}/endpoint.get.test.json"), "{detail}");
                assert!(detail.contains("GET /cars/{vin}"), "{detail}");
                assert!(detail.contains("<baseline>"), "{detail}");
                assert!(detail.contains("1 case(s) considered"), "{detail}");
            }
            other => panic!("expected NoMatch, got {other:?}"),
        }
    }

    #[test]
    fn select_returns_the_matched_case_ref_with_its_index_and_display_file() {
        let session = session_with_flag(None);
        let inbound = Inbound::new(header(SCENARIO_HEADER, "db-down"));
        match session.select(&route("get", "/cars/{vin}"), &inbound.as_request()) {
            MockSelection::Case {
                case: Some(case),
                mocks,
                scenario,
            } => {
                assert_eq!(case.name, "db down");
                assert_eq!(case.index, 2);
                assert_eq!(case.file, PathBuf::from("/cars/{vin}/endpoint.get.test.json"));
                assert_eq!(mocks.get("car"), Some(&MockOutcome::Fail("x".to_string())));
                assert_eq!(scenario.name.as_deref(), Some("db-down"));
            }
            other => panic!("expected a matched case, got {other:?}"),
        }
    }

    fn served<'a>(status: u16, body: &'a serde_json::Value, unmocked: &'a [Unmocked]) -> Served<'a> {
        Served {
            status,
            body,
            unmocked,
            request_id: "rid",
            elapsed: Duration::from_millis(1),
        }
    }

    #[test]
    fn observe_records_a_pass_when_the_served_response_satisfies_the_matched_expect() {
        let session = session_with_flag(None);
        let inbound = Inbound::new(HeaderMap::new());
        let route = route("get", "/cars/{vin}");
        let selection = session.select(&route, &inbound.as_request());
        session.observe(&route, &selection, &served(200, &json!({ "maker": "Honda" }), &[]));
        assert_eq!(session.summary().passed, 1);
    }

    #[test]
    fn observe_records_a_fail_when_the_served_status_contradicts_the_matched_expect() {
        let session = session_with_flag(None);
        let inbound = Inbound::new(HeaderMap::new());
        let route = route("get", "/cars/{vin}");
        let selection = session.select(&route, &inbound.as_request());
        session.observe(&route, &selection, &served(500, &json!({}), &[]));
        let summary = session.summary();
        assert_eq!(summary.failed, 1);
        assert!(summary.has_problems());
    }

    #[test]
    fn observe_records_served_not_pass_when_the_matched_case_has_no_expect_at_all() {
        let session = session_with_flag(None);
        let inbound = Inbound::new(header(SCENARIO_HEADER, "pricing-down"));
        let route = route("get", "/cars/{vin}");
        let selection = session.select(&route, &inbound.as_request());
        session.observe(&route, &selection, &served(200, &json!({}), &[]));
        let summary = session.summary();
        assert_eq!(summary.served, 1);
        assert_eq!(summary.passed, 0, "an empty expect asserts nothing, so nothing passed");
    }

    #[test]
    fn observe_lets_a_required_unmocked_source_take_precedence_over_an_expect_mismatch() {
        let session = session_with_flag(None);
        let inbound = Inbound::new(HeaderMap::new());
        let route = route("get", "/cars/{vin}");
        let selection = session.select(&route, &inbound.as_request());
        let unmocked = [Unmocked {
            name: "pricing".to_string(),
            optional: false,
        }];
        session.observe(&route, &selection, &served(501, &json!({}), &unmocked));
        let summary = session.summary();
        assert_eq!(summary.not_mocked, 1);
        assert_eq!(summary.failed, 0, "NOT MOCKED wins over what would otherwise be a status mismatch");
    }

    #[test]
    fn observe_treats_an_optional_unmocked_source_as_degradation_not_a_problem() {
        let session = session_with_flag(None);
        let inbound = Inbound::new(HeaderMap::new());
        let route = route("get", "/cars/{vin}");
        let selection = session.select(&route, &inbound.as_request());
        let unmocked = [Unmocked {
            name: "pricing".to_string(),
            optional: true,
        }];
        session.observe(&route, &selection, &served(200, &json!({ "maker": "Honda" }), &unmocked));
        let summary = session.summary();
        assert_eq!(summary.passed, 1);
        assert!(!summary.has_problems());
    }

    #[test]
    fn observe_on_a_route_with_no_test_file_is_served_or_not_mocked_depending_on_required_sources() {
        let session = session_with_flag(None);
        let inbound = Inbound::new(HeaderMap::new());
        let route = route("get", "/untested");
        let selection = session.select(&route, &inbound.as_request());
        session.observe(&route, &selection, &served(200, &json!({}), &[]));
        let required = [Unmocked {
            name: "car".to_string(),
            optional: false,
        }];
        session.observe(&route, &selection, &served(501, &json!({}), &required));
        let summary = session.summary();
        assert_eq!((summary.served, summary.not_mocked), (1, 1));
    }

    #[test]
    fn observe_counts_a_no_match_and_a_reject_as_unmatched() {
        let session = session_with_flag(None);
        let route = route("get", "/cars/{vin}");
        let rejected = Inbound::new(header(SCENARIO_HEADER, "made-up"));
        let selection = session.select(&route, &rejected.as_request());
        session.observe(&route, &selection, &served(400, &json!({}), &[]));

        let no_match = MockSelection::NoMatch {
            scenario: ScenarioChoice {
                name: None,
                source: ScenarioSource::Baseline,
            },
            detail: "nothing".to_string(),
        };
        session.observe(&route, &no_match, &served(404, &json!({}), &[]));
        assert_eq!(session.summary().unmatched, 2);
    }

    #[test]
    fn a_matched_case_save_block_makes_its_value_visible_to_a_later_request_on_another_route() {
        let session = MockSession::new(
            vec![
                loaded(
                    "post",
                    "/cars",
                    r#"{ "cases": [ { "name": "create", "expect": {}, "save": { "vin": "response.body.vin" } } ] }"#,
                ),
                loaded(
                    "get",
                    "/cars/{vin}",
                    r#"{ "cases": [ { "name": "read back", "request": { "path": { "vin": "{{memory.vin}}" } }, "mocks": { "car": { "vin": "{{memory.vin}}" } }, "expect": {} } ] }"#,
                ),
            ],
            None,
            text_report(),
        )
        .unwrap();

        let post_route = route("post", "/cars");
        let post_inbound = Inbound::new(HeaderMap::new());
        let selection = session.select(&post_route, &post_inbound.as_request());
        session.observe(&post_route, &selection, &served(201, &json!({ "vin": "NEW123" }), &[]));

        let get_route = route("get", "/cars/{vin}");
        let mut get_inbound = Inbound::new(HeaderMap::new());
        get_inbound.path.insert("vin".to_string(), "NEW123".to_string());
        match session.select(&get_route, &get_inbound.as_request()) {
            MockSelection::Case { case: Some(case), mocks, .. } => {
                assert_eq!(case.name, "read back");
                assert_eq!(
                    mocks.get("car"),
                    Some(&MockOutcome::Success(json!({ "vin": "NEW123" }))),
                    "the served mock itself is memory-substituted too"
                );
            }
            other => panic!("the GET must match via the saved vin, got {other:?}"),
        }
    }

    #[test]
    fn a_report_file_is_created_up_front_and_finalized_with_every_entry_and_no_temp_file() {
        let dir = std::env::temp_dir().join(format!(
            "frogs-session-report-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("report.json");

        let session = MockSession::new(
            vec![loaded("get", "/cars/{vin}", TWO_SCENARIOS)],
            Some("db-down".to_string()),
            ReportConfig {
                format: ReportFormat::Json,
                file: Some(path.clone()),
            },
        )
        .unwrap();
        let initial: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).expect("the initial report must already be valid JSON");
        assert_eq!(initial["summary"]["requests"], 0);
        assert_eq!(initial["scenarioFlag"], "db-down");

        let route = route("get", "/cars/{vin}");
        let inbound = Inbound::new(HeaderMap::new());
        let selection = session.select(&route, &inbound.as_request());
        session.observe(&route, &selection, &served(500, &json!({}), &[]));
        let summary = session.finish();
        assert_eq!(summary.requests, 1);

        let final_report: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(final_report["summary"]["requests"], 1);
        assert_eq!(final_report["entries"][0]["scenario"], "db-down");
        assert_eq!(final_report["entries"][0]["scenarioSource"], "flag");
        let leftovers: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unwritable_report_file_is_a_startup_error() {
        let path = std::env::temp_dir()
            .join(format!("frogs-session-missing-dir-{}", std::process::id()))
            .join("nope/report.json");
        let err = MockSession::new(
            vec![],
            None,
            ReportConfig {
                format: ReportFormat::Junit,
                file: Some(path.clone()),
            },
        )
        .err()
        .expect("a report file that can't be created must fail before a port is bound");
        assert!(err.contains("cannot write report file"), "{err}");
    }
}
