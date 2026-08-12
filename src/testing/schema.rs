use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(crate) use crate::endpoint::MockOutcome;

/// One `datasources/endpoints/<path>/endpoint.<method>.test.json` file.
/// Sibling to the endpoint file it tests, same "config lives next to what
/// it configures" pattern as everything else in this project.
#[derive(Debug, Serialize, Deserialize)]
pub struct TestFile {
    pub cases: Vec<TestCase>,
}

/// One test case. Cases in a file's `cases` array always run in order,
/// never in parallel — this is what makes `save`/`{{memory.X}}` well
/// defined at all: a later case can rely on an earlier one's saved value
/// existing, with no ambiguity from concurrent execution.
#[derive(Debug, Serialize, Deserialize)]
pub struct TestCase {
    pub name: String,
    #[serde(default, skip_serializing_if = "TestRequest::is_empty")]
    pub request: TestRequest,
    /// Keyed by source name (matching `endpoint.<method>.json`'s own
    /// `sources` keys) — or the reserved name `verifier`, for mocking the
    /// endpoint's security check instead of one of its data sources. Empty
    /// (or omitted) means every source runs for real: a full integration
    /// case, same file format as a fully-mocked unit case.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub mocks: HashMap<String, MockOutcome>,
    pub expect: Expectation,
    /// Values to carry forward into later cases in the same file, keyed by
    /// the name a later case references as `{{memory.<name>}}`. Reset at
    /// the start of every file (never shared across files, never across
    /// runs) — see `testing::memory`.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub save: HashMap<String, SaveEntry>,
}

/// The inbound request this case simulates — path/query params, an
/// optional body, and headers. `headers` isn't in the design doc's own
/// worked example (which never exercises a protected endpoint), but is
/// needed for real symmetry with a real request: a security verifier only
/// ever reads `header.*` (see `security::verify`), so an *unmocked*
/// verifier check on a protected endpoint has no other way to receive a
/// credential in a test case.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TestRequest {
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub path: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub query: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
}

impl TestRequest {
    fn is_empty(&self) -> bool {
        self.path.is_empty() && self.query.is_empty() && self.headers.is_empty() && self.body.is_none()
    }
}

/// What a case asserts about the real response. Both fields are optional —
/// a case can check status only, body only, or both — but at least
/// checking *something* is the point of writing a case at all, so an
/// entirely empty `expect` (while not a parse error) is a case that can
/// never fail, worth flagging when the runner exists (Point 4), not here.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Expectation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Compared field by field once a matcher (Point 3) is wired up — for
    /// now this is deserialized as plain JSON, matcher tokens (`"$any"`,
    /// `"$type:string"`) included, since they're just ordinary strings
    /// until something gives them special meaning at comparison time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
}

/// One `save` entry: where to pull the value from (a `response.status` or
/// `response.body[.<dotted path>]` reference, resolved against the case's
/// own real response — see `testing::memory`), and an optional transform
/// to apply before storing it. The bare-string form (`"carId":
/// "response.body.id"`) is exactly the object form with `transform`
/// omitted — `#[serde(untagged)]` picks whichever shape matches, the same
/// "a string or a detailed object" pattern `endpoint::schema::ResponseField`
/// already uses for `response` field mappings.
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SaveEntry {
    Plain(String),
    Detailed {
        from: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        transform: Option<String>,
    },
}

impl SaveEntry {
    /// The `response.*` path to read, and the raw transform string (not yet
    /// parsed into `memory::Transform` — parsing happens at apply time, so
    /// a malformed transform is a per-case runtime concern, not a reason
    /// the whole file fails to load).
    pub fn parts(&self) -> (&str, Option<&str>) {
        match self {
            SaveEntry::Plain(from) => (from, None),
            SaveEntry::Detailed { from, transform } => (from, transform.as_deref()),
        }
    }
}

#[derive(Debug)]
pub enum TestLoadError {
    Io(std::io::Error),
    Parse(serde_json::Error),
}

impl std::fmt::Display for TestLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TestLoadError::Io(e) => write!(f, "failed to read test file: {e}"),
            TestLoadError::Parse(e) => write!(f, "failed to parse test file: {e}"),
        }
    }
}

impl std::error::Error for TestLoadError {}

pub fn load(path: &std::path::Path) -> Result<TestFile, TestLoadError> {
    let contents = std::fs::read_to_string(path).map_err(TestLoadError::Io)?;
    serde_json::from_str(&contents).map_err(TestLoadError::Parse)
}

/// Writes a whole `TestFile` back out — `frogs test record`'s only writer.
/// Round-trips the entire file (not just an appended case), so an existing
/// hand-authored case's formatting gets normalized the same way `generate`
/// already normalizes stub/reference JSON; its *content* is untouched,
/// since deserializing into `TestFile` and serializing back out is exactly
/// the round trip a plain-string `save` entry or a `MockOutcome::Fail`
/// mock already preserves (see their own `Deserialize`/`Serialize` impls).
pub fn save_to(path: &std::path::Path, test_file: &TestFile) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(test_file).expect("TestFile always serializes");
    std::fs::write(path, json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn as_success(outcome: &MockOutcome) -> Option<&Value> {
        match outcome {
            MockOutcome::Success(v) => Some(v),
            MockOutcome::Fail(_) => None,
        }
    }

    /// The design doc's own worked example, verbatim — kept as a shared
    /// constant (rather than read from `examples/cars-demo`) so this and
    /// `a_loaded_test_file_round_trips_through_save_to_unchanged` don't
    /// depend on a file the test suite doesn't own.
    const GET_BY_VIN_TEST_FIXTURE: &str = r#"{
      "cases": [
        {
          "name": "happy path",
          "request": { "path": { "vin": "1HGCM82633A004352" } },
          "mocks": {
            "verifier": { "active": true },
            "car":     { "vin": "1HGCM82633A004352", "maker": "Honda", "model": "Accord" },
            "pricing": { "amount": 24500, "currency": "USD" }
          },
          "expect": { "status": 200, "body": { "maker": "Honda", "price": 24500 } }
        },
        {
          "name": "pricing service down — optional source, should degrade gracefully",
          "request": { "path": { "vin": "1HGCM82633A004352" } },
          "mocks": {
            "verifier": { "active": true },
            "car":     { "vin": "1HGCM82633A004352", "maker": "Honda" },
            "pricing": { "fail": "datasource.http.timeout" }
          },
          "expect": { "status": 200, "body": { "price": null } }
        },
        {
          "name": "car not found",
          "request": { "path": { "vin": "UNKNOWN" } },
          "mocks": {
            "verifier": { "active": true },
            "car": { "fail": "datasource.sql.not_found" }
          },
          "expect": { "status": 404 }
        },
        {
          "name": "no api key — verifier mocked as inactive",
          "request": { "path": { "vin": "1HGCM82633A004352" } },
          "mocks": {
            "verifier": { "active": false }
          },
          "expect": { "status": 401 }
        }
      ]
    }"#;

    fn write_get_by_vin_fixture(dir: &Path) -> std::path::PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let path = dir.join("endpoint.get.test.json");
        std::fs::write(&path, GET_BY_VIN_TEST_FIXTURE).unwrap();
        path
    }

    #[test]
    fn parses_the_get_by_vin_test_fixture() {
        let dir = std::env::temp_dir().join(format!(
            "frogs-testing-schema-parse-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let path = write_get_by_vin_fixture(&dir);
        let test_file = load(&path).expect("fixture should parse cleanly");
        let _ = std::fs::remove_dir_all(&dir);

        // Plus a fourth case (added once Point 4 wired verifier mocking up)
        // covering a mocked-inactive verifier rejecting the request — the
        // endpoint became security-protected in Phase 3, after this
        // fixture's original three cases were written.
        assert_eq!(test_file.cases.len(), 4);

        let happy = &test_file.cases[0];
        assert_eq!(happy.name, "happy path");
        assert_eq!(happy.request.path.get("vin"), Some(&"1HGCM82633A004352".to_string()));
        assert_eq!(as_success(&happy.mocks["verifier"]).unwrap()["active"], true);
        assert_eq!(as_success(&happy.mocks["car"]).unwrap()["maker"], "Honda");
        assert_eq!(as_success(&happy.mocks["pricing"]).unwrap()["amount"], 24500);
        assert_eq!(happy.expect.status, Some(200));
        assert_eq!(happy.expect.body.as_ref().unwrap()["price"], 24500);

        let degraded = &test_file.cases[1];
        assert_eq!(degraded.mocks["pricing"], MockOutcome::Fail("datasource.http.timeout".to_string()));
        assert_eq!(degraded.expect.status, Some(200));

        let not_found = &test_file.cases[2];
        assert_eq!(not_found.request.path.get("vin"), Some(&"UNKNOWN".to_string()));
        assert_eq!(not_found.mocks["car"], MockOutcome::Fail("datasource.sql.not_found".to_string()));
        assert_eq!(not_found.expect.status, Some(404));
        assert!(not_found.expect.body.is_none());

        let unauthenticated = &test_file.cases[3];
        assert_eq!(as_success(&unauthenticated.mocks["verifier"]).unwrap()["active"], false);
        assert_eq!(unauthenticated.expect.status, Some(401));
    }

    #[test]
    fn a_mock_object_with_a_fail_key_and_other_fields_is_a_literal_success_value() {
        let json = r#"{ "fail": "not actually a code", "other": true }"#;
        let mock: MockOutcome = serde_json::from_str(json).unwrap();
        assert_eq!(mock, MockOutcome::Success(serde_json::json!({ "fail": "not actually a code", "other": true })));
    }

    #[test]
    fn a_fail_value_that_is_not_a_string_is_a_literal_success_value() {
        let json = r#"{ "fail": 42 }"#;
        let mock: MockOutcome = serde_json::from_str(json).unwrap();
        assert_eq!(mock, MockOutcome::Success(serde_json::json!({ "fail": 42 })));
    }

    #[test]
    fn a_bare_scalar_mock_is_a_literal_success_value() {
        let mock: MockOutcome = serde_json::from_str("42").unwrap();
        assert_eq!(mock, MockOutcome::Success(serde_json::json!(42)));
    }

    #[test]
    fn mocks_and_request_default_to_empty_when_omitted() {
        let json = r#"{ "cases": [{ "name": "no-op", "expect": {} }] }"#;
        let test_file: TestFile = serde_json::from_str(json).unwrap();
        let case = &test_file.cases[0];
        assert!(case.mocks.is_empty());
        assert!(case.request.path.is_empty());
        assert!(case.request.query.is_empty());
        assert!(case.request.headers.is_empty());
        assert!(case.request.body.is_none());
        assert_eq!(case.expect.status, None);
        assert_eq!(case.expect.body, None);
        assert!(case.save.is_empty());
    }

    #[test]
    fn a_plain_string_save_entry_has_no_transform() {
        let json = r#"{ "carId": "response.body.id" }"#;
        let save: HashMap<String, SaveEntry> = serde_json::from_str(json).unwrap();
        assert_eq!(save["carId"].parts(), ("response.body.id", None));
    }

    #[test]
    fn a_detailed_save_entry_carries_its_transform() {
        let json = r#"{ "nextPosition": { "from": "response.body.queuePosition", "transform": "add:1" } }"#;
        let save: HashMap<String, SaveEntry> = serde_json::from_str(json).unwrap();
        assert_eq!(save["nextPosition"].parts(), ("response.body.queuePosition", Some("add:1")));
    }

    #[test]
    fn a_detailed_save_entry_with_no_transform_is_equivalent_to_plain() {
        let json = r#"{ "from": "response.body.vin" }"#;
        let entry: SaveEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.parts(), ("response.body.vin", None));
    }

    #[test]
    fn a_request_header_can_supply_a_real_credential_for_an_unmocked_verifier() {
        let json = r#"{
            "cases": [{
                "name": "authenticated with a real key",
                "request": { "headers": { "X-Api-Key": "good-key" } },
                "expect": { "status": 200 }
            }]
        }"#;
        let test_file: TestFile = serde_json::from_str(json).unwrap();
        assert_eq!(test_file.cases[0].request.headers.get("X-Api-Key"), Some(&"good-key".to_string()));
    }

    #[test]
    fn a_request_body_is_parsed_for_write_style_cases() {
        let json = r#"{
            "cases": [{
                "name": "create car",
                "request": { "body": { "maker": "Honda", "model": "Accord" } },
                "mocks": { "car": { "id": 42 } },
                "expect": { "status": 201 }
            }]
        }"#;
        let test_file: TestFile = serde_json::from_str(json).unwrap();
        assert_eq!(test_file.cases[0].request.body, Some(serde_json::json!({ "maker": "Honda", "model": "Accord" })));
    }

    #[test]
    fn a_verifier_mock_is_just_another_map_entry_at_parse_time() {
        let json = r#"{
            "cases": [{
                "name": "authenticated",
                "mocks": { "verifier": { "active": true } },
                "expect": { "status": 200 }
            }]
        }"#;
        let test_file: TestFile = serde_json::from_str(json).unwrap();
        assert!(test_file.cases[0].mocks.contains_key("verifier"));
    }

    #[test]
    fn malformed_json_is_a_clear_parse_error() {
        let dir = std::env::temp_dir().join(format!(
            "frogs-testing-schema-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("endpoint.get.test.json");
        std::fs::write(&path, "{ not valid json").unwrap();

        let err = load(&path).expect_err("malformed JSON must fail to load");
        assert!(matches!(err, TestLoadError::Parse(_)));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_file_is_a_clear_io_error() {
        let path = std::env::temp_dir().join("frogs-testing-schema-definitely-does-not-exist.test.json");
        let err = load(&path).expect_err("a missing file must fail to load");
        assert!(matches!(err, TestLoadError::Io(_)));
    }

    /// `frogs test record`'s exact write path: load the real `cars-demo`
    /// fixture, write it back out via `save_to`, and confirm reloading it
    /// reproduces the same cases byte-for-byte in content (formatting can
    /// change; the `fail`/plain-`save`-entry shapes and every value must
    /// not) — this is what proves round-tripping an existing hand-authored
    /// file through the typed structures is safe before Point 6 ever
    /// appends a new case to one.
    #[test]
    fn a_loaded_test_file_round_trips_through_save_to_unchanged() {
        let source_dir = std::env::temp_dir().join(format!(
            "frogs-testing-schema-roundtrip-source-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let source_path = write_get_by_vin_fixture(&source_dir);
        let original = load(&source_path).expect("fixture should parse cleanly");
        let _ = std::fs::remove_dir_all(&source_dir);

        let dir = std::env::temp_dir().join(format!(
            "frogs-testing-schema-roundtrip-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("endpoint.get.test.json");

        save_to(&path, &original).expect("saving should succeed");
        let reloaded = load(&path).expect("the freshly written file should parse cleanly");

        assert_eq!(reloaded.cases.len(), original.cases.len());
        for (a, b) in original.cases.iter().zip(reloaded.cases.iter()) {
            assert_eq!(a.name, b.name);
            assert_eq!(a.request.path, b.request.path);
            assert_eq!(a.mocks, b.mocks);
            assert_eq!(a.expect.status, b.expect.status);
            assert_eq!(a.expect.body, b.expect.body);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_to_appends_are_visible_after_reloading() {
        let dir = std::env::temp_dir().join(format!(
            "frogs-testing-schema-append-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("endpoint.get.test.json");

        let mut test_file = TestFile { cases: vec![] };
        test_file.cases.push(TestCase {
            name: "recorded case".to_string(),
            request: TestRequest::default(),
            mocks: HashMap::from([("car".to_string(), MockOutcome::Success(serde_json::json!({ "vin": "X" })))]),
            expect: Expectation { status: Some(200), body: None },
            save: HashMap::new(),
        });
        save_to(&path, &test_file).unwrap();

        let reloaded = load(&path).expect("should parse cleanly");
        assert_eq!(reloaded.cases.len(), 1);
        assert_eq!(reloaded.cases[0].name, "recorded case");
        assert_eq!(reloaded.cases[0].mocks["car"], MockOutcome::Success(serde_json::json!({ "vin": "X" })));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
