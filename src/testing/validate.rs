use std::collections::HashMap;

use super::session::{LoadedTestFile, test_file_display};
use crate::endpoint::EndpointFile;
use crate::endpoint::mock::{RouteKey, VERIFIER_MOCK_KEY};

/// Startup-time corpus checks — every finding is a warning `frogs test`
/// prints before serving, never a startup failure: a slightly-wrong test
/// file is worth pointing out, but the rest of the corpus still serves.
/// `routable` is every route `build_router` would register (keyed the
/// same way `LoadedTestFile::route` is), with its parsed endpoint file.
pub fn validate_corpus(files: &[LoadedTestFile], routable: &HashMap<RouteKey, EndpointFile>) -> Vec<String> {
    let mut warnings = Vec::new();

    for loaded in files {
        let display = test_file_display(&loaded.route);
        let route_params = path_params(&loaded.route.path);

        match &loaded.endpoint {
            None => warnings.push(format!("{display}: no sibling endpoint.{}.json — its cases can never be served", loaded.route.method)),
            Some(_) if !routable.contains_key(&loaded.route) => {
                warnings.push(format!(
                    "{display}: endpoint.{}.json is not a routable method — its cases can never be served",
                    loaded.route.method
                ));
            }
            Some(_) => {}
        }

        for (index, case) in loaded.file.cases.iter().enumerate() {
            let label = format!("{display} case #{} \"{}\"", index + 1, case.name);

            if case.scenario.as_deref() == Some("") {
                warnings.push(format!("{label}: scenario is an empty string — treated as untagged"));
            }

            if let Some(endpoint) = &loaded.endpoint {
                for key in case.mocks.keys() {
                    if key == VERIFIER_MOCK_KEY {
                        if endpoint.security.is_none() {
                            warnings.push(format!("{label}: mocks a verifier but the endpoint declares no security scheme"));
                        }
                    } else if !endpoint.sources.contains_key(key) {
                        warnings.push(format!("{label}: mock '{key}' names no source of this endpoint — it will never be consulted"));
                    }
                }
            }

            for key in case.request.path.keys() {
                if !route_params.iter().any(|p| p == key) {
                    warnings.push(format!("{label}: request.path '{key}' is not a {{param}} of route {}", loaded.route.path));
                }
            }

            let effective_scenario = case.scenario.as_deref().filter(|s| !s.is_empty());
            for (earlier_index, earlier) in loaded.file.cases[..index].iter().enumerate() {
                let earlier_scenario = earlier.scenario.as_deref().filter(|s| !s.is_empty());
                if earlier_scenario == effective_scenario && earlier.request == case.request {
                    warnings.push(format!(
                        "{label}: identical request block to case #{} \"{}\" under the same scenario — it is shadowed and can never be selected",
                        earlier_index + 1,
                        earlier.name
                    ));
                    break;
                }
            }
        }
    }

    let mut untested: Vec<String> = routable
        .iter()
        .filter(|(route, endpoint)| !endpoint.sources.is_empty() && !files.iter().any(|f| &f.route == *route))
        .map(|(route, _)| format!("{} {}", route.method.to_uppercase(), route.path))
        .collect();
    untested.sort();
    for route in untested {
        warnings.push(format!(
            "{route}: has sources but no .test.json file — every request will fail with test.source_not_mocked"
        ));
    }

    warnings
}

fn path_params(path: &str) -> Vec<String> {
    path.split('/')
        .filter_map(|segment| segment.strip_prefix('{').and_then(|s| s.strip_suffix('}')))
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::schema::TestFile;
    use std::path::PathBuf;

    fn route(method: &str, path: &str) -> RouteKey {
        RouteKey {
            method: method.to_string(),
            path: path.to_string(),
        }
    }

    fn endpoint(json: &str) -> EndpointFile {
        serde_json::from_str(json).expect("endpoint fixture JSON should parse")
    }

    fn loaded(method: &str, path: &str, cases_json: &str, endpoint: Option<EndpointFile>) -> LoadedTestFile {
        let file: TestFile = serde_json::from_str(cases_json).expect("test-file fixture JSON should parse");
        LoadedTestFile {
            route: route(method, path),
            path: PathBuf::from("unused"),
            file,
            endpoint,
        }
    }

    const CAR_ENDPOINT: &str =
        r#"{ "operationId": "getCar", "sources": { "car": { "type": "sql", "connection": "db", "script": "car.sql" } }, "response": { "maker": "sources.car.maker" } }"#;

    fn routable_with_car() -> HashMap<RouteKey, EndpointFile> {
        HashMap::from([(route("get", "/cars/{vin}"), endpoint(CAR_ENDPOINT))])
    }

    fn one_warning_containing(warnings: &[String], needle: &str) {
        let hits: Vec<&String> = warnings.iter().filter(|w| w.contains(needle)).collect();
        assert_eq!(hits.len(), 1, "expected exactly one warning containing {needle:?}, got {warnings:#?}");
    }

    #[test]
    fn a_clean_corpus_produces_no_warnings() {
        let files = vec![loaded(
            "get",
            "/cars/{vin}",
            r#"{ "cases": [ { "name": "ok", "request": { "path": { "vin": "AAA" } }, "mocks": { "car": { "maker": "Honda" } }, "expect": {} } ] }"#,
            Some(endpoint(CAR_ENDPOINT)),
        )];
        assert!(validate_corpus(&files, &routable_with_car()).is_empty());
    }

    #[test]
    fn warns_when_a_test_file_has_no_sibling_endpoint_file() {
        let files = vec![loaded("get", "/cars/{vin}", r#"{ "cases": [] }"#, None)];
        let warnings = validate_corpus(&files, &HashMap::new());
        one_warning_containing(&warnings, "no sibling endpoint.get.json");
        assert!(warnings[0].starts_with("/cars/{vin}/endpoint.get.test.json:"), "{warnings:?}");
    }

    #[test]
    fn warns_when_the_sibling_endpoint_file_is_not_a_routable_method() {
        // A parseable `endpoint.options.json` sits next to the test file,
        // but `build_router` never registers OPTIONS, so `routable` lacks it.
        let files = vec![loaded("options", "/cars/{vin}", r#"{ "cases": [] }"#, Some(endpoint(CAR_ENDPOINT)))];
        let warnings = validate_corpus(&files, &routable_with_car());
        one_warning_containing(&warnings, "endpoint.options.json is not a routable method");
    }

    #[test]
    fn warns_when_a_case_scenario_is_an_empty_string() {
        let files = vec![loaded(
            "get",
            "/cars/{vin}",
            r#"{ "cases": [ { "name": "blank tag", "scenario": "", "mocks": { "car": {} }, "expect": {} } ] }"#,
            Some(endpoint(CAR_ENDPOINT)),
        )];
        let warnings = validate_corpus(&files, &routable_with_car());
        one_warning_containing(&warnings, "scenario is an empty string");
        assert!(warnings[0].contains("case #1 \"blank tag\""), "{warnings:?}");
    }

    #[test]
    fn warns_when_a_case_mocks_a_verifier_on_an_endpoint_with_no_security() {
        let files = vec![loaded(
            "get",
            "/cars/{vin}",
            r#"{ "cases": [ { "name": "keyed", "mocks": { "car": {}, "verifier": { "active": true } }, "expect": {} } ] }"#,
            Some(endpoint(CAR_ENDPOINT)),
        )];
        let warnings = validate_corpus(&files, &routable_with_car());
        one_warning_containing(&warnings, "mocks a verifier but the endpoint declares no security scheme");
    }

    #[test]
    fn a_verifier_mock_on_a_secured_endpoint_is_not_a_warning() {
        let secured = endpoint(
            r#"{ "operationId": "getCar", "security": "apiKeyAuth", "sources": { "car": { "type": "sql", "connection": "db", "script": "car.sql" } }, "response": {} }"#,
        );
        let files = vec![loaded(
            "get",
            "/cars/{vin}",
            r#"{ "cases": [ { "name": "keyed", "mocks": { "car": {}, "verifier": { "active": true } }, "expect": {} } ] }"#,
            Some(secured),
        )];
        let routable = HashMap::from([(
            route("get", "/cars/{vin}"),
            endpoint(
                r#"{ "operationId": "getCar", "security": "apiKeyAuth", "sources": { "car": { "type": "sql", "connection": "db", "script": "car.sql" } }, "response": {} }"#,
            ),
        )]);
        assert!(validate_corpus(&files, &routable).is_empty());
    }

    #[test]
    fn warns_when_a_mock_key_names_no_source_of_the_endpoint() {
        let files = vec![loaded(
            "get",
            "/cars/{vin}",
            r#"{ "cases": [ { "name": "renamed", "mocks": { "car": {}, "pricing": { "amount": 1 } }, "expect": {} } ] }"#,
            Some(endpoint(CAR_ENDPOINT)),
        )];
        let warnings = validate_corpus(&files, &routable_with_car());
        one_warning_containing(&warnings, "mock 'pricing' names no source of this endpoint");
    }

    #[test]
    fn warns_when_a_request_path_key_is_not_a_param_of_the_route() {
        let files = vec![loaded(
            "get",
            "/cars/{vin}",
            r#"{ "cases": [ { "name": "typo", "request": { "path": { "vim": "AAA" } }, "mocks": { "car": {} }, "expect": {} } ] }"#,
            Some(endpoint(CAR_ENDPOINT)),
        )];
        let warnings = validate_corpus(&files, &routable_with_car());
        one_warning_containing(&warnings, "request.path 'vim' is not a {param} of route /cars/{vin}");
    }

    #[test]
    fn warns_when_a_later_case_repeats_an_earlier_request_block_under_the_same_scenario() {
        let files = vec![loaded(
            "get",
            "/cars/{vin}",
            r#"{ "cases": [
                { "name": "first", "request": { "path": { "vin": "AAA" } }, "mocks": { "car": {} }, "expect": {} },
                { "name": "shadowed", "request": { "path": { "vin": "AAA" } }, "mocks": { "car": {} }, "expect": {} }
            ] }"#,
            Some(endpoint(CAR_ENDPOINT)),
        )];
        let warnings = validate_corpus(&files, &routable_with_car());
        one_warning_containing(&warnings, "identical request block to case #1 \"first\" under the same scenario");
        assert!(warnings[0].contains("case #2 \"shadowed\""), "{warnings:?}");
    }

    #[test]
    fn an_identical_request_block_under_a_different_scenario_is_not_shadowed() {
        let files = vec![loaded(
            "get",
            "/cars/{vin}",
            r#"{ "cases": [
                { "name": "baseline", "request": { "path": { "vin": "AAA" } }, "mocks": { "car": {} }, "expect": {} },
                { "name": "db down", "scenario": "db-down", "request": { "path": { "vin": "AAA" } }, "mocks": { "car": { "fail": "x" } }, "expect": {} }
            ] }"#,
            Some(endpoint(CAR_ENDPOINT)),
        )];
        assert!(validate_corpus(&files, &routable_with_car()).is_empty());
    }

    #[test]
    fn warns_when_a_routable_endpoint_with_sources_has_no_test_file_at_all() {
        let warnings = validate_corpus(&[], &routable_with_car());
        one_warning_containing(&warnings, "GET /cars/{vin}: has sources but no .test.json file");
        assert!(warnings[0].contains("test.source_not_mocked"), "{warnings:?}");
    }

    #[test]
    fn a_source_less_routable_endpoint_with_no_test_file_is_not_a_warning() {
        let routable = HashMap::from([(route("get", "/ping"), endpoint(r#"{ "operationId": "ping", "sources": {}, "response": {} }"#))]);
        assert!(validate_corpus(&[], &routable).is_empty(), "nothing to mock means nothing can go unmocked");
    }
}
