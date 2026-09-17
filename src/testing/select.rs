use std::collections::HashMap;

use axum::http::HeaderMap;

use super::expect::matches_subset;
use super::memory::Memory;
use super::schema::TestCase;
use crate::endpoint::mock::InboundRequest;

/// Two-stage case selection for one inbound request: keep the cases
/// eligible under `active` (untagged, or tagged with exactly it), then
/// among those whose `request` block the inbound request satisfies, pick
/// the most specific — a case tagged with the active scenario beats an
/// untagged one, then more declared constraints beat fewer, then earlier
/// in the file beats later. An empty `request` is a rank-0 catch-all.
/// Returns the winner's index in `cases` alongside it, or `None` when
/// nothing matched.
pub(crate) fn select_case<'a>(cases: &'a [TestCase], active: Option<&str>, request: &InboundRequest<'_>, memory: &Memory) -> Option<(usize, &'a TestCase)> {
    let mut best: Option<(Rank, usize, &TestCase)> = None;
    for (index, case) in cases.iter().enumerate() {
        let tagged_with_active = match (&case.scenario, active) {
            (None, _) => false,
            (Some(tag), Some(active)) if tag == active => true,
            (Some(_), _) => continue,
        };
        if !request_matches(case, request, memory) {
            continue;
        }
        let rank = Rank {
            scenario: u8::from(tagged_with_active),
            constraints: constraint_count(case),
        };
        // Strictly greater, so an equal rank keeps the earlier case.
        if best.as_ref().is_none_or(|(best_rank, _, _)| rank > *best_rank) {
            best = Some((rank, index, case));
        }
    }
    best.map(|(_, index, case)| (index, case))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Rank {
    scenario: u8,
    constraints: usize,
}

fn constraint_count(case: &TestCase) -> usize {
    let request = &case.request;
    request.path.len() + request.query.len() + request.headers.len() + usize::from(request.body.is_some())
}

/// Every declared constraint must hold; undeclared keys are unconstrained.
/// Header names compare case-insensitively (via `HeaderMap`'s own lookup),
/// values exactly; a body compares as a subset with `expect`'s matcher
/// rules. Case values are `{{memory.X}}`-substituted first.
fn request_matches(case: &TestCase, request: &InboundRequest<'_>, memory: &Memory) -> bool {
    let declared = &case.request;
    if !string_map_matches(&memory.substitute_string_map(&declared.path), request.path_params) {
        return false;
    }
    if !string_map_matches(&memory.substitute_string_map(&declared.query), request.query_params) {
        return false;
    }
    if !headers_match(&memory.substitute_string_map(&declared.headers), request.headers) {
        return false;
    }
    match &declared.body {
        Some(body) => matches_subset(&memory.substitute(body), request.body),
        None => true,
    }
}

fn string_map_matches(declared: &HashMap<String, String>, inbound: &HashMap<String, String>) -> bool {
    declared.iter().all(|(key, value)| inbound.get(key) == Some(value))
}

fn headers_match(declared: &HashMap<String, String>, inbound: &HeaderMap) -> bool {
    declared.iter().all(|(name, value)| match inbound.get(name.as_str()) {
        Some(actual) => actual.to_str().is_ok_and(|actual| actual == value),
        None => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::schema::{SaveEntry, TestFile};
    use serde_json::json;

    fn cases(json: &str) -> Vec<TestCase> {
        let file: TestFile = serde_json::from_str(json).expect("test fixture JSON should parse");
        file.cases
    }

    /// Owns the four borrowed parts an `InboundRequest` points into, so a
    /// test can build one fluently and hand out a borrow.
    struct Inbound {
        path: HashMap<String, String>,
        query: HashMap<String, String>,
        headers: HeaderMap,
        body: serde_json::Value,
    }

    impl Inbound {
        fn empty() -> Self {
            Inbound {
                path: HashMap::new(),
                query: HashMap::new(),
                headers: HeaderMap::new(),
                body: serde_json::Value::Null,
            }
        }

        fn path(mut self, key: &str, value: &str) -> Self {
            self.path.insert(key.to_string(), value.to_string());
            self
        }

        fn query(mut self, key: &str, value: &str) -> Self {
            self.query.insert(key.to_string(), value.to_string());
            self
        }

        fn header(mut self, name: &'static str, value: &str) -> Self {
            self.headers.insert(name, value.parse().unwrap());
            self
        }

        fn body(mut self, body: serde_json::Value) -> Self {
            self.body = body;
            self
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

    fn winner_name(cases: &[TestCase], active: Option<&str>, inbound: &Inbound) -> Option<String> {
        select_case(cases, active, &inbound.as_request(), &Memory::new()).map(|(_, case)| case.name.clone())
    }

    #[test]
    fn a_more_specific_case_beats_a_less_specific_one_regardless_of_declaration_order() {
        let cases = cases(
            r#"{ "cases": [
                { "name": "catch-all", "request": {}, "expect": {} },
                { "name": "by vin", "request": { "path": { "vin": "AAA" } }, "expect": {} },
                { "name": "by vin and query", "request": { "path": { "vin": "AAA" }, "query": { "full": "true" } }, "expect": {} }
            ] }"#,
        );
        let inbound = Inbound::empty().path("vin", "AAA").query("full", "true");
        assert_eq!(winner_name(&cases, None, &inbound).as_deref(), Some("by vin and query"));
    }

    #[test]
    fn an_equal_specificity_tie_goes_to_the_earlier_case_in_the_file() {
        let cases = cases(
            r#"{ "cases": [
                { "name": "first", "request": { "path": { "vin": "AAA" } }, "expect": {} },
                { "name": "second", "request": { "path": { "vin": "AAA" } }, "expect": {} }
            ] }"#,
        );
        let inbound = Inbound::empty().path("vin", "AAA");
        let (index, case) = select_case(&cases, None, &inbound.as_request(), &Memory::new()).expect("both cases match");
        assert_eq!(index, 0);
        assert_eq!(case.name, "first");
    }

    #[test]
    fn a_case_tagged_with_the_active_scenario_beats_an_untagged_one_even_when_less_specific() {
        let cases = cases(
            r#"{ "cases": [
                { "name": "baseline (more specific)", "request": { "path": { "vin": "AAA" }, "query": { "full": "true" } }, "expect": {} },
                { "name": "pricing down", "scenario": "pricing-down", "request": { "path": { "vin": "AAA" } }, "expect": {} }
            ] }"#,
        );
        let inbound = Inbound::empty().path("vin", "AAA").query("full", "true");
        assert_eq!(winner_name(&cases, Some("pricing-down"), &inbound).as_deref(), Some("pricing down"));
        assert_eq!(
            winner_name(&cases, None, &inbound).as_deref(),
            Some("baseline (more specific)"),
            "with no active scenario the tagged case is out of the running entirely"
        );
    }

    #[test]
    fn a_case_tagged_with_a_different_scenario_is_excluded_entirely() {
        let cases = cases(
            r#"{ "cases": [
                { "name": "db down", "scenario": "db-down", "request": {}, "expect": {} }
            ] }"#,
        );
        let inbound = Inbound::empty();
        assert_eq!(winner_name(&cases, Some("pricing-down"), &inbound), None, "tagged for another scenario");
        assert_eq!(winner_name(&cases, None, &inbound), None, "tagged cases are never part of the untagged baseline");
    }

    #[test]
    fn untagged_cases_remain_eligible_under_a_scenario_no_case_in_this_file_is_tagged_for() {
        let cases = cases(r#"{ "cases": [ { "name": "baseline", "request": {}, "expect": {} } ] }"#);
        assert_eq!(winner_name(&cases, Some("pricing-down"), &Inbound::empty()).as_deref(), Some("baseline"));
    }

    #[test]
    fn a_case_with_an_empty_request_block_is_a_catch_all_for_any_inbound_request() {
        let cases = cases(r#"{ "cases": [ { "name": "catch-all", "expect": {} } ] }"#);
        let inbound = Inbound::empty().path("vin", "ZZZ").query("x", "1").header("x-anything", "v").body(json!({ "k": 1 }));
        assert_eq!(winner_name(&cases, None, &inbound).as_deref(), Some("catch-all"));
    }

    #[test]
    fn a_declared_path_param_that_does_not_match_excludes_the_case() {
        let cases = cases(r#"{ "cases": [ { "name": "by vin", "request": { "path": { "vin": "AAA" } }, "expect": {} } ] }"#);
        assert_eq!(winner_name(&cases, None, &Inbound::empty().path("vin", "BBB")), None);
        assert_eq!(winner_name(&cases, None, &Inbound::empty()), None, "an absent param is a mismatch too");
    }

    #[test]
    fn a_declared_query_param_that_does_not_match_excludes_the_case() {
        let cases = cases(r#"{ "cases": [ { "name": "by maker", "request": { "query": { "maker": "Honda" } }, "expect": {} } ] }"#);
        assert_eq!(winner_name(&cases, None, &Inbound::empty().query("maker", "Toyota")), None);
        assert_eq!(winner_name(&cases, None, &Inbound::empty().query("maker", "Honda")).as_deref(), Some("by maker"));
    }

    #[test]
    fn header_names_match_case_insensitively_but_values_exactly() {
        let cases = cases(r#"{ "cases": [ { "name": "keyed", "request": { "headers": { "X-Api-Key": "good-key" } }, "expect": {} } ] }"#);
        assert_eq!(
            winner_name(&cases, None, &Inbound::empty().header("x-api-key", "good-key")).as_deref(),
            Some("keyed"),
            "a lowercase inbound header name must satisfy a mixed-case declared one"
        );
        assert_eq!(
            winner_name(&cases, None, &Inbound::empty().header("x-api-key", "GOOD-KEY")),
            None,
            "values compare exactly"
        );
        assert_eq!(winner_name(&cases, None, &Inbound::empty()), None);
    }

    #[test]
    fn a_declared_body_matches_as_a_subset_with_any_and_type_matchers() {
        let cases = cases(
            r#"{ "cases": [
                { "name": "honda", "request": { "body": { "maker": "Honda", "year": "$type:number", "vin": "$any" } }, "expect": {} }
            ] }"#,
        );
        let matching = Inbound::empty().body(json!({ "maker": "Honda", "year": 2020, "vin": "AAA", "extra": "ignored" }));
        assert_eq!(winner_name(&cases, None, &matching).as_deref(), Some("honda"));

        let wrong_type = Inbound::empty().body(json!({ "maker": "Honda", "year": "2020", "vin": "AAA" }));
        assert_eq!(winner_name(&cases, None, &wrong_type), None, "$type:number must reject a string year");

        let missing_key = Inbound::empty().body(json!({ "maker": "Honda", "year": 2020 }));
        assert_eq!(winner_name(&cases, None, &missing_key), None, "$any still requires the key to be present");
    }

    #[test]
    fn a_body_constraint_counts_as_one_unit_of_specificity() {
        let cases = cases(
            r#"{ "cases": [
                { "name": "catch-all", "request": {}, "expect": {} },
                { "name": "by body", "request": { "body": { "maker": "Honda" } }, "expect": {} }
            ] }"#,
        );
        let inbound = Inbound::empty().body(json!({ "maker": "Honda" }));
        assert_eq!(winner_name(&cases, None, &inbound).as_deref(), Some("by body"));
    }

    #[test]
    fn memory_placeholders_in_a_case_request_are_substituted_before_matching() {
        let cases = cases(
            r#"{ "cases": [
                { "name": "created car", "request": { "path": { "vin": "{{memory.vin}}" }, "body": { "id": "{{memory.id}}" } }, "expect": {} }
            ] }"#,
        );
        let mut memory = Memory::new();
        memory.save(
            &HashMap::from([
                ("vin".to_string(), SaveEntry::Plain("response.body.vin".to_string())),
                ("id".to_string(), SaveEntry::Plain("response.body.id".to_string())),
            ]),
            201,
            &json!({ "vin": "AAA", "id": 42 }),
        );
        let inbound = Inbound::empty().path("vin", "AAA").body(json!({ "id": 42 }));
        let selected = select_case(&cases, None, &inbound.as_request(), &memory);
        assert!(selected.is_some(), "memory.vin must resolve to AAA and memory.id to the number 42 before comparing");

        let unresolved = select_case(&cases, None, &inbound.as_request(), &Memory::new());
        assert!(unresolved.is_none(), "with nothing saved the placeholder stays literal and can't match");
    }
}
