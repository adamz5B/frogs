//! Milestone 2: `scopesFrom` loading, scope-claim parsing, scopes through `verify`/the cache, and
//! the bounded `VerifierCache`.

use std::collections::HashMap;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use serde_json::{Value, json};

use super::*;
use crate::sql::{SqlDriver, SqlError, SqlValue};

fn temp(name: &str) -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "frogs-scope-{name}-{}-{}-{n}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(dir.join("sql/db")).unwrap();
    std::fs::create_dir_all(dir.join("http")).unwrap();
    std::fs::write(dir.join("sql/db/verify.sql"), "SELECT 1;").unwrap();
    dir
}

fn load_with(verifier_json: &str) -> Result<SecurityConfig, SecurityLoadError> {
    let dir = temp("load");
    std::fs::create_dir_all(dir.join("verifiers")).unwrap();
    std::fs::write(dir.join("schemes.json"), r#"{ "s": { "verifier": "v.json" } }"#).unwrap();
    std::fs::write(dir.join("verifiers/v.json"), verifier_json).unwrap();
    let result = SecurityConfig::load(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    result
}

fn sql_verifier_json(extra: &str) -> String {
    format!(
        r#"{{ "type": "sql", "connection": "db", "script": "verify.sql", "parameters": [{{ "name": "key", "from": "header.X-Api-Key" }}], "validIf": "row.active = true"{extra} }}"#
    )
}

// ---------------------------------------------------------------- loading `scopesFrom`

#[test]
fn a_sql_or_http_verifier_with_scopes_from_loads_with_a_compiled_scopes_path() {
    let config = load_with(&sql_verifier_json(r#", "scopesFrom": "row.scope""#)).unwrap();
    assert!(config.verifiers["s"].scopes_path.is_some());
    let http =
        load_with(r#"{ "type": "http", "request": "r.json", "parameters": [], "validIf": "response.active = true", "scopesFrom": "response.data.scope" }"#).unwrap();
    assert!(http.verifiers["s"].scopes_path.is_some());
    assert!(
        load_with(&sql_verifier_json("")).unwrap().verifiers["s"].scopes_path.is_none(),
        "absent means not enforceable"
    );
}

#[test]
fn an_empty_or_malformed_scopes_from_is_a_load_error() {
    for bad in ["", "scope", "row.", ".scope", "row..scope", " "] {
        let error = load_with(&sql_verifier_json(&format!(r#", "scopesFrom": "{bad}""#)))
            .err()
            .unwrap_or_else(|| panic!("{bad:?} must fail"))
            .to_string();
        assert!(error.contains("scopesFrom"), "{bad:?}: {error}");
    }
}

#[test]
fn scopes_from_on_an_mtls_verifier_is_a_load_error() {
    let error = load_with(r#"{ "type": "mtls", "validIf": "cert.cn = a", "scopesFrom": "cert.scope" }"#)
        .expect_err("refused")
        .to_string();
    assert!(error.contains("scopesFrom"), "{error}");
}

// ---------------------------------------------------------------- scope-claim parsing

fn extract(value: Value) -> Option<Vec<String>> {
    ScopesPath::parse("row.scope")
        .unwrap()
        .extract(&json!({ "scope": value }))
        .map(|scopes| scopes.to_vec())
}

#[test]
fn a_string_claim_is_split_on_single_spaces_with_empty_pieces_dropped() {
    assert_eq!(extract(json!("cars.read  cars.write")), Some(vec!["cars.read".to_string(), "cars.write".to_string()]));
    assert_eq!(extract(json!("  a ")), Some(vec!["a".to_string()]));
    assert_eq!(extract(json!("")), Some(Vec::new()), "an empty claim is a present claim granting nothing");
}

#[test]
fn a_string_claim_is_not_split_on_tabs_or_newlines() {
    assert_eq!(extract(json!("a\tb c")), Some(vec!["a\tb".to_string(), "c".to_string()]));
}

#[test]
fn an_array_claim_of_strings_is_taken_verbatim_and_never_split() {
    assert_eq!(
        extract(json!(["cars.read", "has space"])),
        Some(vec!["cars.read".to_string(), "has space".to_string()])
    );
}

#[test]
fn a_mixed_array_a_number_an_object_null_or_a_missing_path_is_no_scopes_at_all() {
    assert_eq!(extract(json!(["a", 1])), None);
    assert_eq!(extract(json!([null])), None);
    assert_eq!(extract(json!(5)), None);
    assert_eq!(extract(json!(true)), None);
    assert_eq!(extract(json!({ "a": 1 })), None);
    assert_eq!(extract(Value::Null), None);
    assert_eq!(ScopesPath::parse("row.scope").unwrap().extract(&json!({ "other": "a" })), None);
    assert_eq!(ScopesPath::parse("row.a.b").unwrap().extract(&json!({ "a": "x" })), None);
}

#[test]
fn a_nested_scope_path_is_followed() {
    let path = ScopesPath::parse("response.data.scope").unwrap();
    assert_eq!(path.extract(&json!({ "data": { "scope": "a b" } })).unwrap().to_vec(), ["a", "b"]);
}

#[test]
fn sixty_four_scopes_are_accepted_and_sixty_five_are_none_never_truncated() {
    let sixty_four: Vec<String> = (0..64).map(|n| format!("s{n}")).collect();
    assert_eq!(extract(json!(sixty_four.clone())).unwrap().len(), 64);
    assert_eq!(extract(json!(sixty_four.join(" "))).unwrap().len(), 64);
    let sixty_five: Vec<String> = (0..65).map(|n| format!("s{n}")).collect();
    assert_eq!(extract(json!(sixty_five.clone())), None);
    assert_eq!(extract(json!(sixty_five.join(" "))), None);
}

#[test]
fn a_claim_over_four_kibibytes_is_none_and_one_at_the_limit_is_kept() {
    let at_limit = vec!["x".repeat(64); 64];
    assert_eq!(at_limit.iter().map(String::len).sum::<usize>(), 4096);
    assert_eq!(extract(json!(at_limit)).unwrap().len(), 64);
    let over = vec!["x".repeat(65); 64];
    assert_eq!(extract(json!(over)), None);
    assert_eq!(extract(json!("y".repeat(5 * 1024))), None, "one 5 KiB scope");
}

// ---------------------------------------------------------------- scopes through `verify`

#[derive(Debug)]
struct CountingDriver {
    calls: Arc<AtomicUsize>,
    /// One answer per call, the last repeated; `None` fails the call.
    answers: Mutex<Vec<Option<HashMap<String, SqlValue>>>>,
}

#[async_trait::async_trait]
impl SqlDriver for CountingDriver {
    async fn query(&self, _script: &str, _params: &HashMap<String, SqlValue>) -> Result<Vec<HashMap<String, SqlValue>>, SqlError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut answers = self.answers.lock().unwrap();
        let answer = if answers.len() > 1 { answers.remove(0) } else { answers[0].clone() };
        match answer {
            Some(row) => Ok(vec![row]),
            None => Err(SqlError::QueryFailed("simulated outage".to_string())),
        }
    }
}

fn answer(active: bool, scope: SqlValue) -> Option<HashMap<String, SqlValue>> {
    Some(HashMap::from([("active".to_string(), SqlValue::Bool(active)), ("scope".to_string(), scope)]))
}

fn text(value: &str) -> SqlValue {
    SqlValue::Text(value.to_string())
}

struct Harness {
    root: PathBuf,
    calls: Arc<AtomicUsize>,
    drivers: HashMap<String, Box<dyn SqlDriver>>,
    verifier: LoadedVerifier,
    cache: VerifierCache,
    client: reqwest::Client,
}

impl Harness {
    fn new(answers: Vec<Option<HashMap<String, SqlValue>>>, cache_ttl: Option<u64>) -> Harness {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut drivers: HashMap<String, Box<dyn SqlDriver>> = HashMap::new();
        drivers.insert(
            "db".to_string(),
            Box::new(CountingDriver {
                calls: calls.clone(),
                answers: Mutex::new(answers),
            }),
        );
        let ttl = cache_ttl.map(|t| format!(r#", "cacheTtlSeconds": {t}"#)).unwrap_or_default();
        let def: VerifierDef = serde_json::from_str(&sql_verifier_json(&format!(r#"{ttl}, "scopesFrom": "row.scope""#))).unwrap();
        let verifier = LoadedVerifier {
            valid_if: ValidIf::parse(def.valid_if()).unwrap(),
            scopes_path: Some(ScopesPath::parse(def.scopes_from().unwrap()).unwrap()),
            def,
            mtls: None,
        };
        Harness {
            root: temp("verify"),
            calls,
            drivers,
            verifier,
            cache: VerifierCache::new(),
            client: reqwest::Client::new(),
        }
    }

    async fn verify(&self, key: &str) -> Result<verify::Granted, verify::VerifyErrorCause> {
        let mut headers = HeaderMap::new();
        headers.insert(HeaderName::from_static("x-api-key"), HeaderValue::from_str(key).unwrap());
        verify(
            "s",
            &self.verifier,
            &self.drivers,
            Path::new(&self.root.join("sql")),
            &self.root.join("http"),
            &self.client,
            &headers,
            None,
            &self.cache,
            NonZeroU64::new(5_000).unwrap(),
        )
        .await
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

fn granted(result: Result<verify::Granted, verify::VerifyErrorCause>) -> Option<Vec<String>> {
    result.expect("a valid credential").scopes.map(|scopes| scopes.to_vec())
}

#[tokio::test]
async fn a_fresh_valid_verification_returns_the_scopes_from_the_resolved_result() {
    let h = Harness::new(vec![answer(true, text("cars.read cars.write"))], None);
    assert_eq!(granted(h.verify("k").await), Some(vec!["cars.read".to_string(), "cars.write".to_string()]));
}

#[tokio::test]
async fn a_cached_valid_verdict_returns_its_stored_scopes_without_calling_the_datasource_again() {
    let h = Harness::new(vec![answer(true, text("cars.read"))], Some(60));
    assert_eq!(granted(h.verify("k").await), Some(vec!["cars.read".to_string()]));
    assert_eq!(granted(h.verify("k").await), Some(vec!["cars.read".to_string()]));
    assert_eq!(h.calls(), 1, "the second call was a cache hit");
}

#[tokio::test]
async fn a_verifier_without_a_cache_ttl_recomputes_the_scopes_on_every_request() {
    let h = Harness::new(vec![answer(true, text("a")), answer(true, text("b"))], None);
    assert_eq!(granted(h.verify("k").await), Some(vec!["a".to_string()]));
    assert_eq!(
        granted(h.verify("k").await),
        Some(vec!["b".to_string()]),
        "a revoked/changed scope is seen immediately"
    );
    assert_eq!(h.calls(), 2);
}

#[tokio::test]
async fn an_unusable_scope_claim_in_a_valid_result_is_valid_with_no_scopes_and_stays_that_way_from_the_cache() {
    let h = Harness::new(vec![answer(true, SqlValue::Int(7))], Some(60));
    assert_eq!(granted(h.verify("k").await), None);
    assert_eq!(granted(h.verify("k").await), None, "the cache hit also has no scopes");
    assert_eq!(h.calls(), 1);
}

#[tokio::test]
async fn an_array_claim_from_the_datasource_is_taken_element_by_element() {
    let h = Harness::new(vec![answer(true, SqlValue::Array(vec![text("a b"), text("c")]))], None);
    assert_eq!(granted(h.verify("k").await), Some(vec!["a b".to_string(), "c".to_string()]));
}

#[tokio::test]
async fn an_invalid_verdict_is_cached_without_scopes_and_reads_back_as_invalid() {
    let h = Harness::new(vec![answer(false, text("admin"))], Some(60));
    assert!(matches!(h.verify("k").await, Err(verify::VerifyErrorCause::Invalid)));
    assert!(matches!(h.verify("k").await, Err(verify::VerifyErrorCause::Invalid)));
    assert_eq!(h.calls(), 1);
}

#[tokio::test]
async fn a_datasource_outage_is_never_cached_so_the_next_request_asks_again() {
    let h = Harness::new(vec![None, answer(true, text("a"))], Some(60));
    assert!(matches!(h.verify("k").await, Err(verify::VerifyErrorCause::Unavailable(_))));
    assert_eq!(granted(h.verify("k").await), Some(vec!["a".to_string()]));
    assert_eq!(h.calls(), 2);
}

#[tokio::test]
async fn different_credentials_never_share_a_cached_scope_set() {
    let h = Harness::new(vec![answer(true, text("a")), answer(true, text("b"))], Some(60));
    assert_eq!(granted(h.verify("one").await), Some(vec!["a".to_string()]));
    assert_eq!(granted(h.verify("two").await), Some(vec!["b".to_string()]));
    assert_eq!(granted(h.verify("one").await), Some(vec!["a".to_string()]));
}

// ---------------------------------------------------------------- the bounded cache

fn scopes(items: &[&str]) -> Option<Arc<[String]>> {
    Some(items.iter().map(|s| s.to_string()).collect::<Vec<_>>().into())
}

const LONG: Duration = Duration::from_secs(3600);

#[test]
fn scopes_are_stored_only_for_a_valid_verdict() {
    let cache = VerifierCache::new();
    cache.set("valid".to_string(), true, scopes(&["a"]), LONG);
    cache.set("invalid".to_string(), false, scopes(&["admin"]), LONG);
    assert_eq!(cache.get("valid").unwrap().1.unwrap().to_vec(), ["a"]);
    let (valid, stored) = cache.get("invalid").unwrap();
    assert!(!valid && stored.is_none(), "a rejected credential never carries scopes");
}

#[test]
fn a_valid_entry_stored_without_scopes_reads_back_as_none() {
    let cache = VerifierCache::new();
    cache.set("k".to_string(), true, None, LONG);
    assert_eq!(cache.get("k").map(|(valid, scopes)| (valid, scopes.is_none())), Some((true, true)));
}

#[test]
fn at_the_high_water_mark_an_invalid_insert_is_skipped_while_a_valid_one_still_fits() {
    let cache = VerifierCache::with_capacity(100); // high water 75
    for n in 0..75 {
        cache.set(format!("v{n}"), true, None, LONG);
    }
    cache.set("bad".to_string(), false, None, LONG);
    assert!(cache.get("bad").is_none(), "the top quarter is reserved for valid results");
    cache.set("good".to_string(), true, None, LONG);
    assert!(cache.get("good").is_some());
}

#[test]
fn an_invalid_flood_can_never_push_out_or_block_valid_results() {
    let cache = VerifierCache::with_capacity(100);
    for n in 0..1_000 {
        cache.set(format!("bad{n}"), false, None, LONG);
    }
    for n in 0..25 {
        cache.set(format!("good{n}"), true, None, LONG);
    }
    for n in 0..25 {
        assert!(cache.get(&format!("good{n}")).is_some(), "good{n} must have been cached");
    }
    let invalid_kept = (0..1_000).filter(|n| cache.get(&format!("bad{n}")).is_some()).count();
    assert_eq!(invalid_kept, 75, "negative results stop at the high-water mark");
}

#[test]
fn at_the_cap_with_every_entry_live_a_new_valid_insert_is_skipped_but_nothing_is_evicted() {
    let cache = VerifierCache::with_capacity(100);
    for n in 0..100 {
        cache.set(format!("v{n}"), true, None, LONG);
    }
    cache.set("extra".to_string(), true, None, LONG);
    assert!(cache.get("extra").is_none());
    for n in 0..100 {
        assert!(cache.get(&format!("v{n}")).is_some(), "v{n}");
    }
}

#[test]
fn overwriting_an_existing_key_is_allowed_at_the_cap_and_at_the_high_water_mark() {
    let cache = VerifierCache::with_capacity(100);
    for n in 0..100 {
        cache.set(format!("v{n}"), true, scopes(&["old"]), LONG);
    }
    cache.set("v5".to_string(), true, scopes(&["new"]), LONG);
    assert_eq!(cache.get("v5").unwrap().1.unwrap().to_vec(), ["new"]);
    cache.set("v6".to_string(), false, None, LONG);
    assert_eq!(
        cache.get("v6").map(|(valid, _)| valid),
        Some(false),
        "an overwrite never grows the map, so the high-water rule does not apply"
    );
}

#[test]
fn expired_entries_are_purged_first_so_a_full_cache_of_stale_results_accepts_new_ones() {
    let cache = VerifierCache::with_capacity(100);
    for n in 0..100 {
        cache.set(format!("old{n}"), true, None, Duration::from_millis(1));
    }
    std::thread::sleep(Duration::from_millis(20));
    cache.set("fresh".to_string(), true, None, LONG);
    assert!(cache.get("fresh").is_some());
    assert!(cache.purge_scan_count() >= 1);
}

#[test]
fn a_flood_of_inserts_at_the_cap_runs_at_most_one_expiry_scan_per_second() {
    let cache = VerifierCache::with_capacity(100);
    for n in 0..100 {
        cache.set(format!("v{n}"), true, None, LONG);
    }
    let before = cache.purge_scan_count();
    for n in 0..1_000 {
        cache.set(format!("bad{n}"), false, None, LONG);
    }
    let scans = cache.purge_scan_count() - before;
    assert!(scans <= 1, "{scans} scans for 1,000 inserts: an unauthenticated flood must not cost O(n) each");
}

#[test]
fn nothing_is_scanned_while_the_cache_is_below_the_high_water_mark() {
    let cache = VerifierCache::with_capacity(100);
    for n in 0..50 {
        cache.set(format!("v{n}"), n % 2 == 0, None, LONG);
    }
    assert_eq!(cache.purge_scan_count(), 0);
}

#[tokio::test]
async fn a_skipped_insert_still_answers_correctly_through_verify_because_the_next_call_just_re_verifies() {
    let h = Harness::new(vec![answer(false, text("")), answer(false, text(""))], Some(60));
    let cache = VerifierCache::with_capacity(100);
    for n in 0..75 {
        cache.set(format!("filler{n}"), true, None, LONG);
    }
    let h = Harness { cache, ..h };
    assert!(matches!(h.verify("k").await, Err(verify::VerifyErrorCause::Invalid)));
    assert!(matches!(h.verify("k").await, Err(verify::VerifyErrorCause::Invalid)));
    assert_eq!(h.calls(), 2, "the invalid verdict was not cached past the high-water mark");
}
