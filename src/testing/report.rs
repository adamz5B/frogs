use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde_json::Value;

use super::expect::Mismatch;
use crate::endpoint::mock::{ScenarioSource, Unmocked};

/// `--report <text|json|junit>` — `text` streams one line per request to
/// stdout as it happens; `json`/`junit` are written to `--report-file`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ReportFormat {
    Text,
    Json,
    Junit,
}

/// A served response body larger than this is stored truncated in the
/// report (with a marker) rather than in full — a report is a session log,
/// not a byte-exact capture.
pub const BODY_CAP_BYTES: usize = 64 * 1024;

/// What one request's matched `expect` (if any) said about what was served.
/// `NotMocked` takes precedence over an `expect` mismatch: a required
/// source the enforcer had to fail can't have produced the response the
/// case's author was asserting on.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    Pass,
    Fail(Vec<Mismatch>),
    Unmatched,
    NotMocked(Vec<String>),
    Served,
}

impl Verdict {
    pub fn label(&self) -> &'static str {
        match self {
            Verdict::Pass => "PASS",
            Verdict::Fail(_) => "FAIL",
            Verdict::Unmatched => "UNMATCHED",
            Verdict::NotMocked(_) => "NOT MOCKED",
            Verdict::Served => "SERVED",
        }
    }

    fn json_name(&self) -> &'static str {
        match self {
            Verdict::Pass => "pass",
            Verdict::Fail(_) => "fail",
            Verdict::Unmatched => "unmatched",
            Verdict::NotMocked(_) => "notMocked",
            Verdict::Served => "served",
        }
    }
}

/// One served request, as the report records it.
#[derive(Debug, Clone)]
pub struct Entry {
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    /// Lowercase, as `RouteKey::method` carries it; rendered uppercase.
    pub method: String,
    /// The route's OpenAPI-style display path (`/cars/{vin}`).
    pub path: String,
    /// Client-supplied via `X-Request-Id` when correlation is on — treated
    /// as untrusted text everywhere it's rendered.
    pub request_id: String,
    pub scenario: Option<String>,
    pub scenario_source: ScenarioSource,
    pub case_name: Option<String>,
    pub case_file: Option<String>,
    pub status: u16,
    pub body: Value,
    pub verdict: Verdict,
    /// Why nothing was served from a case — `Unmatched` only: either no
    /// case matched or the request named an unknown scenario.
    pub unmatched_reason: Option<String>,
    pub unmocked: Vec<Unmocked>,
    pub elapsed_ms: u64,
}

#[derive(Debug)]
pub struct Report {
    pub started_at: DateTime<Utc>,
    pub scenario_flag: Option<String>,
    pub entries: Vec<Entry>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Summary {
    pub requests: usize,
    pub passed: usize,
    pub failed: usize,
    pub unmatched: usize,
    pub not_mocked: usize,
    pub served: usize,
}

impl Summary {
    /// The exit-code rule: anything that isn't a pass or a plain serve.
    pub fn has_problems(&self) -> bool {
        self.failed + self.unmatched + self.not_mocked > 0
    }
}

pub fn summary(entries: &[Entry]) -> Summary {
    summary_of(entries.iter())
}

fn summary_of<'a>(entries: impl Iterator<Item = &'a Entry>) -> Summary {
    let mut summary = Summary::default();
    for entry in entries {
        summary.requests += 1;
        match entry.verdict {
            Verdict::Pass => summary.passed += 1,
            Verdict::Fail(_) => summary.failed += 1,
            Verdict::Unmatched => summary.unmatched += 1,
            Verdict::NotMocked(_) => summary.not_mocked += 1,
            Verdict::Served => summary.served += 1,
        }
    }
    summary
}

/// The stored form of a served body: as-is when small enough, otherwise
/// its serialized prefix (cut on a char boundary) plus a marker.
pub fn cap_body(body: &Value) -> Value {
    let serialized = serde_json::to_string(body).unwrap_or_default();
    if serialized.len() <= BODY_CAP_BYTES {
        return body.clone();
    }
    let mut cut = BODY_CAP_BYTES;
    while !serialized.is_char_boundary(cut) {
        cut -= 1;
    }
    Value::String(format!("{}...[truncated {} bytes]", &serialized[..cut], serialized.len() - cut))
}

fn scenario_display(entry: &Entry) -> String {
    match &entry.scenario {
        Some(name) => format!("{name} ({})", entry.scenario_source.label()),
        None => "none".to_string(),
    }
}

/// One `text`-format line (plus indented continuation lines for a FAIL's
/// mismatches), ASCII only. Anything client-supplied is rendered through
/// `ascii_only` so a hostile header can't smuggle control characters or
/// line breaks into the log.
pub fn render_text_line(entry: &Entry) -> String {
    let mut line = format!(
        "#{:04} {} {} {} [scenario: {}]",
        entry.sequence,
        entry.timestamp.format("%H:%M:%S%.3f"),
        entry.method.to_uppercase(),
        ascii_only(&entry.path),
        ascii_only(&scenario_display(entry))
    );
    match &entry.verdict {
        Verdict::Unmatched => {
            let reason = entry.unmatched_reason.as_deref().unwrap_or("no matching case");
            line.push_str(&format!(" {} -> {} {}", ascii_only(reason), entry.status, entry.verdict.label()));
        }
        Verdict::NotMocked(names) => {
            line.push_str(&format!(
                " unmocked (required): {} -> {} {}",
                ascii_only(&names.join(", ")),
                entry.status,
                entry.verdict.label()
            ));
        }
        Verdict::Pass | Verdict::Fail(_) | Verdict::Served => {
            match &entry.case_name {
                Some(name) => line.push_str(&format!(" case \"{}\"", ascii_only(name))),
                None => line.push_str(" no test file"),
            }
            line.push_str(&format!(" -> {} {}", entry.status, entry.verdict.label()));
        }
    }
    if let Verdict::Fail(mismatches) = &entry.verdict {
        for mismatch in mismatches {
            line.push_str(&format!(
                "\n    {}: expected {}, got {}",
                ascii_only(&mismatch.path),
                ascii_only(&mismatch.expected),
                ascii_only(&mismatch.actual)
            ));
        }
    }
    let optional: Vec<&str> = entry.unmocked.iter().filter(|u| u.optional).map(|u| u.name.as_str()).collect();
    if !optional.is_empty() {
        line.push_str(&format!("\n    unmocked (optional, degraded): {}", ascii_only(&optional.join(", "))));
    }
    line
}

/// Every text line so far, one per request — what `--report-file` holds
/// for the `text` format.
pub fn render_text(report: &Report) -> String {
    let mut out = String::new();
    for entry in &report.entries {
        out.push_str(&render_text_line(entry));
        out.push('\n');
    }
    out
}

pub fn render_summary_line(summary: &Summary) -> String {
    format!(
        "{} request(s): {} passed, {} failed, {} unmatched, {} not mocked, {} served",
        summary.requests, summary.passed, summary.failed, summary.unmatched, summary.not_mocked, summary.served
    )
}

/// Printable ASCII only — every other byte (control characters, non-ASCII)
/// becomes `?`, so the streamed log stays one line per request no matter
/// what a client put in a header or a case author put in a name.
fn ascii_only(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii() && !c.is_ascii_control() { c } else { '?' }).collect()
}

pub fn render_json(report: &Report, ended_at: DateTime<Utc>) -> String {
    let entries: Vec<Value> = report.entries.iter().map(entry_json).collect();
    let summary = summary(&report.entries);
    let document = serde_json::json!({
        "startedAt": report.started_at.to_rfc3339(),
        "endedAt": ended_at.to_rfc3339(),
        "scenarioFlag": report.scenario_flag,
        "entries": entries,
        "summary": {
            "requests": summary.requests,
            "passed": summary.passed,
            "failed": summary.failed,
            "unmatched": summary.unmatched,
            "notMocked": summary.not_mocked,
            "served": summary.served,
        },
    });
    serde_json::to_string_pretty(&document).expect("a report document always serializes")
}

fn entry_json(entry: &Entry) -> Value {
    let mismatches: Vec<Value> = match &entry.verdict {
        Verdict::Fail(mismatches) => mismatches
            .iter()
            .map(|m| serde_json::json!({ "path": m.path, "expected": m.expected, "actual": m.actual }))
            .collect(),
        _ => Vec::new(),
    };
    let unmocked: Vec<Value> = entry.unmocked.iter().map(|u| serde_json::json!({ "name": u.name, "optional": u.optional })).collect();
    serde_json::json!({
        "sequence": entry.sequence,
        "timestamp": entry.timestamp.to_rfc3339(),
        "method": entry.method.to_uppercase(),
        "path": entry.path,
        "requestId": entry.request_id,
        "scenario": entry.scenario,
        "scenarioSource": entry.scenario_source.label(),
        "case": entry.case_name,
        "file": entry.case_file,
        "status": entry.status,
        "body": entry.body,
        "verdict": entry.verdict.json_name(),
        "unmatchedReason": entry.unmatched_reason,
        "mismatches": mismatches,
        "unmocked": unmocked,
        "elapsedMs": entry.elapsed_ms,
    })
}

/// Hand-rendered JUnit XML: one `<testsuite>` per route, one `<testcase>`
/// per request. Every field that reaches the output — including the
/// client-supplied request id, mismatch text, and body — goes through
/// `xml_escape`.
pub fn render_junit(report: &Report) -> String {
    let mut suites: BTreeMap<String, Vec<&Entry>> = BTreeMap::new();
    for entry in &report.entries {
        suites.entry(format!("{} {}", entry.method.to_uppercase(), entry.path)).or_default().push(entry);
    }
    let overall = summary(&report.entries);

    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str(&format!(
        "<testsuites name=\"frogs test\" tests=\"{}\" failures=\"{}\" timestamp=\"{}\">\n",
        overall.requests,
        overall.failed + overall.unmatched + overall.not_mocked,
        xml_escape(&report.started_at.to_rfc3339())
    ));
    for (route, entries) in &suites {
        let suite_summary = summary_of(entries.iter().copied());
        xml.push_str(&format!(
            "  <testsuite name=\"{}\" tests=\"{}\" failures=\"{}\">\n",
            xml_escape(route),
            suite_summary.requests,
            suite_summary.failed + suite_summary.unmatched + suite_summary.not_mocked
        ));
        for entry in entries {
            let mut name = format!("#{:04} {}", entry.sequence, entry.case_name.as_deref().unwrap_or("(no case)"));
            if let Some(scenario) = &entry.scenario {
                name.push_str(&format!(" [{scenario}]"));
            }
            xml.push_str(&format!(
                "    <testcase classname=\"{}\" name=\"{}\" time=\"{:.3}\">\n",
                xml_escape(route),
                xml_escape(&name),
                entry.elapsed_ms as f64 / 1000.0
            ));
            let failure_message = match &entry.verdict {
                Verdict::Fail(mismatches) => Some(
                    mismatches
                        .iter()
                        .map(|m| format!("{}: expected {}, got {}", m.path, m.expected, m.actual))
                        .collect::<Vec<_>>()
                        .join("; "),
                ),
                Verdict::Unmatched => Some(entry.unmatched_reason.clone().unwrap_or_else(|| "no matching case".to_string())),
                Verdict::NotMocked(names) => Some(format!("required source(s) not mocked: {}", names.join(", "))),
                Verdict::Pass | Verdict::Served => None,
            };
            if let Some(message) = failure_message {
                xml.push_str(&format!(
                    "      <failure message=\"{}\" type=\"{}\">{}</failure>\n",
                    xml_escape(&message),
                    xml_escape(entry.verdict.label()),
                    xml_escape(&serde_json::to_string(&entry.body).unwrap_or_default())
                ));
            }
            xml.push_str(&format!(
                "      <system-out>status={} requestId={} scenario={} body={}</system-out>\n",
                entry.status,
                xml_escape(&entry.request_id),
                xml_escape(&scenario_display(entry)),
                xml_escape(&serde_json::to_string(&entry.body).unwrap_or_default())
            ));
            xml.push_str("    </testcase>\n");
        }
        xml.push_str("  </testsuite>\n");
    }
    xml.push_str("</testsuites>\n");
    xml
}

/// Escapes all five XML-significant characters — attribute values and
/// text content alike go through this one function, so a client-supplied
/// value can't terminate an attribute or inject an element.
pub fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            // XML 1.0 forbids most control characters outright; dropping
            // them beats producing a document parsers reject.
            c if c.is_control() && c != '\n' && c != '\t' && c != '\r' => {}
            c => out.push(c),
        }
    }
    out
}

/// Writes `content` to `<path>.<pid>.tmp` then renames it over `path`, so
/// a reader never sees a half-written report. The pid in the temp name
/// keeps two mock servers pointed at the same report file from clobbering
/// each other's temp file mid-write.
pub fn write_atomic(path: &Path, content: &str) -> io::Result<()> {
    let mut temp = path.as_os_str().to_owned();
    temp.push(format!(".{}.tmp", std::process::id()));
    let temp = std::path::PathBuf::from(temp);
    std::fs::write(&temp, content)?;
    if let Err(e) = std::fs::rename(&temp, path) {
        let _ = std::fs::remove_file(&temp);
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn entry(sequence: u64, verdict: Verdict) -> Entry {
        Entry {
            sequence,
            timestamp: DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z").unwrap().with_timezone(&Utc),
            method: "get".to_string(),
            path: "/cars/{vin}".to_string(),
            request_id: "req-1".to_string(),
            scenario: None,
            scenario_source: ScenarioSource::Baseline,
            case_name: Some("happy path".to_string()),
            case_file: Some("/cars/{vin}/endpoint.get.test.json".to_string()),
            status: 200,
            body: json!({ "maker": "Honda" }),
            verdict,
            unmatched_reason: None,
            unmocked: Vec::new(),
            elapsed_ms: 12,
        }
    }

    fn mismatch() -> Mismatch {
        Mismatch {
            path: "body.maker".to_string(),
            expected: "\"Honda\"".to_string(),
            actual: "\"Toyota\"".to_string(),
        }
    }

    fn report(entries: Vec<Entry>) -> Report {
        Report {
            started_at: DateTime::parse_from_rfc3339("2026-01-02T03:00:00Z").unwrap().with_timezone(&Utc),
            scenario_flag: Some("db-down".to_string()),
            entries,
        }
    }

    #[test]
    fn summary_counts_every_verdict_into_its_own_bucket() {
        let entries = vec![
            entry(1, Verdict::Pass),
            entry(2, Verdict::Pass),
            entry(3, Verdict::Fail(vec![mismatch()])),
            entry(4, Verdict::Unmatched),
            entry(5, Verdict::NotMocked(vec!["car".to_string()])),
            entry(6, Verdict::Served),
        ];
        let summary = summary(&entries);
        assert_eq!(
            summary,
            Summary {
                requests: 6,
                passed: 2,
                failed: 1,
                unmatched: 1,
                not_mocked: 1,
                served: 1,
            }
        );
    }

    #[test]
    fn has_problems_is_false_for_only_passes_and_plain_serves() {
        let summary = summary(&[entry(1, Verdict::Pass), entry(2, Verdict::Served)]);
        assert!(!summary.has_problems());
        assert!(!Summary::default().has_problems(), "an empty session is not a failed one");
    }

    #[test]
    fn has_problems_is_true_for_a_fail_an_unmatched_or_a_not_mocked_alone() {
        for verdict in [Verdict::Fail(vec![mismatch()]), Verdict::Unmatched, Verdict::NotMocked(vec!["car".to_string()])] {
            let label = verdict.label();
            assert!(
                summary(&[entry(1, Verdict::Pass), entry(2, verdict)]).has_problems(),
                "one {label} entry must flip the exit code"
            );
        }
    }

    #[test]
    fn render_json_carries_the_scenario_per_entry_and_the_summary_counts() {
        let mut tagged = entry(2, Verdict::Fail(vec![mismatch()]));
        tagged.scenario = Some("pricing-down".to_string());
        tagged.scenario_source = ScenarioSource::Header;
        let report = report(vec![entry(1, Verdict::Pass), tagged]);

        let document: Value = serde_json::from_str(&render_json(&report, Utc::now())).expect("render_json must produce valid JSON");

        assert_eq!(document["scenarioFlag"], "db-down");
        assert_eq!(document["entries"][0]["scenario"], Value::Null);
        assert_eq!(document["entries"][0]["scenarioSource"], "baseline");
        assert_eq!(document["entries"][0]["verdict"], "pass");
        assert_eq!(document["entries"][1]["scenario"], "pricing-down");
        assert_eq!(document["entries"][1]["scenarioSource"], "header");
        assert_eq!(document["entries"][1]["verdict"], "fail");
        assert_eq!(document["entries"][1]["mismatches"][0]["path"], "body.maker");
        assert_eq!(document["entries"][1]["method"], "GET", "rendered uppercase even though RouteKey carries lowercase");
        assert_eq!(document["summary"]["requests"], 2);
        assert_eq!(document["summary"]["passed"], 1);
        assert_eq!(document["summary"]["failed"], 1);
        assert_eq!(document["summary"]["notMocked"], 0);
    }

    #[test]
    fn render_junit_emits_a_failure_element_for_fail_unmatched_and_not_mocked_but_not_pass_or_served() {
        let mut unmatched = entry(2, Verdict::Unmatched);
        unmatched.unmatched_reason = Some("no case matched".to_string());
        let report = report(vec![
            entry(1, Verdict::Pass),
            unmatched,
            entry(3, Verdict::NotMocked(vec!["car".to_string()])),
            entry(4, Verdict::Fail(vec![mismatch()])),
            entry(5, Verdict::Served),
        ]);

        let xml = render_junit(&report);

        assert_eq!(
            xml.matches("<failure ").count(),
            3,
            "exactly one <failure> per FAIL/UNMATCHED/NOT MOCKED entry:\n{xml}"
        );
        assert!(
            xml.contains("tests=\"5\" failures=\"3\""),
            "the <testsuites> totals must agree with the entries:\n{xml}"
        );
        assert!(xml.contains("type=\"UNMATCHED\""));
        assert!(xml.contains("type=\"NOT MOCKED\""));
        assert!(xml.contains("type=\"FAIL\""));
        assert!(xml.contains("required source(s) not mocked: car"));
        assert!(xml.contains("<testsuite name=\"GET /cars/{vin}\""));
    }

    #[test]
    fn render_junit_names_the_scenario_in_the_testcase_name() {
        let mut tagged = entry(1, Verdict::Pass);
        tagged.scenario = Some("pricing-down".to_string());
        tagged.scenario_source = ScenarioSource::ControlPlane;
        let xml = render_junit(&report(vec![tagged]));
        assert!(xml.contains("name=\"#0001 happy path [pricing-down]\""), "{xml}");
        assert!(xml.contains("scenario=pricing-down (control-plane)"), "{xml}");
    }

    #[test]
    fn xml_escape_handles_all_five_significant_characters() {
        assert_eq!(xml_escape("a&b<c>d\"e'f"), "a&amp;b&lt;c&gt;d&quot;e&apos;f");
    }

    #[test]
    fn xml_escape_drops_control_characters_but_keeps_tab_newline_and_carriage_return() {
        assert_eq!(xml_escape("a\u{0}b\u{1b}c\td\ne\rf"), "abc\td\ne\rf");
    }

    #[test]
    fn a_hostile_request_id_cannot_break_out_of_the_junit_attribute_it_is_rendered_into() {
        let mut hostile = entry(1, Verdict::Pass);
        hostile.request_id = "\"/><testcase name=\"injected\"><failure message=\"x".to_string();
        let xml = render_junit(&report(vec![hostile]));

        assert!(
            !xml.contains("<testcase name=\"injected\">"),
            "the raw request id must never appear as markup:\n{xml}"
        );
        assert_eq!(xml.matches("<testcase ").count(), 1, "only the one genuine testcase element:\n{xml}");
        assert_eq!(
            xml.matches("<failure").count(),
            0,
            "a PASS entry must not gain a <failure> from its request id:\n{xml}"
        );
        assert!(xml.contains("requestId=&quot;/&gt;&lt;testcase name=&quot;injected&quot;&gt;&lt;failure message=&quot;x"));
    }

    #[test]
    fn render_text_line_records_the_scenario_and_its_source_on_every_line() {
        let mut tagged = entry(7, Verdict::Pass);
        tagged.scenario = Some("db-down".to_string());
        tagged.scenario_source = ScenarioSource::Flag;
        let line = render_text_line(&tagged);
        assert!(
            line.starts_with("#0007 03:04:05.000 GET /cars/{vin} [scenario: db-down (flag)] case \"happy path\" -> 200 PASS"),
            "{line}"
        );

        let baseline = render_text_line(&entry(8, Verdict::Served));
        assert!(baseline.contains("[scenario: none]"), "{baseline}");
    }

    #[test]
    fn render_text_line_strips_control_characters_and_non_ascii_from_client_supplied_text() {
        let mut hostile = entry(1, Verdict::Unmatched);
        hostile.unmatched_reason = Some("line one\nline two\u{1b}[31m red".to_string());
        let line = render_text_line(&hostile);
        assert_eq!(
            line.lines().count(),
            1,
            "an UNMATCHED line must stay one line no matter what the reason contains: {line:?}"
        );
        assert!(!line.contains('\u{1b}'));
    }

    #[test]
    fn render_text_line_lists_optional_unmocked_sources_as_degraded_without_changing_the_verdict() {
        let mut degraded = entry(1, Verdict::Pass);
        degraded.unmocked = vec![Unmocked {
            name: "pricing".to_string(),
            optional: true,
        }];
        let line = render_text_line(&degraded);
        assert!(line.contains("-> 200 PASS"), "{line}");
        assert!(line.contains("unmocked (optional, degraded): pricing"), "{line}");
    }

    #[test]
    fn render_summary_line_names_every_bucket() {
        let line = render_summary_line(&Summary {
            requests: 6,
            passed: 2,
            failed: 1,
            unmatched: 1,
            not_mocked: 1,
            served: 1,
        });
        assert_eq!(line, "6 request(s): 2 passed, 1 failed, 1 unmatched, 1 not mocked, 1 served");
    }

    #[test]
    fn cap_body_keeps_a_small_body_as_is() {
        let body = json!({ "maker": "Honda" });
        assert_eq!(cap_body(&body), body);
    }

    #[test]
    fn cap_body_truncates_an_oversized_body_on_a_char_boundary_with_a_marker() {
        // Multi-byte characters straddling the cap: `é` is two bytes, so
        // a naive byte slice at BODY_CAP_BYTES would split one.
        let big = "é".repeat(BODY_CAP_BYTES);
        let capped = cap_body(&Value::String(big));
        let Value::String(text) = capped else { panic!("a capped body is a string") };
        assert!(text.contains("...[truncated "), "{}", &text[text.len() - 40..]);
        assert!(text.ends_with(" bytes]"));
        let prefix = &text[..text.find("...[truncated").unwrap()];
        assert!(prefix.len() <= BODY_CAP_BYTES);
    }

    #[test]
    fn write_atomic_leaves_the_content_in_place_and_no_temp_file_behind() {
        let dir = std::env::temp_dir().join(format!(
            "frogs-report-write-atomic-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("report.json");

        write_atomic(&path, "first").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "first");
        write_atomic(&path, "second").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "second", "a second write replaces the first");

        let leftovers: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "no .tmp file may survive a successful rename: {leftovers:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_atomic_into_a_missing_directory_is_an_error_not_a_panic() {
        let path = std::env::temp_dir()
            .join(format!("frogs-report-missing-{}-{}", std::process::id(), 0))
            .join("nope/report.json");
        assert!(write_atomic(&path, "x").is_err());
    }
}
