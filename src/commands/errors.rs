use std::collections::HashMap;
use std::io;
use std::path::Path;

use crate::config::Config;
use crate::errors::ErrorDefinition;
use crate::project::{api_base, require_project_root};

/// Batches every entry in `config/errors.discovered.json` into a new,
/// dated file under `config/errors/`, then purges the scratch file — see
/// the design doc's "Freezing discovered errors into the registry" section.
/// A manual, deliberate action; the server itself never runs this, only
/// nudges toward it via the startup warning (see `commands::run`).
pub fn freeze(cwd: &Path) -> io::Result<()> {
    let root = require_project_root(cwd);
    let api_dir = api_base(&root);
    let config = Config::load_or_exit(&api_dir);

    if config.discovered_errors.is_empty() {
        println!("config/errors.discovered.json is empty — nothing to freeze");
        return Ok(());
    }

    let mut to_write: HashMap<String, ErrorDefinition> = HashMap::new();
    let mut frozen: Vec<String> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    for (code, entry) in config.discovered_errors.iter() {
        // Already hand-classified since it was first discovered — freezing
        // it again would conflict with the existing definition the next
        // time the registry loads, so skip it rather than write a
        // duplicate the server would refuse to start with.
        if config.errors.get(code).is_some() {
            skipped.push(code.clone());
            continue;
        }
        to_write.insert(
            code.clone(),
            ErrorDefinition {
                http_status: entry.http_status,
                expose_detail: entry.expose_detail,
                include_exception_name: false,
            },
        );
        frozen.push(code.clone());
    }
    frozen.sort();
    skipped.sort();

    let errors_dir = api_dir.join("config/errors");
    if !to_write.is_empty() {
        std::fs::create_dir_all(&errors_dir)?;
        let output_path = errors_dir.join(format!("discovered-{}.json", chrono::Utc::now().format("%Y-%m-%d")));

        // Running `freeze` twice in one day lands on the same filename —
        // merge into it rather than clobbering an earlier batch from
        // earlier today. Safe to just extend: any code already in this
        // file is also in the registry `config.errors` was loaded from, so
        // it would already have been routed into `skipped` above.
        let mut existing: HashMap<String, ErrorDefinition> = match std::fs::read_to_string(&output_path) {
            Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
            Err(err) if err.kind() == io::ErrorKind::NotFound => HashMap::new(),
            Err(err) => return Err(err),
        };
        existing.extend(to_write);

        let json = serde_json::to_string_pretty(&existing).expect("error definitions always serialize");
        std::fs::write(&output_path, json)?;
        println!("wrote {} entries to {}", frozen.len(), output_path.display());
    }

    if !skipped.is_empty() {
        println!(
            "skipped {} entries already classified in config/errors/: {}",
            skipped.len(),
            skipped.join(", ")
        );
    }

    let discovered_path = api_dir.join("config/errors.discovered.json");
    crate::errors::DiscoveredErrors::default().save(&discovered_path)?;
    println!("purged config/errors.discovered.json");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    /// Same shape `commands::stop`'s tests use: a project root
    /// `require_project_root` accepts without exiting the process, with
    /// `api/` scaffolded underneath since that's where `errors freeze`
    /// actually reads/writes.
    fn temp_project() -> PathBuf {
        // A per-process atomic counter alongside PID+nanosecond timestamp —
        // the timestamp alone has occasionally collided under heavy parallel
        // `cargo test` load on Windows (coarser effective clock resolution
        // than raw nanoseconds suggest); see the same fix in
        // `commands::generate`'s and `config::mod`'s own test helpers.
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "frogs-errors-freeze-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(root.join("api/config")).unwrap();
        fs::write(root.join("openapi.yaml"), "openapi: 3.0.3\ninfo: { title: t, version: '1' }\npaths: {}\n").unwrap();
        root
    }

    fn discovered_entry_json(http_status: u16, expose_detail: bool) -> String {
        format!(
            r#"{{
              "_discovered": true,
              "httpStatus": {http_status},
              "exposeDetail": {expose_detail},
              "occurrences": 3,
              "firstSeen": "2026-07-16T10:03:00Z",
              "lastSeen": "2026-07-16T10:41:00Z",
              "sampleMessage": "pool timed out while waiting for an open connection"
            }}"#
        )
    }

    fn dated_output_path(root: &Path) -> PathBuf {
        root.join("api/config/errors")
            .join(format!("discovered-{}.json", chrono::Utc::now().format("%Y-%m-%d")))
    }

    #[test]
    fn nothing_to_freeze_when_the_discovered_file_does_not_exist() {
        let root = temp_project();
        assert!(freeze(&root).is_ok());
        assert!(!root.join("api/config/errors").exists(), "no output directory should be created");
    }

    #[test]
    fn freezes_a_discovered_entry_into_a_new_dated_file() {
        let root = temp_project();
        fs::write(
            root.join("api/config/errors.discovered.json"),
            format!(r#"{{ "datasource.sql.unknown:PoolTimedOut": {} }}"#, discovered_entry_json(500, false)),
        )
        .unwrap();

        freeze(&root).unwrap();

        let output = fs::read_to_string(dated_output_path(&root)).expect("dated file should be written");
        let written: HashMap<String, ErrorDefinition> = serde_json::from_str(&output).unwrap();
        assert_eq!(written.len(), 1);
        let def = &written["datasource.sql.unknown:PoolTimedOut"];
        assert_eq!(def.http_status, 500);
        assert!(!def.expose_detail);

        let purged = fs::read_to_string(root.join("api/config/errors.discovered.json")).unwrap();
        let purged: HashMap<String, serde_json::Value> = serde_json::from_str(&purged).unwrap();
        assert!(purged.is_empty(), "the scratch file should be emptied after freezing");
    }

    #[test]
    fn skips_an_entry_already_classified_in_config_errors() {
        let root = temp_project();
        fs::create_dir_all(root.join("api/config/errors")).unwrap();
        fs::write(
            root.join("api/config/errors/core.json"),
            r#"{ "auth.invalid_credentials": { "httpStatus": 401, "exposeDetail": true } }"#,
        )
        .unwrap();
        fs::write(
            root.join("api/config/errors.discovered.json"),
            format!(
                r#"{{
                  "auth.invalid_credentials": {},
                  "datasource.http.unknown:Timeout": {}
                }}"#,
                discovered_entry_json(403, true),
                discovered_entry_json(502, false)
            ),
        )
        .unwrap();

        freeze(&root).unwrap();

        let output = fs::read_to_string(dated_output_path(&root)).unwrap();
        let written: HashMap<String, ErrorDefinition> = serde_json::from_str(&output).unwrap();
        assert_eq!(written.len(), 1, "the already-classified code must not be written into the new file");
        assert!(written.contains_key("datasource.http.unknown:Timeout"));
        assert!(!written.contains_key("auth.invalid_credentials"));

        // Already-classified entries are purged from the scratch file too —
        // they've served their purpose (nudging toward hand-classification,
        // which already happened here).
        let purged = fs::read_to_string(root.join("api/config/errors.discovered.json")).unwrap();
        let purged: HashMap<String, serde_json::Value> = serde_json::from_str(&purged).unwrap();
        assert!(purged.is_empty());
    }

    /// The one case `skips_an_entry_already_classified_in_config_errors`
    /// doesn't cover: *every* discovered entry is already classified, so
    /// there's nothing left to actually write — `to_write` stays empty.
    /// Real, previously-unverified question: does `freeze` correctly skip
    /// creating `config/errors/discovered-<date>.json` at all in that case
    /// (rather than writing an empty file), while still purging the
    /// scratch file and reporting what it skipped?
    #[test]
    fn nothing_new_to_write_when_every_discovered_entry_is_already_classified() {
        let root = temp_project();
        fs::create_dir_all(root.join("api/config/errors")).unwrap();
        fs::write(
            root.join("api/config/errors/core.json"),
            r#"{ "auth.invalid_credentials": { "httpStatus": 401, "exposeDetail": true } }"#,
        )
        .unwrap();
        fs::write(
            root.join("api/config/errors.discovered.json"),
            format!(r#"{{ "auth.invalid_credentials": {} }}"#, discovered_entry_json(403, true)),
        )
        .unwrap();

        assert!(freeze(&root).is_ok());

        assert!(
            !dated_output_path(&root).exists(),
            "nothing new to freeze means no dated file should be written at all"
        );

        let purged = fs::read_to_string(root.join("api/config/errors.discovered.json")).unwrap();
        let purged: HashMap<String, serde_json::Value> = serde_json::from_str(&purged).unwrap();
        assert!(purged.is_empty(), "the scratch file should still be purged even when nothing was frozen");
    }

    #[test]
    fn a_second_freeze_the_same_day_merges_rather_than_clobbers() {
        let root = temp_project();
        fs::create_dir_all(root.join("api/config/errors")).unwrap();
        fs::write(
            dated_output_path(&root),
            r#"{ "datasource.sql.unknown:PoolTimedOut": { "httpStatus": 500, "exposeDetail": false } }"#,
        )
        .unwrap();
        fs::write(
            root.join("api/config/errors.discovered.json"),
            format!(r#"{{ "datasource.http.unknown:Timeout": {} }}"#, discovered_entry_json(502, false)),
        )
        .unwrap();

        freeze(&root).unwrap();

        let output = fs::read_to_string(dated_output_path(&root)).unwrap();
        let written: HashMap<String, ErrorDefinition> = serde_json::from_str(&output).unwrap();
        assert_eq!(written.len(), 2, "the earlier same-day entry must survive alongside the new one");
        assert!(written.contains_key("datasource.sql.unknown:PoolTimedOut"));
        assert!(written.contains_key("datasource.http.unknown:Timeout"));
    }
}
