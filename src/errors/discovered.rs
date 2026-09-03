use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One auto-discovered, previously-unclassified error code. Written only in
/// `debugMode`, and only ever read back by the freeze tool or the
/// request-time fallback lookup — never merged into the canonical registry
/// automatically.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredEntry {
    #[serde(rename = "_discovered")]
    pub discovered: bool,
    #[serde(rename = "httpStatus")]
    pub http_status: u16,
    #[serde(rename = "exposeDetail")]
    pub expose_detail: bool,
    pub occurrences: u64,
    #[serde(rename = "firstSeen")]
    pub first_seen: DateTime<Utc>,
    #[serde(rename = "lastSeen")]
    pub last_seen: DateTime<Utc>,
    #[serde(rename = "sampleMessage")]
    pub sample_message: String,
}

/// The auto-managed `config/errors.discovered.json` scratch file — deliberately
/// outside `config/errors/` so it's never accidentally picked up as canonical.
#[derive(Debug, Default)]
pub struct DiscoveredErrors {
    entries: HashMap<String, DiscoveredEntry>,
}

impl DiscoveredErrors {
    /// Loads the scratch file, or starts empty if it doesn't exist yet — this
    /// file only comes into existence once the first unlisted error occurs
    /// under `debugMode`, so a fresh project having none yet is the normal case.
    pub fn load(path: &Path) -> io::Result<Self> {
        match fs::read_to_string(path) {
            Ok(contents) => {
                // A hand-corrupted scratch file shouldn't block startup —
                // it's auto-managed, so starting fresh is the safe recovery.
                let entries = serde_json::from_str(&contents).unwrap_or_default();
                Ok(Self { entries })
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(err) => Err(err),
        }
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        let json = serde_json::to_string_pretty(&self.entries).expect("discovered entries always serialize");
        fs::write(path, json)
    }

    /// Not called anywhere in the live request path yet — the design doc's
    /// 3-tier lookup (canonical registry -> `errors.discovered.json` ->
    /// `unexpected.error`) only has tiers 1 and 3 wired up in
    /// `endpoint::error_envelope` today, so a hand-edited discovered entry
    /// (before `errors freeze` promotes it) currently has no effect on a
    /// live response. Kept, tested, and documented rather than deleted:
    /// this is a real gap to close deliberately, not dead code to discard.
    #[allow(dead_code)]
    pub fn lookup(&self, key: &str) -> Option<&DiscoveredEntry> {
        self.entries.get(key)
    }

    /// Every discovered entry, keyed by its code — what `errors freeze`
    /// walks to decide what to promote into `config/errors/`.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &DiscoveredEntry)> {
        self.entries.iter()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Records one occurrence of an unlisted error under `key` (by
    /// convention `<datasourceType>.unknown:<ExceptionTypeName>`), updating
    /// an existing entry's `occurrences`/`lastSeen` in place rather than
    /// duplicating it.
    pub fn record(&mut self, key: &str, http_status: u16, expose_detail: bool, sample_message: &str) {
        let now = Utc::now();
        self.entries
            .entry(key.to_string())
            .and_modify(|entry| {
                entry.occurrences += 1;
                entry.last_seen = now;
            })
            .or_insert(DiscoveredEntry {
                discovered: true,
                http_status,
                expose_detail,
                occurrences: 1,
                first_seen: now,
                last_seen: now,
                sample_message: sample_message.to_string(),
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempfile() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "frogs-discovered-test-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ))
    }

    #[test]
    fn missing_file_starts_empty() {
        let path = tempfile();
        let discovered = DiscoveredErrors::load(&path).unwrap();
        assert!(discovered.is_empty());
    }

    #[test]
    fn a_hand_corrupted_file_starts_empty_rather_than_failing_to_load() {
        // Per this struct's own doc comment: an auto-managed scratch file
        // that's been hand-corrupted or truncated shouldn't block startup —
        // starting fresh is the safe recovery, same "collapse to nothing to
        // act on" posture `server::pidfile::read` has for its own run.json.
        let path = tempfile();
        fs::write(&path, "{ not valid json").unwrap();

        let discovered = DiscoveredErrors::load(&path).unwrap();
        assert!(discovered.is_empty(), "a corrupted scratch file must load as empty, not error out");

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn record_then_reload_round_trips() {
        let path = tempfile();
        let mut discovered = DiscoveredErrors::load(&path).unwrap();
        discovered.record(
            "datasource.sql.unknown:PoolTimedOut",
            500,
            false,
            "pool timed out while waiting for an open connection",
        );
        discovered.save(&path).unwrap();

        let reloaded = DiscoveredErrors::load(&path).unwrap();
        let entry = reloaded.lookup("datasource.sql.unknown:PoolTimedOut").expect("recorded entry should round-trip");
        assert_eq!(entry.occurrences, 1);
        assert!(entry.discovered);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn repeated_occurrences_update_in_place() {
        let path = tempfile();
        let mut discovered = DiscoveredErrors::load(&path).unwrap();
        discovered.record("plugin.hmac-verifier.unknown:Timeout", 500, false, "first");
        discovered.record("plugin.hmac-verifier.unknown:Timeout", 500, false, "second");

        assert_eq!(discovered.len(), 1);
        let entry = discovered.lookup("plugin.hmac-verifier.unknown:Timeout").unwrap();
        assert_eq!(entry.occurrences, 2);
    }
}
