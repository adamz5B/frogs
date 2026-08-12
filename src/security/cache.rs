use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A small TTL cache for verifier results, one shared instance per running
/// server (not per route) so two endpoints protected by the *same* scheme
/// share a cached result for the same credential instead of each paying
/// their own round-trip. Keyed by whatever the caller builds the key as —
/// see `verify::cache_key`, which folds in both the scheme name and the
/// exact credential value(s) bound, so caching one caller's result can
/// never leak into another caller's.
///
/// Only successful checks (valid *or* invalidated by `validIf`) are ever
/// cached — a verifier's own datasource failing is never cached, since
/// caching a transient DB/HTTP outage would keep rejecting every caller,
/// valid credential or not, until the entry expired.
#[derive(Debug, Default)]
pub struct VerifierCache {
    entries: Mutex<HashMap<String, (bool, Instant)>>,
}

impl VerifierCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// `None` if there's no unexpired entry for this key — either it was
    /// never cached, or its TTL already passed. An expired entry is left
    /// in place rather than evicted here; `set` overwrites it on the next
    /// check, so a TTL cache doesn't need eager cleanup to stay correct.
    pub fn get(&self, key: &str) -> Option<bool> {
        let entries = self.entries.lock().unwrap();
        entries
            .get(key)
            .and_then(|(valid, expires_at)| if Instant::now() < *expires_at { Some(*valid) } else { None })
    }

    pub fn set(&self, key: String, valid: bool, ttl: Duration) {
        let mut entries = self.entries.lock().unwrap();
        entries.insert(key, (valid, Instant::now() + ttl));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unset_key_misses() {
        let cache = VerifierCache::new();
        assert_eq!(cache.get("apiKeyAuth\u{1}key=good-key"), None);
    }

    #[test]
    fn a_set_key_hits_before_its_ttl_expires() {
        let cache = VerifierCache::new();
        cache.set("k".to_string(), true, Duration::from_secs(30));
        assert_eq!(cache.get("k"), Some(true));
    }

    #[test]
    fn caches_a_negative_result_too() {
        let cache = VerifierCache::new();
        cache.set("k".to_string(), false, Duration::from_secs(30));
        assert_eq!(cache.get("k"), Some(false));
    }

    #[test]
    fn an_expired_entry_misses() {
        let cache = VerifierCache::new();
        // A TTL of zero is already expired by the time `get` checks
        // `Instant::now()`, without needing a real sleep in the test.
        cache.set("k".to_string(), true, Duration::from_secs(0));
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(cache.get("k"), None);
    }

    #[test]
    fn setting_again_overwrites_the_previous_entry() {
        let cache = VerifierCache::new();
        cache.set("k".to_string(), false, Duration::from_secs(30));
        cache.set("k".to_string(), true, Duration::from_secs(30));
        assert_eq!(cache.get("k"), Some(true));
    }
}
