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
        let Ok(entries) = self.entries.lock() else {
            tracing::error!(
                mutex = "security::VerifierCache entries (get)",
                "recovered a poisoned mutex by treating it as a cache miss — forces full re-verification rather than risking a stale cached result"
            );
            return None;
        };
        entries
            .get(key)
            .and_then(|(valid, expires_at)| if Instant::now() < *expires_at { Some(*valid) } else { None })
    }

    pub fn set(&self, key: String, valid: bool, ttl: Duration) {
        let Ok(mut entries) = self.entries.lock() else {
            tracing::error!(
                mutex = "security::VerifierCache entries (set)",
                "recovered a poisoned mutex by not caching this result — every later check re-verifies for real rather than reading a possibly-inconsistent map"
            );
            return;
        };
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

    /// Poisons `entries` (a previous caller panicked while holding the
    /// lock), then confirms `get` fails closed — `None`, forcing a full
    /// re-verification — rather than panicking itself or ever serving a
    /// possibly-stale cached `valid`. This is the ONE poisoning site in the
    /// codebase that deliberately does NOT use `into_inner()`, unlike every
    /// other site this fix touches.
    #[test]
    fn a_poisoned_entries_mutex_makes_get_return_none_instead_of_panicking() {
        let cache = VerifierCache::new();
        cache.set("k".to_string(), true, Duration::from_secs(30));

        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        std::thread::scope(|scope| {
            let handle = scope.spawn(|| {
                let _guard = cache.entries.lock().unwrap();
                panic!("deliberately poisoning the mutex for this test");
            });
            let _ = handle.join();
        });
        std::panic::set_hook(previous_hook);

        assert!(cache.entries.lock().is_err(), "sanity check: the mutex really is poisoned at this point");
        assert_eq!(
            cache.get("k"),
            None,
            "a poisoned cache must fail closed — forcing full re-verification rather than risking a stale cached result"
        );
    }

    /// Same poisoning setup, but exercising `set` — must degrade to "don't
    /// cache this result" (return without writing) rather than propagating
    /// the poison as a panic.
    #[test]
    fn a_poisoned_entries_mutex_makes_set_a_no_op_instead_of_panicking() {
        let cache = VerifierCache::new();

        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        std::thread::scope(|scope| {
            let handle = scope.spawn(|| {
                let _guard = cache.entries.lock().unwrap();
                panic!("deliberately poisoning the mutex for this test");
            });
            let _ = handle.join();
        });
        std::panic::set_hook(previous_hook);

        // The only real assertion here is that this doesn't panic — a
        // permanently-poisoned mutex means `get` would return `None`
        // regardless of whether `set` actually wrote anything.
        cache.set("k".to_string(), true, Duration::from_secs(30));
    }
}
