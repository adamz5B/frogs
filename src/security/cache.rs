use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::DEFAULT_VERIFIER_CACHE_MAX_ENTRIES;

/// An expiry scan is O(entries) under the one mutex every `get` needs, so once the map is
/// full of live entries an unauthenticated flood must not be able to trigger one per request.
const PURGE_MIN_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug)]
struct Entry {
    valid: bool,
    /// Only ever `Some` when `valid`: a rejected credential never has granted scopes.
    scopes: Option<Arc<[String]>>,
    expires_at: Instant,
}

#[derive(Debug, Default)]
struct Inner {
    map: HashMap<String, Entry>,
    /// The earliest `expires_at` in `map` (`None` when empty): nothing can be purged before it.
    next_purge_at: Option<Instant>,
    last_purge_at: Option<Instant>,
    #[cfg(test)]
    purge_scans: u64,
}

/// A small, size-bounded TTL cache for verifier results, one shared instance per running
/// server (not per route) so two endpoints protected by the *same* scheme
/// share a cached result for the same credential instead of each paying
/// their own round-trip. Keyed by whatever the caller builds the key as —
/// see `verify::cache_key` (a `v2:`-prefixed SHA-256 over a length-prefixed
/// encoding of the scheme name, a certificate-dependent verifier's client
/// certificate fingerprint, and the exact credential value(s) bound), so
/// caching one caller's result can never leak into another caller's.
///
/// Only successful checks (valid *or* invalidated by `validIf`) are ever
/// cached — a verifier's own datasource failing is never cached, since
/// caching a transient DB/HTTP outage would keep rejecting every caller,
/// valid credential or not, until the entry expired.
///
/// The bound is per entry, not per byte: the top quarter of `cap` is reserved for valid
/// results, so a flood of bad credentials can never stop a good one being cached, and a full
/// map skips the insert rather than evicting (the request is still answered correctly).
#[derive(Debug)]
pub struct VerifierCache {
    entries: Mutex<Inner>,
    cap: usize,
    high_water: usize,
    skip_warned: AtomicBool,
}

impl Default for VerifierCache {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_VERIFIER_CACHE_MAX_ENTRIES as usize)
    }
}

impl VerifierCache {
    #[cfg(test)]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(cap: usize) -> Self {
        VerifierCache {
            entries: Mutex::new(Inner::default()),
            cap,
            high_water: cap * 3 / 4,
            skip_warned: AtomicBool::new(false),
        }
    }

    /// `None` if there's no unexpired entry for this key — either it was
    /// never cached, or its TTL already passed. An expired entry is left
    /// in place rather than evicted here; `set` overwrites it on the next
    /// check, so a TTL cache doesn't need eager cleanup to stay correct.
    pub fn get(&self, key: &str) -> Option<(bool, Option<Arc<[String]>>)> {
        let Ok(inner) = self.entries.lock() else {
            tracing::error!(
                mutex = "security::VerifierCache entries (get)",
                "recovered a poisoned mutex by treating it as a cache miss — forces full re-verification rather than risking a stale cached result"
            );
            return None;
        };
        inner.map.get(key).and_then(|entry| {
            if Instant::now() < entry.expires_at {
                Some((entry.valid, entry.scopes.clone()))
            } else {
                None
            }
        })
    }

    pub fn set(&self, key: String, valid: bool, scopes: Option<Arc<[String]>>, ttl: Duration) {
        let skipped = {
            let Ok(mut inner) = self.entries.lock() else {
                tracing::error!(
                    mutex = "security::VerifierCache entries (set)",
                    "recovered a poisoned mutex by not caching this result — every later check re-verifies for real rather than reading a possibly-inconsistent map"
                );
                return;
            };
            let now = Instant::now();
            let scopes = if valid { scopes } else { None };
            let mut skipped = false;
            if !inner.map.contains_key(&key) {
                if inner.map.len() >= self.high_water {
                    Self::purge_if_due(&mut inner, now);
                }
                let len = inner.map.len();
                skipped = if valid { len >= self.cap } else { len >= self.high_water };
            }
            if !skipped {
                let expires_at = now + ttl;
                inner.next_purge_at = Some(inner.next_purge_at.map_or(expires_at, |earliest| earliest.min(expires_at)));
                inner.map.insert(key, Entry { valid, scopes, expires_at });
            }
            skipped
        };
        if skipped && !self.skip_warned.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                "the verifier cache is nearly full, so some verifier results are not being cached (more verifier calls, nothing is answered wrongly) — \
                 raise verifierCacheMaxEntries in config/server.json if this is expected load"
            );
        }
    }

    fn purge_if_due(inner: &mut Inner, now: Instant) {
        let due = inner.next_purge_at.is_some_and(|at| now >= at) && inner.last_purge_at.is_none_or(|last| now.duration_since(last) >= PURGE_MIN_INTERVAL);
        if !due {
            return;
        }
        inner.map.retain(|_, entry| now < entry.expires_at);
        inner.next_purge_at = inner.map.values().map(|entry| entry.expires_at).min();
        inner.last_purge_at = Some(now);
        #[cfg(test)]
        {
            inner.purge_scans += 1;
        }
    }

    /// How many expiry scans have run, so a test can prove a flood of inserts does not rescan per call.
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn purge_scan_count(&self) -> u64 {
        self.entries.lock().map(|inner| inner.purge_scans).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unset_key_misses() {
        let cache = VerifierCache::new();
        assert!(cache.get("apiKeyAuth\u{1}key=good-key").is_none());
    }

    #[test]
    fn a_set_key_hits_before_its_ttl_expires() {
        let cache = VerifierCache::new();
        cache.set("k".to_string(), true, None, Duration::from_secs(30));
        assert_eq!(cache.get("k").map(|(valid, _)| valid), Some(true));
    }

    #[test]
    fn caches_a_negative_result_too() {
        let cache = VerifierCache::new();
        cache.set("k".to_string(), false, None, Duration::from_secs(30));
        assert_eq!(cache.get("k").map(|(valid, _)| valid), Some(false));
    }

    #[test]
    fn an_expired_entry_misses() {
        let cache = VerifierCache::new();
        // A TTL of zero is already expired by the time `get` checks
        // `Instant::now()`, without needing a real sleep in the test.
        cache.set("k".to_string(), true, None, Duration::from_secs(0));
        std::thread::sleep(Duration::from_millis(5));
        assert!(cache.get("k").is_none());
    }

    #[test]
    fn setting_again_overwrites_the_previous_entry() {
        let cache = VerifierCache::new();
        cache.set("k".to_string(), false, None, Duration::from_secs(30));
        cache.set("k".to_string(), true, None, Duration::from_secs(30));
        assert_eq!(cache.get("k").map(|(valid, _)| valid), Some(true));
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
        cache.set("k".to_string(), true, None, Duration::from_secs(30));

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
        assert!(
            cache.get("k").is_none(),
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
        cache.set("k".to_string(), true, None, Duration::from_secs(30));
    }
}
