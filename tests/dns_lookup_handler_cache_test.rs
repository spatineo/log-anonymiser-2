// Rust port of DnsLookupHandlerCacheTest.java
//
// The Java test does not exercise the real DNS resolver.  Instead it wraps a
// controllable mock behind a caching layer and verifies:
//   1. NXDOMAIN is returned as a failure result
//   2. A second lookup for the same address hits the cache (resolver called once)
//   3. Trailing dots on PTR names are stripped before storing / returning
//
// An additional test covers LRU eviction, which was not present in the Java
// version because the Java cache was unbounded by default.
//
// The `CachingDnsLookupHandler` in the production code bundles the real hickory
// resolver and cannot accept a mock.  We therefore mirror the Java approach of
// using a `TestCachingHandler` — a thin caching wrapper around a mock inner
// handler — to test the caching logic in isolation.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

use log_anonymiser::dns::{DnsLookupHandler, DnsLookupResult};
use lru::LruCache;

// ── Counting mock ─────────────────────────────────────────────────────────────

/// Returns a fixed result for every address and counts how many times it was
/// called.  Mirrors the Mockito mock + verify(mock, times(N)) pattern.
struct CountingMock {
    result: DnsLookupResult,
    call_count: Arc<AtomicUsize>,
}

impl CountingMock {
    fn returning_nxdomain() -> Self {
        CountingMock {
            result: DnsLookupResult { success: false, reverse_name: None },
            call_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn returning_name(name: &'static str) -> Self {
        CountingMock {
            result: DnsLookupResult {
                success: true,
                reverse_name: Some(name.to_string()),
            },
            call_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn call_count(&self) -> usize {
        self.call_count.load(Ordering::SeqCst)
    }
}

impl DnsLookupHandler for CountingMock {
    fn lookup(&self, _addr: &str) -> DnsLookupResult {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        self.result.clone()
    }
}

// ── Per-address mock ──────────────────────────────────────────────────────────

/// Returns different results per address.  Used for the LRU eviction test.
struct PerAddressMock {
    map: HashMap<&'static str, DnsLookupResult>,
    call_count: AtomicUsize,
}

impl PerAddressMock {
    fn new() -> Self {
        PerAddressMock { map: HashMap::new(), call_count: AtomicUsize::new(0) }
    }

    fn add(&mut self, addr: &'static str, name: &'static str) {
        self.map.insert(addr, DnsLookupResult {
            success: true,
            reverse_name: Some(name.to_string()),
        });
    }

    fn call_count(&self) -> usize {
        self.call_count.load(Ordering::SeqCst)
    }
}

impl DnsLookupHandler for PerAddressMock {
    fn lookup(&self, addr: &str) -> DnsLookupResult {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        self.map
            .get(addr)
            .cloned()
            .unwrap_or(DnsLookupResult { success: false, reverse_name: None })
    }
}

// ── Caching wrapper under test ────────────────────────────────────────────────

/// A caching wrapper around any `DnsLookupHandler`.  Mirrors the Java
/// `TestCachingHandler` from `DnsLookupHandlerCacheTest`.
///
/// This is the structure whose behaviour the tests verify:
///   - cache hit → inner handler not called again
///   - PTR trailing dot stripped before caching
///   - LRU eviction when the cache is full
struct TestCachingHandler<H: DnsLookupHandler> {
    inner: H,
    cache: Mutex<LruCache<String, DnsLookupResult>>,
}

impl<H: DnsLookupHandler> TestCachingHandler<H> {
    fn new(inner: H, capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity).expect("capacity must be non-zero");
        TestCachingHandler { inner, cache: Mutex::new(LruCache::new(cap)) }
    }
}

impl<H: DnsLookupHandler> DnsLookupHandler for TestCachingHandler<H> {
    fn lookup(&self, addr: &str) -> DnsLookupResult {
        // Cache check
        {
            let mut cache = self.cache.lock().unwrap();
            if let Some(cached) = cache.get(addr) {
                return cached.clone();
            }
        }

        // Cache miss — resolve and strip trailing dot from PTR name
        let mut result = self.inner.lookup(addr);
        if let Some(ref name) = result.reverse_name.clone() {
            result.reverse_name = Some(name.trim_end_matches('.').to_string());
        }

        // Store; if another thread raced us, keep theirs
        let mut cache = self.cache.lock().unwrap();
        if !cache.contains(addr) {
            cache.put(addr.to_string(), result.clone());
        }
        result
    }
}

// ── Helper ────────────────────────────────────────────────────────────────────

const DEFAULT_CAPACITY: usize = 100_000;

// ── Tests ─────────────────────────────────────────────────────────────────────

/// NXDOMAIN (DNS lookup failure) must be returned as an unsuccessful result.
/// Mirrors testNxdomainReturnsNegativeResult().
#[test]
fn test_nxdomain_returns_failure() {
    let mock = CountingMock::returning_nxdomain();
    let handler = TestCachingHandler::new(mock, DEFAULT_CAPACITY);

    let result = handler.lookup("10.10.10.1");

    assert!(!result.success);
    assert_eq!(handler.inner.call_count(), 1);
}

/// A second lookup for the same address must return the cached result without
/// calling the inner resolver again.
/// Mirrors testCachingWorks().
#[test]
fn test_caching_works() {
    let mock = CountingMock::returning_nxdomain();
    let handler = TestCachingHandler::new(mock, DEFAULT_CAPACITY);

    let result1 = handler.lookup("10.10.10.1");
    let result2 = handler.lookup("10.10.10.1");

    assert!(!result1.success);
    assert!(!result2.success);
    // Inner resolver called exactly once; second lookup came from cache
    assert_eq!(handler.inner.call_count(), 1);
}

/// A PTR record name ending with a trailing dot (as returned by DNS) must have
/// the dot stripped before it is stored or returned.
/// Mirrors testReverseNameFromPTRRRecordIsReturnedCorrectly().
#[test]
fn test_reverse_name_trailing_dot_removed() {
    let mock = CountingMock::returning_name("host.name.com.");
    let handler = TestCachingHandler::new(mock, DEFAULT_CAPACITY);

    let result = handler.lookup("10.10.10.1");

    assert!(result.success);
    assert_eq!(result.reverse_name.as_deref(), Some("host.name.com"));
}

/// The cached result (with dot already stripped) is also returned without a
/// trailing dot on subsequent lookups.
#[test]
fn test_cached_reverse_name_has_no_trailing_dot() {
    let mock = CountingMock::returning_name("host.name.com.");
    let handler = TestCachingHandler::new(mock, DEFAULT_CAPACITY);

    let _ = handler.lookup("10.10.10.1"); // populate cache
    let result = handler.lookup("10.10.10.1"); // cache hit

    assert_eq!(result.reverse_name.as_deref(), Some("host.name.com"));
    // Inner called only once despite two lookups
    assert_eq!(handler.inner.call_count(), 1);
}

/// When the LRU cache is full, inserting a new entry evicts the
/// least-recently-used one.  A subsequent lookup for the evicted address
/// calls the inner resolver again.
#[test]
fn test_lru_eviction() {
    let mut mock = PerAddressMock::new();
    mock.add("10.0.0.1", "host-a.example.com");
    mock.add("10.0.0.2", "host-b.example.com");
    mock.add("10.0.0.3", "host-c.example.com");

    // Cache holds only 2 entries
    let handler = TestCachingHandler::new(mock, 2);

    // Fill cache: 10.0.0.1 is LRU, 10.0.0.2 is MRU
    handler.lookup("10.0.0.1");
    handler.lookup("10.0.0.2");
    assert_eq!(handler.inner.call_count(), 2);

    // Insert 10.0.0.3 → 10.0.0.1 (LRU) is evicted
    handler.lookup("10.0.0.3");
    assert_eq!(handler.inner.call_count(), 3);

    // 10.0.0.2 and 10.0.0.3 are still cached — inner not called again
    handler.lookup("10.0.0.2");
    handler.lookup("10.0.0.3");
    assert_eq!(handler.inner.call_count(), 3);

    // 10.0.0.1 was evicted — inner must be called again
    let result = handler.lookup("10.0.0.1");
    assert_eq!(handler.inner.call_count(), 4);
    assert_eq!(result.reverse_name.as_deref(), Some("host-a.example.com"));
}

/// Different addresses are cached independently.
#[test]
fn test_different_addresses_cached_independently() {
    let mock = CountingMock::returning_nxdomain();
    let handler = TestCachingHandler::new(mock, DEFAULT_CAPACITY);

    handler.lookup("10.0.0.1");
    handler.lookup("10.0.0.2");
    handler.lookup("10.0.0.1"); // cache hit
    handler.lookup("10.0.0.2"); // cache hit

    // Each unique address resolved exactly once
    assert_eq!(handler.inner.call_count(), 2);
}
