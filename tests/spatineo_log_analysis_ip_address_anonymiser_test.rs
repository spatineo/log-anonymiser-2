// Rust port of SpatineoLogAnalysisIpAddressAnonymiserTest.java
//
// Tests SpatineoAnonymiser::process_address_string() in isolation, using a
// controllable mock DnsLookupHandler rather than real DNS — mirroring the
// Mockito-based approach in the Java test.

use std::collections::HashMap;

use log_anonymiser::anonymiser::{IpAddressAnonymiser, SpatineoAnonymiser};
use log_anonymiser::dns::{DnsLookupHandler, DnsLookupResult};

// ── Mock DNS handler ──────────────────────────────────────────────────────────

/// Returns a fixed result for a specific address; falls back to failure for
/// anything not registered.  Mirrors `mock(DnsLookupHandler.class)` +
/// `when(mock.lookup(addr)).thenReturn(result)`.
struct MockDns {
    map: HashMap<&'static str, DnsLookupResult>,
}

impl MockDns {
    fn new() -> Self {
        MockDns { map: HashMap::new() }
    }

    fn when(&mut self, addr: &'static str, success: bool, name: Option<&'static str>) -> &mut Self {
        self.map.insert(addr, DnsLookupResult {
            success,
            reverse_name: name.map(|s| s.to_string()),
        });
        self
    }
}

impl DnsLookupHandler for MockDns {
    fn lookup(&self, addr: &str) -> DnsLookupResult {
        self.map
            .get(addr)
            .cloned()
            .unwrap_or(DnsLookupResult { success: false, reverse_name: None })
    }
}

// ── Helper: build an anonymiser with 8/80 bit defaults ───────────────────────

fn anonymiser(dns: MockDns, allow_private: bool) -> SpatineoAnonymiser {
    SpatineoAnonymiser::new(Box::new(dns), 8, 80, allow_private)
}

fn default_anonymiser(dns: MockDns) -> SpatineoAnonymiser {
    anonymiser(dns, false)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn test_basic_anonymisation_dns_lookup_success() {
    let mut dns = MockDns::new();
    dns.when("10.10.10.10", true, Some("hello.world.com"));
    let anon = default_anonymiser(dns);

    assert_eq!(
        anon.process_address_string("10.10.10.10"),
        "{!1{10.10.10.0/24,world.com}}"
    );
}

#[test]
fn test_basic_anonymisation_no_reverse_dns() {
    let mut dns = MockDns::new();
    dns.when("10.10.10.10", false, None);
    let anon = default_anonymiser(dns);

    assert_eq!(
        anon.process_address_string("10.10.10.10"),
        "{!1{10.10.10.0/24}}"
    );
}

#[test]
fn test_ipv4_address_with_port() {
    let mut dns = MockDns::new();
    dns.when("10.10.10.10", false, None);
    let anon = default_anonymiser(dns);

    // Port must appear after the closing braces
    assert_eq!(
        anon.process_address_string("10.10.10.10:4123"),
        "{!1{10.10.10.0/24}}:4123"
    );
}

#[test]
fn test_basic_anonymisation_dns_gives_weird_name() {
    // The PTR response is an in-addr.arpa delegation name — not a valid domain
    let mut dns = MockDns::new();
    dns.when("10.10.10.10", true, Some("124.0/25.8.118.188.in-addr.arpa"));
    let anon = default_anonymiser(dns);

    // Invalid domain name → PSL lookup fails → no domain in output
    assert_eq!(
        anon.process_address_string("10.10.10.10"),
        "{!1{10.10.10.0/24}}"
    );
}

#[test]
fn test_basic_anonymisation_dns_gives_local_address_local_names_are_disabled() {
    let mut dns = MockDns::new();
    dns.when("10.10.10.10", true, Some("foo.hello.local"));
    // allow_private = false (default)
    let anon = anonymiser(dns, false);

    // ".local" is not in the public suffix list → private → not allowed → no domain
    assert_eq!(
        anon.process_address_string("10.10.10.10"),
        "{!1{10.10.10.0/24}}"
    );
}

#[test]
fn test_basic_anonymisation_dns_gives_local_address_local_names_are_enabled() {
    let mut dns = MockDns::new();
    dns.when("10.10.10.10", true, Some("foo.hello.local"));
    // allow_private = true
    let anon = anonymiser(dns, true);

    // Private names allowed → full reverse name included
    assert_eq!(
        anon.process_address_string("10.10.10.10"),
        "{!1{10.10.10.0/24,foo.hello.local}}"
    );
}

#[test]
fn test_basic_anonymisation_amazonaws_dot_com() {
    // compute-1.amazonaws.com is in the PSL, so the full EC2 hostname is itself
    // the top private domain (one label above the public suffix).
    let mut dns = MockDns::new();
    dns.when("10.10.10.10", true, Some("ec2-34-233-233-138.compute-1.amazonaws.com"));
    let anon = anonymiser(dns, false);

    assert_eq!(
        anon.process_address_string("10.10.10.10"),
        "{!1{10.10.10.0/24,ec2-34-233-233-138.compute-1.amazonaws.com}}"
    );
}
