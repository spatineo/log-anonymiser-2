// Rust port of IpAddressAnonymiserTest.java
//
// Tests the two public free functions exposed by the anonymiser module:
//   - identify_domain_name()  (mirrors identifyDomainName())
//   - anonymise_ip()          (mirrors anonymiseIp())
//
// The IPv4 masking tests use the `ipnet` crate as a cross-check, mirroring the
// Java tests that used Apache Commons Net SubnetUtils for the same purpose.

use ipnet::Ipv4Net;
use log_anonymiser::anonymiser::{anonymise_ip, identify_domain_name};

// ── Domain name extraction (identifyDomainName) ───────────────────────────────

#[test]
fn test_domain_name_extraction() {
    let name = identify_domain_name("www.google.com", false);
    assert_eq!(name, Some("google.com".to_string()));
}

#[test]
fn test_domain_name_extraction_co_uk() {
    let name = identify_domain_name("www.ordnancesurvey.co.uk", false);
    assert_eq!(name, Some("ordnancesurvey.co.uk".to_string()));
}

#[test]
fn test_domain_name_extraction_cyprus() {
    let name = identify_domain_name("weba.moi.dls.gov.cy", false);
    assert_eq!(name, Some("dls.gov.cy".to_string()));
}

#[test]
fn test_bare_tld_no_domain() {
    // "com" is itself a public suffix — return it as-is (same behaviour as Guava)
    let name = identify_domain_name("com", false);
    assert_eq!(name, Some("com".to_string()));
}

// ── IPv4 masking (anonymiseIp) ────────────────────────────────────────────────

#[test]
fn test_ipv4_masking_8_bits() {
    let result = anonymise_ip("192.168.1.127", 8, 80).unwrap();
    assert_eq!(result, "192.168.1.0/24");
}

#[test]
fn test_ipv4_masking_6_bits() {
    let result = anonymise_ip("192.168.1.218", 6, 80).unwrap();
    assert_eq!(result, "192.168.1.192/26");
}

#[test]
fn test_ipv4_masking_7_bits() {
    let addr = "192.168.1.255";
    let result = anonymise_ip(addr, 7, 80).unwrap();
    assert_eq!(result, "192.168.1.128/25");

    // Cross-check with ipnet (mirrors SubnetUtils cross-check in Java)
    let net: Ipv4Net = format!("{}/25", addr).parse().unwrap();
    let expected = format!("{}/25", net.network());
    assert_eq!(result, expected);
}

#[test]
fn test_all_anon_bits_and_match_with_ipnet() {
    // For every prefix length 0–32, verify masking against ipnet's network address.
    // Mirrors testAllAnonBitsAndMatchWithCommonsNet() which used SubnetUtils.
    let addr = "255.255.255.255";
    for bits in 0u32..=32 {
        let prefix_len = 32 - bits;
        let result = anonymise_ip(addr, bits, 80).unwrap();

        let net: Ipv4Net = format!("{}/{}", addr, prefix_len).parse().unwrap();
        let expected = format!("{}/{}", net.network(), prefix_len);

        assert_eq!(result, expected, "bits_to_anonymize={}", bits);
    }
}

// ── IPv6 masking (anonymiseIp) ────────────────────────────────────────────────

#[test]
fn test_ipv6_masking_80_bits() {
    let result = anonymise_ip("fe80::f043:57ff:fe35:77c7", 8, 80).unwrap();
    assert_eq!(result, "fe80::/48");
}

#[test]
fn test_ipv6_masking_80_bits_zeros_in_source() {
    let result = anonymise_ip("fe80:0000:0000:0000:f043:57ff:fe35:77c7", 8, 80).unwrap();
    assert_eq!(result, "fe80::/48");
}

#[test]
fn test_ipv6_masking_80_bits_partly_in_upper_case() {
    let result = anonymise_ip("fE80:0000:0000:0000:f043:57Ff:fe35:77C7", 8, 80).unwrap();
    assert_eq!(result, "fe80::/48");
}

#[test]
fn test_ipv6_masking_80_bits_www_google_com() {
    let result = anonymise_ip("2a00:1450:400f:80c::2004", 8, 80).unwrap();
    assert_eq!(result, "2a00:1450:400f::/48");
}
