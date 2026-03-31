// Rust port of AnonymisatorIPv4Test.java
//
// The Java test wires up an AnonymiserProcessor with a stub IpAddressAnonymiser
// that unconditionally returns "--foundit--" for every matched address.
// Every test calls processor.process_line() directly and asserts the result.

use log_anonymiser::anonymiser::IpAddressAnonymiser;
use log_anonymiser::processor::AnonymiserProcessor;

// ── Stub anonymiser (mirrors the anonymous inner class in setUp()) ─────────────

struct AlwaysFoundIt;

impl IpAddressAnonymiser for AlwaysFoundIt {
    fn process_address_string(&self, _address: &str) -> String {
        "--foundit--".to_string()
    }
}

fn processor() -> AnonymiserProcessor {
    AnonymiserProcessor::new(Box::new(AlwaysFoundIt), 1, false)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn test_one_address_in_middle() {
    assert_eq!(
        processor().process_line("Hello 194.100.34.1 world"),
        "Hello --foundit-- world"
    );
}

#[test]
fn test_address_part_of_another_string_should_not_match1() {
    // Prefix "foo" directly before the address — must not match
    assert_eq!(
        processor().process_line("Hello foo194.100.34.1 world"),
        "Hello foo194.100.34.1 world"
    );
}

#[test]
fn test_address_part_of_another_string_should_not_match2() {
    // Suffix "foo" directly after the address — must not match
    assert_eq!(
        processor().process_line("Hello 194.100.34.1foo world"),
        "Hello 194.100.34.1foo world"
    );
}

#[test]
fn test_address_part_of_another_string_should_not_match3() {
    // Both prefix and suffix — must not match
    assert_eq!(
        processor().process_line("Hello bar194.100.34.1foo world"),
        "Hello bar194.100.34.1foo world"
    );
}

#[test]
fn test_one_address_at_start() {
    assert_eq!(
        processor().process_line("194.100.34.1 world"),
        "--foundit-- world"
    );
}

#[test]
fn test_one_address_at_start_with_whitespace() {
    assert_eq!(
        processor().process_line(" 194.100.34.1 world"),
        " --foundit-- world"
    );
}

#[test]
fn test_one_address_at_end() {
    assert_eq!(
        processor().process_line("Hello 194.100.34.1"),
        "Hello --foundit--"
    );
}

#[test]
fn test_one_address_at_end_with_whitespace() {
    assert_eq!(
        processor().process_line("Hello 194.100.34.1 "),
        "Hello --foundit-- "
    );
}

#[test]
fn test_two_addresses_in_middle() {
    assert_eq!(
        processor().process_line("Hello 194.100.34.1 10.1.1.0 world"),
        "Hello --foundit-- --foundit-- world"
    );
}

#[test]
fn test_two_addresses_one_start_one_middle() {
    assert_eq!(
        processor().process_line("194.100.34.1 hello 10.1.1.0 world"),
        "--foundit-- hello --foundit-- world"
    );
}

#[test]
fn test_two_addresses_one_middle_one_end() {
    assert_eq!(
        processor().process_line("Hello 194.100.34.1 world 10.1.1.0"),
        "Hello --foundit-- world --foundit--"
    );
}

#[test]
fn test_two_addresses_one_start_one_end() {
    assert_eq!(
        processor().process_line("194.100.34.1 hello world 10.1.1.0"),
        "--foundit-- hello world --foundit--"
    );
}

#[test]
fn test_port_separated_by_colon() {
    // The port is part of the matched token; the stub anonymiser absorbs it
    assert_eq!(
        processor().process_line("Hello 194.100.34.1:1234 world"),
        "Hello --foundit-- world"
    );
}

#[test]
fn test_port_separated_by_colon_comma_separated() {
    assert_eq!(
        processor().process_line("Hello 194.100.34.1:1234,127.0.0.1:32176 world"),
        "Hello --foundit--,--foundit-- world"
    );
}

#[test]
fn test_x_forwarded_for_commas() {
    assert_eq!(
        processor().process_line("Hello 194.100.34.1,255.255.255.255,9.1.2.3 world"),
        "Hello --foundit--,--foundit--,--foundit-- world"
    );
}

#[test]
fn test_x_forwarded_for_commas_with_spaces_after_comma() {
    assert_eq!(
        processor().process_line("Hello 194.100.34.1, 255.255.255.255, 9.1.2.3 world"),
        "Hello --foundit--, --foundit--, --foundit-- world"
    );
}

#[test]
fn test_weird_row_with_commas_and_colons() {
    assert_eq!(
        processor().process_line("84.192.245.70:59913, 84.192.245.70:59913,127.0.0.1 23.97.211.140 - -"),
        "--foundit--, --foundit--,--foundit-- --foundit-- - -"
    );
}

#[test]
fn test_address_in_quotes() {
    assert_eq!(
        processor().process_line(r#"Hello "127.0.0.1" world"#),
        r#"Hello "--foundit--" world"#
    );
}

#[test]
fn test_address_with_port_in_quotes() {
    assert_eq!(
        processor().process_line(r#"Hello "127.0.0.1:1234" world"#),
        r#"Hello "--foundit--" world"#
    );
}

#[test]
fn test_address_with_port_in_start_of_quotes() {
    assert_eq!(
        processor().process_line(r#"Hello "127.0.0.1:1234, stuff" world"#),
        r#"Hello "--foundit--, stuff" world"#
    );
}

#[test]
fn test_address_in_start_of_quotes() {
    assert_eq!(
        processor().process_line(r#"Hello "127.0.0.1, stuff" world"#),
        r#"Hello "--foundit--, stuff" world"#
    );
}

#[test]
fn test_address_end_of_quotes() {
    assert_eq!(
        processor().process_line(r#"Hello "foo, 127.0.0.1" world"#),
        r#"Hello "foo, --foundit--" world"#
    );
}

#[test]
fn test_address_with_port_end_of_quotes() {
    assert_eq!(
        processor().process_line(r#"Hello "foo, 127.0.0.1:1234" world"#),
        r#"Hello "foo, --foundit--" world"#
    );
}

#[test]
fn test_address_in_single_quotes() {
    assert_eq!(
        processor().process_line("Hello '127.0.0.1' world"),
        "Hello '--foundit--' world"
    );
}

#[test]
fn test_address_with_port_in_single_quotes() {
    assert_eq!(
        processor().process_line("Hello '127.0.0.1:1234' world"),
        "Hello '--foundit--' world"
    );
}

#[test]
fn test_address_with_port_in_start_of_single_quotes() {
    assert_eq!(
        processor().process_line("Hello '127.0.0.1:1234, stuff' world"),
        "Hello '--foundit--, stuff' world"
    );
}

#[test]
fn test_address_in_start_of_single_quotes() {
    assert_eq!(
        processor().process_line("Hello '127.0.0.1, stuff' world"),
        "Hello '--foundit--, stuff' world"
    );
}

#[test]
fn test_address_end_of_single_quotes() {
    assert_eq!(
        processor().process_line("Hello 'foo, 127.0.0.1' world"),
        "Hello 'foo, --foundit--' world"
    );
}

#[test]
fn test_address_with_port_end_of_single_quotes() {
    assert_eq!(
        processor().process_line("Hello 'foo, 127.0.0.1:1234' world"),
        "Hello 'foo, --foundit--' world"
    );
}

#[test]
fn test_this_is_not_an_ip_address() {
    // Leading zero makes the first octet invalid (027 is not a valid octet)
    assert_eq!(
        processor().process_line("Hello 'foo, 027.0.0.1:1234' world"),
        "Hello 'foo, 027.0.0.1:1234' world"
    );
}

#[test]
fn test_address_with_all_ip_start_end_0_to_255() {
    // Every value 0–255 must be accepted as first and last octet
    for i in 0u32..=255 {
        let line = format!("Hello 'foo, {}.0.0.{}:1234' world", i, i);
        assert_eq!(
            processor().process_line(&line),
            "Hello 'foo, --foundit--' world",
            "failed for i={i}"
        );
    }
}

#[test]
fn test_x_forwarded_for() {
    assert_eq!(
        processor().process_line("Hello 62.159.68.218,172.22.89.43,62.159.68.218 world"),
        "Hello --foundit--,--foundit--,--foundit-- world"
    );
}

#[test]
fn test_x_forwarded_for_with_miis_space() {
    // IIS MIIS log format: '+' encodes a space between addresses
    assert_eq!(
        processor().process_line("Hello 62.159.68.218,+172.22.89.43 world"),
        "Hello --foundit--,+--foundit-- world"
    );
}

#[test]
fn test_x_forwarded_for_with_miis_space_multiple() {
    assert_eq!(
        processor().process_line("Hello 62.159.68.218,+172.22.89.43,+62.159.68.218 world"),
        "Hello --foundit--,+--foundit--,+--foundit-- world"
    );
}

#[test]
fn test_cloudfront_x_forwarded_for() {
    // CloudFront encodes comma+space as ',\x20' in W3C logs
    assert_eq!(
        processor().process_line(r"Hello 62.159.68.218,\x20172.22.89.43,\x2062.159.68.218 world"),
        r"Hello --foundit--,\x20--foundit--,\x20--foundit-- world"
    );
}
