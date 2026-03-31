// Rust port of AnonymisatorIPv6Test.java
//
// The Java test wires up an AnonymiserProcessor with a stub IpAddressAnonymiser
// that returns "--founditX--" when the matched address starts with 'f', and
// "--foundit--" otherwise.  Every test calls processor.process_line() directly
// and asserts the resulting string.

use log_anonymiser::anonymiser::IpAddressAnonymiser;
use log_anonymiser::processor::AnonymiserProcessor;

// ── Stub anonymiser (mirrors the anonymous inner class in setUp()) ─────────────

struct PrefixStub;

impl IpAddressAnonymiser for PrefixStub {
    fn process_address_string(&self, address: &str) -> String {
        if address.starts_with('f') {
            "--founditX--".to_string()
        } else {
            "--foundit--".to_string()
        }
    }
}

fn processor() -> AnonymiserProcessor {
    AnonymiserProcessor::new(Box::new(PrefixStub), 1, false)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn test_one_address_in_middle() {
    assert_eq!(
        processor().process_line("Hello 2001:0db8:85a3:0000:0000:8a2e:0370:7334 world"),
        "Hello --foundit-- world"
    );
}

#[test]
fn test_address_with_url_escaped_character() {
    // The %20 is a lookahead boundary char, so the address stops before it
    assert_eq!(
        processor().process_line("Hello 2001:0db8:85a3:0000:0000:8a2e:0370:7334%20 world"),
        "Hello --foundit--%20 world"
    );
}

#[test]
fn test_address_part_of_another_string_should_not_match1() {
    // Prefix "foo" immediately before the address — must not match
    assert_eq!(
        processor().process_line("Hello foo2001:0db8:85a3:0000:0000:8a2e:0370:7334 world"),
        "Hello foo2001:0db8:85a3:0000:0000:8a2e:0370:7334 world"
    );
}

#[test]
fn test_address_part_of_another_string_should_not_match2() {
    // Suffix "foo" immediately after the address — must not match
    assert_eq!(
        processor().process_line("Hello 2001:0db8:85a3:0000:0000:8a2e:0370:7334foo world"),
        "Hello 2001:0db8:85a3:0000:0000:8a2e:0370:7334foo world"
    );
}

#[test]
fn test_address_part_of_another_string_should_not_match3() {
    // Both prefix and suffix — must not match
    assert_eq!(
        processor().process_line("Hello bar2001:0db8:85a3:0000:0000:8a2e:0370:7334foo world"),
        "Hello bar2001:0db8:85a3:0000:0000:8a2e:0370:7334foo world"
    );
}

#[test]
fn test_one_address_at_start() {
    assert_eq!(
        processor().process_line("2001:0db8:85a3:0000:0000:8a2e:0370:7334 world"),
        "--foundit-- world"
    );
}

#[test]
fn test_only_an_address() {
    assert_eq!(
        processor().process_line("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
        "--foundit--"
    );
}

#[test]
fn test_one_address_at_start_with_whitespace() {
    assert_eq!(
        processor().process_line(" 2001:0db8:85a3:0000:0000:8a2e:0370:7334 world"),
        " --foundit-- world"
    );
}

#[test]
fn test_one_address_at_end() {
    assert_eq!(
        processor().process_line("Hello 2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
        "Hello --foundit--"
    );
}

#[test]
fn test_one_address_at_end_all_upper_case() {
    assert_eq!(
        processor().process_line("Hello 2001:0DB8:85A3:0000:0000:8A2E:0370:7334"),
        "Hello --foundit--"
    );
}

#[test]
fn test_not_really_an_address_too_many_16_byte_parts() {
    // Nine colon-separated groups — exceeds the 8-group maximum; must not match
    assert_eq!(
        processor().process_line("Hello 2001:0db8:85a3:0000:0000:8a2e:0370:7334:1234"),
        "Hello 2001:0db8:85a3:0000:0000:8a2e:0370:7334:1234"
    );
}

#[test]
fn test_one_address_at_end_with_whitespace() {
    assert_eq!(
        processor().process_line("Hello 2001:0db8:85a3:0000:0000:8a2e:0370:7334 "),
        "Hello --foundit-- "
    );
}

#[test]
fn test_two_addresses_in_middle() {
    // fe80-prefixed address → "--founditX--", other → "--foundit--"
    assert_eq!(
        processor().process_line(
            "Hello 2001:0db8:85a3:0000:0000:8a2e:0370:7334 fe80::f043:57ff:fe35:77c7 world"
        ),
        "Hello --foundit-- --founditX-- world"
    );
}

#[test]
fn test_two_addresses_separated_by_plus() {
    // IIS MIIS log format: addresses joined with '+'
    assert_eq!(
        processor().process_line(
            "Hello 2001:0db8:85a3:0000:0000:8a2e:0370:7334+fe80::f043:57ff:fe35:77c7 world"
        ),
        "Hello --foundit--+--founditX-- world"
    );
}

#[test]
fn test_two_addresses_one_start_one_middle() {
    assert_eq!(
        processor().process_line(
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334 hello fe80::f043:57ff:fe35:77c7 world"
        ),
        "--foundit-- hello --founditX-- world"
    );
}

#[test]
fn test_two_addresses_one_middle_one_end() {
    assert_eq!(
        processor().process_line(
            "Hello 2001:0db8:85a3:0000:0000:8a2e:0370:7334 world fe80::f043:57ff:fe35:77c7"
        ),
        "Hello --foundit-- world --founditX--"
    );
}

#[test]
fn test_two_addresses_one_start_one_end() {
    assert_eq!(
        processor().process_line(
            "fe80::f043:57ff:fe35:77c7 hello world 2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        ),
        "--founditX-- hello world --foundit--"
    );
}

#[test]
fn test_x_forwarded_for_commas() {
    let addr = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
    let line = format!("Hello {addr},{addr},{addr} world");
    assert_eq!(
        processor().process_line(&line),
        "Hello --foundit--,--foundit--,--foundit-- world"
    );
}

#[test]
fn test_x_forwarded_for_commas_with_spaces_after_commas() {
    let addr = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
    let line = format!("Hello {addr}, {addr}, {addr} world");
    assert_eq!(
        processor().process_line(&line),
        "Hello --foundit--, --foundit--, --foundit-- world"
    );
}

#[test]
fn test_address_in_quotes() {
    assert_eq!(
        processor().process_line(r#"Hello "2001:0db8:85a3:0000:0000:8a2e:0370:7334" world"#),
        r#"Hello "--foundit--" world"#
    );
}

#[test]
fn test_address_in_start_of_quotes() {
    assert_eq!(
        processor().process_line(r#"Hello "2001:0db8:85a3:0000:0000:8a2e:0370:7334, stuff" world"#),
        r#"Hello "--foundit--, stuff" world"#
    );
}

#[test]
fn test_address_end_of_quotes() {
    assert_eq!(
        processor().process_line(r#"Hello "foo, 2001:0db8:85a3:0000:0000:8a2e:0370:7334" world"#),
        r#"Hello "foo, --foundit--" world"#
    );
}

#[test]
fn test_address_in_single_quotes() {
    assert_eq!(
        processor().process_line("Hello '2001:0db8:85a3:0000:0000:8a2e:0370:7334' world"),
        "Hello '--foundit--' world"
    );
}

#[test]
fn test_address_in_start_of_single_quotes() {
    assert_eq!(
        processor().process_line("Hello '2001:0db8:85a3:0000:0000:8a2e:0370:7334, stuff' world"),
        "Hello '--foundit--, stuff' world"
    );
}

#[test]
fn test_address_end_of_single_quotes() {
    assert_eq!(
        processor().process_line("Hello 'foo, 2001:0db8:85a3:0000:0000:8a2e:0370:7334' world"),
        "Hello 'foo, --foundit--' world"
    );
}
