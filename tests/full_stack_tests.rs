//! Integration tests mirroring FullStackTest.java
//! These test the complete pipeline: processor → anonymiser → DNS handler

use std::collections::HashMap;
use std::io::Cursor;

use log_anonymiser::anonymiser::SpatineoAnonymiser;
use log_anonymiser::dns::{DnsLookupHandler, DnsLookupResult};
use log_anonymiser::processor::AnonymiserProcessor;

struct MapDnsHandler {
    map: HashMap<String, DnsLookupResult>,
}

impl MapDnsHandler {
    fn new() -> Self {
        MapDnsHandler { map: HashMap::new() }
    }
    fn add(&mut self, addr: &str, success: bool, name: Option<&str>) {
        self.map.insert(addr.to_string(), DnsLookupResult {
            success,
            reverse_name: name.map(|s| s.to_string()),
        });
    }
}

impl DnsLookupHandler for MapDnsHandler {
    fn lookup(&self, addr: &str) -> DnsLookupResult {
        self.map.get(addr).cloned().unwrap_or(DnsLookupResult { success: false, reverse_name: None })
    }
}

fn make_processor(dns: MapDnsHandler) -> AnonymiserProcessor {
    let anonymiser = SpatineoAnonymiser::new(Box::new(dns), 8, 80, false);
    AnonymiserProcessor::new(Box::new(anonymiser), 1, false)
}

fn run_processor(processor: &AnonymiserProcessor, input: &str) -> String {
    let mut output: Vec<u8> = Vec::new();
    processor.process(Cursor::new(input), &mut output).unwrap();
    let mut result = String::from_utf8(output).unwrap();
    if result.ends_with('\n') {
        result.pop();
    }
    result
}

#[test]
fn test_row_with_ports_and_commas() {
    let mut dns = MapDnsHandler::new();
    // "localhost" has no public suffix → domain is stripped
    dns.add("127.0.0.1", true, Some("localhost"));
    dns.add("192.168.1.72", true, Some("localhost"));
    dns.add("192.168.1.123", true, Some("localhost"));

    let processor = make_processor(dns);
    let input = "127.0.0.1:59913, 192.168.1.72:59913,127.0.0.1 192.168.1.123 - - [01/Feb/2016:21:05:40 +0000] ...";
    let result = run_processor(&processor, input);

    assert_eq!(
        result,
        "{!1{127.0.0.0/24}}:59913, {!1{192.168.1.0/24}}:59913,{!1{127.0.0.0/24}} {!1{192.168.1.0/24}} - - [01/Feb/2016:21:05:40 +0000] ..."
    );
}

#[test]
fn test_row_with_number_looks_like_ip_but_4_digits() {
    // "8.15.3497.0" — 3497 exceeds 255, so the regex should NOT match it
    let dns = MapDnsHandler::new();
    let processor = make_processor(dns);
    let input = "[08/Nov/2018:14:59:34 +0200] Version number SpatialWeb 8.15.3497.0 ...";
    let result = run_processor(&processor, input);
    assert_eq!(result, "[08/Nov/2018:14:59:34 +0200] Version number SpatialWeb 8.15.3497.0 ...");
}

#[test]
fn test_row_with_number_looks_like_ip_but_not_ip() {
    // "8.15.1.0" looks like a valid IP — anonymiser cannot distinguish it from a version
    let mut dns = MapDnsHandler::new();
    dns.add("8.15.1.0", true, Some("localhost"));
    let processor = make_processor(dns);
    let input = "[08/Nov/2018:14:59:34 +0200] Version number SpatialWeb 8.15.1.0 ...";
    let result = run_processor(&processor, input);
    assert_eq!(result, "[08/Nov/2018:14:59:34 +0200] Version number SpatialWeb {!1{8.15.1.0/24}} ...");
}

#[test]
fn test_miis_log_with_multiple_ips() {
    let mut dns = MapDnsHandler::new();
    dns.add("8.15.1.0", true, Some("localhost"));
    dns.add("8.15.1.1", true, Some("foobar.com"));
    dns.add("8.15.1.2", true, Some("gah.com"));

    let processor = make_processor(dns);
    let input = "2025-02-03 06:46:14 8.15.1.0 GET /TeklaOGCWeb/WMS.ashx LAYERS=Kantakartta&TRANSPARENT=true&SERVICE=WMS&VERSION=1.1.1&REQUEST=GetMap&STYLES=&FORMAT=image%2Fpng&cscale=50&SRS=EPSG%3A3878&BBOX=24517377.400616,6693043.2824233,24517380.787281,6693046.6690881&WIDTH=256&HEIGHT=256 443 KeyAquaRajapinta {!1{172.21.41.0/24}} Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/132.0.0.0+Safari/537.36 https://vihti.keyaqua.keypro.fi/ 200 0 0 1203 8.15.1.1,+8.15.1.2";

    let result = run_processor(&processor, input);
    assert_eq!(
        result,
        "2025-02-03 06:46:14 {!1{8.15.1.0/24}} GET /TeklaOGCWeb/WMS.ashx LAYERS=Kantakartta&TRANSPARENT=true&SERVICE=WMS&VERSION=1.1.1&REQUEST=GetMap&STYLES=&FORMAT=image%2Fpng&cscale=50&SRS=EPSG%3A3878&BBOX=24517377.400616,6693043.2824233,24517380.787281,6693046.6690881&WIDTH=256&HEIGHT=256 443 KeyAquaRajapinta {!1{172.21.41.0/24}} Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/132.0.0.0+Safari/537.36 https://vihti.keyaqua.keypro.fi/ 200 0 0 1203 {!1{8.15.1.0/24,foobar.com}},+{!1{8.15.1.0/24,gah.com}}"
    );
}
