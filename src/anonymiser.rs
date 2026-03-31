use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;

use lru::LruCache;
use once_cell::sync::OnceCell;
use regex::Regex;

use crate::dns::DnsLookupHandler;

pub trait IpAddressAnonymiser: Send + Sync {
    fn process_address_string(&self, address: &str) -> String;
}

// ── Port extractor for IPv4 ───────────────────────────────────────────────────

fn ipv4_port_regex() -> &'static Regex {
    static RE: OnceCell<Regex> = OnceCell::new();
    RE.get_or_init(|| {
        // Matches "a.b.c.d:port" where a is non-zero, others can be 0
        Regex::new(r"^([1-9][0-9]*\.(?:[1-9][0-9]*|0)\.(?:[1-9][0-9]*|0)\.(?:[1-9][0-9]*|0))(:[0-9]+)$").unwrap()
    })
}

// ── IP masking ────────────────────────────────────────────────────────────────

/// Zero the last `bits_to_anonymize` bits of an IPv4 address.
/// Returns the masked address and prefix length.
fn mask_ipv4(addr: Ipv4Addr, bits_to_anonymize: u32) -> (Ipv4Addr, u32) {
    let prefix_len = 32 - bits_to_anonymize;
    let mut bytes = addr.octets();
    let mut bits = bits_to_anonymize;
    let mut idx: i32 = 3;
    while bits >= 8 && idx >= 0 {
        bytes[idx as usize] = 0;
        idx -= 1;
        bits -= 8;
    }
    if bits > 0 && idx >= 0 {
        let mask = 0xffu8 ^ ((1u8 << bits) - 1);
        bytes[idx as usize] &= mask;
    }
    (Ipv4Addr::from(bytes), prefix_len)
}

/// Zero the last `bits_to_anonymize` bits of an IPv6 address.
fn mask_ipv6(addr: Ipv6Addr, bits_to_anonymize: u32) -> (Ipv6Addr, u32) {
    let prefix_len = 128 - bits_to_anonymize;
    let mut bytes = addr.octets(); // [u8; 16]
    let mut bits = bits_to_anonymize;
    let mut idx: i32 = 15;
    while bits >= 8 && idx >= 0 {
        bytes[idx as usize] = 0;
        idx -= 1;
        bits -= 8;
    }
    if bits > 0 && idx >= 0 {
        let mask = 0xffu8 ^ ((1u8 << bits) - 1);
        bytes[idx as usize] &= mask;
    }
    (Ipv6Addr::from(bytes), prefix_len)
}

/// Returns `"<masked>/<prefix>"` for any IP address string.
pub fn anonymise_ip(address: &str, ipv4_bits: u32, ipv6_bits: u32) -> anyhow::Result<String> {
    let ip: IpAddr = address.parse()
        .map_err(|e| anyhow::anyhow!("Cannot parse IP '{}': {}", address, e))?;
    Ok(match ip {
        IpAddr::V4(v4) => {
            let (masked, prefix) = mask_ipv4(v4, ipv4_bits);
            format!("{}/{}", masked, prefix)
        }
        IpAddr::V6(v6) => {
            let (masked, prefix) = mask_ipv6(v6, ipv6_bits);
            format!("{}/{}", masked, prefix)
        }
    })
}

// ── Domain name extraction (PSL) ──────────────────────────────────────────────

/// Convert an FQDN to its top private domain using the Public Suffix List.
/// Mirrors Guava's InternetDomainName.topPrivateDomain() logic.
pub fn identify_domain_name(dns_name: &str, allow_private: bool) -> Option<String> {
    match addr::parse_domain_name(dns_name) {
        Err(_) => None,
        Ok(name) => {
            if !name.has_known_suffix() {
                // Private / non-public-suffix domain
                if allow_private {
                    Some(dns_name.to_string())
                } else {
                    None
                }
            } else {
                match name.root() {
                    None => {
                        // The name IS a public suffix (e.g., "com")
                        Some(dns_name.to_string())
                    }
                    Some(root) => Some(root.to_string()),
                }
            }
        }
    }
}

// ── Main anonymiser implementation ────────────────────────────────────────────

pub struct SpatineoAnonymiser {
    dns: Box<dyn DnsLookupHandler>,
    ipv4_bits: u32,
    ipv6_bits: u32,
    allow_private: bool,
    /// Cache of addresses for which DNS lookup previously failed, to skip retrying.
    failed_cache: Mutex<LruCache<String, ()>>,
}

impl SpatineoAnonymiser {
    pub fn new(
        dns: Box<dyn DnsLookupHandler>,
        ipv4_bits: u32,
        ipv6_bits: u32,
        allow_private: bool,
    ) -> Self {
        use std::num::NonZeroUsize;
        SpatineoAnonymiser {
            dns,
            ipv4_bits,
            ipv6_bits,
            allow_private,
            failed_cache: Mutex::new(LruCache::new(NonZeroUsize::new(1000).unwrap())),
        }
    }

    fn reverse_name(&self, ip_addr: &str) -> Option<String> {
        let result = self.dns.lookup(ip_addr);
        if result.success {
            result.reverse_name
        } else {
            None
        }
    }

    fn produce_output(domain_name: Option<&str>, anonymised_ip: &str, postfix: Option<&str>) -> String {
        let mut ret = format!("{{!1{{{}", anonymised_ip);
        if let Some(domain) = domain_name {
            ret.push(',');
            ret.push_str(domain);
        }
        ret.push_str("}}");
        if let Some(p) = postfix {
            ret.push_str(p);
        }
        ret
    }
}

impl IpAddressAnonymiser for SpatineoAnonymiser {
    fn process_address_string(&self, address: &str) -> String {
        // Extract optional port suffix for IPv4 addresses
        let (addr_without_port, postfix): (String, Option<String>) = if let Some(caps) = ipv4_port_regex().captures(address) {
            let ip = caps.get(1).unwrap().as_str().to_string();
            let port = caps.get(2).unwrap().as_str().to_string();
            (ip, Some(port))
        } else {
            (address.to_string(), None)
        };

        let anonymised_ip = match anonymise_ip(&addr_without_port, self.ipv4_bits, self.ipv6_bits) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Error anonymising IP '{}': {}", addr_without_port.as_str(), e);
                return address.to_string();
            }
        };

        let domain_name: Option<String> = {
            let in_failed_cache = self.failed_cache.lock().unwrap().contains(&addr_without_port);
            if in_failed_cache {
                None
            } else {
                match self.reverse_name(&addr_without_port) {
                    None => None,
                    Some(reverse) => identify_domain_name(&reverse, self.allow_private),
                }
            }
        };

        Self::produce_output(domain_name.as_deref(), &anonymised_ip, postfix.as_deref())
    }
}
