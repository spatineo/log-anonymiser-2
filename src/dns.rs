use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::Result;
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::Resolver;
use lru::LruCache;

pub const DEFAULT_DNS_CACHE_SIZE: usize = 100_000;

#[derive(Clone, Debug)]
pub struct DnsLookupResult {
    pub success: bool,
    pub reverse_name: Option<String>,
}

pub trait DnsLookupHandler: Send + Sync {
    fn lookup(&self, addr: &str) -> DnsLookupResult;
}

// ── Disabled DNS handler ──────────────────────────────────────────────────────

pub struct DisabledDnsLookupHandler;

impl DnsLookupHandler for DisabledDnsLookupHandler {
    fn lookup(&self, _addr: &str) -> DnsLookupResult {
        DnsLookupResult { success: false, reverse_name: None }
    }
}

// ── Real DNS handler with cache ───────────────────────────────────────────────

pub struct CachingDnsLookupHandler {
    resolver: Resolver,
    cache: Mutex<LruCache<String, DnsLookupResult>>,
}

impl CachingDnsLookupHandler {
    pub fn new(servers: &[String], timeout_millis: u64, max_cache_size: Option<usize>) -> Result<Self> {
        let capacity = NonZeroUsize::new(max_cache_size.unwrap_or(DEFAULT_DNS_CACHE_SIZE))
            .expect("dns cache size must be non-zero");

        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_millis(timeout_millis);

        let resolver = if servers.is_empty() {
            let (sys_config, _) = hickory_resolver::system_conf::read_system_conf()?;
            Resolver::new(sys_config, opts)?
        } else {
            let mut config = ResolverConfig::new();
            for server in servers {
                let addr: std::net::SocketAddr = format!("{}:53", server).parse()?;
                config.add_name_server(NameServerConfig::new(addr, Protocol::Udp));
            }
            Resolver::new(config, opts)?
        };

        Ok(Self { resolver, cache: Mutex::new(LruCache::new(capacity)) })
    }
}

impl DnsLookupHandler for CachingDnsLookupHandler {
    fn lookup(&self, addr: &str) -> DnsLookupResult {
        // Check cache first
        {
            let mut cache = self.cache.lock().unwrap();
            if let Some(cached) = cache.get(addr) {
                return cached.clone();
            }
        }

        let result = self.lookup_from_dns(addr);

        // Store in cache; if the entry was raced in by another thread, keep theirs
        let mut cache = self.cache.lock().unwrap();
        if !cache.contains(addr) {
            cache.put(addr.to_string(), result.clone());
        }
        result
    }
}

impl CachingDnsLookupHandler {
    fn lookup_from_dns(&self, addr: &str) -> DnsLookupResult {
        let ip: IpAddr = match addr.parse() {
            Ok(ip) => ip,
            Err(_) => return DnsLookupResult { success: false, reverse_name: None },
        };

        match self.resolver.reverse_lookup(ip) {
            Ok(response) => {
                let name = response.iter().next().map(|n| {
                    let s = n.to_string();
                    s.trim_end_matches('.').to_string()
                });
                DnsLookupResult { success: name.is_some(), reverse_name: name }
            }
            Err(_) => DnsLookupResult { success: false, reverse_name: None },
        }
    }
}
