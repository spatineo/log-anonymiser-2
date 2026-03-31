use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::Result;
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::xfer::Protocol;
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
    resolver: TokioResolver,
    runtime: tokio::runtime::Runtime,
    cache: Mutex<LruCache<String, DnsLookupResult>>,
}

impl CachingDnsLookupHandler {
    pub fn new(servers: &[String], timeout_millis: u64, max_cache_size: Option<usize>) -> Result<Self> {
        let capacity = NonZeroUsize::new(max_cache_size.unwrap_or(DEFAULT_DNS_CACHE_SIZE))
            .expect("dns cache size must be non-zero");

        let runtime = tokio::runtime::Runtime::new()?;

        let resolver = if servers.is_empty() {
            println!("System DNS");
            let mut builder = TokioResolver::builder_tokio()?;
            println!(" - a1");
            builder.options_mut().timeout = Duration::from_millis(timeout_millis);
            println!(" - a2");
            builder.build()
        } else {
            println!("Custom DNS");
            let mut config = ResolverConfig::new();
            println!(" - b1");
            for server in servers {
                println!("   - {}", server);
                let addr: std::net::SocketAddr = format!("{}:53", server).parse()?;
                config.add_name_server(NameServerConfig::new(addr, Protocol::Udp));
            }
            let mut builder = TokioResolver::builder_with_config(config, TokioConnectionProvider::default());
            println!(" - b2");
            builder.options_mut().timeout = Duration::from_millis(timeout_millis);
            println!(" - b3");
            builder.build()
        };

        Ok(Self { resolver, runtime, cache: Mutex::new(LruCache::new(capacity)) })
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

        match self.runtime.block_on(self.resolver.reverse_lookup(ip)) {
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
