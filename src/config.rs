use crate::dns::DEFAULT_DNS_CACHE_SIZE;

/// Runtime configuration for the anonymiser
#[derive(Clone)]
pub struct Config {
    pub dns_enabled: bool,
    pub dns_servers: Vec<String>,
    pub dns_timeout_millis: u64,
    pub dns_cache_max_size: usize,
    pub parallel_threads: usize,
    pub ipv4_bits_to_anonymize: u32,
    pub ipv6_bits_to_anonymize: u32,
    pub allow_full_private_addresses: bool,
    pub compress_input: Option<bool>,
    pub compress_output: Option<bool>,
    pub trace: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            dns_enabled: true,
            dns_servers: vec![],
            dns_timeout_millis: 30_000,
            dns_cache_max_size: DEFAULT_DNS_CACHE_SIZE,
            parallel_threads: 32,
            ipv4_bits_to_anonymize: 8,
            ipv6_bits_to_anonymize: 80,
            allow_full_private_addresses: false,
            compress_input: None,
            compress_output: None,
            trace: false,
        }
    }
}
