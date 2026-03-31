use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Parser;

use log_anonymiser::anonymiser::SpatineoAnonymiser;
use log_anonymiser::config::Config;
use log_anonymiser::dns::{CachingDnsLookupHandler, DisabledDnsLookupHandler};
use log_anonymiser::io::InputOutput;
use log_anonymiser::processor::AnonymiserProcessor;

/// Command-line tool for anonymising access log files.
#[derive(Parser)]
#[command(name = "log-anonymiser", about = "Anonymises IP addresses in web server log files")]
struct Cli {
    /// Input log file
    input: PathBuf,
    /// Output log file (must not exist)
    output: PathBuf,

    /// Return full private DNS names (e.g. hello.local) when DNS returns them
    #[arg(long = "dns.allowprivate")]
    dns_allowprivate: bool,

    /// Disable DNS lookups (enabled by default)
    #[arg(long = "dns.disabled")]
    dns_disabled: bool,

    /// DNS server(s) to use as a comma-delimited list, e.g. --dns.server=8.8.8.8,8.8.4.4
    #[arg(long = "dns.server")]
    dns_server: Option<String>,

    /// DNS lookup timeout in milliseconds
    #[arg(long = "dns.timeoutmillis", default_value = "30000")]
    dns_timeoutmillis: u64,

    /// Maximum number of DNS PTR lookup results to keep in the LRU cache
    #[arg(long = "dns.cachemaxsize", default_value = "100000")]
    dns_cachemaxsize: usize,

    /// Number of concurrent threads for parallel DNS lookups
    #[arg(long = "threads", default_value = "32")]
    threads: usize,

    /// How many bits in IPv4 addresses to mask/anonymise
    #[arg(long = "mask.ipv4", default_value = "8")]
    mask_ipv4: u32,

    /// How many bits in IPv6 addresses to mask/anonymise
    #[arg(long = "mask.ipv6", default_value = "80")]
    mask_ipv6: u32,

    /// Is the input file gzip compressed true/false (default: autodetect from extension)
    #[arg(long = "compress.input")]
    compress_input: Option<bool>,

    /// Should the output file be gzip compressed true/false (default: same as input)
    #[arg(long = "compress.output")]
    compress_output: Option<bool>,

    /// Log a trace line to stdout for every processed log row (line number, addresses masked,
    /// running total, and processing time in microseconds)
    #[arg(long = "trace")]
    trace: bool,
}

fn run() -> Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    // Validate mask ranges
    if cli.mask_ipv4 > 32 {
        bail!("Illegal IPv4 mask {}: must be 0-32", cli.mask_ipv4);
    }
    if cli.mask_ipv6 > 128 {
        bail!("Illegal IPv6 mask {}: must be 0-128", cli.mask_ipv6);
    }

    // Validate file arguments
    if !cli.input.exists() {
        bail!("{}: does not exist", cli.input.display());
    }
    if cli.input.is_dir() {
        bail!("{}: is a directory", cli.input.display());
    }
    if cli.output.exists() {
        bail!("{}: exists already!", cli.output.display());
    }

    let config = Config {
        dns_enabled: !cli.dns_disabled,
        dns_servers: cli.dns_server
            .as_deref()
            .map(|s| s.split(',').map(|p| p.trim().to_string()).filter(|s| !s.is_empty()).collect())
            .unwrap_or_default(),
        dns_timeout_millis: cli.dns_timeoutmillis,
        dns_cache_max_size: cli.dns_cachemaxsize,
        parallel_threads: if cli.dns_disabled { 1 } else { cli.threads },
        ipv4_bits_to_anonymize: cli.mask_ipv4,
        ipv6_bits_to_anonymize: cli.mask_ipv6,
        allow_full_private_addresses: cli.dns_allowprivate,
        compress_input: cli.compress_input,
        compress_output: cli.compress_output,
        trace: cli.trace,
    };

    // Build DNS handler
    let dns_handler: Box<dyn log_anonymiser::dns::DnsLookupHandler> = if config.dns_enabled {
        Box::new(CachingDnsLookupHandler::new(
            &config.dns_servers,
            config.dns_timeout_millis,
            Some(config.dns_cache_max_size),
        )?)
    } else {
        Box::new(DisabledDnsLookupHandler)
    };

    let anonymiser = SpatineoAnonymiser::new(
        dns_handler,
        config.ipv4_bits_to_anonymize,
        config.ipv6_bits_to_anonymize,
        config.allow_full_private_addresses,
    );

    let processor = AnonymiserProcessor::new(Box::new(anonymiser), config.parallel_threads, config.trace);

    let mut io = InputOutput::new(config.compress_input, config.compress_output);
    let input = io.open_input(&cli.input)?;
    let output = io.open_output(&cli.output)?;

    processor.process(input, output)?;

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}
