use std::io::{BufRead, BufReader, Read, Write};
use std::time::Instant;

use anyhow::Result;
use fancy_regex::Regex;
use once_cell::sync::OnceCell;
use rayon::prelude::*;

use crate::anonymiser::IpAddressAnonymiser;

// ── IP-matching regex (ported from Java) ─────────────────────────────────────

const IPV4_MATCHER: &str =
    r"(?:(?:0|1[0-9]?[0-9]?|2[0-4]?[0-9]?|25[0-5]?|[3-9][0-9]?)\.){3}(?:0|1[0-9]?[0-9]?|2[0-4]?[0-9]?|25[0-5]?|[3-9][0-9]?)";

const IPV6_MATCHER: &str =
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4})?:)?(?:(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])\.){3}(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])\.){3}(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])";

fn ip_regex() -> &'static Regex {
    static RE: OnceCell<Regex> = OnceCell::new();
    RE.get_or_init(|| {
        let pattern = format!(
            r#"(?<=[\s,"'+]|,\\x20|^)({}(?::[0-9]+)?|{})(?=[\s,"'%+]|$)"#,
            IPV4_MATCHER, IPV6_MATCHER
        );
        Regex::new(&pattern).expect("invalid IP regex")
    })
}

// ── Processor ────────────────────────────────────────────────────────────────

pub struct AnonymiserProcessor {
    pub anonymiser: Box<dyn IpAddressAnonymiser>,
    pub parallel_threads: usize,
    pub trace: bool,
}

impl AnonymiserProcessor {
    pub fn new(anonymiser: Box<dyn IpAddressAnonymiser>, parallel_threads: usize, trace: bool) -> Self {
        AnonymiserProcessor { anonymiser, parallel_threads, trace }
    }

    pub fn process(&self, input: impl Read, mut output: impl Write) -> Result<()> {
        let reader = BufReader::new(input);
        let lines: Vec<String> = reader.lines().collect::<std::io::Result<_>>()?;

        // Each element: (processed_line, addresses_masked, elapsed_micros)
        let results: Vec<(String, usize, u128)> = if self.parallel_threads > 1 {
            log::info!("Using multithreading with {} threads", self.parallel_threads);
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(self.parallel_threads)
                .build()?;
            pool.install(|| {
                lines.par_iter()
                    .map(|line| self.process_line_timed(line))
                    .collect()
            })
        } else {
            log::info!("Using single-thread mode");
            lines.iter().map(|line| self.process_line_timed(line)).collect()
        };

        let mut running_total: usize = 0;
        for (line_no, (text, count, elapsed_us)) in results.into_iter().enumerate() {
            if self.trace {
                running_total += count;
                println!(
                    "line {}: masked ips = {} (running total = {}) elapsed_us = {}",
                    line_no + 1,
                    count,
                    running_total,
                    elapsed_us
                );
            }
            output.write_all(text.as_bytes())?;
            output.write_all(b"\n")?;
        }
        Ok(())
    }

    /// Replace every IP address on a single line with its anonymised token.
    pub fn process_line(&self, line: &str) -> String {
        self.process_line_timed(line).0
    }

    /// Returns `(processed_line, addresses_masked, elapsed_micros)`.
    fn process_line_timed(&self, line: &str) -> (String, usize, u128) {
        let start = Instant::now();
        let re = ip_regex();
        let mut output = String::with_capacity(line.len() + 32);
        let mut last_end = 0;
        let mut count = 0usize;

        for cap_result in re.captures_iter(line) {
            match cap_result {
                Err(e) => {
                    log::warn!("Regex error on line: {}", e);
                    break;
                }
                Ok(caps) => {
                    // Group 0 = full match; the IP is group 1 (lookbehind/lookahead are zero-width)
                    let full = caps.get(0).unwrap();
                    let ip_match = caps.get(1).unwrap();

                    // Text between last match end and the start of the current match
                    output.push_str(&line[last_end..full.start()]);
                    last_end = full.end();

                    // Replace the IP with anonymised token; the lookahead char stays outside the match
                    let replacement = self.anonymiser.process_address_string(ip_match.as_str());
                    output.push_str(&replacement);
                    count += 1;
                }
            }
        }

        output.push_str(&line[last_end..]);
        (output, count, start.elapsed().as_micros())
    }
}
