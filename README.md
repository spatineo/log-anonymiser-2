# Log Anonymiser

This tool is a command line anonymiser for access log files. The tool searches for IPv4 and IPv6 addresses in input files and anonymises them by removing a configurable number of bits from the end of the addresses. In addition to just anonymising, the tool also performs a reverse DNS lookup of the original address and stores the first level subdomain of the address.

The tool has been developed by Spatineo Inc specifically for use with [Spatineo Monitor](https://www.spatineo.com/monitor/) log analysis. The tool is released under GPLv3 to allow our users and others to build and share developments of the tool.

Source code and released are available at [GitHub](https://github.com/spatineo/log-anonymiser-2)

The log anonymiser is built with Rust

## Releases

### 2.0.0

First release of the rust version

### 1.x / Legacy

Java based tool available in separate repository: https://github.com/spatineo/log-anonymiser


# Build instructions

## Linux (default)

```shell
cargo build --release
```

# Windows (requires mingw toolchain)

```shell
rustup target add x86_64-pc-windows-gnu
sudo apt-get install gcc-mingw-w64-x86-64
cargo build --release --target x86_64-pc-windows-gnu
```

