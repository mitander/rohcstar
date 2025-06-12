# ROHCスター

[![LICENSE](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI Status](https://github.com/mitander/rohcstar/actions/workflows/ci.yml/badge.svg)](https://github.com/mitander/rohcstar/actions)

**Rohcstar is a modern and memory-safe Rust implementation of the Robust Header Compression (ROHC) framework.**

> [!WARNING]
> This ROHC implementation is in early development phase.
> The API is unstable, features are incomplete, and breaking changes should be expected.

## Overview

Rohcstar implements RFC 3095 to compress IP/UDP/RTP headers from 40-60 bytes down to 1-3 bytes. Built for real-world use with focus on correctness, performance, and maintainability.

**Current Status:**
- Profile 0x0001 (RTP/UDP/IP) Unidirectional Mode: Complete
- All packet types implemented (IR, IR-DYN, UO-0, UO-1 variants)
- Robust state machines with proper error recovery
- Comprehensive test coverage

**Coming Next:**
- Additional profiles (UDP/IP, ESP/IP)
- Bidirectional modes (O-mode, R-mode)
- Performance optimizations

## Usage

```rust
use rohcstar::{RohcEngine, RohcProfile};
use rohcstar::profiles::profile1::{Profile1Handler, RtpUdpIpv4Headers};
use std::time::Duration;

let mut engine = RohcEngine::new(16, Duration::from_secs(300));
engine.register_profile_handler(Box::new(Profile1Handler::new()))?;

// Compress
let headers = RtpUdpIpv4Headers {
    ip_src: "192.168.1.10".parse()?,
    ip_dst: "192.168.1.20".parse()?,
    udp_src_port: 5004,
    udp_dst_port: 5006,
    rtp_ssrc: 0x12345678.into(),
    rtp_sequence_number: 100.into(),
    rtp_timestamp: 8000.into(),
    ..Default::default()
};

let mut buffer = [0u8; 128];
let compressed_len = engine.compress(
    0.into(),
    Some(RohcProfile::RtpUdpIp),
    &headers.into(),
    &mut buffer,
)?;

// Decompress
let decompressed = engine.decompress(&buffer[..compressed_len])?;
```

## Performance

Rohcstar includes a benchmark suite to measure and monitor performance of critical ROHC operations:
*   **Packet Parsing**: Raw parsing performance of RTP/UDP/IPv4 headers (>3 GiB/s)
*   **LSB Operations**: Core W-LSB encoding/decoding algorithms (<5 ns per operation)
*   **CRC Operations**: CRC-3 and CRC-8 calculations for packet validation (>800 MiB/s)
*   **Compression Pipeline**: Full compression workflow including packet type selection
*   **Decompression Pipeline**: Full decompression with context reconstruction
*   **Full Roundtrip**: End-to-end compression and decompression cycles (<600 ns)
*   **Context Management**: Context creation, lookup, and management overhead

### Running Benchmarks

```bash
# Quick benchmark run
./scripts/run_benchmarks.sh --quick

# Run specific benchmark group
./scripts/run_benchmarks.sh packet_parsing

# Full benchmarks with HTML reports
./scripts/run_benchmarks.sh --full --html

# Direct cargo usage
cd rohcstar && cargo bench --bench rohc_benchmarks
```

See [BENCHMARKS.md](docs/BENCHMARKS.md) for detailed performance analysis, optimization guidance, benchmark descriptions, and CI/CD integration.

## Development

### Building

```bash
cargo build --release
cargo test
cargo bench
```

### Style

See [STYLE.md](docs/STYLE.md) and [NAMING_CONVENTIONS.md](docs/NAMING_CONVENTIONS.md).

Key points:
- Correctness over performance
- Measure everything
- No premature abstractions
- Comprehensive tests required

### Contributing

1. Follow style guide strictly
2. Add tests for new features
3. Benchmark performance changes
4. Update documentation

## Documentation

- [Design](docs/DESIGN.md) - Architecture and implementation
- [Style Guide](docs/STYLE.md) - Code conventions
- [ROHC Bible](docs/THE_ROHC_BIBLE.md) - RFC reference
- [Benchmarks](docs/BENCHMARKS.md) - Performance analysis

## License

Rohcstar is licensed under the [MIT License](LICENSE).
