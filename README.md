# ROHCスター

[![LICENSE](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI Status](https://github.com/mitander/rohcstar/actions/workflows/ci.yml/badge.svg)](https://github.com/mitander/rohcstar/actions)

**Rohcstar is a modern and memory-safe Rust implementation of the Robust Header Compression (ROHC) framework.**

> [!WARNING]
> This ROHC implementation is in early development phase.
> The API is unstable, features are incomplete, and breaking changes should be expected.

## Vision & Philosophy

*   **RFC Adherence & Robustness:** Faithfully implement ROHC standards, focusing on robust context synchronization and recovery mechanisms under packet loss and reordering, critical for wireless network performance.
*   **Memory Safety & Security:** Leverage Rust's strengths to create a secure ROHC solution suitable for critical telecom infrastructure like 5G PDCP layers.
*   **Performance & Efficiency:** Target high compression/decompression throughput and low CPU overhead, making it suitable for embedded systems and high-volume data flows.
*   **Modularity & Testability:** Employ a clean, modular architecture for easy maintenance, extension with new ROHC profiles (e.g., ROHCv2, ROHC-TCP), and comprehensive validation.
*   **Fuzz-Driven Development:** Utilize Drifter extensively from day one to continuously test for correctness, security vulnerabilities, and protocol conformance.

## Current Status

*   **Profile 0x0001 (RTP/UDP/IP) Unidirectional Mode:**
    *   [✓] Full compression and decompression support for all packet types:
        *   IR (Initialization and Refresh)
        *   IR-DYN (Dynamic chain, including TS_STRIDE signaling)
        *   UO-0 (Smallest UO packet)
        *   UO-1-SN (Sequence Number)
        *   UO-1-TS (Timestamp)
        *   UO-1-ID (IP Identification)
        *   UO-1-RTP (Scaled Timestamp)
    *   [✓] Robust decompressor state machine (NC, SC, FC, SO transitions).
    *   [✓] TS_STRIDE detection and handling for efficient timestamp compression.
    *   [✓] Context management with CID handling and activity-based timeouts.
    *   [✓] Comprehensive test suite covering core functionality and edge cases.
    *   [✓] Basic fuzzing harness integrated for robustness testing.

## Core Features

*   **ROHC Profiles:**
    *   **Implemented (U-mode):** Profile 0x0001 (RTP/UDP/IP).
    *   **Planned:** Profile 0x0002 (UDP/IP), Profile 0x0003 (IP-only), Profile 0x0000 (Uncompressed).
*   **Compression Modes:**
    *   **Implemented:** Unidirectional (U-mode) for Profile 1.
    *   **Planned:** Bidirectional Optimistic (O-mode), Bidirectional Reliable (R-mode).
*   **Context Management:** Robust handling of compression/decompression contexts, CID management, and state synchronization according to RFC 3095.
*   **Packet Processing:** Efficient and RFC-compliant parsing and building of ROHC packets and relevant L3/L4 headers.
*   **State Machine Implementation:** Clear and correct implementation of ROHC operational states (IR, FO, SO and NC, SC, FC, SO) and transitions.

## Performance Benchmarking

Rohcstar includes a comprehensive benchmark suite to measure and monitor performance of critical ROHC operations:

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

## Basic Usage

```rust
use rohcstar::packet_defs::GenericUncompressedHeaders;
use rohcstar::profiles::profile1::{Profile1Handler, RtpUdpIpv4Headers};
use rohcstar::time::SystemClock;
use rohcstar::{EngineError, RohcEngine, RohcProfile};
use std::sync::Arc;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a ROHC engine
    let mut engine = RohcEngine::new(
        20,                       // IR refresh interval
        Duration::from_secs(300), // Context timeout
        Arc::new(SystemClock),    // Clock implementation
    );

    // Register Profile 1 handler for RTP/UDP/IP compression
    engine.register_profile_handler(Box::new(Profile1Handler::new()))?;

    // Create headers to compress
    let headers = RtpUdpIpv4Headers {
        ip_src: "192.168.1.10".parse().unwrap(),
        ip_dst: "192.168.1.20".parse().unwrap(),
        udp_src_port: 10010,
        udp_dst_port: 20020,
        rtp_ssrc: 0x12345678.into(),
        rtp_sequence_number: 100.into(),
        rtp_timestamp: 1000.into(),
        ..Default::default()
    };
    let generic_headers = GenericUncompressedHeaders::RtpUdpIpv4(headers);

    // Compress packet
    let mut compressed_buf = [0u8; 128];
    let compressed_len = engine.compress(
        0.into(),                    // Context ID
        Some(RohcProfile::RtpUdpIp), // Profile hint
        &generic_headers,
        &mut compressed_buf,
    )?;
    let compressed_packet = &compressed_buf[..compressed_len];
    println!("Compressed packet: {} bytes", compressed_len);

    // Decompress packet - graceful packet loss handling
    match engine.decompress(compressed_packet) {
        Ok(decompressed_headers) => {
            println!("Decompressed headers: {:#?}", decompressed_headers);
        }
        Err(rohcstar::RohcError::Engine(EngineError::PacketLoss { .. })) => {
            todo!("handle packet loss")
        }
        Err(e) => {
            panic!("failed to decompress: {e} ");
        }
    }

    Ok(())
}
```

## Integration with Drifter Fuzzer

The co-development of Rohcstar with its fuzzing counterpart, [Drifter](https://github.com/mitander/drifter), is a core principle and will be instrumental in:
*   **Decompressor Validation:** Sending malformed, unexpected, and state-conflicting ROHC packet sequences.
*   **Compressor Validation:** Feeding diverse and edge-case uncompressed packet streams.
*   **State Machine Integrity:** Generating sequences to explore and validate ROHC state transitions and context synchronization logic rigorously.
*   **Security:** Uncovering memory safety issues, panics, and other potential vulnerabilities.
*   **Conformance Testing:** (Future) Assisting in validating against known ROHC traces and expected behaviors described in RFCs.

## Documentation

*   **[Design Document](docs/DESIGN_DOCUMENT.md)** - Detailed architecture, components, and roadmap
*   **[The ROHC Bible](docs/THE_ROHC_BIBLE.md)** - Comprehensive ROHC protocol reference and implementation guide
*   **[Style Guide](docs/STYLE.md)** - Code conventions and development standards
*   **[Benchmarks](docs/BENCHMARKS.md)** - Performance analysis and optimization guidance

## License

Rohcstar is licensed under the [MIT License](LICENSE).
