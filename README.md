# ROHCスター

[![LICENSE](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
<!-- TODO: Add CI Status Badge when available: [![CI Status](https://github.com/your_username/rohcstar/actions/workflows/rust.yml/badge.svg)](https://github.com/your_username/rohcstar/actions) -->

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

## Basic Usage

```rust
use rohcstar::{RohcEngine, GenericUncompressedHeaders, RohcProfile};
use rohcstar::profiles::profile1::{Profile1Handler, RtpUdpIpv4Headers, Timestamp};
use std::net::Ipv4Addr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Create an engine
    let mut engine = RohcEngine::new(20); // Default IR refresh interval

    // 2. Register a profile handler
    engine.register_profile_handler(Box::new(Profile1Handler::new()))?;

    // 3. Prepare uncompressed headers (example for Profile 1)
    let uncompressed_rtp_headers = RtpUdpIpv4Headers {
        ip_src: "192.168.1.10".parse().unwrap(),
        ip_dst: "192.168.1.20".parse().unwrap(),
        udp_src_port: 10010,
        udp_dst_port: 20020,
        rtp_ssrc: 0x12345678,
        rtp_sequence_number: 100,
        rtp_timestamp: Timestamp::new(1000),
        rtp_marker: false,
        // ... other fields can be defaulted or set explicitly
        ..Default::default()
    };
    let generic_headers = GenericUncompressedHeaders::RtpUdpIpv4(uncompressed_rtp_headers.clone());

    // 4. Compress
    let cid = 0u16; // Context ID
    let compressed_packet = engine.compress(cid, Some(RohcProfile::RtpUdpIp), &generic_headers)?;
    println!("Compressed packet length: {}", compressed_packet.len());

    // 5. Decompress
    let decompressed_headers_generic = engine.decompress(&compressed_packet)?;

    if let Some(rtp_headers_out) = decompressed_headers_generic.as_rtp_udp_ipv4() {
        assert_eq!(rtp_headers_out.rtp_ssrc, uncompressed_rtp_headers.rtp_ssrc);
        assert_eq!(rtp_headers_out.rtp_sequence_number, uncompressed_rtp_headers.rtp_sequence_number);
        println!("Decompression successful, SN matched: {}", rtp_headers_out.rtp_sequence_number);
    } else {
        eprintln!("Decompression failed or returned unexpected header type.");
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

## Design

For an in-depth understanding of Rohcstar's architecture, components, and roadmap, please refer to the [DESIGN_DOCUMENT.md](docs/DESIGN_DOCUMENT.md).

## License

Rohcstar is licensed under the [MIT License](LICENSE).
