# ROHCスター

[![LICENSE](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

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

## Core Features (Conceptual / In Development)

*   **ROHC Profiles:**
    *   **MVP:** Profile 0x0001 (RTP/UDP/IP).
    *   **Post-MVP:** Profile 0x0002 (UDP/IP), Profile 0x0003 (IP-only), Profile 0x0000 (Uncompressed).
*   **Compression Modes:**
    *   **MVP:** Unidirectional (U-mode).
    *   **Post-MVP:** Bidirectional Optimistic (O-mode), Bidirectional Reliable (R-mode).
*   **Context Management:** Robust handling of compression/decompression contexts, CID management, and state synchronization according to RFC 3095.
*   **Packet Processing:** Efficient and RFC-compliant parsing and building of ROHC packets and relevant L3/L4 headers.
*   **State Machine Implementation:** Clear and correct implementation of ROHC operational states (IR, FO, SO and NC, SC, FC) and transitions.

## Design

For a in-depth understanding of Rohcstar's architecture, components and roadmap, please refer to the [DESIGN_DOCUMENT.md](docs/DESIGN_DOCUMENT.md).

## Integration with Drifter Fuzzer

The co-development of Rohcstar with its fuzzing counterpart, [Drifter](https://github.com/mitander/drifter), is a core principle and will be instrumental in:
*   **Decompressor Validation:** Sending malformed, unexpected, and state-conflicting ROHC packet sequences.
*   **Compressor Validation:** Feeding diverse and edge-case uncompressed packet streams.
*   **State Machine Integrity:** Generating sequences to explore and validate ROHC state transitions and context synchronization logic rigorously.
*   **Security:** Uncovering memory safety issues, panics, and other potential vulnerabilities.
*   **Conformance Testing:** (Future) Assisting in validating against known ROHC traces and expected behaviors described in RFCs.

## License

Rohcstar is licensed under the [MIT License](LICENSE).
