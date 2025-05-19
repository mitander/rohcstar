# ROHCスター

[![LICENSE](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Rohcstar is a modern, memory-safe, and performant Rust implementation of the Robust Header Compression (ROHC) framework.**

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

## Current Status

Rohcstar is currently in the early stages of development (MVP for ROHC Profile 1 (RTP/UDP/IP) in U-mode).

*   [x] **Detailed Design Document:** Initial version drafted ([docs/DESIGN_DOCUMENT.md](docs/DESIGN_DOCUMENT.md)).
*   [x] **Core Data Structures:**
    *   [x] For uncompressed L3/L4 headers (`RtpUdpIpv4Headers`).
    *   [x] For ROHC contexts (`RtpUdpIpP1CompressorContext`, `RtpUdpIpP1DecompressorContext`).
    *   [x] For internal ROHC packet representations (MVP versions of `RohcIrProfile1Packet`, `RohcUo0PacketProfile1`, `RohcUo1PacketProfile1`).
*   [x] **Packet Processing Utilities:**
    *   [x] Parser for uncompressed IPv4/UDP/RTP headers.
    *   [x] LSB encoding/decoding functions.
    *   [x] CRC-3 and CRC-8 calculation functions (using `crc` crate).
*   [x] **ROHC Packet Parsers/Builders (Profile 1, U-mode MVP):**
    *   [x] IR packet builder and parser.
    *   [x] UO-0 packet builder and parser (basic version for CID 0).
    *   [x] UO-1-SN packet builder and parser (basic version for SN and Marker bit).
*   [x] **Profile 1 U-mode Logic (MVP):**
    *   [x] Basic compressor logic (`compress_rtp_udp_ip_umode`) handling IR/FO (UO-0, UO-1-SN) transitions and IR refresh.
    *   [x] Basic decompressor logic (`decompress_rtp_udp_ip_umode`) handling IR/FO (UO-0, UO-1-SN) packets, context updates, and basic CRC verification state changes (FC->SC).
*   [x] **Context Management (MVP):**
    *   [x] `SimpleContextManager` for single CID (0) operation.
*   [x] **Unit Tests:** For packet processing, LSB encoding, CRC, context initialization, and individual profile logic components.
*   [x] **Integration Tests:** For end-to-end compress/decompress flow for IR -> UO-0/UO-1 sequences, including CID 0 and small non-zero CIDs.
*   [ ] **Initial Fuzzing Harness (Next Major Step):**
    *   [ ] Decompressor fuzz target using Drifter.

*(This section will be updated regularly to reflect development progress.)*

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
