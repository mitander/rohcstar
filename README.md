# ROHCスター

[![LICENSE](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Rohcstar is a modern, memory-safe, and performant Rust implementation of the Robust Header Compression (ROHC) framework.**

The primary goal of Rohcstar is to provide a reliable, extensible, and thoroughly-tested library for header compression, with an initial focus on profiles critical for **LTE/5G networks (e.g., IP/UDP/RTP for VoNR, general UDP/IP traffic)** and other bandwidth-constrained or lossy wireless environments where efficient spectrum use is paramount.

Rohcstar is being built with a strong emphasis on correctness, security, and resilience against challenging link conditions. Its development is tightly coupled with its dedicated fuzzing companion [Drifter](https://github.com/mitander/drifter), ensuring continuous validation from the earliest stages.

## Vision & Philosophy

*   **RFC Adherence & Robustness:** Faithfully implement ROHC standards, focusing on robust context synchronization and recovery mechanisms under packet loss and reordering, critical for wireless network performance.
*   **Memory Safety & Security:** Leverage Rust's strengths to create a secure ROHC solution suitable for critical telecom infrastructure like 5G PDCP layers.
*   **Performance & Efficiency:** Target high compression/decompression throughput and low CPU overhead, making it suitable for embedded systems and high-volume data flows.
*   **Modularity & Testability:** Employ a clean, modular architecture for easy maintenance, extension with new ROHC profiles (e.g., ROHCv2, ROHC-TCP), and comprehensive validation.
*   **Fuzz-Driven Development:** Utilize Drifter extensively from day one to continuously test for correctness, security vulnerabilities, and protocol conformance.

## Core Features (MVP)

*   **ROHC Profiles:**
    *   **MVP:** Profile 0x0001 (RTP/UDP/IP).
    *   **Post-MVP:** Profile 0x0002 (UDP/IP), Profile 0x0003 (IP-only), Profile 0x0000 (Uncompressed).
*   **Compression Modes:**
    *   **MVP:** Unidirectional (U-mode).
    *   **Post-MVP:** Bidirectional Optimistic (O-mode), Bidirectional Reliable (R-mode).
*   **Context Management:** Robust handling of compression/decompression contexts, CID management, and state synchronization according to RFC 3095.
*   **Packet Processing:** Efficient and RFC-compliant parsing and building of ROHC packets and relevant L3/L4 headers.
*   **State Machine Implementation:** Clear and correct implementation of ROHC operational states (IR, FO, SO and NC, SC, FC) and transitions.

## Current Status (MVP)

Rohcstar is in the early stages of development. The current focus is on establishing the core architecture and implementing the MVP for ROHC Profile 1 (RTP/UDP/IP) in U-mode.

*   [ ] Detailed Design Document ([docs/DESIGN_DOCUMENT.md](docs/DESIGN_DOCUMENT.md)).
*   [ ] Core data structures for ROHC contexts and packet representations defined.
*   [ ] Initial parser/builder for Profile 1 IR and UO-0 packets.
*   [ ] Basic U-mode compressor logic for Profile 1 (IR <-> FO transitions).
*   [ ] Basic U-mode decompressor logic for Profile 1.
*   [ ] Unit tests for packet processing, LSB encoding, CRC, and state transitions.
*   [ ] Initial fuzzing harness for the decompressor using Drifter.

*(This section will be updated regularly to reflect development progress.)*

## Why Rohcstar?

In an era of ever-increasing mobile data and diverse network applications (VoNR, IoT, Industrial 5G), efficient use of constrained wireless spectrum is paramount. Robust Header Compression (ROHC) plays a critical role in reducing protocol overhead, especially for small packets common in real-time and IoT traffic, directly impacting QoS and network capacity.

Rohcstar aims to be a high-quality, open-source Rust alternative in this space, prioritizing safety, correctness, and modern development practices. It directly addresses the demanding requirements of 5G PDCP layers and other environments where robust and efficient header compression is essential.

## Design & Architecture

For a comprehensive understanding of Rohcstar's design, including its components, state machine modeling, RFC conformance strategy, testing strategy, and integration with the Drifter fuzzer, please consult the [DESIGN_DOCUMENT.md](docs/DESIGN_DOCUMENT.md).

## Integration with Drifter Fuzzer

The co-development of Rohcstar with its fuzzing counterpart, Drifter, is a core principle. Drifter will be instrumental in:
*   **Decompressor Validation:** Sending malformed, unexpected, and state-conflicting ROHC packet sequences.
*   **Compressor Validation:** Feeding diverse and edge-case uncompressed packet streams.
*   **State Machine Integrity:** Generating sequences to explore and validate ROHC state transitions and context synchronization logic rigorously.
*   **Security:** Uncovering memory safety issues, panics, and other potential vulnerabilities.
*   **Conformance Testing:** (Future) Assisting in validating against known ROHC traces and expected behaviors described in RFCs.

## License

Rohcstar is licensed under the [MIT License](LICENSE).
