# Rohcstar Design Document

## 1. Introduction

Rohcstar is a modern and memory-safe Rust implementation of the Robust Header Compression (ROHC) framework, primarily targeting RFC 3095. This document outlines its current architecture, implemented features, and future roadmap based on the existing codebase.

**Current Status:**
The project is in an early development phase. The primary focus has been on implementing **ROHC Profile 0x0001 (RTP/UDP/IP)** in **Unidirectional mode (U-mode)**. Core components like the ROHC engine, context management, error handling, and essential packet processing utilities (CRC, W-LSB encoding) are in place. Extensive integration tests for Profile 1 U-mode packet types (IR, UO-0, UO-1-SN, UO-1-TS) have been developed. Fuzz testing for the Profile 1 decompressor has begun.

## 2. Core Principles

The development of Rohcstar adheres to the following principles:

*   **RFC Adherence & Robustness:** Faithfully implement ROHC standards (initially RFC 3095), focusing on robust context synchronization and recovery mechanisms.
*   **Memory Safety & Security:** Leverage Rust's strengths to create a secure ROHC solution.
*   **Performance & Efficiency:** Target high compression/decompression throughput and low CPU overhead. Current release builds are optimized for size (`opt-level = 'z'`).
*   **Modularity & Testability:** Employ a clean, modular architecture for easy maintenance, extension with new ROHC profiles, and comprehensive validation. This is evident in the trait-based design for profile handlers and contexts.
*   **Extensive Testing:** Prioritize unit, integration, and fuzz testing to ensure correctness and robustness. `cargo-husky` is used to enforce code quality via pre-commit and pre-push hooks.
*   **Fuzz-Driven Development:** Utilize fuzzing (initially with `Drifter` in mind, and internal fuzz harnesses) from an early stage to continuously test for correctness, security vulnerabilities, and protocol conformance.

## 3. Architecture Overview

Rohcstar is designed with a modular architecture:

*   **`RohcEngine` (`src/engine.rs`):**
    *   The central orchestrator for ROHC operations.
    *   Manages a collection of `ProfileHandler` trait objects, dispatching compression/decompression tasks to the appropriate handler based on Profile ID.
    *   Owns the `ContextManager`.
    *   Handles initial parsing of incoming packets to determine CID (implicit CID 0 or via Add-CID octet) and can peek at the Profile ID from IR packets to instantiate new decompressor contexts.

*   **`ProfileHandler` Trait (`src/traits.rs`):**
    *   Defines the interface for ROHC profile implementations.
    *   Responsibilities include:
        *   Declaring the `RohcProfile` ID it handles.
        *   Creating profile-specific compressor and decompressor contexts.
        *   Implementing the core `compress` and `decompress` logic for that profile.

*   **`ContextManager` (`src/context_manager.rs`):**
    *   Stores and manages ROHC compressor and decompressor contexts.
    *   Uses `HashMap` to store `Box<dyn RohcCompressorContext>` and `Box<dyn RohcDecompressorContext>` keyed by CID.
    *   Provides methods for adding, retrieving, and removing contexts.

*   **`RohcCompressorContext` / `RohcDecompressorContext` Traits (`src/traits.rs`):**
    *   Define the basic interface for profile-specific contexts.
    *   Contexts store the state necessary for a particular compression/decompression flow.
    *   Support `as_any()` / `as_any_mut()` for downcasting to concrete types within profile handlers.

*   **Profile Implementations (`src/profiles/`):**
    *   Currently, **Profile 0x0001 (RTP/UDP/IP)** is implemented in `src/profiles/profile1/`.
    *   Each profile module contains:
        *   `handler.rs`: The `ProfileHandler` implementation.
        *   `context.rs`: Profile-specific context structs (e.g., `Profile1CompressorContext`, `Profile1DecompressorContext`) and their operational modes.
        *   `packet_types.rs`: Structs representing ROHC packet formats for the profile (e.g., `IrPacket`, `Uo0Packet`, `Uo1Packet` for Profile 1).
        *   `packet_processor.rs`: Functions for parsing and building ROHC packets of that profile.
        *   `protocol_types.rs`: Structs for the uncompressed headers the profile handles (e.g., `RtpUdpIpv4Headers`).
        *   `constants.rs`: Profile-specific constants.

*   **Error Handling (`src/error.rs`):**
    *   A dedicated `RohcError` enum, along with `RohcParsingError` and `RohcBuildingError`, is defined using `thiserror` for structured error reporting.

*   **Packet Definitions (`src/packet_defs.rs`):**
    *   Generic definitions like `RohcProfile` enum and `GenericUncompressedHeaders` enum (currently supporting `RtpUdpIpv4` and `TestRaw`).

*   **Utility Modules:**
    *   `crc.rs`: Implements ROHC CRC-3 and CRC-8.
    *   `encodings.rs`: Implements W-LSB encoding/decoding.
    *   `constants.rs`: Generic ROHC constants.

## 4. Implemented ROHC Profiles

### 4.1. Profile 0x0001 (RTP/UDP/IP - RFC 3095)

This is the primary profile currently implemented and tested.

*   **Supported Protocols:** IPv4, UDP, RTP.
*   **Supported Modes:**
    *   **Unidirectional (U-mode):** This is the currently implemented and tested mode.
*   **Implemented Packet Types (U-mode):**
    *   **IR (Initialization and Refresh):** Full static and dynamic chain transmission (`P1_ROHC_IR_PACKET_TYPE_WITH_DYN`). Static-only IR parsing is present but not actively used by the compressor.
    *   **UO-0:** Highly compressed packets (1 byte for CID 0) conveying SN LSBs.
    *   **UO-1-SN:** Conveys SN LSBs and the Marker bit.
    *   **UO-1-TS:** Conveys TS LSBs; SN is implicitly incremented.
    *   *(UO-1-ID is mentioned as a TODO in `Profile1Handler` but not yet implemented).*
*   **Compressor Context (`Profile1CompressorContext`):**
    *   **Modes:** `InitializationAndRefresh`, `FirstOrder`.
    *   Tracks static fields (IP addresses, UDP ports, SSRC).
    *   Tracks dynamic fields (last sent SN, TS, Marker).
    *   Manages IR refresh interval.
*   **Decompressor Context (`Profile1DecompressorContext`):**
    *   **Modes:** `NoContext`, `StaticContext`, `FullContext`.
    *   Stores reconstructed static and dynamic fields.
    *   Tracks W-LSB parameters (`p_sn`, `p_ts`, `expected_lsb_sn_width`, `expected_lsb_ts_width`).
    *   Manages CRC failure count for FC -> SC transitions.

## 5. Context Management

*   **Context Identification (CID):**
    *   Implicit CID 0 is supported.
    *   Small CIDs (1-15) are supported via Add-CID octet (prefix `0b1110_0000`). The engine parses this octet.
    *   Large CIDs (>15) are not currently supported for IR packet building by the `build_profile1_ir_packet` helper, though the CID field itself is `u16`.
*   **Context Storage:**
    *   `ContextManager` uses `HashMap<u16, Box<dyn RohcContextTrait>>`.
*   **Context Lifecycle:**
    *   Compressor contexts are created by the `RohcEngine` (via the `ProfileHandler`) on the first `compress` call for a new CID if a `profile_id_hint` is provided.
    *   Decompressor contexts are created by the `RohcEngine` (via the `ProfileHandler`) on the first `decompress` call for a new CID if the packet is an IR packet from which the profile can be inferred.
    *   IR packets establish/refresh context.
    *   UO packets update dynamic state within an established context.
    *   Profile 1 Decompressor transitions:
        *   NC -> FC (on successful IR).
        *   FC -> SC (on `P1_DECOMPRESSOR_FC_TO_SC_CRC_FAILURE_THRESHOLD` consecutive CRC failures for UO-0, UO-1-SN, UO-1-TS packets).
        *   SC -> NC (logic for this transition based on k2/n2 failures is defined in constants but not explicitly shown in `Profile1Handler` decompress logic yet).

## 6. Packet Processing

*   **Parsing:**
    *   `src/profiles/profile1/packet_processor.rs` contains parsers for Profile 1 IR, UO-0, UO-1-SN, and UO-1-TS packets.
    *   It also includes `parse_rtp_udp_ipv4_headers` for parsing uncompressed packets.
*   **Building:**
    *   `src/profiles/profile1/packet_processor.rs` contains builders for Profile 1 IR, UO-0, UO-1-SN, and UO-1-TS packets.
*   **CRC Calculation (`src/crc.rs`):**
    *   `calculate_rohc_crc3` (for UO-0).
    *   `calculate_rohc_crc8` (for IR, UO-1).
*   **W-LSB Encoding/Decoding (`src/encodings.rs`):**
    *   `encode_lsb` and `decode_lsb` functions are implemented for `u64` values, supporting `p_offset` and various LSB widths.
    *   `value_in_lsb_interval` for checking W-LSB window.

## 7. Error Handling

*   Custom error types are defined in `src/error.rs`:
    *   `RohcError`: Top-level error enum.
    *   `RohcParsingError`: For errors during packet parsing (e.g., `NotEnoughData`, `InvalidProfileId`, `CrcMismatch`).
    *   `RohcBuildingError`: For errors during packet construction (e.g., `BufferTooSmall`, `ContextInsufficient`).
*   `thiserror` crate is used for ergonomic error definitions.

## 8. Testing Strategy

*   **Unit Tests:** Present in most modules (e.g., `crc.rs`, `encodings.rs`, `context_manager.rs`, profile-specific modules).
*   **Integration Tests (`tests/` directory):**
    *   Extensive tests for ROHC Profile 1 U-mode operations.
    *   Dedicated files for IR (`profile1_ir_tests.rs`), UO-0 (`profile1_uo0_tests.rs`), UO-1-SN (`profile1_uo1_sn_tests.rs`), UO-1-TS (`profile1_ui1_ts_tests.rs` - *note: filename `ui1` likely means UO-1*), and general U-mode flows (`profile1_umode_flow_tests.rs`).
    *   These tests cover various scenarios, including sequence number wraparounds, marker toggling, SN jumps, CRC failures, and packet type selection logic.
    *   A common test utilities module (`tests/common/mod.rs`) provides helpers like `create_rtp_headers` and `establish_ir_context`.
*   **Fuzz Testing (`src/fuzz_harnesses.rs`):**
    *   A fuzz harness (`rohc_profile1_umode_decompressor_harness`) is implemented for the Profile 1 U-mode decompressor.
    *   This indicates an early commitment to fuzzing for robustness.

## 9. Development Practices

*   **Git Hooks:** `cargo-husky` is configured with pre-commit and pre-push hooks:
    *   `pre-commit`: Runs `cargo fmt --check`.
    *   `commit-msg`: Enforces Conventional Commits format for commit messages, including subject length and lowercase start.
    *   `pre-push`: Runs `cargo test --all` and `cargo audit`.
*   **Code Formatting:** `rustfmt` is used.
*   **Dependency Management:** `Cargo` is used.
*   **License:** MIT License.

## 10. Roadmap

### Current State

*   **ROHC Engine:** Core logic for managing profile handlers and contexts. CID parsing (implicit 0, Add-CID small CIDs).
*   **Profile 0x0001 (RTP/UDP/IP):**
    *   **U-mode:** Implemented.
    *   **Packet Types:** IR, UO-0, UO-1-SN, UO-1-TS implemented and tested.
    *   **Contexts:** `Profile1CompressorContext` (IR, FO modes) and `Profile1DecompressorContext` (NC, SC, FC modes) implemented.
*   **Context Management:** Basic CID management (0 and small CIDs 1-15).
*   **Utilities:** CRC-3/CRC-8, W-LSB encoding/decoding.
*   **Error Handling:** Custom error types implemented.
*   **Testing:** Good unit and integration test coverage for P1 U-mode. Initial fuzz harness for P1 decompressor.
*   **Development Practices:** CI/CD friendly setup with `cargo-husky`.

### Next Steps / Future Work

*   **Profile 0x0001 Enhancements:**
    *   Implement UO-1-ID packet type.
    *   Implement full state transitions for SC -> NC in decompressor (k2/n2 logic).
    *   Implement FO -> IR transitions based on LSB encoding insufficiency.
    *   Robustness improvements: Handle more edge cases, packet reordering (if applicable to U-mode handling logic), and diverse uncompressed packet streams.
*   **Other ROHC Modes for Profile 0x0001:**
    *   Bidirectional Optimistic (O-mode).
    *   Bidirectional Reliable (R-mode).
    *   This will involve implementing feedback processing.
*   **Additional ROHC Profiles:**
    *   Profile 0x0002 (UDP/IP).
    *   Profile 0x0003 (IP-only).
    *   Profile 0x0000 (Uncompressed passthrough).
    *   Profile 0x0006 (TCP/IP) - more complex.
*   **ROHCv2 (RFC 5225):** Consider support for ROHCv2 features and profiles.
*   **Performance Optimization:** Benchmark and optimize critical paths in compression/decompression.
*   **Expanded Fuzzing:**
    *   More comprehensive fuzzing for the P1 decompressor, covering all packet types and state transitions.
    *   Fuzzing for the P1 compressor.
    *   Fuzzing for other profiles as they are implemented.
*   **API Stability:** Review and stabilize the public API as features mature.
*   **Documentation:** Continue to improve internal and external documentation.
*   **Large CID Handling:** Fully implement support for large CIDs if required by target use cases.
