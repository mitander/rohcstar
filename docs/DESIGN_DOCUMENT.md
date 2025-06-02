# Rohcstar Design Document

**Last Updated:** June 3, 2025

## 1. Introduction & Vision

Rohcstar is a modern, memory-safe, and high-performance Rust implementation of the Robust Header Compression (ROHC) framework (RFC 3095 and related standards).

**Core Goals:**
*   **RFC Compliance & Robustness:** Faithfully implement ROHC, prioritizing reliable context synchronization and error recovery.
*   **Memory Safety & Security:** Leverage Rust's strengths for a secure solution.
*   **Performance & Efficiency:** Target high throughput and low overhead for demanding network applications.
*   **Modularity & Testability:** Employ a clean architecture for ease of maintenance, extension, and validation.

## 2. High-Level Architecture

Rohcstar's architecture is centered around a few key components:

```
+-----------------------------------------------------------------------------------+
|                                  Application / User                               |
+------------------------------------^-----------^----------------------------------+
                                     |           |
               Uncompressed Headers  |           | ROHC Packets
        (GenericUncompressedHeaders) |           | (Vec<u8>)
                                     |           |
+------------------------------------v-----------+----------------------------------+
|                              RohcEngine (src/engine.rs)                           |
|-----------------------------------------------------------------------------------|
| - Registers ProfileHandlers                                                       |
| - Manages ContextManager/ContextStore                                             |
| - Handles CID parsing (Add-CID) & dispatch                                        |
| - Peeks Profile ID for new CIDs                                                   |
|                                                                                   |
| + compress(cid, profile_hint, headers)                                            |
| + decompress(rohc_packet_bytes)                                                   |
|                                                                                   |
| Internal Components (Conceptual/Future Refactor):                                 |
| [ PacketFramer ]  [ ProfileDispatcher ]                                           |
+-----------------|--------------------|----------------^---------------------------+
                  |                    |                | Profile Logic
                  | Context Ops        | Profile        | (compress/decompress)
                  v                    v                |
+-----------------------------------+ +---------------------------------------------+
| ContextManager / ContextStore     | | ProfileHandler Trait (src/traits.rs)        |
| (src/context_manager.rs)          | |---------------------------------------------|
|-----------------------------------| | - Implemented by:                           |
| - Stores CompressorContexts       | |   - Profile1Handler (src/profiles/profile1) |
| - Stores DecompressorContexts     | |   - ProfileXHandler ...                     |
| - (Future: Optimized Storage,     | | - Owns profile-specific logic, packet types,|
|   Timeouts)                       | |   state machines, context definitions.      |
+-----------------------------------+ +---------------------------------------------+
                                                 |
                                                 | Uses
                                                 v
+-----------------------------------------------------------------------------------+
| Core Utilities:                                                                   |
| - Packet Definitions (src/packet_defs.rs, profiles/.../packet_types.rs)           |
| - Packet Processors (profiles/.../packet_processor.rs)                            |
| - Encodings (src/encodings.rs - W-LSB)                                            |
| - CRC (src/crc.rs - CRC-3, CRC-8)                                                 |
+-----------------------------------------------------------------------------------+
```

1.  **`RohcEngine`:**
    *   The primary public interface and orchestrator.
    *   Manages `ProfileHandler` registration and `ContextManager`.
    *   Handles CID detection (Add-CID octets, implicit CID 0) and dispatch to appropriate handlers.
    *   Responsible for context creation calls.

2.  **`ProfileHandler` Trait:**
    *   An interface defining the contract for specific ROHC profile implementations (e.g., Profile 1 for RTP/UDP/IP).
    *   Each profile handler implements `compress()`, `decompress()`, and context creation methods.

3.  **Compressor & Decompressor Contexts:**
    *   Stateful objects (e.g., `Profile1CompressorContext`) that store all necessary information for a single compression/decompression flow (per CID).
    *   Include static fields (IPs, ports, SSRC) and dynamic fields (last SN, TS, IP-ID, LSB parameters, operational mode, TS Stride info).

4.  **`ContextManager`:**
    *   Manages the storage, retrieval, and lifecycle (including timeouts) of all active contexts.
    *   Currently uses `HashMap`, with plans for optimized storage (e.g., array for small CIDs, hybrid model).

5.  **Packet Processing Modules:**
    *   **`packet_defs.rs`:** Generic definitions like `RohcProfile` and `GenericUncompressedHeaders`.
    *   **`profiles::profileX::packet_types.rs`:** Structs representing ROHC-specific packet formats (e.g., `IrPacket`, `Uo0Packet`).
    *   **`profiles::profileX::packet_processor.rs`:** Low-level functions for parsing and building ROHC packets and uncompressed headers.
    *   **`encodings.rs`:** Core encoding schemes like W-LSB.
    *   **`crc.rs`:** ROHC-specific CRC-3 and CRC-8 calculations, including `CrcCalculators` for reuse.

## 3. Profile 1 (RTP/UDP/IP) U-Mode Implementation (MVP Focus)

### 3.1. Context (`profiles::profile1::context.rs`)

*   **`Profile1CompressorContext`:** Tracks last sent SN, TS, Marker, IP-ID, SSRC, static IPs/ports, current LSB widths, `p` offsets, IR refresh counters, TS Stride/Scaled mode parameters, and operational mode (IR, FO, SO).
*   **`Profile1DecompressorContext`:** Tracks last reconstructed SN, TS, Marker, IP-ID, SSRC, static IPs/ports, expected LSB widths, `p` offsets, operational mode (NC, SC, FC, SO), TS Stride/Scaled mode parameters, and state transition counters (CRC failures, success streaks, confidence levels).

### 3.2. Packet Types & Processing

*   **IR (Initialization/Refresh):**
    *   Used for context establishment and refresh.
    *   Carries static chain (IPs, ports, SSRC) and optional dynamic chain (SN, TS, Marker, TS_STRIDE extension).
    *   CRC-8 protected.
    *   Handled by `build_profile1_ir_packet` and `parse_profile1_ir_packet`.
*   **UO-0 (Optimistic Type 0):**
    *   Highly compressed (1 byte for CID 0).
    *   Carries 4 LSBs of SN and 3-bit CRC.
    *   TS is implicitly reconstructed (potentially using context's TS stride), Marker, and IP-ID are implicit from context.
    *   Handled by `build_profile1_uo0_packet` and `parse_profile1_uo0_packet`.
*   **UO-1 (Optimistic Type 1):**
    *   More robust updates. CRC-8 protected.
    *   **UO-1-SN:** Carries LSBs of SN (typically 8 bits) and current Marker bit. TS is implicitly reconstructed (potentially using context's TS stride).
    *   **UO-1-TS:** Carries LSBs of TS (typically 16 bits). SN is implicit (SN_ref + 1). Marker implicit.
    *   **UO-1-ID:** Carries LSBs of IP-ID (typically 8 bits). SN is implicit (SN_ref + 1). TS, Marker implicit (TS potentially using context's TS stride).
    *   **UO-1-RTP:** Carries TS_SCALED and current Marker bit. SN is implicit (SN_ref + 1). Relies on established TS stride.
    *   Handled by `build_profile1_uo1_*_packet` and `parse_profile1_uo1_*_packet` variants.

### 3.3. State Machines (RFC 3095, Section 5.3)

*   **Compressor (U-mode):** IR → FO → SO
    *   **IR (Initialization & Refresh):** Sends IR/IR-DYN. Triggered by: new flow, SSRC change, refresh interval, significant context desync (e.g., LSB insufficiency).
    *   **FO (First Order):** Sends UO-0, UO-1 packets. Transitions to SO after a number of successful FO packets.
    *   **SO (Second Order):** Sends optimized UO packets. Maintains high confidence.
*   **Decompressor (U-mode):** NC → SC → FC → SO (and fallbacks)
    *   **NC (No Context):** Only accepts IR packets to move to FC.
    *   **SC (Static Context):** Static part known. Needs IR or specific UO-1 to move to FC or update. Persistent errors lead to NC.
    *   **FC (Full Context):** Full context known. Processes UO-0, UO-1. Errors lead to SC. Consecutive successes can lead to SO.
    *   **SO (Second Order):** Highest confidence. Processes UO-0, UO-1. Errors or low confidence lead to NC. IR leads to FC.

## 4. Key Algorithms

*   **W-LSB (Window-based Least Significant Bits):** (RFC 3095, Sec 4.5) Used for encoding/decoding SN, TS, IP-ID. Implemented in `src/encodings.rs`.
*   **CRC-3/ROHC & CRC-8/ROHC:** (RFC 3095, Sec 5.9) For packet integrity. Implemented in `src/crc.rs` (with `CrcCalculators` for reuse).

## 5. Immediate Enhancements & Future Architectural Goals

This section outlines both immediate priorities currently underway and longer-term architectural vision.

### 5.1. Immediate Priorities
*   **Enhanced Type Safety:** Introduce newtypes for critical identifiers like `ContextId`, `SequenceNumber` (Note: `Timestamp` is already implemented).
*   **Performance Optimizations:**
    *   Explore advanced buffer pooling strategies for packet `Vec<u8>`s.
    *   Benchmark and refine CRC calculation paths (reuse is in place, further optimization may be possible).
*   **Formalize Conventions:** Ensure `NAMING_CONVENTIONS.md` is comprehensive and strictly followed.
*   **Expand Test Coverage:** Continue to enhance unit, integration, and fuzz testing, especially for state transitions and error recovery paths.

### 5.2. Post-MVP / Future Enhancements
*   **Performance:**
    *   Further optimize header parsing pathways.
*   **Engine Architecture:**
    *   Consider further `RohcEngine` decomposition into logical units like `PacketFramer`, `ProfileDispatcher` if complexity warrants.
*   **Context Storage:**
    *   Optimize `ContextManager` with hybrid array/HashMap storage based on CID ranges.
*   **Error Handling:**
    *   Introduce richer `ErrorContext` within `RohcError` for improved diagnostics.
*   **Configuration:**
    *   Develop a central `RohcConfig` mechanism for engine and profile tuning.
*   **Observability:**
    *   Integrate optional metrics collection for performance monitoring and operational insights.

## 6. Testing Strategy

*   **Unit Tests:** (`#[cfg(test)] mod tests`) for individual functions and components.
*   **Integration Tests:** (`tests/` directory) for end-to-end flows and component interactions for Profile 1 U-mode.
*   **Property-Based Tests:** For encoding/decoding logic (e.g., using `proptest`).
*   **Deterministic Simulations (`rohcstar-sim`):** Custom simulator in the `rohcstar-sim` crate for validating complex state transitions, different packet sequences, and channel conditions (loss).
*   **Fuzz Testing:**
    *   **Harnesses:** `src/fuzz_harnesses.rs` provides integration points for fuzzing specific components, primarily the decompressor.
    *   **External Fuzzers (e.g., Drifter):** Planned deeper integration with stateful network protocol fuzzers like Drifter for advanced robustness and security testing.
