# Rohcstar Design Document

**Last Updated:** May 27, 2025

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
    *   Include static fields (IPs, ports, SSRC) and dynamic fields (last SN, TS, IP-ID, LSB parameters, operational mode).

4.  **`ContextManager` (or `ContextStore`):**
    *   Manages the storage, retrieval, and lifecycle (including timeouts - *MVP TODO*) of all active contexts.
    *   Currently uses `HashMap`, with plans for optimized storage (e.g., array for small CIDs, hybrid model).

5.  **Packet Processing Modules:**
    *   **`packet_defs.rs`:** Generic definitions like `RohcProfile` and `GenericUncompressedHeaders`.
    *   **`profiles::profileX::packet_types.rs`:** Structs representing ROHC-specific packet formats (e.g., `IrPacket`, `Uo0Packet`).
    *   **`profiles::profileX::packet_processor.rs`:** Low-level functions for parsing and building ROHC packets and uncompressed headers.
    *   **`encodings.rs`:** Core encoding schemes like W-LSB.
    *   **`crc.rs`:** ROHC-specific CRC-3 and CRC-8 calculations.

## 3. Profile 1 (RTP/UDP/IP) U-Mode Implementation (MVP Focus)

### 3.1. Context (`profiles::profile1::context.rs`)

*   **`Profile1CompressorContext`:** Tracks last sent SN, TS, Marker, IP-ID, SSRC, static IPs/ports, current LSB widths, `p` offsets, IR refresh counters, and operational mode (IR, FO, SO).
*   **`Profile1DecompressorContext`:** Tracks last reconstructed SN, TS, Marker, IP-ID, SSRC, static IPs/ports, expected LSB widths, `p` offsets, operational mode (NC, SC, FC, SO), and state transition counters (CRC failures, success streaks, confidence levels).

### 3.2. Packet Types & Processing

*   **IR (Initialization/Refresh):**
    *   Used for context establishment and refresh.
    *   Carries static chain (IPs, ports, SSRC) and optional dynamic chain (SN, TS, Marker).
    *   CRC-8 protected.
    *   Handled by `build_profile1_ir_packet` and `parse_profile1_ir_packet`.
*   **UO-0 (Optimistic Type 0):**
    *   Highly compressed (1 byte for CID 0).
    *   Carries 4 LSBs of SN and 3-bit CRC.
    *   TS, Marker, IP-ID are implicit from context.
    *   Handled by `build_profile1_uo0_packet` and `parse_profile1_uo0_packet`.
*   **UO-1 (Optimistic Type 1):**
    *   More robust updates. CRC-8 protected.
    *   **UO-1-SN:** Carries LSBs of SN (typically 8 bits) and current Marker bit. TS implicit.
    *   **UO-1-TS:** Carries LSBs of TS (typically 16 bits). SN is implicit (SN_ref + 1). Marker implicit.
    *   **UO-1-ID:** Carries LSBs of IP-ID (typically 8 bits). SN is implicit (SN_ref + 1). TS, Marker implicit.
    *   Handled by `build_profile1_uo1_*_packet` and `parse_profile1_uo1_*_packet` variants.

### 3.3. State Machines (RFC 3095, Section 5.3)

*   **Compressor (U-mode):** IR → FO → SO
    *   **IR (Initialization & Refresh):** Sends IR/IR-DYN. Triggered by: new flow, SSRC change, refresh interval, significant context desync (LSB insufficiency - *MVP TODO*).
    *   **FO (First Order):** Sends UO-0, UO-1 packets. Transitions to SO after a number of successful FO packets.
    *   **SO (Second Order):** Sends optimized UO packets. Maintains high confidence.
*   **Decompressor (U-mode):** NC → SC → FC → SO (and fallbacks)
    *   **NC (No Context):** Only accepts IR packets to move to FC.
    *   **SC (Static Context):** Static part known. Needs IR or specific UO-1 to move to FC or update. Persistent errors lead to NC.
    *   **FC (Full Context):** Full context known. Processes UO-0, UO-1. Errors lead to SC. Consecutive successes can lead to SO.
    *   **SO (Second Order):** Highest confidence. Processes UO-0, UO-1. Errors or low confidence lead to NC. IR leads to FC.

## 4. Key Algorithms

*   **W-LSB (Window-based Least Significant Bits):** (RFC 3095, Sec 4.5) Used for encoding/decoding SN, TS, IP-ID. Implemented in `src/encodings.rs`.
*   **CRC-3/ROHC & CRC-8/ROHC:** (RFC 3095, Sec 5.9) For packet integrity. Implemented in `src/crc.rs`.

## 5. Future Architectural Enhancements (Post-MVP)

*   **Type Safety:** Introduce newtypes for `ContextId`, `SequenceNumber`, `Timestamp`, etc.
*   **Performance Optimizations:**
    *   CRC calculator reuse.
    *   Buffer pooling for packet `Vec<u8>`s.
    *   Optimized header parsing (currently a bottleneck).
*   **Engine Decomposition:** Split `RohcEngine` into `PacketFramer`, `ProfileDispatcher`, `ContextStore`.
*   **Context Storage Optimization:** Hybrid array/HashMap `ContextStore`.
*   **Error Handling:** Richer `ErrorContext` in `RohcError`.
*   **Configuration Management:** Central `RohcConfig`.
*   **Observability:** Optional metrics collection.

## 6. Testing Strategy

*   **Unit Tests:** (`#[cfg(test)] mod tests`) for individual functions and components.
*   **Integration Tests:** (`tests/` directory) for end-to-end flows and component interactions for Profile 1 U-mode.
*   **Property-Based Tests:** For encoding/decoding logic (`proptest`).
*   **Fuzz Testing:** (External tool: Drifter) for decompressor robustness and state machine validation. `src/fuzz_harnesses.rs` provides integration points.
*   **Deterministic Simulations:** For validating complex state transitions under specific sequences.
