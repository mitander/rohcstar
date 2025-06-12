# Rohcstar Design Document

## 1. Architecture Overview

Rohcstar is a production-ready ROHC implementation focusing on correctness, performance, and maintainability.

**Design Principles:**

- **Correctness:** RFC-compliant with robust state machines and comprehensive error handling
- **Performance:** Zero-allocation packet processing with measured >3 GiB/s throughput
- **Simplicity:** Clean, obvious code over clever abstractions
- **Extensibility:** Modular profile system for easy addition of new ROHC profiles

**See also:**

- [STYLE.md](STYLE.md) for code and documentation standards
- [NAMING_CONVENTIONS.md](NAMING_CONVENTIONS.md) for strict naming rules

## 2. Component Architecture

The system is built around focused, single-responsibility components:

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
| - Serialization Modules (profiles/.../serialization/*)                            |
| - Encodings (src/encodings.rs - W-LSB)                                            |
| - CRC (src/crc.rs - CRC-3, CRC-8)                                                 |
+-----------------------------------------------------------------------------------+
```

**Core Components:**

1. **`RohcEngine`** - Main API orchestrating compression/decompression
   - Profile handler registration and management
   - CID detection and packet dispatch
   - Context lifecycle management
2. **`ProfileHandler`** - Extensible interface for ROHC profiles
   - Profile-specific compression/decompression logic
   - Context creation and management
   - State machine implementation
3. **Context System** - Per-CID state tracking
   - `CompressorContext`: Static fields (IPs, ports) and dynamic state (SN, TS, modes)
   - `DecompressorContext`: Reconstruction state and confidence tracking
   - Automatic timeout and cleanup
4. **Modular Serialization** - Focused packet processing
   - `ir_packets.rs`: IR/IR-DYN packet handling
   - `uo0_packets.rs`: UO-0 packet processing
   - `uo1_packets.rs`: UO-1 variant processing
   - `headers.rs`: Uncompressed header parsing
5. **Core Utilities**
   - `encodings.rs`: W-LSB algorithms with window management
   - `crc.rs`: CRC-3/CRC-8 with reusable calculators
   - `types.rs`: Type-safe wrappers for primitives

## 3. Profile 1 Implementation (Complete)

### 3.1. Context Management

**`Profile1CompressorContext`:**

- Static fields: IP addresses, UDP ports, SSRC
- Dynamic state: Last SN/TS/IP-ID, operational mode (IR/FO/SO)
- Optimization state: LSB widths, TS stride detection, IR refresh counters
  **`Profile1DecompressorContext`:**
- Reconstruction state: Expected values, LSB parameters
- Operational mode: NC/SC/FC/SO with transition logic
- Confidence tracking: CRC success/failure counters, state confidence

### 3.2. Packet Types (All Implemented)

**IR/IR-DYN Packets:**

- Context establishment and refresh
- Static chain (IPs, ports, SSRC) + dynamic chain (SN, TS, extensions)
- CRC-8 protection, TS_STRIDE signaling support
  **UO-0 Packets:**
- Minimal 1-byte format (CID 0)
- 4-bit SN LSBs + 3-bit CRC
- Implicit TS/marker reconstruction using stride
  **UO-1 Variants:**
- **UO-1-SN**: 8-bit SN LSBs + marker, implicit TS via stride
- **UO-1-TS**: 16-bit TS LSBs, implicit SN increment
- **UO-1-ID**: 8-bit IP-ID LSBs, implicit SN/TS
- **UO-1-RTP**: TS_SCALED + marker for established stride contexts

### 3.3. State Machine Implementation

**Compressor States (U-mode):**

- **IR**: Context establishment, triggered by new flows or refresh intervals
- **FO**: Mixed packet types, building confidence
- **SO**: Optimized packets with established patterns
  **Decompressor States (U-mode):**
- **NC**: No context, accepts only IR packets
- **SC**: Static context known, limited packet acceptance
- **FC**: Full context, processes all packet types
- **SO**: High confidence, optimal processing
  State transitions managed by dedicated modules with clear event handling and counter management.

### 3.4. Implementation Modules

- **`state_machine.rs`**: Core processing logic per decompressor mode
- **`state_transitions.rs`**: Event-driven transition logic with counters
- **`state_types.rs`**: Type-safe state and counter definitions
- **`discriminator.rs`**: Packet type identification and routing

## 4. Core Algorithms

**W-LSB Encoding (RFC 3095 Section 4.5):**

- Window-based LSB encoding/decoding for SN, TS, IP-ID
- Optimized window calculations with wraparound handling
- Configurable interpretation intervals
  **CRC Protection (RFC 3095 Section 5.9):**
- CRC-3 for UO-0 packets, CRC-8 for others
- Reusable calculators for performance
- Recovery algorithms for error detection

## 5. Current Status & Future Roadmap

### 5.1. Completed Features

- **Type Safety**: Newtype wrappers for all primitives (`ContextId`, `SequenceNumber`, etc.)
- **Zero-Allocation Processing**: Stack-allocated buffers, reusable CRC calculators
- **Modular Architecture**: Focused serialization modules with clear separation of concerns
- **Defensive Programming**: Comprehensive bounds checking and strategic assertions
- **Performance Optimization**: >3 GiB/s parsing, <600ns roundtrip measured
- **Documentation**: Complete API documentation following established conventions

### 5.2. Future Enhancements

- **Additional Profiles**: Profile 0/2/3 implementation
- **Bidirectional Modes**: O-mode and R-mode support
- **Context Optimization**: Hybrid storage for improved CID lookup performance
- **Advanced Observability**: Optional metrics collection for production monitoring

## 6. Testing & Validation

**Comprehensive Test Coverage:**

- **Unit Tests**: Individual component validation with >90% coverage
- **Integration Tests**: End-to-end Profile 1 U-mode flows
- **Property-Based Tests**: LSB encoding/decoding invariants
- **State Machine Tests**: Complete transition coverage
  **Robustness Validation:**
- **Deterministic Simulation**: Custom simulator (`rohcstar-sim`) for complex scenarios
- **Fuzzing Integration**: Built-in harnesses + Drifter co-development
- **Performance Testing**: Continuous benchmarking with regression detection
  **Production Readiness:**
- Comprehensive error handling with graceful degradation
- Memory safety guarantees through Rust's type system
- Deterministic behavior under packet loss conditions
