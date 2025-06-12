# Rohcstar Design

## Overview

Rohcstar implements ROHC (RFC 3095) - a protocol for compressing IP/UDP/RTP headers from 40-60 bytes down to 1-3 bytes. Built with focus on correctness, performance, and maintainability.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Application                      │
└────────────────────────┬────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────┐
│                   RohcEngine                        │
│  - Profile registration and dispatch                │
│  - Context management (create, lookup, timeout)     │
│  - CID parsing and packet routing                   │
└────────────┬─────────────────────┬──────────────────┘
             │                     │
┌────────────▼──────────┐  ┌───────▼──────────────────┐
│   ContextManager      │  │   ProfileHandler trait   │
│ - Context storage     │  │ - Profile-specific logic │
│ - Timeout handling    │  │ - Packet serialization   │
│ - CID allocation      │  │ - State machines         │
└───────────────────────┘  └──────────────────────────┘
```

### Core Components

**RohcEngine**: API entry point. Routes packets to correct profile handler.

**ProfileHandler**: Interface for compression profiles. Each profile implements:
- `compress()`: Headers → ROHC packet
- `decompress()`: ROHC packet → Headers
- Context creation and state management

**Context System**: Per-stream state tracking
- Static fields: IPs, ports, SSRC
- Dynamic state: SN, TS, modes, counters
- Automatic cleanup on timeout

### Design Principles

1. **Zero-allocation packet processing**: Pre-allocate everything
2. **Profile isolation**: Each profile is independent
3. **Explicit state machines**: Clear transitions, no implicit behavior
4. **Measured performance**: Benchmark everything

## Profile 1 Implementation

### Packet Types

All RFC 3095 Profile 1 packets implemented:
- **IR/IR-DYN**: Context initialization
- **UO-0**: 1-byte minimal update
- **UO-1 variants**: 2-byte updates (SN/TS/ID/RTP)

### State Machines

**Compressor**:
- IR → FO → SO (increasing compression)
- Periodic refresh to maintain sync

**Decompressor**:
- NC → SC → FC → SO (increasing confidence)
- CRC failures trigger transitions

### Key Algorithms

**W-LSB Encoding**: Window-based compression for SN/TS/IP-ID
- Optimal k-bit selection
- Wraparound handling

**TS_STRIDE**: Timestamp compression via linear prediction
- Automatic detection
- Fallback on irregularities

## Testing Strategy

**Unit Tests**: Component isolation, high coverage

**Integration Tests**: Full compression/decompression flows

**Deterministic Simulation**: Reproducible testing of complex scenarios
- Fixed RNG seeds
- Controlled packet loss patterns
- Predictable timing

**Fuzzing**: Continuous testing with Drifter
- Malformed packet sequences
- State machine exploration
- Memory safety validation

## Performance

Current benchmarks (Apple M1):
- Packet parsing: >3 GiB/s
- Full roundtrip: <600ns
- Zero allocations in hot path

See BENCHMARKS.md for detailed analysis.

## Future Work

1. Additional profiles (0x0002 UDP/IP, 0x0003 ESP/IP)
2. Bidirectional modes (O-mode, R-mode)
3. ROHCv2 support
4. Hardware acceleration hooks
