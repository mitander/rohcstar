# Rohcstar - Design Summary

## Architecture Overview

A high-performance ROHC (Robust Header Compression) implementation focused on zero-allocation packet processing and RFC 3095 compliance.

### Core Components

```
ROHC Engine      → Profile dispatch, context management, CID parsing
Profile Handlers → Compression/decompression logic, packet selection
Context Manager  → Per-flow state, timeout handling, CID allocation
CRC System      → Packet integrity verification, pre-allocated calculators
Encoding Layer  → W-LSB encoding/decoding, optimized hot paths
Serialization   → Packet marshaling/unmarshaling, zero-copy where possible
```

## Key Design Decisions

### 1. Zero-Allocation Packet Processing

**Choice**: Pre-allocated buffers and object pools for all hot paths.

**Implementation**:

```rust
pub struct RohcEngine {
    // Pre-allocated at startup
    compression_buffer: Box<[u8; MAX_ROHC_PACKET_SIZE]>,
    decompression_buffer: Box<[u8; MAX_UNCOMPRESSED_SIZE]>,
    crc_workspace: Box<[u8; CRC_WORKSPACE_SIZE]>,

    // Object pools for concurrent operations
    crc_calculators: Pool<CrcCalculators>,
}
```

**Rationale**: ROHC processors handle millions of packets per second in network equipment. Any allocation in the packet processing path destroys performance.

### 2. Module Organization by Complexity

**Choice**: Deep modules for complex domains, shallow for utilities.

```
src/
├── engine.rs                    # Shallow: API orchestration
├── context_manager.rs           # Shallow: Simple state management
├── crc.rs                      # Shallow: Utility functions
├── profiles/                   # Deep: Complex compression logic
│   ├── profile1/
│   │   ├── mod.rs              # Public API only
│   │   ├── engine.rs           # Core compression orchestration
│   │   ├── compression/        # Deep: Complex compression subsystem
│   │   │   ├── mod.rs
│   │   │   ├── ir_packets.rs
│   │   │   ├── uo_packets.rs
│   │   │   └── packet_selection.rs
│   │   ├── decompression/      # Deep: Complex decompression subsystem
│   │   │   ├── mod.rs
│   │   │   ├── state_machine.rs
│   │   │   ├── packet_parsing.rs
│   │   │   └── recovery.rs
│   │   └── context/            # Deep: Context state management
│   │       ├── mod.rs
│   │       ├── compressor.rs
│   │       ├── decompressor.rs
│   │       └── transitions.rs
└── encodings/                  # Deep: W-LSB algorithms
    ├── mod.rs
    ├── wlsb.rs
    └── optimized.rs
```

**Rule**: If a file exceeds 400 lines, consider a subdirectory.

### 3. Error Handling Strategy

**Choice**: Structured errors with domain context, distinguish recoverable from critical.

```rust
pub enum RohcError {
    // Recoverable: Expected network conditions
    #[error("Packet CRC mismatch: expected {expected:02x}, got {calculated:02x} in {packet_type}")]
    CrcMismatch { expected: u8, calculated: u8, packet_type: &'static str },

    #[error("Context {cid} not found for profile {profile:?}")]
    ContextNotFound { cid: ContextId, profile: RohcProfile },

    // Critical: Implementation bugs
    #[error("W-LSB decoding failed: {value} outside window [{start}..{end}]")]
    LsbDecodingFailed { value: u64, start: u64, end: u64 },
}
```

**Rationale**: ROHC operates on lossy networks - packet loss and corruption are expected, not bugs. Clear error context enables debugging without overwhelming logs.

### 4. Profile System Architecture

**Choice**: Trait-based profiles with compile-time dispatch where possible.

```rust
pub trait ProfileHandler: Send + Sync {
    fn profile_id(&self) -> RohcProfile;

    // Zero-allocation APIs
    fn compress(&self, context: &mut dyn RohcCompressorContext,
                headers: &GenericUncompressedHeaders, out: &mut [u8]) -> Result<usize>;

    fn decompress(&self, context: &mut dyn RohcDecompressorContext,
                  packet: &[u8]) -> Result<GenericUncompressedHeaders>;
}
```

**Rationale**: Enables multiple profiles while maintaining type safety and performance. Dynamic dispatch overhead is acceptable for per-packet (not per-bit) operations.

## Critical Components

### W-LSB Encoding Engine

```rust
pub struct WLsbEncoder {
    // Pre-computed lookup tables for common cases
    k_bit_table: [u8; 65536],           // value → minimum k-bits
    window_cache: HashMap<(u64, u8, i64), (u64, u64)>,  // (ref, k, p) → window
}
```

Optimized for UO-0 sequence numbers (4-bit, p=0) - the most common case.

### Context Management

```rust
pub struct ContextManager {
    compressor_contexts: HashMap<ContextId, Box<dyn RohcCompressorContext>>,
    decompressor_contexts: HashMap<ContextId, Box<dyn RohcDecompressorContext>>,

    // LRU eviction for memory bounds
    access_order: LinkedList<ContextId>,
    last_cleanup: Instant,
}
```

Automatic cleanup prevents memory leaks in long-running network equipment.

### CRC Calculation System

```rust
pub struct CrcCalculators {
    crc3_calculator: Crc<u8>,
    crc8_calculator: Crc<u8>,

    // Workspace to avoid repeated allocations
    workspace: Vec<u8>,
}
```

Reusable calculators eliminate repeated CRC table initialization.

## Performance Strategy

### Measurement-Driven Optimization

Every optimization requires benchmark proof:

```
BENCHMARK: profile1_uo0_compression
Before: 1.2μs per packet, 15 allocations
After:  0.8μs per packet, 0 allocations
Change: Pre-allocated buffers + UO-0 fast path
Worth it: 33% improvement × millions of packets/sec = significant
```

### Hot Path Optimization

1. **UO-0 Fast Path**: Dedicated function for most common packet type
2. **CRC Reuse**: Pre-allocated calculators, never recreate CRC instances
3. **Buffer Pools**: Reuse buffers across packet processing
4. **Lookup Tables**: Pre-compute expensive calculations

### Zero-Allocation Guarantees

```rust
// GOOD: Write into provided buffer
pub fn compress(&mut self, headers: &Headers, out: &mut [u8]) -> Result<usize>

// BAD: Allocates on every compression
pub fn compress(&mut self, headers: &Headers) -> Result<Vec<u8>>
```

All packet processing APIs use caller-provided buffers.

## Development Phases

### Phase 1: Core Implementation (Weeks 1-4)

- Profile 1 U-mode compression/decompression
- Basic context management
- CRC verification
- **Ship: Working ROHC library**

### Phase 2: Performance Optimization (Weeks 5-6)

- Zero-allocation packet processing
- UO-0 fast path
- Buffer reuse patterns
- **Ship: Production-ready performance**

### Phase 3: Robustness (Weeks 7-8)

- Comprehensive error recovery
- Property-based testing
- Fuzzing integration
- **Ship: Network equipment ready**

### Phase 4: Additional Profiles (Weeks 9-12)

- Profile 0 (IP-only)
- Profile 2 (UDP-only)
- Profile extensions
- **Ship: Complete ROHC implementation**

## Testing Strategy

### Multi-Layer Validation

1. **Unit Tests**: Algorithm correctness, edge cases
2. **Property Tests**: Protocol invariants (W-LSB roundtrip, CRC verification)
3. **Compliance Tests**: RFC 3095 test vectors
4. **Fuzzing**: Malformed packet handling with `cargo-fuzz`
5. **Performance Tests**: Regression prevention with criterion

```rust
// Property test example
proptest! {
    #[test]
    fn wlsb_encoding_roundtrip_preserves_value(
        value in 0u64..1000000,
        k_bits in 1u8..16,
        p_offset in -100i64..100
    ) {
        let encoded = encode_lsb(value, k_bits)?;
        let decoded = decode_lsb(encoded, value, k_bits, p_offset)?;
        prop_assert_eq!(decoded, value);
    }
}
```

### Mock Environment for Deterministic Testing

```rust
pub struct MockRohcEnvironment {
    packet_generator: PacketGenerator,
    loss_simulator: PacketLossSimulator,
    corruption_injector: CorruptionInjector,
}
```

Enables testing rare conditions (packet loss, corruption) deterministically.

## Memory Management

### Buffer Management Strategy

```rust
pub struct RohcEngine {
    // Hot path buffers - never reallocate
    packet_buffer: [u8; MAX_PACKET_SIZE],
    crc_input_buffer: [u8; MAX_CRC_INPUT],

    // Cold path - allow allocation for setup/teardown
    profile_handlers: HashMap<RohcProfile, Box<dyn ProfileHandler>>,
}
```

### Context Lifecycle

```rust
impl ContextManager {
    pub fn cleanup_expired(&mut self, timeout: Duration) {
        // Periodic cleanup, not per-packet
        let cutoff = Instant::now() - timeout;
        self.contexts.retain(|_, ctx| ctx.last_accessed() > cutoff);
    }
}
```

## Anti-Patterns Avoided

- **No allocation in packet processing**: All buffers pre-allocated
- **No utils.rs modules**: Focused, domain-specific modules only
- **No premature abstraction**: Traits only when 2+ implementations exist
- **No string-heavy errors**: Structured errors with typed fields
- **No blocking I/O**: All APIs are synchronous for embedding in async contexts

## RFC Compliance Strategy

```rust
// RFC references in code for traceability
impl Profile1Handler {
    /// RFC 3095 Section 5.7.1: IR packet format
    fn build_ir_packet(&self, context: &Context) -> Result<IrPacket> {
        // Implementation directly follows RFC structure
    }
}
```

Comprehensive RFC 3095 test vectors ensure specification compliance.

## Future Considerations

- **ROHCv2 Support**: Architecture supports future protocol versions
- **Hardware Acceleration**: Buffer management compatible with DMA
- **Multi-threading**: Context isolation enables parallel processing
- **Custom Allocators**: Buffer pools can use custom allocators for embedded systems

## Philosophy

Build the fastest, most reliable ROHC implementation. Measure everything. Optimize based on real network equipment requirements, not theoretical performance.

Priority: **Correctness → Performance → Features**
