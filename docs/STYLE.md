# Rohcstar Style Guide

> **This is CORRECTNESS, not preference.**
>
> Every rule prevents bugs. Every violation introduces technical debt.
> This guide is mandatory and must be followed without exception.

Production-grade ROHC implementation built on three foundational pillars:

## The Three Pillars

### 1. ROBUSTNESS
Code should be bulletproof like TigerBeetle. Every edge case handled, every invariant enforced.

### 2. CONSISTENCY
Patterns must be identical across the codebase. No exceptions, no "this time is different."

### 3. SIMPLICITY
Obvious code wins. No clever tricks. Future maintainers should understand immediately.

## Core Principles (Non-Negotiable)

1. **Correctness > Performance > Features** - Always
2. **Explicit > Implicit** - No magic
3. **Simple > Clever** - Boring code is good code
4. **Measure > Assume** - Data over opinions
5. **Static > Dynamic** - Zero allocations in hot paths
6. **Assert > Hope** - Heavy defensive programming

## Architecture

### Module Organization

```
src/
  profiles/
    profile1/
      mod.rs              // Public API only
      compressor.rs       // Compression logic
      decompressor.rs     // Decompression logic
      state.rs            // State machines
      packets.rs          // Packet structures
      constants.rs        // Profile1-specific constants
```

**Size Limits**
- Modules: <500 lines
- Functions: <50 lines (exception: state machines)
- Structs: <10 fields

**Code Proximity Rule**
- Related code lives together (no "utils" modules)
- Tests next to implementation (in same file for private functions)
- Constants defined where used, not in separate files

## Naming Conventions

### Functions

```rust
// Action - Mutates state or has side effects
compress_packet()
update_context()
initialize_engine()

// Query - Read-only, no side effects
is_valid()
has_context()
context_count()

// Conversion - Type transformations
as_bytes()        // Borrowing (&T -> &U)
into_packet()     // Consuming (T -> U)

// Fallible - Returns Result<T, E>
try_compress()
parse_packet()

// Optional - Returns Option<T>
find_context()
get_profile()
```

### Types

```rust
// Domain objects
RohcEngine
Profile1Handler      // Not Profile1ProfileHandler
IrPacket            // Not IRPacket
RtpHeaders          // Not RTPHeaders

// Contexts with clear ownership
Profile1CompressorContext    // Not P1CompressorCtx

// State enums
enum CompressorMode {
    Unidirectional,  // Not UNIDIRECTIONAL
    Optimistic,
}
```

### Constants

```rust
// Profile-specific: P<num>_<COMPONENT>_<DETAIL>
P1_IR_PACKET_TYPE
P1_UO0_SN_BITS

// Generic ROHC: ROHC_<COMPONENT>_<DETAIL>
ROHC_CID_MAX
ROHC_VERSION

// Module-level: <COMPONENT>_<DETAIL>
DEFAULT_TIMEOUT
MAX_CONTEXTS
```

### Tests

Pattern: `p<profile>_<component>_<scenario>`

```rust
#[test]
fn p1_ir_packet_handles_zero_stride() { }

#[test]
fn engine_context_timeout_removes_stale() { }
```

## Type Safety

### Newtype Pattern

Zero-cost type safety for domain values:

```rust
// Definition (use macro for consistency)
rohc_newtype!(ContextId, u16);
rohc_newtype!(SequenceNumber, u16);

// Production code: ALWAYS use ::new()
let cid = ContextId::new(5);

// Test code: .into() allowed for brevity
let cid: ContextId = 5.into();
```

### No Nullable Fields

```rust
// Bad: Nullable fields that are "usually" present
struct Context {
    stride: Option<u32>,  // Only None before first calculation
}

// Good: Explicit states
enum ContextState {
    Initializing { packets_seen: u8 },
    Established { stride: NonZeroU32 },
}
```

## Memory Management

### Static Allocation

**No malloc in hot paths**. Preallocate everything at initialization:

```rust
pub struct RohcEngine {
    // Static allocation
    packet_buffer: [u8; MAX_PACKET_SIZE],
    context_pool: [CompressorContext; MAX_CONTEXTS],
    crc_tables: CrcTables,  // Computed once at startup
}

// Bad: Dynamic allocation per packet
fn compress(&mut self) -> Vec<u8>

// Good: Write into provided buffer
fn compress(&mut self, out: &mut [u8]) -> Result<usize, RohcError>
```

### Zero-Copy Patterns

```rust
// Borrow when possible
pub fn compress(&mut self, headers: &Headers) -> Result<&[u8], RohcError>

// Return Cow for conditional ownership
pub fn get_packet(&self) -> Cow<'_, [u8]>

// Never allocate unnecessarily
pub fn get_cid(&self) -> ContextId  // Not Vec<u8>!
```

## Error Handling

### Result vs Panic

```rust
// Recoverable error: Return Result
if packet.len() < MIN_SIZE {
    return Err(RohcError::PacketTooSmall { size: packet.len() });
}

// Debug invariant: debug_assert (free in release)
debug_assert!(self.state.is_valid());

// Critical safety: assert (rare)
assert!(index < self.buffer.len(), "buffer overflow");
```

### Error Naming

Be explicit about WHERE and WHY:

```rust
pub enum RohcError {
    // Specific location and context
    CompressorContextNotFound { cid: ContextId },
    Profile1IrPacketTooSmall { size: usize, minimum: usize },
    DecompressorCrcMismatch { expected: u8, actual: u8 },

    // Not just "InvalidPacket" or "Error"
}
```

## Testing Strategy

### Deterministic Simulation

Test entire sessions deterministically:

```rust
pub struct DeterministicSimulator {
    clock: MockClock,
    rng: StdRng,
    packet_loss: Vec<bool>,      // Predetermined loss pattern
    network_delay: Vec<Duration>, // Predetermined delays
}

#[test]
fn simulate_10k_packet_session() {
    let sim = DeterministicSimulator::from_seed(0xDEADBEEF);
    // Verify correctness under all network conditions
}
```

### Test Categories

```rust
// Unit: Single component
#[test]
fn lsb_encode_handles_wraparound() { }

// Property: Invariants via quickcheck
#[quickcheck]
fn compression_decompression_roundtrip(headers: Headers) -> bool {
    compress_then_decompress(headers) == headers
}

// Conformance: RFC test vectors
#[test]
fn p1_ir_packet_matches_rfc_example_1() { }

// Performance: Regression tests
#[test]
fn perf_compress_uo0_under_500ns() {
    assert_duration!(compress_uo0(&headers), < 500ns);
}
```

### Coverage Requirements
- Unit tests: 90% line coverage
- State machines: 100% transition coverage
- Public API: Every path tested

## Performance

### Benchmark-Driven Development

**No performance changes without data:**

1. Write benchmark FIRST
2. Measure baseline
3. Make change
4. Measure again
5. Keep only if >10% improvement

```rust
// Required for optimization PRs:
// BENCHMARK RESULTS:
// Before: 487ns per packet
// After:  423ns per packet
// Improvement: 13.1%
```

### Performance Assertions

```rust
// Assert performance characteristics in tests
#[test]
fn perf_critical_path() {
    assert_no_allocations!(engine.compress_uo0(&headers));
    assert_cpu_cycles!(engine.decompress(&packet), < 1000);
}
```

### Hot Path Rules
1. **No allocations** in packet processing
2. **Reuse resources** (CRC tables, buffers)
3. **Profile first** - no guessing
4. **Inline carefully** - measure impact

## Defensive Programming

### Strategic Assertion Philosophy

ROHC is fault-tolerant by design - packet loss is expected and handled. Focus assertions on **critical invariants** that prevent undefined behavior, not every calculation.

**Assert These (Critical)**:
- Entry point parameter validation
- Array bounds that could cause crashes
- State machine invariant violations
- Context consistency that affects correctness
- Buffer size guarantees before writes

**Don't Assert These (Acceptable)**:
- Packet loss scenarios (protocol handles these)
- Temporary calculation steps
- Performance-critical inner loops
- Expected error conditions

### Assert Then Assume

**MANDATORY**: ALL `debug_assert!` calls MUST include descriptive messages.

Assert invariants at boundaries, then rely on them:

```rust
pub fn compress_uo0(&mut self, ctx: &Context) -> Result<&[u8], RohcError> {
    // Assert critical invariants at entry
    debug_assert!(ctx.is_established(), "State violation: UO-0 requires established context");
    debug_assert!(self.buffer.len() >= UO0_MAX_SIZE, "Buffer overflow: {} < {}", self.buffer.len(), UO0_MAX_SIZE);
    debug_assert!(ctx.sequence_number.is_some(), "State violation: missing sequence number");

    // Now safely assume these hold - no more checks needed
    let sn = ctx.sequence_number.unwrap(); // Safe after assertion
}
```

**Never do this**:
```rust
debug_assert!(value > 0);          // ❌ BAD: No message
debug_assert!(buf.len() >= 10);    // ❌ BAD: No message
```

**Always do this**:
```rust
debug_assert!(value > 0, "Invalid value: {} must be positive", value);           // ✅ GOOD
debug_assert!(buf.len() >= 10, "Buffer overflow: {} < 10", buf.len());          // ✅ GOOD
```

### State Validation (Critical Paths Only)

```rust
fn transition_to_fo(&mut self) -> Result<(), RohcError> {
    // State transitions must be validated - corruption here breaks everything
    debug_assert!(
        matches!(self.state, State::IR | State::FO),
        "Invalid transition to FO from {:?}", self.state
    );

    match self.state {
        State::IR => {
            self.state = State::FO;
            Ok(())
        }
        _ => Err(RohcError::InvalidTransition {
            from: self.state,
            to: State::FO
        }),
    }
}
```

### Buffer Safety (Non-Negotiable)

**Standard Message Format**: All buffer assertions MUST use this exact pattern:

```rust
fn write_header(&mut self, data: &[u8]) -> Result<usize, RohcError> {
    // Buffer overflows are never acceptable
    debug_assert!(
        self.pos + data.len() <= self.buffer.len(),
        "Buffer overflow: {} + {} > {}",
        self.pos, data.len(), self.buffer.len()
    );

    // Write safely
    self.buffer[self.pos..self.pos + data.len()].copy_from_slice(data);
    self.pos += data.len();
    Ok(data.len())
}
```

**Message Patterns** (MANDATORY - NO DEVIATIONS):
```rust
// Buffer write bounds
"Buffer overflow: {} + {} > {}"     // For write operations
"Buffer overflow: {} < {}"          // For size requirements

// Range violations
"Range violation: {} not in {}-{}"  // For value ranges
"Range violation: {} >= {}"         // For upper bounds

// State violations
"State violation: description"      // For invalid state combinations
"Invalid stride: {} must be positive" // For stride validation

// Counter overflows
"Counter overflow: {} > {}"         // For counter limits
```

## Documentation

Comments explain WHY, not WHAT. Omit obvious comments.

### When to Comment

- Complex algorithms not obvious from reading
- Critical invariants and unsafe code reasoning
- Public API contracts

### Examples

```rust
/// Compresses headers using W-LSB encoding.
pub fn compress(&mut self, headers: &Headers) -> Result<&[u8], RohcError>

// Use full window to handle timestamp wraparound
let ts_window = calculate_lsb_window(ts_bits + 2);
```

## Tools & Automation

- `cargo fmt` - Before every commit
- `cargo clippy -- -D warnings` - In CI
- `cargo test` - Including performance tests
- `cargo bench` - Before optimization PRs

## Summary

This style guide optimizes for:
- **Correctness**: Through types, tests, and assertions
- **Performance**: Through measurement and static allocation
- **Maintainability**: Through consistency and simplicity

When in doubt, choose the approach that makes bugs impossible, performance predictable, and code obvious.
