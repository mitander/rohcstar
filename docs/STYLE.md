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

## Documentation Standards

All documentation must be consistent, complete, and production-ready. No exceptions.

### Module Documentation (`//!`)

Every module MUST have module-level documentation explaining its purpose:

```rust
//! ROHC Profile 1 decompression for RTP/UDP/IP packets.
//!
//! Implements RFC 3095 profile 0x0001 decompression with robust CRC recovery
//! and conservative false positive prevention.
```

**Structure**:
- First line: Brief summary ending with period
- Empty line
- Detailed explanation (2-4 lines max)
- Reference RFC sections when applicable

### Function Documentation

#### Public Functions (`pub fn`, `pub(crate) fn`, `pub(super) fn`)

**MANDATORY**: All public functions MUST have complete documentation:

```rust
/// Compresses headers using W-LSB encoding for Profile 1 packets.
///
/// Analyzes header changes and selects optimal packet type based on RFC 3095 rules.
/// Updates compressor context state including timestamp stride detection.
///
/// # Parameters
/// - `context`: Mutable compressor context containing state and configuration
/// - `headers`: Uncompressed headers of the current packet to compress
/// - `out`: Output buffer to write the compressed packet into
///
/// # Returns
/// The number of bytes written to the output buffer.
///
/// # Errors
/// - [`RohcError::Building`] - No suitable packet type available
/// - [`RohcError::Internal`] - Internal logic error
pub fn compress(&mut self, context: &mut Context, headers: &Headers, out: &mut [u8]) -> Result<usize, RohcError>
```

**Required Sections**:
1. **Summary**: One line describing what the function does
2. **Details**: 1-3 lines explaining the approach (optional if obvious)
3. **`# Parameters`**: Every parameter with brief description
4. **`# Returns`**: What is returned and what it means
5. **`# Errors`** (if function returns Result): Each error variant that can occur

#### Private Functions (`fn`)

**RULE**: Private functions should NOT use `///` documentation. Use brief `//` comments only when the function is complex or non-obvious:

```rust
// Calculates minimum wrapping distance between two sequence numbers
fn min_wrapping_distance_u16<T, U>(a: T, b: U) -> u16
where
    T: Into<u16>,
    U: Into<u16>,
{
    let a_val = a.into();
    let b_val = b.into();
    let forward = a_val.wrapping_sub(b_val);
    let backward = b_val.wrapping_sub(a_val);
    forward.min(backward)
}

// Simple helper functions need no comments
fn can_use_uo0(marker_changed: bool, sn_delta: u16) -> bool {
    !marker_changed && sn_delta > 0 && sn_delta < 16
}
```

### Inline Comments

#### Keep These Comments (Valuable)

Comments that explain **WHY** a value is set or **business logic**:

```rust
RtpUdpIpv4Headers {
    ip_total_length: 0,     // Typically set by higher layers or network stack
    ip_dont_fragment: true, // Common assumption for ROHC Profile 1
    ip_checksum: 0,         // Recalculated by network stack
    udp_checksum: 0,        // May be 0 if not used, or recalculated
    rtp_padding: context.rtp_padding, // Assumed false unless payload indicates otherwise
    rtp_csrc_count: 0,      // Assumed 0 for Profile 1
}

// Use full window to handle timestamp wraparound at boundaries
let ts_window = calculate_lsb_window(ts_bits + 2);

// Profile 1 mandates specific CRC input format per RFC 3095 Section 5.7.7.4
let crc_input = prepare_generic_uo_crc_input_payload(ssrc, sn, ts, marker);
```

#### Remove These Comments (Noise)

Comments that restate the code or add no value:

```rust
// BAD - Remove these
let result = compress_packet();  // Compress the packet
counter += 1;                    // Increment counter
return Ok(headers);              // Return success

// BAD - Obvious state updates
self.state = State::Active;      // Set state to active
```

#### Comment Maintenance Rules

1. **Update comments with code changes** - Stale comments are worse than no comments
2. **Remove TODO comments** - Fix immediately or create GitHub issue
3. **No debugging comments** - Remove `println!`, `dbg!`, etc.
4. **No commented-out code** - Delete it; use git history if needed

### Import Organization

**MANDATORY**: All imports must follow this exact order with blank lines between groups:

```rust
// 1. Standard library
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Instant;

// 2. External dependencies (alphabetical by crate name)
use criterion::{Criterion, black_box};
use thiserror::Error;

// 3. Crate-local imports (alphabetical, grouped by module)
use crate::constants::{IP_PROTOCOL_UDP, RTP_VERSION};
use crate::error::{RohcError, RohcParsingError};
use crate::types::{ContextId, SequenceNumber};

// 4. Relative imports (super, self)
use super::constants::P1_UO0_SN_LSB_WIDTH_DEFAULT;
use super::packet_types::Uo0Packet;
```

**FORBIDDEN**: Inline imports in function bodies:

```rust
// ❌ NEVER do this
fn compress() {
    use crate::types::SequenceNumber;
    let sn = SequenceNumber::new(42);
}

// ✅ Always import at module level
use crate::types::SequenceNumber;

fn compress() {
    let sn = SequenceNumber::new(42);
}
```

### Documentation Examples

#### Good Module Documentation

```rust
//! UO-1 packet serialization and deserialization for Profile 1.
//!
//! This module handles the creation and parsing of UO-1 (Unidirectional Optimistic, Order 1)
//! packet variants: UO-1-SN, UO-1-TS, UO-1-ID, and UO-1-RTP. Each variant carries different
//! combinations of sequence number, timestamp, IP-ID, and marker bit information depending
//! on which fields have changed since the last packet.
```

#### Good Function Documentation

```rust
/// Prepares CRC input payload for UO-1-ID packet validation.
///
/// Creates the standardized byte sequence used for CRC calculation in UO-1-ID packets.
/// This extends the generic UO CRC input with the IP-ID LSB field for UO-1-ID validation.
///
/// # Parameters
/// - `context_ssrc`: RTP SSRC from compressor context
/// - `sn_for_crc`: Sequence number to include in CRC calculation
/// - `ts_for_crc`: Timestamp to include in CRC calculation
/// - `marker_for_crc`: RTP marker bit to include in CRC calculation
/// - `ip_id_lsb_for_crc`: IP-ID LSB value specific to UO-1-ID packets
///
/// # Returns
/// Fixed-size array containing the CRC input payload (12 bytes)
pub fn prepare_uo1_id_specific_crc_input_payload(
    context_ssrc: Ssrc,
    sn_for_crc: SequenceNumber,
    ts_for_crc: Timestamp,
    marker_for_crc: bool,
    ip_id_lsb_for_crc: u8,
) -> [u8; 12]
```

## Commit Style

All commits must follow these strict formatting rules to maintain clean git history:

### Commit Message Format

```
type(scope): brief description

Optional longer explanation if needed
- Bullet points for multiple changes
- Keep each line under 72 characters
```

### Type Categories

- **feat**: New feature or significant enhancement
- **fix**: Bug fix or correction
- **refactor**: Code restructuring without behavior change  
- **style**: Formatting, naming, organization (no logic change)
- **docs**: Documentation additions or improvements
- **test**: Adding or improving tests
- **chore**: Tooling, dependencies, or maintenance

### Scope Guidelines

- **profile1**: Changes to Profile 1 implementation
- **engine**: RohcEngine modifications
- **style**: Style guide or formatting changes
- **crc**: CRC calculation improvements
- **buffer-safety**: Buffer bounds and safety improvements

### Examples

```bash
# Good commits
feat(profile1): add UO-1-RTP packet support with TS_SCALED encoding
fix(buffer-safety): add bounds checking to IR deserialization  
refactor(profile1): break down packet_processor into focused modules
style(defensive): standardize debug_assert! patterns across codebase
docs(profile1): add complete Parameter/Returns sections to UO-1 functions

# Bad commits  
Update stuff           # No type or scope
Fix bug in thing       # Too vague
Added new feature      # Wrong tense, no scope
```

### Rules

1. **Present tense**: "add feature" not "added feature"
2. **Lowercase**: Never capitalize the description
3. **No period**: End descriptions without punctuation
4. **Specific scope**: Use module names, not generic terms
5. **Descriptive**: Explain WHAT and WHY, not HOW
6. **Atomic**: Each commit should be a single logical change

### Pre-commit Requirements

Every commit MUST pass:
- `cargo fmt --check` - Code formatting
- `cargo clippy -- -D warnings` - Linting
- `cargo test` - All tests pass

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
