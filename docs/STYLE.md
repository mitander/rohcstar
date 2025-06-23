# Rohcstar Style Guide

## Core Philosophy

Write code that works, performs well, and doesn't make future-you hate current-you.

Three things matter:

1. **Correctness** - It should do what the RFC says
2. **Performance** - It should be fast (and we can prove it)
3. **Simplicity** - It should be obvious what's happening

## Architecture

### Module Organization

Modules are focused and small. No utils.rs, no grab bags.

```
src/
  profiles/
    profile1/
      mod.rs              // Public API only
      compression.rs      // Compression logic
      decompression.rs    // Decompression logic
      state_machine.rs    // State transitions
      packet_types.rs     // Packet definitions
```

## Type Safety

Use newtypes where mixing parameters would be catastrophic:

```rust
// YES - Easy to mix up positional u16 parameters
rohc_newtype!(ContextId, u16);
rohc_newtype!(SequenceNumber, u16);

// NO - Over-engineering for clear types
struct BufferSize(usize);  // Just use usize
```

## Defensive Programming

### Assertion Strategy

Assert critical invariants that would corrupt state or cause undefined behavior. ROHC is designed for lossy networks - packet loss and corruption are expected conditions, not bugs.

```rust
// YES: Prevents memory corruption
debug_assert!(index < buffer.len(), "Buffer overflow: {} >= {}", index, buffer.len());

// YES: Catches state machine violation
debug_assert!(self.mode != Mode::NoContext, "Invalid state: UO-0 requires context");

// NO: Expected network condition
if packet.len() < MIN_SIZE {
    return Err(RohcError::PacketTooSmall { size: packet.len() });
}

// NO: Normal ROHC operation
if crc_calculated != crc_received {
    self.handle_crc_failure();
}
```

### Error Handling

```rust
// Recoverable: Return Result
pub fn compress(&mut self, headers: &Headers) -> Result<&[u8], RohcError>

// Invariant violation: debug_assert with message
debug_assert!(self.contexts.len() <= MAX_CONTEXTS, "Context overflow: {} > {}",
             self.contexts.len(), MAX_CONTEXTS);

// Critical safety: assert (rare, documented why)
assert!(ptr.is_aligned(), "Unaligned pointer would cause UB on this platform");
```

## Memory Management

### Zero Allocation Principle

Packet processing paths must not allocate.

```rust
pub struct RohcEngine {
    // Pre-allocated at init
    packet_buffer: [u8; MAX_PACKET_SIZE],
    crc_calculator: CrcCalculator,  // Reused, not created per packet
}

// Good: Write into provided buffer
fn compress(&mut self, headers: &Headers, out: &mut [u8]) -> Result<usize, RohcError>

// Bad: Allocates per call
fn compress(&mut self, headers: &Headers) -> Result<Vec<u8>, RohcError>
```

## Documentation

### Module Documentation

Every module has a purpose statement:

```rust
//! Profile 1 compression for RTP/UDP/IP packets.
//!
//! Implements RFC 3095 profile 0x0001 with W-LSB encoding and
//! TS_STRIDE detection for optimal compression ratios.
```

### Function Documentation

Public functions get focused docs following Rust ecosystem patterns. Private functions get comments only when non-obvious.

````rust
/// Compresses RTP/UDP/IP headers into ROHC packet.
///
/// Analyzes headers and context state to determine optimal packet type
/// (IR, UO-0, UO-1, etc.) and generates the corresponding ROHC packet.
/// Updates compressor context state and statistics.
///
/// # Errors
/// - `RohcError::Internal` - Context downcast failed
/// - `RohcError::UnsupportedProfile` - Headers not compatible with Profile 1
/// - `RohcError::Building` - Packet construction failed
///
/// # Examples
/// ```
/// let mut buffer = [0u8; 1500];
/// let size = handler.compress(&mut context, &headers, &mut buffer)?;
/// ```
fn compress(
    &self,
    context_dyn: &mut dyn RohcCompressorContext,
    headers_generic: &GenericUncompressedHeaders,
    out: &mut [u8],
) -> Result<usize, RohcError>


// Private function - comment only if complex
// Calculates minimum K value for W-LSB encoding per RFC 3095 Section 4.5.1
fn calculate_k_value(v_ref: u16, v: u16) -> u8
````

**Documentation Pattern:**

- **Purpose-focused descriptions**: "Compresses headers" not "Returns compressed data"
- **Document returns only when non-obvious**:

  ```rust
  /// Returns `None` if stride is not established or result exceeds 8 bits.
  fn calculate_ts_scaled(&self, ts: u32) -> Option<u8>

  /// Returns a slice valid until the next compression operation.
  fn get_buffer(&mut self) -> &[u8]
  ```

- **Skip return docs when obvious**:

  ```rust
  // GOOD - signature tells the story
  /// Creates a new ROHC engine.
  fn new() -> RohcEngine

  // BAD - redundant with signature
  /// Returns a new ROHC engine.
  fn new() -> RohcEngine
  ```

- `# Errors` section with specific error variants
- `# Examples` section showing typical usage
- No `# Parameters` - good parameter names and types are self-documenting

### Inline Comments

Only explain **why**, never **what**:

```rust
// Good: Explains RFC requirement
// RFC 3095 5.7.7.4: CRC includes static fields for IR packets only
let crc_input = if is_ir_packet {
    include_static_fields(data)
} else {
    data
};

// Bad: Restates code
let seq_num = seq_num + 1;  // Increment sequence number
```

## Testing

### Test Organization

```rust
// Unit tests in same file
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compress_uo0_with_established_stride() {
        // Test one specific behavior
    }
}

// Integration tests in tests/
#[test]
fn profile1_thousand_packet_session() {
    // End-to-end validation
}
```

### Test Naming

Pattern: `<component>_<scenario>_<expected_outcome>`

```rust
#[test]
fn lsb_encode_wraparound_selects_minimal_k() { }

#[test]
fn decompressor_nc_state_rejects_uo_packets() { }
```

## Performance

### Measure, Don't Guess

If you claim something is faster, show me the numbers.

```rust
// Every optimization needs proof:
// BENCHMARK: compress_uo0
// Before: 487ns per packet
// After:  391ns per packet
// Improvement: 19.7%
//
// Worth it? That's 96ns for something we do millions of times.
```

### Benchmarking Rules

1. Write the benchmark first
2. Use real packet data (not zeros)
3. Check if the "improvement" actually matters
4. Put the numbers in your commit message

## Commit Messages

Keep it simple, be specific about what changed.

```
type(scope): what you did

Why you did it (if not obvious).

BENCHMARK: [only if you changed performance]
```

Examples:

```bash
feat(profile1): add UO-1-RTP packet support
fix(lsb): handle 32-bit wraparound correctly
refactor(engine): split monster function into readable pieces
bench(crc): reuse calculator, 86% faster

The last one would include:
BENCHMARK: crc_calculate
Before: 89ns per packet
After: 12ns per packet
```

## Automated Quality Enforcement

Style guides are useless if they aren't enforced. We use a three-tiered approach combining standard tools with custom checks.

### Standard Tools (CI Required)

- `rustfmt --check`: Code formatting consistency
- `cargo clippy`: Standard lints with cognitive complexity limits
- Custom tidy system: Project-specific quality ratchets

### Tidy System Philosophy

Our custom tidy system focuses on what standard tools cannot catch:

**Level 1: Critical Enforcement** (CI Breaking)

- Memory safety (no `.unwrap()` without safety comments)
- Public API clarity (unambiguous naming)
- Architectural integrity (no anti-pattern modules)
- Documentation completeness

**Level 2: Quality Ratchets** (Prevent Regression)

- Module size high-water mark (650 lines)
- Struct field count limits (12 fields max)
- Conscious growth with justification

**Level 3: Guidelines** (Human Judgment)

- Internal naming conventions
- Code clarity suggestions
- Professional discretion trusted

### Config (`clippy.toml`)

```toml
# Cognitive complexity - the real measure of function complexity

cognitive-complexity-threshold = 25
# Clippy is smart enough to exclude comments and documentation, so it only measures the production code’s complexity.
too-many-lines-threshold = 1000

```

## The Bottom Line

Write code like someone else will maintain it. Because they will. And that someone might be you in six months wondering what you were thinking.

When in doubt:

- Make it correct first
- Make it fast second (with proof)
- Make it fancy never
