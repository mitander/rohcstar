# Rohcstar Naming Conventions

Simple, binary rule: Public APIs must be unambiguous. Private code uses professional judgment.

## Functions

### Patterns

```rust
// Actions (mutate state or have side effects)
compress_packet()
update_context()
send_feedback()

// Queries (read-only, pure)
is_valid()
has_context()
can_use_uo0()

// Conversions
as_bytes()        // Borrowing (&T -> &U)
into_packet()     // Consuming (T -> U)
from_headers()    // Constructor

// Fallible operations
try_parse()       // Returns Result
parse_packet()    // Also returns Result (try_ optional for clarity)

// Optional operations
find_context()    // Returns Option
```

### The Binary Rule

**Public APIs (pub): STRICT** - Mechanically enforced

- Function names: `compress_packet` not `compress_pkt`
- Parameters: `context: &mut Context` not `ctx: &mut Context`
- Struct fields: `pub sequence_number: u16` not `pub sn: u16`
- Return types: Clear and unambiguous

**Private Code: PROFESSIONAL JUDGMENT** - Code review enforced

- Use whatever is clearest in context
- Short closures: `ctx` is fine if obvious
- RFC implementation: `k`, `p`, `sn` when matching spec
- Long functions: Prefer descriptive names
- Team review validates appropriateness

## Types

```rust
// Structs
RohcEngine           // Not ROHC_Engine or Engine
Profile1Handler      // Not Profile1ProfileHandler
CompressorContext    // Not Context or CompressorCtx

// Enums and variants
enum DecompressorMode {
    NoContext,       // Not NC
    StaticContext,   // Not SC
    FullContext,     // Not FC
}

// Newtypes for parameter safety
struct ContextId(u16);
struct SequenceNumber(u16);
```

## Constants

```rust
// Profile-specific: P<profile>_<component>_<detail>
const P1_IR_PACKET_TYPE: u8 = 0xFC;
const P1_UO0_CRC_BITS: u8 = 3;

// Generic ROHC: ROHC_<component>_<detail>
const ROHC_MAX_CID: u16 = 16383;
const ROHC_LARGE_CID_THRESHOLD: u16 = 16;

// Module-level: <COMPONENT>_<DETAIL>
const MAX_PACKET_SIZE: usize = 2048;
const DEFAULT_WINDOW_SIZE: u16 = 64;
```

## Examples

```rust
// ❌ PUBLIC API - FAILS CI
pub fn compress(ctx: &mut Context, sn: u16) -> Result<Vec<u8>, RohcError>
pub struct Packet { pub ctx_id: u16 }

// ✅ PUBLIC API - PASSES CI
pub fn compress(
    context: &mut CompressorContext,
    sequence_number: u16,
) -> Result<Vec<u8>, RohcError>

pub struct Packet {
    pub context_id: ContextId,
    pub sequence_number: u16,
}

// ✅ PRIVATE CODE - YOUR CHOICE (validated in code review)
fn process_packet(ctx: &Context) {          // OK: Team decides
    let sn = ctx.sequence_number();         // OK: RFC notation
}

self.contexts.iter_mut().for_each(|ctx| {   // OK: Short, obvious
    ctx.update_timestamp();
});

fn decode_w_lsb(lsb: u64, v_ref: u64, k: u8, p: i64) -> u64 {
    // RFC 3095 Section 4.5.1 notation
    let window_size = 1u64 << k;
}
```

## Test Names

Pattern: `<component>_<scenario>_<outcome>`

```rust
#[test]
fn ir_packet_zero_stride_encodes_correctly() { }

#[test]
fn decompressor_crc_failure_maintains_context() { }

#[test]
fn engine_timeout_removes_inactive_contexts() { }
```

## Modules and Files

```rust
mod compression;      // Not compressor or compress
mod decompression;    // Not decompressor
mod state_machine;    // Not states or state_mgmt
```

## Documentation

**Purpose-focused descriptions** - Describe what the function does, not what it returns:

```rust
// GOOD - describes purpose
/// Compresses RTP/UDP/IP headers into ROHC packet.
fn compress(&mut self, headers: &Headers) -> Result<&[u8], RohcError>

/// Creates a new ROHC engine with specified configuration.
fn new(config: Config) -> RohcEngine

// BAD - restates signature
/// Returns compressed packet data.
/// Returns a new ROHC engine.
```

**Document returns only when non-obvious:**

```rust
// GOOD - return semantics aren't clear from signature
/// Returns `None` if stride is not established or result exceeds 8 bits.
fn calculate_ts_scaled(&self, ts: u32) -> Option<u8>

/// Returns a slice valid until the next compression operation.
fn get_buffer(&mut self) -> &[u8]

/// Returns the previous value.
fn replace(&mut self, new_value: T) -> T

// BAD - obvious from signature + name
/// Returns the length.
fn len(&self) -> usize
```

**Standard pattern:**

- Brief purpose statement (required)
- Longer explanation if behavior is complex (optional)
- `# Errors` section for fallible functions (required)
- `# Examples` section for public APIs (encouraged)
- No `# Parameters` - good names and types are self-documenting

## Error Types

```rust
pub enum RohcError {
    // Include context in variant name
    ContextNotFound { cid: ContextId },
    BufferTooSmall { required: usize, available: usize },
    InvalidTransition { from: State, to: State },

    // Not just "Invalid" or "Error"
}
```

## Enforcement

**Mechanical (CI Breaking via Tidy System)**

- Public function names with abbreviations (`ctx` → `context`)
- Public function parameters with abbreviations (`seq_num` → `sequence_number`)
- Public struct fields with abbreviations
- Public API documentation completeness
- Anti-pattern module names (`utils.rs`, `helpers.rs`)

**Human (Code Review)**

- Internal naming clarity and appropriateness
- RFC notation when it enhances understanding
- Variable naming based on context and purpose
- Overall code readability and maintainability

## Philosophy

**Why the Binary Rule?**

1. **Zero Decision Fatigue**: No need to assess "scope length" or "RFC compliance"
2. **Clear Boundaries**: Public contract vs. private implementation
3. **Trust Professionals**: Developers can judge what's clearest internally
4. **Mechanical Enforcement**: Simple rule that's easy to check automatically

**Public APIs are Forever**
Once published, changing `ctx` to `context` in a public function breaks every user. The external contract must be unambiguous from day one.

**Private Code Evolves**
Internal naming can be refactored, improved, and adapted as the team learns. A 3-character variable in a closure might be perfect; a 50-line function might need descriptive names. Professional judgment applies.

### Guideline: Name Variables for What They Are

Strive to name variables based on the value they hold. Often, this is closely related to the function that produced the value. For example, a variable holding the result of `compress_packet()` can often be clearly named `compressed_packet`.

However, this is a principle, not a strict rule. Use your judgment. If a different name provides more clarity about the variable's purpose or its state in the program's logic (e.g., `stale_context` vs. `current_context`), prefer that more descriptive name. **Clarity is the ultimate goal.**

## Migration Guide

If you have existing code:

1. **Public APIs**: Fix immediately (CI will catch these)
2. **Private code**: Fix during normal refactoring
3. **Tests**: Be pragmatic, focus on clarity
4. **RFC implementation**: Use spec notation when it helps
