# Rohcstar Naming Conventions

Consistency enables skimmability. Same concept, same name, everywhere.

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

### Rules

1. Use full words: `sequence_number` not `seq_num` or `sn`
2. Exception: Universally known acronyms (CRC, IP, UDP, RTP)
3. Parameters match struct fields they populate

## Types

```rust
// Structs
RohcEngine           // Not ROHC_Engine or Engine
Profile1Handler      // Not Profile1ProfileHandler
CompressorContext   // Not Context or CompressorCtx

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

## Variables

```rust
// Local variables - descriptive
let packet_length = calculate_length();     // Not len or pkt_len
let compressor_context = get_context(cid);  // Not ctx
let sequence_number = extract_sn(packet);   // Not sn or seq_num

// Common patterns
let mut output_buffer = [0u8; 128];
let bytes_written = compress(&mut output_buffer)?;
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

## Forbidden

```rust
// Never use these patterns:
let ctx = get_context();        // Use context
let sn = seq_num;              // Use sequence_number
struct PacketParser;           // Too generic - Profile1PacketParser
const TIMEOUT: u64 = 300;      // Which timeout? CONTEXT_TIMEOUT_SECS
```

## RFC Term Mapping

When RFC uses abbreviations, we expand them:

- SN → sequence_number
- TS → timestamp
- CID → context_id
- SSRC → ssrc (universally known in RTP context)
