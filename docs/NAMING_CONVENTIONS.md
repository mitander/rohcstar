# Rohcstar Naming Conventions

_consistency, clarity, and simple code._

## Core Philosophy

Names should be **immediately obvious** to any engineer reading the code. No abbreviations unless universally understood (e.g., `CRC`, `IP`, `UDP`). Consistency beats cleverness.

## Functions

### Action Verbs (Most Functions)

```rust
compress_packet()           // Action on object
decompress_rohc_data()      // Action with context
calculate_crc_value()       // Computation
validate_buffer_bounds()    // Validation
```

### Boolean Queries (`is_` / `has_` / `can_`)

```rust
is_valid_context()          // State check
has_established_stride()    // Capability check
can_use_uo0_packet()       // Permission check
```

### Fallible Operations (`try_`)

```rust
try_parse_ir_packet()       // May fail parsing
try_decode_lsb_value()      // May fail decoding
try_compress_headers()      // May fail compression
```

### Conversions

```rust
as_bytes()                  // Borrowing conversion (&self -> &[u8])
into_packet()               // Consuming conversion (self -> Packet)
from_raw_data()            // Constructor from primitive
to_network_order()         // Transform to different format
```

### Memory Management

```rust
create_context()            // Allocation/initialization
destroy_context()           // Cleanup/deallocation
reset_state_machine()       // Reset to initial state
```

## Types

### Structs (Clear, No Redundancy)

```rust
Profile1Handler             // NOT Profile1ProfileHandler
IrPacket                   // NOT IRPacket (readability over acronyms)
CompressorContext          // NOT Context (too generic)
DecompressorStateMachine   // NOT StateMachine (ambiguous)
```

### Enums and Variants

```rust
enum DecompressorMode {
    NoContext,              // NOT NC (spell out)
    StaticContext,          // NOT SC
    FullContext,           // NOT FC
    SecondOrder,           // NOT SO
}
enum Profile1PacketType {
    IrPacket,              // NOT IR
    Uo0Packet,             // NOT UO_0
    Uo1IdPacket,           // NOT UO1ID
}
```

### Newtypes (MANDATORY for primitives)

```rust
struct ContextId(u16);      // NOT raw u16
struct SequenceNumber(u16); // NOT raw u16
struct Timestamp(u32);      // NOT raw u32
struct IpId(u16);          // NOT raw u16
struct Ssrc(u32);          // NOT raw u32
```

## Constants

### Profile-Specific Constants

```rust
// Format: P<num>_<COMPONENT>_<DESCRIPTION>
const P1_IR_REFRESH_INTERVAL: u16 = 20;
const P1_UO0_SN_LSB_WIDTH_DEFAULT: u8 = 4;
const P1_CRC_FAILURE_LIMIT: u8 = 3;
const P1_TS_STRIDE_ESTABLISHMENT_THRESHOLD: u16 = 3;
```

### Generic ROHC Constants

```rust
// Format: ROHC_<COMPONENT>_<DESCRIPTION>
const ROHC_CID_MASK: u16 = 0x0F;
const ROHC_PROFILE_RTP_UDP_IP: u16 = 0x0001;
const ROHC_MAX_CONTEXT_COUNT: usize = 16;
```

### Protocol Constants

```rust
// Format: <PROTOCOL>_<COMPONENT>
const IP_PROTOCOL_UDP: u8 = 17;
const RTP_VERSION: u8 = 2;
const UDP_HEADER_LENGTH: u16 = 8;
```

## Variables

### Local Variables (snake_case, descriptive)

```rust
let compressed_packet_length = calculate_length();  // NOT len, l, or size
let decompressor_context = get_context(cid);       // NOT ctx or context
let sequence_number_lsbs = extract_lsbs();         // NOT sn_lsbs or lsbs
```

### Function Parameters (match struct field names)

```rust
fn create_headers(
    source_ip: Ipv4Addr,           // NOT src_ip (spell out)
    destination_ip: Ipv4Addr,      // NOT dst_ip
    sequence_number: SequenceNumber, // NOT sn
    timestamp: Timestamp,          // NOT ts
) -> RtpUdpIpv4Headers
```

## Tests

### Test Function Names

```rust
// Format: <component>_<feature>_<scenario>
fn p1_ir_packet_handles_zero_stride()
fn p1_uo0_compression_succeeds_with_valid_context()
fn p1_decompressor_transitions_nc_on_crc_failure()
fn engine_context_timeout_removes_stale_contexts()
fn lsb_decode_handles_sequence_number_wraparound()
```

### Test Categories

- `p1_` - Profile 1 specific tests
- `engine_` - RohcEngine tests
- `lsb_` - LSB encoding/decoding tests
- `crc_` - CRC calculation tests
- `perf_` - Performance tests

## Modules

### Module Names (singular, descriptive)

```rust
mod compression          // NOT compress
mod decompression       // NOT decompress
mod state_machine       // NOT states
mod serialization       // NOT serialize
mod packet_types        // NOT packets
```

### File Names (match module names)

```
compression.rs          // Implementation
compression_tests.rs    // If separate test file needed
```

## Error Types

### Error Enum Variants

```rust
pub enum RohcError {
    CompressorContextNotFound { cid: ContextId },
    Profile1IrPacketTooSmall { size: usize, minimum: usize },
    DecompressorCrcMismatch { expected: u8, actual: u8 },
    BufferTooSmall { required: usize, available: usize },
}
```

## Forbidden Patterns

### Don't Do This

```rust
// Abbreviations (except universally known)
let ctx = get_context();           // Use context
let pkt = parse_packet();          // Use packet
let hdr = build_header();          // Use header
let buf = allocate_buffer();       // Use buffer
// Hungarian notation
let u16_sequence_number = 100;     // Use SequenceNumber(100)
let str_ip_address = "1.1.1.1";   // Use Ipv4Addr
// Redundant prefixes
struct RohcRohcEngine;             // Use RohcEngine
enum ProfileProfile1Type;         // Use Profile1Type
// Generic names in specific contexts
struct Handler;                    // Use Profile1Handler
struct Context;                    // Use CompressorContext
struct State;                      // Use DecompressorMode
```

### Always Do This

```rust
// Clear, specific names
let compressor_context = get_context();
let rohc_packet = parse_packet();
let rtp_header = build_header();
let packet_buffer = allocate_buffer();
// Newtype wrappers
let sequence_number = SequenceNumber(100);
let ip_address: Ipv4Addr = "1.1.1.1".parse().unwrap();
// Specific, non-redundant names
struct RohcEngine;
enum Profile1PacketType;
```

## Consistency Rules

1. **Same concept, same name everywhere** - If you call it `sequence_number` in one place, don't call it `sn` elsewhere
2. **Struct fields match parameter names** - Function parameters should match the struct field names they populate
3. **Error messages use same terminology** - Error messages should use the same names as the code
4. **Comments use full names** - Never abbreviate in comments, even if code does

## RFC Terminology Mapping

When RFC uses abbreviations, we spell them out in code:

```rust
// RFC Term -> Rohcstar Name
SN          -> sequence_number / SequenceNumber
TS          -> timestamp / Timestamp
CID         -> context_id / ContextId
SSRC        -> ssrc / Ssrc (keep as is - universally known)
LSB         -> least_significant_bits / lsbs (in variables)
CRC         -> crc (universally known)
```

## Enforcement

These conventions are enforced through:

- Code review (mandatory)
- Automated linting where possible
- Documentation examples must follow conventions
- No exceptions without team discussion
