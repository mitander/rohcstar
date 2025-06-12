# The ROHC Bible: RFC 3095 + RFC 4815

## Overview

**RObust Header Compression (ROHC)** is a framework for compressing IP/UDP/RTP headers over error-prone links with long round-trip times (e.g., cellular networks). ROHC can compress 40-60 byte headers down to 1-3 bytes.

**Key Features:**
- Robust against packet loss and bit errors
- Efficient compression (typically 90-95% reduction)
- Multiple compression profiles
- Three operational modes (U, O, R)
- Context-based compression

## Core Concepts

### Context
- **Definition**: State information maintained by compressor/decompressor
- **Static part**: Fields that never change (IP addresses, ports)
- **Dynamic part**: Fields that change predictably (sequence numbers, timestamps)
- **Context ID (CID)**: Identifies different packet streams (0-16383)

### Compression States

#### Compressor States
1. **IR (Initialization & Refresh)**: Sends complete headers
2. **FO (First Order)**: Sends dynamic field changes
3. **SO (Second Order)**: Maximum compression, only sends minimal info

#### Decompressor States
1. **NC (No Context)**: No valid context
2. **SC (Static Context)**: Has static info only
3. **FC (Full Context)**: Complete context available

### Operating Modes

1. **U-mode (Unidirectional)**: No feedback channel, periodic refreshes
2. **O-mode (Optimistic)**: Sparse feedback, error recovery via NACK
3. **R-mode (Reliable)**: Intensive feedback, maximum robustness

## Packet Formats

### General Packet Structure
```
+------------------------+
| Padding (optional)     |
+------------------------+
| Feedback (optional)    |
+------------------------+
| Header (with CID info) |
+------------------------+
| Payload               |
+------------------------+
```

### CID Encoding
- **Small CIDs (0-15)**: 0 bits (CID=0) or 1 byte Add-CID
- **Large CIDs (0-16383)**: 1-2 bytes using self-describing format

### Common Header Fields

#### SN (Sequence Number)
- W-LSB encoded with interpretation intervals:
  - p = 1 if bits(SN) ≤ 4
  - p = 2^(bits(SN)-5) - 1 if bits(SN) > 4

#### TS (Timestamp)
- **Scaled**: TS_SCALED = TS / TS_STRIDE
- **Timer-based**: Uses arrival time for compression
- Interpretation interval: p = 2^(bits(TS)-2) - 1

#### IP-ID
- **Sequential**: Compressed as offset from SN
- **Random**: Sent uncompressed
- **Swapped**: If NBO=0, bytes are swapped

## Profile 0x0001: RTP/UDP/IP

### IR Packet
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 1 1 1 1 1 0|D|      Profile = 0x01          |      CRC      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Static Chain                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Dynamic Chain (if D=1)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Payload                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Compressed Packet Types

#### UO-0 (1 byte + CID)
```
 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+
| 0 |  SN   |CRC|
+-+-+-+-+-+-+-+-+
```
- Discriminator: 0xxxxxxx
- Updates: SN only
- CRC: 3-bit

#### UO-1 (2 bytes + CID)
```
 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+
|1 0|    TS     |
+-+-+-+-+-+-+-+-+
|M|  SN   | CRC |
+-+-+-+-+-+-+-+-+
```
- Discriminator: 10xxxxxx
- Updates: SN, TS
- CRC: 3-bit

#### UOR-2 (3 bytes + CID)
```
 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+
|1 1 0|    TS   |
+-+-+-+-+-+-+-+-+
|TS |M|   SN    |
+-+-+-+-+-+-+-+-+
|X|    CRC      |
+-+-+-+-+-+-+-+-+
```
- Discriminator: 110xxxxx
- Updates: All fields
- CRC: 7-bit
- X: Extension present

### Extension Formats

#### Extension 3 (Most comprehensive)
```
+-+-+-+-+-+-+-+-+
|1 1|S|R-TS|Tsc|I| ip | rtp |
+-+-+-+-+-+-+-+-+
```
Flags indicate presence of:
- S: SN
- R-TS: Scaled TS
- Tsc: TS scaling control
- I: IP-ID
- ip/rtp: IP/RTP header fields

## Profile 0x0002: UDP/IP

Similar to RTP profile but:
- Uses generated 16-bit UDP SN instead of RTP SN
- No RTP-specific fields (M-bit, PT, etc.)
- Packet formats adapted for UDP

### Key Differences
- R-1: TS field replaced by IP-ID
- UO-1: Different bit layout
- UOR-2: Simplified format

## Profile 0x0003: ESP/IP

- Compresses up to ESP header only
- Uses ESP sequence number
- Encryption prevents further compression
- Special handling for NULL encryption

## Profile 0x0000: Uncompressed

- Headers passed through unmodified
- Adds ROHC framing (CID, packet type)
- Used for incompressible packets
- Minimal overhead

## Compression Procedures

### W-LSB Encoding Algorithm
1. Maintain sliding window of reference values
2. Choose k = max(g(v_min, v), g(v_max, v))
3. Send k LSBs of value

### Scaled Timestamp Compression (Corrected from RFC 4815)
1. **Initialization**: Send TS_STRIDE and unscaled TS
2. **TS_OFFSET** = unscaled_TS % TS_STRIDE
3. **Compression**: Send TS_SCALED = TS / TS_STRIDE
4. **Decompression**: TS = TS_SCALED * TS_STRIDE + TS_OFFSET
5. **Wraparound**: Reinitialize by sending unscaled TS

### Timer-Based TS Compression
When no TS bits sent:
- delta_TS = delta_SN * default_slope
- If Tsc=1: default_slope = 1
- If Tsc=0: default_slope = TS_STRIDE

## CRC Calculations (Corrected from RFC 4815)

### Coverage Rules
- **IR/IR-DYN**: Entire uncompressed header excluding Payload and initial Padding octets
- **Compressed headers**: Original uncompressed header
- **Feedback CRC**: Excludes packet type, Size field, and Code octet

### CRC Polynomials
- **3-bit**: C(x) = 1 + x + x³
- **7-bit**: C(x) = 1 + x + x² + x³ + x⁶ + x⁷
- **8-bit**: C(x) = 1 + x + x² + x⁸

### CRC Calculation Order
1. Concatenate CRC-STATIC fields
2. Concatenate CRC-DYNAMIC fields
3. Calculate CRC over concatenation

## Mode Transitions (Enhanced from RFC 4815)

### Transition Parameters
- **C_MODE**: Current compressor mode
- **C_TRANS**: Transition state (P=Pending, D=Done)
- **D_MODE**: Current decompressor mode
- **D_TRANS**: Transition state (I=Initiated, P=Pending, D=Done)

### Transition Rules
1. All feedback during transitions MUST use CRC option
2. Compressor ignores feedback without CRC during transitions
3. Mode inheritance when reusing CID with same profile
4. Enhanced procedures allow sparse feedback with D_TRANS=P

### U-mode Specific
- No feedback channel available
- Periodic IR refreshes to maintain sync
- Conservative state transitions
- CRC failures trigger immediate recovery

## List Compression

### Encoding Types
0. **Generic**: Send complete list
1. **Insertion**: Add items at positions
2. **Removal**: Remove items at positions
3. **Remove then Insert**: Combined operation

### Special Rules (Corrected)
- Reference list must be non-empty for types 1-3
- Both CC fields in RTP must be identical
- 7-bit masks can be used even for lists >7 items
- ESP NULL headers limited to one per chain

## Context Management

### Reinitialization
- **CONTEXT_REINITIALIZATION** signal forces IR state (feedback modes only)
- Must reinitialize ALL contexts
- Mode inherited when reusing CID

### CID Reuse Rules
1. **Same profile**: Inherit mode from old context
2. **Different profile**: Start in initial mode
3. **R-mode CIDs**: Should not reuse for different profile

## Implementation Requirements

### Mandatory Features
- All three modes (U, O, R)
- CRC verification
- W-LSB encoding/decoding
- Context timeout handling

### Channel Parameters
- **MAX_CID**: Maximum context ID (negotiated)
- **LARGE_CIDS**: Boolean for CID format
- **PROFILES**: Supported profiles list
- **MRRU**: Maximum reconstructed size

### Feedback Options (O-mode and R-mode only)
1. **CRC** (Type 1): 8-bit CRC
2. **REJECT** (Type 2): Reject flow
3. **SN-NOT-VALID** (Type 3): Invalid SN
4. **SN** (Type 4): Additional SN bits
5. **CLOCK** (Type 5): Clock resolution
6. **JITTER** (Type 6): Max jitter
7. **LOSS** (Type 7): Loss events

## Error Handling

### CRC Failure Actions
1. Check for SN wraparound (U/O-mode)
2. Attempt reference SN repair
3. Apply k-out-of-n rule for context damage
4. Transition to lower state if needed

### Context Damage Detection
- **k_1 out of n_1**: Full Context → Static Context
- **k_2 out of n_2**: Static Context → No Context
- Values depend on channel BER

## Performance Optimizations

### Compression Efficiency
- SO state: 1 byte headers typical
- FO state: 2-3 byte headers
- IR state: Full headers

### Implementation Tips
- Reuse CRC state for CRC-STATIC portions
- Pool compression contexts
- Optimize W-LSB window operations
- Cache TS_STRIDE calculations
- Pre-allocate packet buffers

## Quick Reference Tables

### Packet Type Summary
| Type | Discriminator | Size | Updates | CRC | Use Case |
|------|--------------|------|---------|-----|----------|
| UO-0 | 0xxxxxxx | 1B | SN | 3-bit | Minimal change |
| UO-1 | 10xxxxxx | 2B | SN,TS | 3-bit | TS update |
| UOR-2 | 110xxxxx | 3B | All | 7-bit | Full update |
| IR | 11111101 | Var | All | 8-bit | Initialize |
| IR-DYN | 11111000 | Var | Dynamic | 8-bit | Reinit dynamic |

### Mode Comparison
| Feature | U-mode | O-mode | R-mode |
|---------|--------|--------|--------|
| Feedback | None | Sparse | Intensive |
| Robustness | Low | Medium | High |
| Efficiency | Medium | High | Medium |
| RTT Sensitivity | No | Medium | High |

### Field Classification
| Class | Examples | Handling |
|-------|----------|----------|
| STATIC | IP addr, ports | Send once |
| STATIC-DEF | Flow label | Send once |
| STATIC-KNOWN | Version | Never send |
| CHANGING | SN, TS | Compress |
| IRREGULAR | Checksum | Send as-is |

## Common Implementation Pitfalls

1. **TS_OFFSET not recalculated** when receiving unscaled TS
2. **Mode not inherited** during CID reuse
3. **CRC coverage** excluding wrong fields
4. **Reference list empty** for encoding types 1-3
5. **IP-ID byte order** confusion with NBO flag
6. **Timer resolution** insufficient for accurate TS prediction
7. **Buffer alignment** issues on embedded platforms
8. **Concurrent context** modification without proper locking

## ROHCv2 Key Differences (RFC 5225)

Since Rohcstar roadmap includes ROHCv2 support:

1. **Improved encoding**: More efficient than ROHCv1
2. **Better repair mechanisms**: Enhanced error recovery
3. **Simplified implementation**: Cleaner specification
4. **Profile differences**: New profile numbers and formats
5. **Backwards compatibility**: Not compatible with ROHCv1

## Compliance Checklist

- [ ] All packet types implemented
- [ ] CRC calculations match spec
- [ ] Mode transitions follow state machine
- [ ] W-LSB encoding correct
- [ ] TS compression handles all cases
- [ ] List compression supports all types
- [ ] Context reuse follows rules
- [ ] Error recovery implemented
- [ ] All three modes supported
- [ ] Feedback handling complete (O/R modes)
