# ROHC Library Technical Debt Roadmap

## 🚨 CRITICAL STYLE VIOLATIONS - HIGHEST PRIORITY

These violations directly violate our STYLE guide and MUST be fixed immediately.

### Module Size Violations (CRITICAL)
**Status**: 🔴 BLOCKING - Multiple modules exceed 500-line limit

1. **packet_processor.rs**: 1,895 lines (3.8x over limit) 
2. **decompressor.rs**: 1,832 lines (3.7x over limit)
3. **context.rs**: 1,289 lines (2.6x over limit)  
4. **compressor.rs**: 1,174 lines (2.3x over limit)
5. **engine.rs**: 977 lines (1.9x over limit)

**Action Plan**:
- Split each into focused submodules
- Preserve public APIs during extraction
- Maximum 300 lines per extraction PR

### Missing Strategic Defensive Programming (CRITICAL)
**Status**: 🔴 BLOCKING - Violates robustness pillar

**Philosophy**: ROHC is fault-tolerant (packet loss expected), focus assertions on critical invariants that prevent undefined behavior.

**Critical assertions needed** (focus areas):
1. **Entry point validation**: Public function parameters
2. **Buffer safety**: Array bounds before writes (crashes)
3. **State machine integrity**: Invalid transitions (corruption) 
4. **Context consistency**: Required fields for operations
5. **CID validity**: Range checks (0-16383)

**Don't over-assert**:
- Packet loss scenarios (expected)
- Performance-critical loops
- Temporary calculations

**Action Plan**:
- Add strategic `debug_assert!` at boundaries only
- Focus on crash/corruption prevention
- Measure performance impact of each assertion

### Function Naming Violations (HIGH)
**Status**: 🟡 CONSISTENCY - Violates verb-based naming

**Anti-patterns in `traits.rs`**:
- `last_accessed()` → `accessed_time()` 
- `set_last_accessed()` → `update_access_time()`
- `set_cid()` → `assign_cid()`

### Unit Test Organization (CONFIRMED)
**Decision**: Follow Rust idioms for test organization

**Rust-idiomatic approach**:
- **Small modules**: Keep tests inline with `#[cfg(test)] mod tests`
- **Large modules**: Use `src/module/tests.rs` for complex tests
- **Split modules first**: Prefer breaking large modules into focused submodules
- **Avoid Go-style**: No `packet_processor_tests.rs` pattern

**Action Plan**:
1. Split oversized modules into focused submodules first
2. Keep simple unit tests inline in each submodule  
3. Move complex/integration-style tests to `tests.rs` if needed
4. Maintain private function test access via module structure

---

## Executive Summary

This roadmap addresses core architectural improvements while maintaining production-grade quality. The implementation strategy prioritizes small, safe, incremental changes to avoid big-bang refactors and reduce merge conflicts.

## Implementation Strategy: Small, Safe, Incremental Changes

### **Core Principle**: No Big Bang Refactors
- **Maximum change size**: 200-300 lines per PR
- **One concept per PR**: Never mix unrelated changes
- **Feature flags**: For larger changes, use conditional compilation
- **Backward compatibility**: Maintain existing APIs during transitions

---

### 2.2 Property-Based Testing Foundation (Week 7-8) 🟢 **LOW**

```rust
// Add to Cargo.toml dev-dependencies
[dev-dependencies]
quickcheck = "1.0"
quickcheck_macros = "1.0"

// tests/property_tests.rs (NEW FILE)
#[quickcheck]
fn lsb_encoding_roundtrip_property(value: u16, reference: u16) -> bool {
    let k = 8; // Start with fixed k, expand later
    let encoded = encode_lsb(value.into(), k).unwrap();
    let decoded = decode_lsb(encoded, reference.into(), k);

    // Property: If within window, must decode correctly
    let window_size = (1u16 << (k - 1)) - 1;
    let delta = value.wrapping_sub(reference);

    if delta <= window_size {
        decoded == value.into()
    } else {
        true // Outside window, any result acceptable
    }
}
```

**Implementation**:
- **PR 18**: Add quickcheck dependency and basic infrastructure (50 lines)
- **PR 19**: Add LSB encoding properties (100 lines)
- **PR 20**: Add CRC properties (100 lines)
- **PR 21**: Add context state machine properties (150 lines)

**Risk**: ZERO - Only adding tests
**Lines changed**: ~400 total

---

## Phase 3: Performance Optimization (Weeks 9-12)

### 3.1 Context Memory Layout (Week 9-10) 🟢 **LOW**

**Strategy**: Reorder fields for cache efficiency without changing semantics

```rust
// Before optimization, measure field access patterns
#[derive(Debug, Clone)]
pub struct Profile1CompressorContext {
    // HOT PATH FIELDS (first 64 bytes - cache line 1)
    pub mode: Profile1CompressorMode,                    // 1 byte
    pub last_sent_rtp_sn_full: SequenceNumber,         // 2 bytes
    pub last_sent_rtp_ts_full: Timestamp,              // 4 bytes
    pub last_sent_rtp_marker: bool,                    // 1 byte
    pub ts_stride_state: TsStrideState,                 // 16 bytes
    pub current_lsb_sn_width: u8,                      // 1 byte
    // ... pack to 64 bytes

    // COLD PATH FIELDS (separate cache line)
    pub last_accessed: Instant,                         // 16 bytes
    pub ip_source: Ipv4Addr,                           // 4 bytes
    // ... rest of fields
}
```

**Implementation**:
- **PR 22**: Add field access tracking to benchmarks (50 lines)
- **PR 23**: Reorder hot path fields first (30 lines)
- **PR 24**: Add cache line validation tests (50 lines)
- **PR 25**: Measure performance improvement (50 lines)

**Risk**: LOW - Only reordering, no logic changes
**Lines changed**: ~180 total

### 3.2 Allocation Tracking & Assertions (Week 11-12) 🟡 **MEDIUM**

```rust
// tests/allocation_tests.rs (NEW FILE)
#[test]
fn test_compression_zero_allocations() {
    let start_allocs = allocation_counter::get();

    // Compress 1000 packets
    for _ in 0..1000 {
        let _ = engine.compress(&headers, &mut buffer).unwrap();
    }

    let end_allocs = allocation_counter::get();
    assert_eq!(start_allocs, end_allocs, "Compression must not allocate");
}

// In production code
#[cfg(debug_assertions)]
macro_rules! assert_no_alloc {
    ($expr:expr) => {{
        let start = allocation_counter::get();
        let result = $expr;
        let end = allocation_counter::get();
        debug_assert_eq!(start, end, "Unexpected allocation in hot path");
        result
    }};
}
```

**Implementation**:
- **PR 26**: Add allocation tracking dependency (10 lines)
- **PR 27**: Add assert_no_alloc macro (50 lines)
- **PR 28**: Add allocation tests for hot paths (150 lines)
- **PR 29**: Add allocation assertions to hot paths (100 lines)

**Risk**: LOW - Debug-only assertions
**Lines changed**: ~310 total

---

## Phase 4: Code Organization (Weeks 13-16)

### 4.1 Module Size Audit & Planning (Week 13) 🟢 **LOW**

```bash
# Audit script: scripts/size_audit.sh
#!/bin/bash
echo "=== Module Size Audit ==="
find src -name "*.rs" -exec wc -l {} + | sort -nr | head -20

echo "=== Function Size Audit ==="
rg "^[[:space:]]*(pub[[:space:]]+)?fn[[:space:]]+" -A 1 |
  grep -E "^\d+:" |
  # Process to find large functions...

echo "=== Struct Field Count ==="
rg "^[[:space:]]*pub struct" -A 50 |
  # Count fields per struct...
```

**Current Violations (Estimated)**:
- `packet_processor.rs`: ~1800 lines (target: <500)
- `decompressor.rs`: ~800 lines (target: <500)
- `compressor.rs`: ~1100 lines (target: <500)
- `Profile1CompressorContext`: 32+ fields (target: <10)

**Implementation**:
- **PR 30**: Add size audit script and CI check (100 lines)
- **PR 31**: Document refactoring plan for large modules (planning only)

**Risk**: ZERO - Only audit tooling
**Lines changed**: ~100 total

### 4.2 Incremental Module Splitting (Week 14-16) 🟡 **MEDIUM**

**Strategy**: Extract cohesive submodules first, preserve public API

```rust
// BEFORE: packet_processor.rs (1800 lines)
pub fn serialize_ir(...) { ... }
pub fn deserialize_ir(...) { ... }
pub fn serialize_uo0(...) { ... }
// ... etc

// AFTER: Gradual extraction
// packet_processor/mod.rs (100 lines - public API only)
pub use ir_packets::{serialize_ir, deserialize_ir};
pub use uo_packets::{serialize_uo0, deserialize_uo0, ...};

// packet_processor/ir_packets.rs (300 lines)
pub fn serialize_ir(...) { ... }
pub fn deserialize_ir(...) { ... }

// packet_processor/uo_packets.rs (400 lines)
pub fn serialize_uo0(...) { ... }
// ...
```

**Implementation Priority**:
1. **PR 32**: Extract IR packet handling (300 lines moved)
2. **PR 33**: Extract UO packet handling (400 lines moved)
3. **PR 34**: Extract header parsing (300 lines moved)
4. **PR 35**: Clean up packet_processor/mod.rs (100 lines)

**Risk**: MEDIUM - But preserves API, extensive testing catches issues
**Lines changed**: ~1800 total (mostly moves)

---

## Phase 5: Advanced Features (Weeks 17-20)

### 5.1 Enhanced Property Testing (Week 17-18) 🟢 **LOW**

```rust
// Expand property testing with sophisticated generators
#[quickcheck]
fn compression_decompression_roundtrip(packet_stream: Vec<RtpPacket>) -> bool {
    let mut compressor = RohcEngine::new();
    let mut decompressor = RohcEngine::new();

    for packet in packet_stream {
        let compressed = compressor.compress(&packet.headers).unwrap();
        let decompressed = decompressor.decompress(&compressed).unwrap();
        if packet.headers != decompressed {
            return false;
        }
    }
    true
}

// Custom generators for realistic test cases
impl Arbitrary for RtpPacketStream {
    fn arbitrary(g: &mut Gen) -> Self {
        // Generate realistic RTP streams with proper:
        // - Sequence number progression
        // - Timestamp stride patterns
        // - Marker bit placement
        // - IP-ID increment patterns
    }
}
```

**Implementation**:
- **PR 36**: Add sophisticated packet stream generators (200 lines)
- **PR 37**: Add roundtrip property tests (150 lines)
- **PR 38**: Add state machine property tests (200 lines)

**Risk**: ZERO - Only adding tests
**Lines changed**: ~550 total

### 5.2 RFC Compliance Assertions (Week 19-20) 🟡 **MEDIUM**

```rust
// Add targeted RFC assertions at boundaries
#[cfg(debug_assertions)]
fn validate_rfc_ir_packet(packet: &[u8]) {
    debug_assert!(packet.len() >= P1_IR_MIN_SIZE,
        "IR packet too small: {} < {}", packet.len(), P1_IR_MIN_SIZE);
    debug_assert!(packet[0] & 0xFE == P1_IR_PACKET_TYPE,
        "Invalid IR packet type: 0b{:08b}", packet[0]);
    // ... more RFC validations
}

// Use at serialization boundaries
pub fn serialize_ir(...) -> Result<usize, RohcError> {
    let len = internal_serialize_ir(...)?;
    #[cfg(debug_assertions)]
    validate_rfc_ir_packet(&out[..len]);
    Ok(len)
}
```

**Implementation**:
- **PR 39**: Add RFC validation functions (200 lines)
- **PR 40**: Add assertions to IR packet handling (50 lines)
- **PR 41**: Add assertions to UO packet handling (100 lines)
- **PR 42**: Add assertion tests (100 lines)

**Risk**: LOW - Debug-only assertions
**Lines changed**: ~450 total

---

## Implementation Guidelines

### **PR Size Limits**
- **Maximum**: 300 lines changed
- **Preferred**: 100-200 lines changed
- **Giant modules**: Move in 300-line chunks

### **Risk Mitigation**
```rust
// Feature flags for large changes
#[cfg(feature = "new-stride-state")]
pub ts_stride_state: TsStrideState,

#[cfg(not(feature = "new-stride-state"))]
pub ts_stride: Option<u32>,
```

### **Testing Strategy**
```rust
// Every PR requires:
// 1. Existing tests pass
// 2. New functionality has tests
// 3. Performance tests show no regression
// 4. If changing hot path, allocation tests pass

#[test]
fn test_pr_42_no_performance_regression() {
    let baseline = Duration::from_nanos(450);
    let actual = benchmark_compression_roundtrip();
    assert!(actual <= baseline * 110 / 100, // Allow 10% degradation
        "Performance regression: {}ns > {}ns", actual.as_nanos(), baseline.as_nanos());
}
```

### **Merge Strategy**
1. **Phase 1**: Merge immediately (critical fixes)
2. **Phase 2-3**: Merge weekly after thorough review
3. **Phase 4-5**: Merge bi-weekly, extensive testing

### **Rollback Plan**
- Keep old APIs during transitions
- Feature flags for new implementations
- Comprehensive before/after benchmarks
- Git bisect-friendly commit structure

---

## Key Performance Targets

Based on STYLE.md requirements and current benchmarks:

- **Packet parsing**: >3 GiB/s ✅ (Currently ~3.5 GiB/s)
- **LSB operations**: <5 ns ❓ (Needs measurement)
- **CRC operations**: >800 MiB/s ❓ (Needs measurement)
- **Full roundtrip**: <600 ns ❓ (Needs measurement)
- **Zero allocations**: Hot paths only ⚠️ (CRC prep violates)

## Critical Technical Debt Issues

### **Production Blockers** 🔴
1. **3 failing state machine tests** - SO→NC transitions incomplete
2. **Missing RFC 3095 test vectors** - Standards compliance unknown
3. **CRC input allocations** - Violates zero-allocation principle

### **High Priority** 🟡
1. **Large module sizes** - Maintainability concerns
2. **Context structure sizes** - Cache efficiency impact
3. **Missing performance baselines** - No regression protection

### **Medium Priority** 🟢
1. **Manual packet parsing** - Maintenance burden
2. **Repetitive recovery logic** - Code duplication
3. **Type safety gaps** - Optional fields mask states

## Success Metrics

- [ ] All tests pass (no ignored tests)
- [ ] RFC compliance validated with test vectors
- [ ] Zero allocations in hot paths verified
- [ ] Performance targets met and protected
- [ ] Module sizes within style guide limits
- [ ] Property-based testing covers critical algorithms
- [ ] Context structures optimized for cache efficiency

---

## Summary

This roadmap prioritizes **safety and incrementality** over speed. Each change is small enough to review thoroughly and revert safely. The **20-week timeline** allows for careful implementation without rushing.

**Week 1-4**: Address production blockers
**Week 5-12**: Improve type safety and performance
**Week 13-20**: Enhance maintainability and robustness

**Total estimated effort**: ~5,000 lines changed over 42 PRs, but most are moves/additions rather than risky modifications.

The codebase already demonstrates exceptional production-grade architecture. These improvements will enhance an already strong foundation rather than fix fundamental problems.
