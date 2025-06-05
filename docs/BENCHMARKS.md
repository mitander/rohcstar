# Rohcstar Benchmarks

## 1. Overview

The benchmark suite measures performance of critical ROHC operations using the Criterion framework. Benchmarks cover packet parsing, LSB operations, CRC calculations, compression/decompression pipelines, context management, and throughput scenarios.

## 2. Running Benchmarks

### Basic Usage

```bash
# Run all benchmarks
cd rohcstar && cargo bench --bench rohc_benchmarks

# Test benchmarks compile and run
cd rohcstar && cargo bench --bench rohc_benchmarks -- --test

# Run specific benchmark group
cd rohcstar && cargo bench --bench rohc_benchmarks -- packet_parsing
```

### Using the Runner Script

```bash
# Quick run (shorter sampling)
./run_benchmarks.sh --quick

# Test mode (compilation only)
./run_benchmarks.sh --test

# Full run with HTML reports
./run_benchmarks.sh --full --html

# Specific benchmark group
./run_benchmarks.sh packet_parsing
```

## 3. Performance Regression Detection

### Automated Checks
The repository includes performance regression detection scripts designed for CI/CD integration. These compare current benchmark results against fixed thresholds to detect significant performance degradations.

```bash
# Manual comprehensive check (~9 seconds)
./scripts/bench_regression_check.sh

# Quick development check (~4.5 seconds, compression only)
./scripts/quick-perf-check.sh

# Check with relaxed thresholds (2x normal)
./scripts/bench_regression_check.sh --threshold-factor 2
```

### CI/CD Integration
Performance checks are designed to run in CI/CD pipelines rather than git hooks for better developer experience:

- **Environment**: Consistent hardware and OS
- **Duration**: No impact on developer workflow
- **Reporting**: Can track performance trends over time
- **Coverage**: Can run comprehensive benchmarks without time pressure

### Performance Thresholds
**Full regression check** (scripts/bench_regression_check.sh):
- Compress first packet: 500ns
- Compress subsequent packet: 200ns
- Decompress IR packet: 500ns
- Decompress UO packet: 100ns
- Full roundtrip: 800ns

**Quick development check** (scripts/quick-perf-check.sh):
- Compress first packet: 400ns (relaxed)
- Compress subsequent packet: 180ns (relaxed)

### Development Workflow
For iterative development, use the quick check for fast feedback:

```bash
# Fast feedback during development
./scripts/quick-perf-check.sh

# Full check when needed
./scripts/bench_regression_check.sh
```

## 4. Benchmark Groups

### packet_parsing
Tests RTP/UDP/IPv4 header parsing performance.

**Test Cases:**
- `minimal_rtp_packet`: 40-byte packet with no CSRC list
- `csrc_list/N`: Packets with 0, 1, 4, 8, 15 CSRC entries

**Key Metrics:** Time per parse operation, throughput in GiB/s

### lsb_operations
Tests W-LSB encoding/decoding algorithms used for sequence numbers, timestamps, and IP IDs.

**Test Cases:**
- `encode/K`: Encoding with K-bit LSB fields (K = 4, 8, 12, 16)
- `decode/K`: Decoding with K-bit LSB fields (K = 4, 8, 12, 16)
- `decode_wraparound_u16`: Edge case testing for wraparound scenarios

**Key Metrics:** Time per encoding/decoding operation

### crc_operations
Tests CRC-3 and CRC-8 calculation performance for packet validation.

**Test Cases:**
- `crc3/N`: CRC-3 calculation on N-byte payloads (N = 1, 4, 8, 16, 32, 64, 128)
- `crc8/N`: CRC-8 calculation on N-byte payloads (N = 1, 4, 8, 16, 32, 64, 128)

**Key Metrics:** Time per CRC calculation, throughput in MiB/s

### compression_pipeline
Tests full compression workflow including context management and packet type selection.

**Test Cases:**
- `compress_first_packet`: Initial packet requiring IR (Initialization and Refresh)
- `compress_subsequent_packet`: Follow-up packets using established context

**Key Metrics:** Time per compression operation

### decompression_pipeline
Tests full decompression workflow including packet parsing and header reconstruction.

**Test Cases:**
- `decompress_ir_packet`: IR packet requiring context creation
- `decompress_uo_packet`: UO (Unidirectional Optimistic) packet using established context

**Key Metrics:** Time per decompression operation

### full_roundtrip
Tests end-to-end performance including compression and decompression.

**Test Cases:**
- `compress_decompress_roundtrip`: Complete cycle with context establishment

**Key Metrics:** Time per complete roundtrip

### context_management
Tests overhead of managing compression and decompression contexts.

**Test Cases:**
- `create_multiple_contexts`: Creating 100 contexts with different CIDs
- `context_lookup_existing`: Looking up and using an existing context

**Key Metrics:** Time per context operation

### memory_patterns
Tests memory allocation overhead and buffer management efficiency.

**Test Cases:**
- `compression_allocations`: Memory allocation overhead during compression of 50 packets
- `buffer_reuse_pattern`: Performance when reusing pre-allocated buffers vs new allocations

**Key Metrics:** Time per allocation pattern

### burst_processing
Tests performance when processing large batches of packets.

**Test Cases:**
- `compress_packet_burst`: Compressing 1000 sequential packets
- `decompress_packet_burst`: Decompressing 1000 sequential packets
- `roundtrip_packet_burst`: Full roundtrip processing of 100 packets

**Key Metrics:** Packets processed per second, time per burst operation

### concurrent_contexts
Tests performance when handling multiple simultaneous data streams.

**Test Cases:**
- `context_creation_scaling/N`: Creating N contexts (N = 1, 5, 10, 15)
- `context_lookup_scaling`: Looking up contexts in pseudo-random pattern

**Key Metrics:** Time per multi-context operation, scalability with number of contexts

## 5. Performance Targets

### Core Operations
- Packet parsing: >3 GiB/s throughput
- LSB operations: <5 ns per operation
- CRC calculations: >800 MiB/s for large payloads

### Pipeline Operations
- First packet compression: <300 ns
- Subsequent packet compression: <150 ns
- IR packet decompression: <300 ns
- UO packet decompression: <80 ns
- Full roundtrip: <600 ns

### System Operations
- Context creation: <300 ns per context
- Context lookup: <150 ns per lookup
- Memory allocation overhead: <300 ns per packet

## 6. Interpreting Results

### Criterion Output Format
```
packet_parsing/minimal_rtp_packet
                        time:   [11.192 ns 11.260 ns 11.277 ns]
                        thrpt:  [3.3035 GiB/s 3.3085 GiB/s 3.3285 GiB/s]
```

- **time**: [lower_bound estimate upper_bound] - Time per operation
- **thrpt**: Throughput (for operations that process data)
- **change**: Performance change from previous run (if available)

### Regression Detection
Monitor these thresholds for performance regressions:

- Packet parsing time: >20% increase
- LSB operation time: >15% increase
- Full roundtrip time: >25% increase
- Context management overhead: >30% increase

## 7. Implementation Notes

### Benchmark Design
- Uses `black_box()` to prevent compiler optimizations
- Realistic test data with proper RTP/UDP/IPv4 packet structures
- Proper context establishment for compression/decompression tests
- Statistical sampling with confidence intervals

### Known Limitations
- CID range limited to 0-15 for Add-CID packet format
- Some benchmarks use periodic IR packets to avoid stride issues
- Large context counts limited by current packet builder implementation

### Platform Considerations
- Results shown are for Apple Silicon (ARM64) architecture
- x86_64 performance typically similar or 10-20% higher
- Embedded targets may see 5-10x lower performance
- WASM targets may see 2-3x lower performance
