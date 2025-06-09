#!/bin/bash

# Performance regression check for rohcstar
# Usage: bench_regression_check.sh [--threshold-factor N]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ROHCSTAR_DIR="$REPO_ROOT/rohcstar"

# Environment-aware performance thresholds (nanoseconds)
if [[ "${GITHUB_ACTIONS}" == "true" ]]; then
    # GitHub Actions runner thresholds (more lenient for x86_64 runners)
    COMPRESS_FIRST_THRESHOLD=650        # ~520ns + margin
    COMPRESS_SUBSEQUENT_THRESHOLD=250   # ~200ns + margin
    DECOMPRESS_IR_THRESHOLD=650         # ~520ns + margin
    DECOMPRESS_UO_THRESHOLD=130         # ~100ns + margin
    ROUNDTRIP_THRESHOLD=950             # ~750ns + margin
else
    # Local development thresholds (tighter for faster hardware)
    COMPRESS_FIRST_THRESHOLD=450        # ~368ns + margin
    COMPRESS_SUBSEQUENT_THRESHOLD=190   # ~157ns + margin
    DECOMPRESS_IR_THRESHOLD=470         # ~390ns + margin
    DECOMPRESS_UO_THRESHOLD=100         # ~82ns + margin
    ROUNDTRIP_THRESHOLD=740             # ~613ns + margin
fi

# Parse threshold factor argument
THRESHOLD_FACTOR=1
if [[ "$1" == "--threshold-factor" && -n "$2" ]]; then
    THRESHOLD_FACTOR="$2"
fi

# Apply threshold factor (use bc for floating point arithmetic)
if command -v bc >/dev/null 2>&1; then
    COMPRESS_FIRST_THRESHOLD=$(echo "$COMPRESS_FIRST_THRESHOLD * $THRESHOLD_FACTOR" | bc | cut -d. -f1)
    COMPRESS_SUBSEQUENT_THRESHOLD=$(echo "$COMPRESS_SUBSEQUENT_THRESHOLD * $THRESHOLD_FACTOR" | bc | cut -d. -f1)
    DECOMPRESS_IR_THRESHOLD=$(echo "$DECOMPRESS_IR_THRESHOLD * $THRESHOLD_FACTOR" | bc | cut -d. -f1)
    DECOMPRESS_UO_THRESHOLD=$(echo "$DECOMPRESS_UO_THRESHOLD * $THRESHOLD_FACTOR" | bc | cut -d. -f1)
    ROUNDTRIP_THRESHOLD=$(echo "$ROUNDTRIP_THRESHOLD * $THRESHOLD_FACTOR" | bc | cut -d. -f1)
else
    # Fallback: only support integer factors if bc not available
    if [[ "$THRESHOLD_FACTOR" =~ ^[0-9]+$ ]]; then
        COMPRESS_FIRST_THRESHOLD=$((COMPRESS_FIRST_THRESHOLD * THRESHOLD_FACTOR))
        COMPRESS_SUBSEQUENT_THRESHOLD=$((COMPRESS_SUBSEQUENT_THRESHOLD * THRESHOLD_FACTOR))
        DECOMPRESS_IR_THRESHOLD=$((DECOMPRESS_IR_THRESHOLD * THRESHOLD_FACTOR))
        DECOMPRESS_UO_THRESHOLD=$((DECOMPRESS_UO_THRESHOLD * THRESHOLD_FACTOR))
        ROUNDTRIP_THRESHOLD=$((ROUNDTRIP_THRESHOLD * THRESHOLD_FACTOR))
    else
        echo "Warning: bc not available, ignoring non-integer threshold factor"
    fi
fi

# Check if we're in the right directory
if [[ ! -d "$ROHCSTAR_DIR" ]]; then
    echo "Error: Could not find rohcstar directory"
    exit 1
fi

cd "$ROHCSTAR_DIR"

echo "Running fast performance regression check..."
echo "Only testing critical benchmarks for git hook performance"
echo "Thresholds: compress_first=${COMPRESS_FIRST_THRESHOLD}ns, compress_subsequent=${COMPRESS_SUBSEQUENT_THRESHOLD}ns"
echo "           decompress_ir=${DECOMPRESS_IR_THRESHOLD}ns, decompress_uo=${DECOMPRESS_UO_THRESHOLD}ns"
echo "           roundtrip=${ROUNDTRIP_THRESHOLD}ns"

# Run only critical benchmarks for fast regression check (one group at a time)
TEMP_FILE=$(mktemp)
echo "Running critical benchmarks (compression, decompression, roundtrip)..."

# Run each benchmark group separately and combine results
cargo bench --bench rohc_benchmarks -- --quick compression_pipeline 2>&1 >> "$TEMP_FILE"
if [ $? -ne 0 ]; then
    echo "Error: Compression pipeline benchmark failed"
    rm -f "$TEMP_FILE"
    exit 1
fi

cargo bench --bench rohc_benchmarks -- --quick decompression_pipeline 2>&1 >> "$TEMP_FILE"
if [ $? -ne 0 ]; then
    echo "Error: Decompression pipeline benchmark failed"
    rm -f "$TEMP_FILE"
    exit 1
fi

cargo bench --bench rohc_benchmarks -- --quick full_roundtrip 2>&1 >> "$TEMP_FILE"
if [ $? -ne 0 ]; then
    echo "Error: Full roundtrip benchmark failed"
    rm -f "$TEMP_FILE"
    exit 1
fi

# Extract performance metrics using simple grep and sed
extract_ns() {
    local bench_name="$1"
    grep -A 1 "$bench_name" "$TEMP_FILE" | grep "time:" | sed -n 's/.*time:.*\[\([0-9.]*\) ns.*/\1/p' | head -1
}

# Extract current performance metrics
COMPRESS_FIRST=$(extract_ns "compress_first_packet")
COMPRESS_SUBSEQUENT=$(extract_ns "compress_subsequent_packet")
DECOMPRESS_IR=$(extract_ns "decompress_ir_packet")
DECOMPRESS_UO=$(extract_ns "decompress_uo_packet")
ROUNDTRIP=$(extract_ns "compress_decompress_roundtrip")

rm -f "$TEMP_FILE"

# Validate extracted metrics
if [[ -z "$COMPRESS_FIRST" || -z "$COMPRESS_SUBSEQUENT" || -z "$DECOMPRESS_IR" || -z "$DECOMPRESS_UO" || -z "$ROUNDTRIP" ]]; then
    echo "Warning: Could not extract performance metrics from benchmark output"
    echo "Skipping performance regression check"
    exit 0
fi

# Convert to integers for comparison (remove decimal points)
COMPRESS_FIRST_INT=${COMPRESS_FIRST%.*}
COMPRESS_SUBSEQUENT_INT=${COMPRESS_SUBSEQUENT%.*}
DECOMPRESS_IR_INT=${DECOMPRESS_IR%.*}
DECOMPRESS_UO_INT=${DECOMPRESS_UO%.*}
ROUNDTRIP_INT=${ROUNDTRIP%.*}

echo "Current performance:"
echo "  Compress first packet: ${COMPRESS_FIRST}ns"
echo "  Compress subsequent: ${COMPRESS_SUBSEQUENT}ns"
echo "  Decompress IR: ${DECOMPRESS_IR}ns"
echo "  Decompress UO: ${DECOMPRESS_UO}ns"
echo "  Full roundtrip: ${ROUNDTRIP}ns"

# Check for regressions
REGRESSION_FOUND=false

check_threshold() {
    local name="$1"
    local current="$2"
    local threshold="$3"

    if [[ "$current" -gt "$threshold" ]]; then
        echo "REGRESSION: $name performance is ${current}ns (threshold: ${threshold}ns)"
        REGRESSION_FOUND=true
    fi
}

check_threshold "Compress first packet" "$COMPRESS_FIRST_INT" "$COMPRESS_FIRST_THRESHOLD"
check_threshold "Compress subsequent" "$COMPRESS_SUBSEQUENT_INT" "$COMPRESS_SUBSEQUENT_THRESHOLD"
check_threshold "Decompress IR" "$DECOMPRESS_IR_INT" "$DECOMPRESS_IR_THRESHOLD"
check_threshold "Decompress UO" "$DECOMPRESS_UO_INT" "$DECOMPRESS_UO_THRESHOLD"
check_threshold "Full roundtrip" "$ROUNDTRIP_INT" "$ROUNDTRIP_THRESHOLD"

if [[ "$REGRESSION_FOUND" == true ]]; then
    echo ""
    echo "Performance regression detected!"
    echo "Consider reviewing recent changes or adjusting thresholds if acceptable."
    exit 1
else
    echo "All benchmarks within acceptable performance thresholds."
    exit 0
fi
