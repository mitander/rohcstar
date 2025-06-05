#!/bin/bash

# Quick performance check for development iteration
# Much faster than full regression check - only tests compression pipeline

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ROHCSTAR_DIR="$REPO_ROOT/rohcstar"

# Simple thresholds for development check
COMPRESS_FIRST_THRESHOLD=400    # Relaxed threshold
COMPRESS_SUBSEQUENT_THRESHOLD=180

if [[ ! -d "$ROHCSTAR_DIR" ]]; then
    echo "Error: Could not find rohcstar directory"
    exit 1
fi

cd "$ROHCSTAR_DIR"

echo "Quick performance check (compression pipeline only)..."
echo "Thresholds: compress_first=${COMPRESS_FIRST_THRESHOLD}ns, compress_subsequent=${COMPRESS_SUBSEQUENT_THRESHOLD}ns"

# Run only compression pipeline for speed
TEMP_FILE=$(mktemp)
if ! cargo bench --bench rohc_benchmarks -- --quick compression_pipeline 2>&1 > "$TEMP_FILE"; then
    echo "Error: Benchmark execution failed"
    rm -f "$TEMP_FILE"
    exit 1
fi

# Extract metrics
extract_ns() {
    local bench_name="$1"
    grep -A 1 "$bench_name" "$TEMP_FILE" | grep "time:" | sed -n 's/.*time:.*\[\([0-9.]*\) ns.*/\1/p' | head -1
}

COMPRESS_FIRST=$(extract_ns "compress_first_packet")
COMPRESS_SUBSEQUENT=$(extract_ns "compress_subsequent_packet")

rm -f "$TEMP_FILE"

if [[ -z "$COMPRESS_FIRST" || -z "$COMPRESS_SUBSEQUENT" ]]; then
    echo "Warning: Could not extract performance metrics"
    exit 0
fi

# Convert to integers
COMPRESS_FIRST_INT=${COMPRESS_FIRST%.*}
COMPRESS_SUBSEQUENT_INT=${COMPRESS_SUBSEQUENT%.*}

echo "Performance: compress_first=${COMPRESS_FIRST}ns, compress_subsequent=${COMPRESS_SUBSEQUENT}ns"

# Check thresholds
if [[ "$COMPRESS_FIRST_INT" -gt "$COMPRESS_FIRST_THRESHOLD" ]]; then
    echo "SLOW: First packet compression is ${COMPRESS_FIRST}ns (threshold: ${COMPRESS_FIRST_THRESHOLD}ns)"
    exit 1
fi

if [[ "$COMPRESS_SUBSEQUENT_INT" -gt "$COMPRESS_SUBSEQUENT_THRESHOLD" ]]; then
    echo "SLOW: Subsequent packet compression is ${COMPRESS_SUBSEQUENT}ns (threshold: ${COMPRESS_SUBSEQUENT_THRESHOLD}ns)"
    exit 1
fi

echo "Performance looks good!"