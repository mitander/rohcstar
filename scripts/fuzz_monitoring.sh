#!/usr/bin/env bash

# ROHC Continuous Fuzzing Monitor with real-time statistics

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Default configuration
PACKETS_PER_RUN=1000
LOSS_RATE=0.01
THREADS=$(nproc 2>/dev/null || echo 4)
UPDATE_INTERVAL=10

usage() {
    cat << EOF
ROHC Fuzz Monitor - Continuous fuzzing with real-time statistics

USAGE:
    $0 [OPTIONS]

OPTIONS:
    --packets NUM        Packets per simulation run (default: $PACKETS_PER_RUN)
    --loss-rate RATE     Packet loss rate 0.0-1.0 (default: $LOSS_RATE)
    --threads NUM        Number of fuzzing threads (default: $THREADS)
    --update-interval S  Stats update interval in seconds (default: $UPDATE_INTERVAL)
    --profile            Run with profiling (perf integration)
    --help               Show this help message

EXAMPLES:
    # Default fuzzing
    $0

    # High-stress fuzzing
    $0 --packets 5000 --loss-rate 0.05 --threads 8

    # Low-latency monitoring
    $0 --packets 100 --update-interval 1

    # Profiling run
    $0 --profile --packets 10000 --threads 1

MONITORING:
    - Press Ctrl+C to stop gracefully
    - Statistics updated every $UPDATE_INTERVAL seconds
    - Implementation bugs tracked separately from network errors
    - Real-time packet throughput measurement

EOF
}

run_fuzz_monitor() {
    echo "Building fuzz monitor..."
    cd "$PROJECT_ROOT/rohcstar-sim"
    cargo build --release --bin fuzz-monitor

    echo "Starting ROHC continuous fuzzing monitor..."
    echo "Use Ctrl+C to stop gracefully"
    echo

    exec cargo run --release --bin fuzz-monitor -- \
        --packets "$PACKETS_PER_RUN" \
        --loss-rate "$LOSS_RATE" \
        --threads "$THREADS" \
        --update-interval "$UPDATE_INTERVAL"
}

run_profiled_fuzz() {
    if ! command -v perf &> /dev/null; then
        echo "Error: perf not available for profiling"
        echo "Install perf or run without --profile"
        exit 1
    fi

    echo "Building optimized fuzz monitor for profiling..."
    cd "$PROJECT_ROOT/rohcstar-sim"
    cargo build --release --bin fuzz-monitor

    echo "Starting profiled fuzzing session..."
    echo "Profiling data will be saved to perf.data"
    echo

    perf record -g --call-graph=dwarf \
        cargo run --release --bin fuzz-monitor -- \
        --packets "$PACKETS_PER_RUN" \
        --loss-rate "$LOSS_RATE" \
        --threads "$THREADS" \
        --update-interval "$UPDATE_INTERVAL"

    echo
    echo "Profiling complete. Analyze with:"
    echo "  perf report"
    echo "  perf annotate"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --packets)
            PACKETS_PER_RUN="$2"
            shift 2
            ;;
        --loss-rate)
            LOSS_RATE="$2"
            shift 2
            ;;
        --threads)
            THREADS="$2"
            shift 2
            ;;
        --update-interval)
            UPDATE_INTERVAL="$2"
            shift 2
            ;;
        --profile)
            PROFILE_MODE=true
            shift
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Validate arguments
if ! [[ "$PACKETS_PER_RUN" =~ ^[0-9]+$ ]] || [[ "$PACKETS_PER_RUN" -lt 1 ]]; then
    echo "Error: packets must be a positive integer"
    exit 1
fi

if ! [[ "$THREADS" =~ ^[0-9]+$ ]] || [[ "$THREADS" -lt 1 ]]; then
    echo "Error: threads must be a positive integer"
    exit 1
fi

if ! [[ "$UPDATE_INTERVAL" =~ ^[0-9]+$ ]] || [[ "$UPDATE_INTERVAL" -lt 1 ]]; then
    echo "Error: update-interval must be a positive integer"
    exit 1
fi

# Run the appropriate mode
if [[ "${PROFILE_MODE:-false}" == "true" ]]; then
    run_profiled_fuzz
else
    run_fuzz_monitor
fi
