#!/bin/bash

# Benchmark Runner Script
#
# This script provides convenient ways to run the ROHC performance benchmarks
# with different configurations and output formats.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROHCSTAR_DIR="$SCRIPT_DIR/../rohcstar"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_usage() {
    echo "Usage: $0 [OPTIONS] [BENCHMARK_FILTER]"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message"
    echo "  -q, --quick         Run quick benchmarks (shorter sampling time)"
    echo "  -f, --full          Run full benchmarks (longer sampling time, more accurate)"
    echo "  -t, --test          Just test that benchmarks compile and run without measuring"
    echo "  -o, --output DIR    Output directory for benchmark results (default: ./benchmark_results)"
    echo "  -c, --compare FILE  Compare with previous benchmark results"
    echo "  --html              Generate HTML reports"
    echo "  --csv               Generate CSV output"
    echo ""
    echo "Benchmark Filters (optional):"
    echo "  packet_parsing      Only run packet parsing benchmarks"
    echo "  lsb_operations      Only run LSB encoding/decoding benchmarks"
    echo "  crc_operations      Only run CRC calculation benchmarks"
    echo "  compression_pipeline Only run compression pipeline benchmarks"
    echo "  decompression_pipeline Only run decompression pipeline benchmarks"
    echo "  full_roundtrip      Only run full roundtrip benchmarks"
    echo "  context_management  Only run context management benchmarks"
    echo "  memory_patterns     Only run memory allocation pattern benchmarks"
    echo "  burst_processing    Only run burst processing benchmarks"
    echo "  concurrent_contexts Only run concurrent context benchmarks"
    echo ""
    echo "Examples:"
    echo "  $0 --quick                    # Quick benchmark run"
    echo "  $0 --full --html              # Full run with HTML report"
    echo "  $0 packet_parsing             # Only packet parsing benchmarks"
    echo "  $0 --compare old_results.json # Compare with previous results"
}

# Default values
QUICK=false
FULL=false
TEST=false
OUTPUT_DIR="./benchmark_results"
COMPARE_FILE=""
HTML=false
CSV=false
BENCHMARK_FILTER=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            print_usage
            exit 0
            ;;
        -q|--quick)
            QUICK=true
            shift
            ;;
        -f|--full)
            FULL=true
            shift
            ;;
        -t|--test)
            TEST=true
            shift
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -c|--compare)
            COMPARE_FILE="$2"
            shift 2
            ;;
        --html)
            HTML=true
            shift
            ;;
        --csv)
            CSV=true
            shift
            ;;
        packet_parsing|lsb_operations|crc_operations|compression_pipeline|decompression_pipeline|full_roundtrip|context_management|memory_patterns|burst_processing|concurrent_contexts)
            BENCHMARK_FILTER="$1"
            shift
            ;;
        *)
            echo -e "${RED}Error: Unknown option $1${NC}"
            print_usage
            exit 1
            ;;
    esac
done

# Validate conflicting options
if [[ "$QUICK" == true && "$FULL" == true ]]; then
    echo -e "${RED}Error: Cannot specify both --quick and --full${NC}"
    exit 1
fi

# Set default to quick if neither quick nor full specified
if [[ "$QUICK" == false && "$FULL" == false && "$TEST" == false ]]; then
    QUICK=true
fi

echo -e "${BLUE}ROHC Benchmark Runner${NC}"
echo "=========================="

# Check if we're in the right directory
if [[ ! -d "$ROHCSTAR_DIR" ]]; then
    echo -e "${RED}Error: Could not find rohcstar directory at $ROHCSTAR_DIR${NC}"
    echo "Please run this script from the repository root."
    exit 1
fi

cd "$ROHCSTAR_DIR"

# Check if Cargo.toml exists
if [[ ! -f "Cargo.toml" ]]; then
    echo -e "${RED}Error: Could not find Cargo.toml in $ROHCSTAR_DIR${NC}"
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)" # Convert to absolute path

echo -e "${GREEN}Output directory: $OUTPUT_DIR${NC}"

# Build benchmark command
CARGO_ARGS="bench --bench rohc_benchmarks"
CRITERION_ARGS=""

if [[ "$TEST" == true ]]; then
    echo -e "${YELLOW}Running benchmark tests...${NC}"
    CRITERION_ARGS="-- --test"
elif [[ "$QUICK" == true ]]; then
    echo -e "${YELLOW}Running quick benchmarks...${NC}"
    CRITERION_ARGS="-- --quick"
elif [[ "$FULL" == true ]]; then
    echo -e "${YELLOW}Running full benchmarks...${NC}"
    # No additional args for full benchmarks
fi

# Add benchmark filter if specified
if [[ -n "$BENCHMARK_FILTER" ]]; then
    CRITERION_ARGS="$CRITERION_ARGS $BENCHMARK_FILTER"
    echo -e "${BLUE}Filtering benchmarks: $BENCHMARK_FILTER${NC}"
fi

# Set up output format
if [[ "$HTML" == true ]]; then
    export CRITERION_HOME="$OUTPUT_DIR/criterion"
    echo -e "${BLUE}HTML reports will be generated in: $OUTPUT_DIR/criterion${NC}"
fi

# Run the benchmarks
echo -e "${GREEN}Running: cargo $CARGO_ARGS $CRITERION_ARGS${NC}"
echo ""

if ! cargo $CARGO_ARGS $CRITERION_ARGS; then
    echo -e "${RED}Benchmark failed!${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}Benchmarks completed successfully!${NC}"

# Generate additional outputs if requested
if [[ "$CSV" == true ]]; then
    echo -e "${YELLOW}Note: CSV output requires criterion to be configured with --output-format=csv${NC}"
    echo "Consider using the HTML reports for detailed analysis."
fi

if [[ -n "$COMPARE_FILE" ]]; then
    if [[ -f "$COMPARE_FILE" ]]; then
        echo -e "${YELLOW}Note: Comparison with previous results requires manual analysis of the reports.${NC}"
        echo "Previous results file: $COMPARE_FILE"
    else
        echo -e "${RED}Warning: Comparison file $COMPARE_FILE not found${NC}"
    fi
fi

if [[ "$HTML" == true && -d "$OUTPUT_DIR/criterion" ]]; then
    echo ""
    echo -e "${GREEN}HTML reports generated!${NC}"
    echo "Open $OUTPUT_DIR/criterion/index.html in your browser to view results."
fi

echo ""
echo -e "${BLUE}Performance Analysis Tips:${NC}"
echo "- packet_parsing: Look for throughput (GiB/s) - higher is better"
echo "- lsb_operations: Time per operation - lower is better"
echo "- crc_operations: Throughput for different payload sizes"
echo "- compression_pipeline: First packet vs subsequent packet performance"
echo "- decompression_pipeline: IR packet vs UO packet performance"
echo "- full_roundtrip: End-to-end latency"
echo "- context_management: Context creation and lookup performance"
echo "- memory_patterns: Memory allocation and buffer reuse efficiency"
echo "- burst_processing: High-throughput packet stream processing"
echo "- concurrent_contexts: Multi-stream and multi-user performance"
