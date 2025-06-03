#!/bin/bash

# Local CI check script - runs the same checks as GitHub Actions CI
# Run this before pushing to catch issues early

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$REPO_ROOT"

echo "Running local CI checks..."
echo "================================"

echo "Checking code formatting..."
cargo fmt --all -- --check
echo "Format check passed"

echo ""
echo "Running Clippy lints..."
cargo clippy --all-targets --all-features -- -D warnings
echo "Clippy passed"

echo ""
echo "Running test suite..."
cargo test --all
echo "Tests passed"

echo ""
echo "Checking performance regression..."
if [[ -f "scripts/bench-regression-check.sh" ]]; then
    chmod +x scripts/bench-regression-check.sh
    ./scripts/bench-regression-check.sh
    echo "Performance check passed"
else
    echo "Performance script not found, skipping"
fi

echo ""
echo "Running simulation checks..."
cd rohcstar-sim

echo "  Running fuzz simulation..."
cargo run -- fuzz --iterations 50 --packets 100 --seed 12345

echo "  Running replay simulation..."
cargo run -- replay --seed 12345 --packets 100

cd "$REPO_ROOT"
echo "Simulation checks passed"

echo ""
echo "All local CI checks passed!"
echo "Ready to push!"