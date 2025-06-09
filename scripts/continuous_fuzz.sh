#!/bin/bash

set -euo pipefail  # Better error handling

NTFY_TOPIC="rohcstar_fuzz"
ENABLE_NOTIFICATIONS=false

# Check for notify argument
if [[ "${1:-}" == "notify" ]]; then
    ENABLE_NOTIFICATIONS=true
    echo "Notifications enabled for topic: $NTFY_TOPIC"
else
    echo "Running without notifications (use 'notify' argument to enable)"
fi

# Setup directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT" || exit 1
echo "Working from project root: $PROJECT_ROOT"

# Function to send notifications
send_notification() {
    local title="$1"
    local message="$2"
    local tags="${3:-warning}"

    if [[ "$ENABLE_NOTIFICATIONS" == "true" ]]; then
        curl -s -X POST "https://ntfy.sh/${NTFY_TOPIC}" \
            -H "Title: $title" \
            -H "Tags: $tags" \
            -d "$message" || echo "Failed to send notification"
    fi
}

# Function to build project
build_project() {
    echo "Building project..."
    if cargo build --release -p rohcstar-sim; then
        echo "Build successful"
        return 0
    else
        echo "Build failed at $(date)"
        send_notification "BUILD FAILED" "Cargo build failed, retrying in 5 minutes"
        return 1
    fi
}

# Function to run fuzzer
run_fuzzer() {
    echo "Starting rohcstar-sim continuous fuzz..."

    local cmd=(
        "./target/release/rohcstar-sim" "fuzz"
        "-p" "500"
        "--infinite"
        "--critical-only"
        "-w" "$(($(nproc) / 2))" # Use 50% of cores
        "--max-loss" "0.3"
        "--enable-git-update-check"
        "--git-update-check-interval-secs" "600"
    )

    if [[ "$ENABLE_NOTIFICATIONS" == "true" ]]; then
        cmd+=("--ntfy-topic" "$NTFY_TOPIC")
    fi

    "${cmd[@]}"
    return $?
}

# Main loop
main() {
    send_notification "FUZZER STARTING" "Continuous fuzzing session started" "rocket"

    while true; do
        echo "=== $(date): Starting new iteration ==="

        # Pull latest changes
        echo "Pulling latest changes..."
        if ! git pull; then
            echo "Git pull failed, continuing with current version"
        fi

        # Build project (retry on failure)
        while ! build_project; do
            sleep 300  # Sleep 5 minutes before retry
        done

        # Run fuzzer
        run_fuzzer
        exit_code=$?

        case $exit_code in
            0)
                echo "Fuzzer exited gracefully (likely due to git update check)"
                echo "Restarting with updated code..."
                continue
                ;;
            130)  # SIGINT (Ctrl+C)
                echo "Received interrupt signal, exiting..."
                send_notification "FUZZER STOPPED" "Fuzzing stopped by user interrupt" "stop"
                exit 0
                ;;
            *)
                echo "Fuzzer crashed with exit code $exit_code at $(date)"
                echo "$(date): Exit code $exit_code" >> simulator_crashes.txt
                send_notification "FUZZER CRASH!" "rohcstar-sim crashed with exit code $exit_code" "boom,warning"
                echo "Sleeping 60 seconds before restart..."
                sleep 60
                ;;
        esac
    done
}

# Trap signals for clean shutdown
trap 'echo "Shutting down..."; exit 0' SIGTERM SIGINT

main "$@"
