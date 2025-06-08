#!/bin/bash

NTFY_TOPIC="rohcstar_fuzz"

# Check for notify argument
ENABLE_NOTIFICATIONS=false
if [[ "$1" == "notify" ]]; then
    ENABLE_NOTIFICATIONS=true
    echo "Notifications enabled for topic: $NTFY_TOPIC"
else
    echo "Running without notifications (use 'notify' argument to enable)"
fi

# Run from project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT" || exit 1
echo "Working from project root: $PROJECT_ROOT"

while true; do
    echo "Pulling latest changes and rebuilding..."
    git pull
    if ! cargo build --release -p rohcstar-sim; then
        echo "Cargo build failed at $(date), sleeping before retry..."
        sleep 300 # Sleep for 5 mins if build fails
        continue
    fi

    echo "Starting rohcstar-sim continious fuzz..."

    # Build command with conditional notifications
    FUZZ_CMD="./target/release/rohcstar-sim fuzz \
        -p 500 \
        --infinite \
        --critical-only \
        -w $(nproc) \
        --max-loss 0.3 \
        --enable-git-update-check \
        --git-update-check-interval-secs 600"

    if [[ "$ENABLE_NOTIFICATIONS" == "true" ]]; then
        FUZZ_CMD="$FUZZ_CMD --ntfy-topic ${NTFY_TOPIC}"
    fi

    eval $FUZZ_CMD

    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        echo "rohcstar-sim exited with non-zero code $EXIT_CODE at $(date)" >> simulator_crashes.txt
        if [[ "$ENABLE_NOTIFICATIONS" == "true" ]]; then
            curl -X POST https://ntfy.sh/"${NTFY_TOPIC}" \
                -H "Title: FUZZER CRASH!" \
                -H "Tags: boom,warning" \
                -d "rohcstar-sim process crashed or exited unexpectedly with code $EXIT_CODE."
        fi
        sleep 60
    else
        echo "rohcstar-sim exiting gracefully..."
        exit 0
    fi
done


