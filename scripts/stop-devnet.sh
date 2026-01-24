#!/bin/bash
# Stop all devnet validator nodes gracefully
#
# Usage:
#   ./scripts/stop-devnet.sh [devnet_dir]
#
# Example:
#   ./scripts/stop-devnet.sh ./devnet
#   ./scripts/stop-devnet.sh  # defaults to ./devnet

set -e

DEVNET_DIR="${1:-./devnet}"
PID_DIR="${DEVNET_DIR}/pids"

if [ ! -d "$PID_DIR" ]; then
    echo "No PID directory found: $PID_DIR"
    echo "Devnet may not be running."
    exit 0
fi

# Find all PID files
PID_FILES=$(ls "${PID_DIR}"/*.pid 2>/dev/null || true)

if [ -z "$PID_FILES" ]; then
    echo "No running nodes found."
    exit 0
fi

echo "Stopping devnet validators..."
echo ""

for PID_FILE in $PID_FILES; do
    NODE_NAME=$(basename "$PID_FILE" .pid)

    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")

        if kill -0 "$PID" 2>/dev/null; then
            echo "Stopping $NODE_NAME (PID $PID)..."
            kill -TERM "$PID" 2>/dev/null || true
        else
            echo "$NODE_NAME not running (stale PID file)"
        fi

        rm -f "$PID_FILE"
    fi
done

# Wait a moment for graceful shutdown
sleep 1

# Check if any processes are still running and force kill if needed
for PID_FILE in $PID_FILES; do
    NODE_NAME=$(basename "$PID_FILE" .pid)
    PID_FILE_PATH="${PID_DIR}/${NODE_NAME}.pid"

    # Re-read in case file was recreated
    if [ -f "$PID_FILE_PATH" ]; then
        PID=$(cat "$PID_FILE_PATH")
        if kill -0 "$PID" 2>/dev/null; then
            echo "Force killing $NODE_NAME (PID $PID)..."
            kill -9 "$PID" 2>/dev/null || true
            rm -f "$PID_FILE_PATH"
        fi
    fi
done

echo ""
echo "Devnet stopped."
