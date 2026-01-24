#!/bin/bash
# Reset devnet state while preserving keys and configuration
#
# This script:
# - Stops all running nodes (if any)
# - Wipes all blockchain state (data directories)
# - Preserves keys and configuration files
# - Clears logs
#
# Usage:
#   ./scripts/reset-devnet.sh [devnet_dir]
#
# Example:
#   ./scripts/reset-devnet.sh ./devnet
#   ./scripts/reset-devnet.sh  # defaults to ./devnet

set -e

DEVNET_DIR="${1:-./devnet}"
SCRIPT_DIR="$(dirname "$0")"

# Ensure the devnet directory exists
if [ ! -d "$DEVNET_DIR" ]; then
    echo "Error: Devnet directory not found: $DEVNET_DIR"
    exit 1
fi

echo "Resetting devnet: $DEVNET_DIR"
echo ""

# Stop any running nodes first
if [ -d "${DEVNET_DIR}/pids" ]; then
    echo "Stopping any running nodes..."
    "$SCRIPT_DIR/stop-devnet.sh" "$DEVNET_DIR"
    echo ""
fi

# Find all node directories
NODES=$(ls -d "${DEVNET_DIR}"/node* 2>/dev/null | sort -V)

if [ -z "$NODES" ]; then
    echo "Warning: No node directories found in $DEVNET_DIR"
fi

# Clear data directories for each node
for NODE_DIR in $NODES; do
    NODE_NAME=$(basename "$NODE_DIR")
    DATA_DIR="${NODE_DIR}/data"

    if [ -d "$DATA_DIR" ]; then
        echo "Clearing data for $NODE_NAME..."
        rm -rf "$DATA_DIR"
        mkdir -p "$DATA_DIR"
    fi
done

# Clear logs directory
LOG_DIR="${DEVNET_DIR}/logs"
if [ -d "$LOG_DIR" ]; then
    echo "Clearing logs..."
    rm -rf "$LOG_DIR"
    mkdir -p "$LOG_DIR"
fi

# Clear PIDs directory
PID_DIR="${DEVNET_DIR}/pids"
if [ -d "$PID_DIR" ]; then
    rm -rf "$PID_DIR"
    mkdir -p "$PID_DIR"
fi

echo ""
echo "Devnet reset complete!"
echo ""
echo "Preserved:"
echo "  - Genesis file"
echo "  - Node configurations"
echo "  - Validator keys"
echo ""
echo "Cleared:"
echo "  - Blockchain state (data directories)"
echo "  - Logs"
echo "  - PID files"
echo ""
echo "To start fresh: ./scripts/start-devnet.sh $DEVNET_DIR"
