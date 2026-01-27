#!/bin/bash
# Reset devnet state while preserving keys and configuration
#
# This script:
# - Stops all running containers (if any)
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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DEVNET_DIR="${1:-$PROJECT_ROOT/devnet}"
DOCKER_DIR="$PROJECT_ROOT/docker"
COMPOSE_FILE="$DOCKER_DIR/docker-compose.yml"

# Ensure the devnet directory exists
if [ ! -d "$DEVNET_DIR" ]; then
    echo "Error: Devnet directory not found: $DEVNET_DIR"
    exit 1
fi

echo "Resetting devnet: $DEVNET_DIR"
echo ""

# Stop any running containers first
if [ -f "$COMPOSE_FILE" ]; then
    if docker info > /dev/null 2>&1; then
        echo "Stopping any running containers..."
        cd "$DOCKER_DIR"
        docker compose down --timeout 5 2>/dev/null || true
        cd - > /dev/null
        echo ""
    fi
fi

# Also clean up old-style PID files if they exist
if [ -d "${DEVNET_DIR}/pids" ]; then
    echo "Cleaning up legacy PID files..."
    for PID_FILE in "${DEVNET_DIR}"/pids/*.pid; do
        if [ -f "$PID_FILE" ]; then
            PID=$(cat "$PID_FILE" 2>/dev/null || true)
            if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
                echo "  Stopping legacy process (PID $PID)..."
                kill -TERM "$PID" 2>/dev/null || true
            fi
        fi
    done
    rm -rf "${DEVNET_DIR}/pids"
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

# Clear logs directory (legacy)
LOG_DIR="${DEVNET_DIR}/logs"
if [ -d "$LOG_DIR" ]; then
    echo "Clearing legacy logs..."
    rm -rf "$LOG_DIR"
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
echo "  - Docker containers"
echo "  - Legacy logs and PID files"
echo ""
echo "To start fresh: ./scripts/start-devnet.sh $DEVNET_DIR"
