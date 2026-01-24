#!/bin/bash
# Start all devnet validator nodes as background processes
#
# Usage:
#   ./scripts/start-devnet.sh [devnet_dir]
#
# Example:
#   ./scripts/start-devnet.sh ./devnet
#   ./scripts/start-devnet.sh  # defaults to ./devnet

set -e

DEVNET_DIR="${1:-./devnet}"
LOG_DIR="${DEVNET_DIR}/logs"
PID_DIR="${DEVNET_DIR}/pids"

# Ensure the devnet directory exists
if [ ! -d "$DEVNET_DIR" ]; then
    echo "Error: Devnet directory not found: $DEVNET_DIR"
    echo ""
    echo "Initialize devnet first with:"
    echo "  cargo run -p cipherd -- devnet init-files --output $DEVNET_DIR"
    exit 1
fi

# Create log and pid directories
mkdir -p "$LOG_DIR"
mkdir -p "$PID_DIR"

# Find all node directories
NODES=$(ls -d "${DEVNET_DIR}"/node* 2>/dev/null | sort -V)

if [ -z "$NODES" ]; then
    echo "Error: No node directories found in $DEVNET_DIR"
    exit 1
fi

echo "Starting devnet validators from: $DEVNET_DIR"
echo ""

# Build cipherd first
echo "Building cipherd..."
cargo build -p cipherd --release
CIPHERD_BIN="$(pwd)/target/release/cipherd"

if [ ! -f "$CIPHERD_BIN" ]; then
    echo "Error: Failed to build cipherd"
    exit 1
fi

# Start each node
for NODE_DIR in $NODES; do
    NODE_NAME=$(basename "$NODE_DIR")
    CONFIG_FILE="${NODE_DIR}/config/node.json"

    if [ ! -f "$CONFIG_FILE" ]; then
        echo "Warning: Config not found for $NODE_NAME, skipping"
        continue
    fi

    LOG_FILE="${LOG_DIR}/${NODE_NAME}.log"
    PID_FILE="${PID_DIR}/${NODE_NAME}.pid"

    # Check if already running
    if [ -f "$PID_FILE" ]; then
        OLD_PID=$(cat "$PID_FILE")
        if kill -0 "$OLD_PID" 2>/dev/null; then
            echo "$NODE_NAME already running (PID $OLD_PID), skipping"
            continue
        fi
        rm -f "$PID_FILE"
    fi

    echo "Starting $NODE_NAME..."

    # Start the node in background
    nohup "$CIPHERD_BIN" start --config "$CONFIG_FILE" > "$LOG_FILE" 2>&1 &
    NODE_PID=$!

    echo "$NODE_PID" > "$PID_FILE"
    echo "  PID: $NODE_PID"
    echo "  Log: $LOG_FILE"

    # Small delay between node starts
    sleep 0.5
done

echo ""
echo "Devnet started successfully!"
echo ""
echo "Logs:     $LOG_DIR/"
echo "PIDs:     $PID_DIR/"
echo ""
echo "To stop:  ./scripts/stop-devnet.sh $DEVNET_DIR"
echo "To reset: ./scripts/reset-devnet.sh $DEVNET_DIR"
echo ""
echo "RPC endpoints:"

# Extract RPC ports from configs
for NODE_DIR in $NODES; do
    NODE_NAME=$(basename "$NODE_DIR")
    CONFIG_FILE="${NODE_DIR}/config/node.json"
    if [ -f "$CONFIG_FILE" ]; then
        HTTP_PORT=$(jq -r '.rpc_http_port // 8545' "$CONFIG_FILE")
        echo "  $NODE_NAME: http://localhost:$HTTP_PORT"
    fi
done
