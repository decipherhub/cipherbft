#!/bin/bash
# Run benchmarks against Docker devnet
#
# Usage: ./scripts/benchmark-docker.sh [tx_count]
#
# Example:
#   ./scripts/benchmark-docker.sh       # defaults to 100 transactions
#   ./scripts/benchmark-docker.sh 1000  # run with 1000 transactions

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TX_COUNT="${1:-100}"

echo "=============================================="
echo "CipherBFT Docker Devnet Benchmark"
echo "=============================================="

# Step 1: Initialize devnet if not exists
if [ ! -d "$PROJECT_ROOT/devnet" ]; then
    echo "Initializing devnet..."
    cargo run -p cipherd -- devnet init-files --validators 3 --output "$PROJECT_ROOT/devnet"
fi

# Step 2: Start devnet using our script
echo ""
echo "Starting Docker Compose devnet..."
"$SCRIPT_DIR/start-devnet.sh" --build

# Step 3: Wait for nodes to be ready
echo ""
echo "Waiting for nodes to be ready..."
sleep 10

# Check if RPC is responding
for i in {1..30}; do
    if curl -s http://localhost:8545 > /dev/null 2>&1; then
        echo "  Validator 0 is ready"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "Error: Nodes failed to start within timeout"
        "$SCRIPT_DIR/stop-devnet.sh"
        exit 1
    fi
    echo "  Waiting... ($i/30)"
    sleep 2
done

# Step 4: Run benchmark
echo ""
"$SCRIPT_DIR/benchmark-simple.sh" http://localhost:8545 "$TX_COUNT"

# Step 5: Show metrics
echo ""
echo "Metrics available at:"
echo "  Prometheus: http://localhost:9090"
echo "  Grafana: http://localhost:3000 (admin/admin)"
echo ""
echo "To stop: ./scripts/stop-devnet.sh"
