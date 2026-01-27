#!/bin/bash
# Run benchmarks against Docker devnet
#
# Usage: ./scripts/benchmark-docker.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=============================================="
echo "CipherBFT Docker Devnet Benchmark"
echo "=============================================="

# Step 1: Initialize devnet if not exists
if [ ! -d "$PROJECT_ROOT/devnet" ]; then
    echo "Initializing devnet..."
    cargo run -p cipherd -- devnet init-files --validators 3 --output "$PROJECT_ROOT/devnet"
fi

# Step 2: Start Docker Compose
echo ""
echo "Starting Docker Compose..."
cd "$PROJECT_ROOT/docker"
docker-compose up -d --build

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
    echo "  Waiting... ($i/30)"
    sleep 2
done

# Step 4: Run benchmark
echo ""
"$SCRIPT_DIR/benchmark-simple.sh" http://localhost:8545 100

# Step 5: Show metrics
echo ""
echo "Metrics available at:"
echo "  Prometheus: http://localhost:9090"
echo "  Grafana: http://localhost:3000 (admin/admin)"
echo ""
echo "To stop: cd docker && docker-compose down"
