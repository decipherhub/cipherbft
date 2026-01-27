#!/bin/bash
# Simple transfer benchmark using cast
#
# Usage: ./scripts/benchmark-simple.sh [RPC_URL] [COUNT] [PRIVATE_KEY]

set -e

RPC_URL="${1:-http://localhost:8545}"
COUNT="${2:-100}"

echo "=============================================="
echo "CipherBFT Simple Transfer Benchmark"
echo "=============================================="
echo "RPC URL: $RPC_URL"
echo "TX Count: $COUNT"
echo ""

# Check if cast is installed
if ! command -v cast &> /dev/null; then
    echo "Error: foundry's cast is not installed"
    echo "Install: curl -L https://foundry.paradigm.xyz | bash"
    exit 1
fi

# Get first account from devnet (has prefunded balance)
# For devnet, we use the test keys
PRIVATE_KEY="${3:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"

echo "Sending $COUNT simple transfers..."
echo ""

START=$(date +%s.%N)

for i in $(seq 1 $COUNT); do
    cast send --rpc-url "$RPC_URL" \
        --private-key "$PRIVATE_KEY" \
        --value 1wei \
        0x0000000000000000000000000000000000000001 \
        --async > /dev/null 2>&1 &

    # Print progress every 10 txs
    if [ $((i % 10)) -eq 0 ]; then
        echo "  Sent $i/$COUNT transactions..."
    fi
done

# Wait for all background jobs
wait

END=$(date +%s.%N)
DURATION=$(echo "$END - $START" | bc)
TPS=$(echo "scale=2; $COUNT / $DURATION" | bc)

echo ""
echo "=============================================="
echo "Results:"
echo "  Transactions: $COUNT"
echo "  Duration: ${DURATION}s"
echo "  Submission TPS: ${TPS}"
echo "=============================================="
