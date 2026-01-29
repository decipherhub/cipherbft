#!/bin/bash
# Debug script to understand the block fetching race condition
# This simulates what cast send does when polling for transaction confirmation

RPC_URL="https://rpc.cipherbft.xyz"

echo "=== Debug Block Fetching ==="
echo "Testing: eth_blockNumber vs eth_getBlockByNumber consistency"
echo ""

# Function to get current block number
get_block_number() {
    curl -s -X POST "$RPC_URL" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' | jq -r '.result'
}

# Function to check if block exists
check_block_exists() {
    local block_num=$1
    local result=$(curl -s -X POST "$RPC_URL" \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBlockByNumber\",\"params\":[\"$block_num\", false],\"id\":1}" | jq -r '.result')

    if [ "$result" == "null" ]; then
        echo "NOT_FOUND"
    else
        echo "FOUND"
    fi
}

echo "Phase 1: Checking current state..."
CURRENT_BLOCK=$(get_block_number)
echo "Current block number: $CURRENT_BLOCK ($(printf '%d' $CURRENT_BLOCK))"
echo "Block exists: $(check_block_exists $CURRENT_BLOCK)"
echo ""

echo "Phase 2: Rapid polling for race condition (20 iterations)..."
echo "Looking for: eth_blockNumber returns N but eth_getBlockByNumber(N) returns null"
echo ""

RACE_FOUND=0
for i in $(seq 1 20); do
    BLOCK_NUM=$(get_block_number)
    BLOCK_EXISTS=$(check_block_exists $BLOCK_NUM)

    if [ "$BLOCK_EXISTS" == "NOT_FOUND" ]; then
        echo "!!! RACE CONDITION DETECTED !!!"
        echo "Block $BLOCK_NUM ($(printf '%d' $BLOCK_NUM)) reported as latest but does NOT exist"
        RACE_FOUND=1
    else
        echo "[$i] Block $BLOCK_NUM exists ✓"
    fi

    # Small delay to let chain progress
    sleep 0.1
done

echo ""
if [ $RACE_FOUND -eq 0 ]; then
    echo "No race condition detected in 20 polls."
    echo "The issue may be specific to transaction submission timing."
fi

echo ""
echo "Phase 3: Testing block range around latest..."
LATEST=$(get_block_number)
LATEST_DEC=$(printf '%d' $LATEST)

echo "Checking blocks $((LATEST_DEC - 5)) to $((LATEST_DEC + 5))..."
for offset in $(seq -5 5); do
    BLOCK_TO_CHECK=$((LATEST_DEC + offset))
    BLOCK_HEX=$(printf '0x%x' $BLOCK_TO_CHECK)
    EXISTS=$(check_block_exists $BLOCK_HEX)
    if [ "$EXISTS" == "NOT_FOUND" ]; then
        echo "  Block $BLOCK_TO_CHECK ($BLOCK_HEX): NOT FOUND"
    else
        echo "  Block $BLOCK_TO_CHECK ($BLOCK_HEX): exists"
    fi
done

echo ""
echo "=== Summary ==="
echo "If race conditions were found, the RPC is advertising blocks before they're stored."
echo "If no race found, the issue may be in transaction receipt polling specifically."
