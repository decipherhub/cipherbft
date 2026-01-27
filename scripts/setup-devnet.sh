#!/bin/bash
# Setup devnet configuration with validator funding
#
# This script initializes a complete devnet environment including:
# - Validator keys and configuration
# - Genesis file with funded validator accounts
# - Docker Compose configuration
#
# Usage:
#   ./scripts/setup-devnet.sh [options]
#
# Options:
#   -n, --validators <N>       Number of validators (default: 4)
#   --stake <ETH>              Initial stake per validator in ETH (default: 32)
#   --balance <ETH>            Initial balance per validator in ETH (default: 100)
#   --chain-id <ID>            Chain ID (default: 85300)
#   --network-id <ID>          Network identifier (default: cipherbft-devnet-1)
#   --output <DIR>             Output directory (default: ./devnet)
#   --extra-alloc <ADDR:ETH>   Extra account allocation (can be repeated)
#   --force                    Overwrite existing devnet directory
#   --help                     Show this help message
#
# Examples:
#   ./scripts/setup-devnet.sh                                    # Default 4 validators, 100 ETH each
#   ./scripts/setup-devnet.sh -n 7 --balance 1000                # 7 validators, 1000 ETH each
#   ./scripts/setup-devnet.sh --extra-alloc 0x123...abc:5000     # Add extra funded account

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Default values
NUM_VALIDATORS=4
INITIAL_STAKE_ETH=32
INITIAL_BALANCE_ETH=100
CHAIN_ID=85300
NETWORK_ID="cipherbft-devnet-1"
OUTPUT_DIR="$PROJECT_ROOT/devnet"
EXTRA_ALLOC=()
FORCE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--validators)
            NUM_VALIDATORS="$2"
            shift 2
            ;;
        --stake)
            INITIAL_STAKE_ETH="$2"
            shift 2
            ;;
        --balance)
            INITIAL_BALANCE_ETH="$2"
            shift 2
            ;;
        --chain-id)
            CHAIN_ID="$2"
            shift 2
            ;;
        --network-id)
            NETWORK_ID="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --extra-alloc)
            EXTRA_ALLOC+=("--extra-alloc" "$2")
            shift 2
            ;;
        --force)
            FORCE=true
            shift
            ;;
        -h|--help)
            sed -n '2,27p' "$0" | sed 's/^# //' | sed 's/^#//'
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Check if output directory exists
if [ -d "$OUTPUT_DIR" ]; then
    if [ "$FORCE" = true ]; then
        echo "Removing existing devnet directory: $OUTPUT_DIR"
        rm -rf "$OUTPUT_DIR"
    else
        echo "Error: Devnet directory already exists: $OUTPUT_DIR"
        echo ""
        echo "Options:"
        echo "  - Use --force to overwrite"
        echo "  - Use --output to specify a different directory"
        echo "  - Use ./scripts/reset-devnet.sh to reset state while keeping keys"
        exit 1
    fi
fi

echo "Setting up devnet with $NUM_VALIDATORS validators..."
echo ""
echo "Configuration:"
echo "  Validators:       $NUM_VALIDATORS"
echo "  Initial Stake:    $INITIAL_STAKE_ETH ETH per validator"
echo "  Initial Balance:  $INITIAL_BALANCE_ETH ETH per validator"
echo "  Chain ID:         $CHAIN_ID"
echo "  Network ID:       $NETWORK_ID"
echo "  Output:           $OUTPUT_DIR"
if [ ${#EXTRA_ALLOC[@]} -gt 0 ]; then
    echo "  Extra Allocs:     ${EXTRA_ALLOC[*]}"
fi
echo ""

# Build the CLI if needed
echo "Building cipherd..."
cargo build -p cipherd --release 2>&1 | grep -E "(Compiling|Finished)" || true
echo ""

# Find the binary
CIPHERD_BIN="$PROJECT_ROOT/target/release/cipherd"
if [ ! -f "$CIPHERD_BIN" ]; then
    CIPHERD_BIN="$PROJECT_ROOT/target/debug/cipherd"
fi

if [ ! -f "$CIPHERD_BIN" ]; then
    echo "Error: cipherd binary not found. Build failed?"
    exit 1
fi

# Run devnet init-files with our configuration
echo "Generating devnet configuration..."
"$CIPHERD_BIN" devnet init-files \
    --validators "$NUM_VALIDATORS" \
    --output "$OUTPUT_DIR" \
    --chain-id "$CHAIN_ID" \
    --network-id "$NETWORK_ID" \
    --initial-stake-eth "$INITIAL_STAKE_ETH" \
    --initial-balance-eth "$INITIAL_BALANCE_ETH" \
    "${EXTRA_ALLOC[@]}"

echo ""

# Generate docker-compose configuration
echo "Generating Docker Compose configuration..."
"$SCRIPT_DIR/generate-compose.sh" "$OUTPUT_DIR" "$PROJECT_ROOT/docker"

echo ""
echo "Devnet setup complete!"
echo ""
echo "Validator accounts funded with:"
echo "  - $INITIAL_STAKE_ETH ETH staked in deposit contract"
echo "  - $INITIAL_BALANCE_ETH ETH available balance (for gas)"
echo ""
echo "Next steps:"
echo "  Start devnet:  ./scripts/start-devnet.sh"
echo "  Reset state:   ./scripts/reset-devnet.sh"
echo "  Stop devnet:   ./scripts/stop-devnet.sh"
echo ""
echo "RPC endpoints (after start):"
for ((i=0; i<NUM_VALIDATORS; i++)); do
    PORT=$((8545 + i * 10))
    echo "  node$i: http://localhost:$PORT"
done
