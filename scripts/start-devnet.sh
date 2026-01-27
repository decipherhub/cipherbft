#!/bin/bash
# Start all devnet validator nodes using Docker Compose
#
# Usage:
#   ./scripts/start-devnet.sh [devnet_dir] [options]
#
# Options:
#   --build    Force rebuild of Docker images
#   --no-monitoring  Skip Prometheus and Grafana services
#   --detach   Run in detached mode (default)
#   --attach   Run in foreground (shows logs)
#
# Example:
#   ./scripts/start-devnet.sh ./devnet
#   ./scripts/start-devnet.sh ./devnet --build
#   ./scripts/start-devnet.sh  # defaults to ./devnet

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Parse arguments
DEVNET_DIR=""
BUILD_FLAG=""
DETACH_FLAG="-d"
MONITORING="true"

for arg in "$@"; do
    case $arg in
        --build)
            BUILD_FLAG="--build"
            ;;
        --no-monitoring)
            MONITORING="false"
            ;;
        --attach)
            DETACH_FLAG=""
            ;;
        --detach)
            DETACH_FLAG="-d"
            ;;
        -*)
            echo "Unknown option: $arg"
            exit 1
            ;;
        *)
            if [ -z "$DEVNET_DIR" ]; then
                DEVNET_DIR="$arg"
            fi
            ;;
    esac
done

DEVNET_DIR="${DEVNET_DIR:-$PROJECT_ROOT/devnet}"
DOCKER_DIR="$PROJECT_ROOT/docker"

# Ensure the devnet directory exists
if [ ! -d "$DEVNET_DIR" ]; then
    echo "Error: Devnet directory not found: $DEVNET_DIR"
    echo ""
    echo "Initialize devnet first with:"
    echo "  cargo run -p cipherd -- devnet init-files --output $DEVNET_DIR"
    exit 1
fi

# Find all node directories
NODES=$(ls -d "${DEVNET_DIR}"/node* 2>/dev/null | sort -V)

if [ -z "$NODES" ]; then
    echo "Error: No node directories found in $DEVNET_DIR"
    exit 1
fi

NODE_COUNT=$(echo "$NODES" | wc -l | tr -d ' ')

echo "Starting devnet with $NODE_COUNT validators using Docker Compose..."
echo ""

# Generate docker-compose.yml
echo "Generating Docker Compose configuration..."
"$SCRIPT_DIR/generate-compose.sh" "$DEVNET_DIR" "$DOCKER_DIR"
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "Error: Docker is not running. Please start Docker first."
    exit 1
fi

# Build services list
SERVICES=""
for NODE_DIR in $NODES; do
    NODE_NAME=$(basename "$NODE_DIR")
    NODE_NUM=${NODE_NAME#node}
    SERVICES="$SERVICES validator-$NODE_NUM"
done

if [ "$MONITORING" = "true" ]; then
    SERVICES="$SERVICES prometheus grafana"
fi

# Start docker-compose
cd "$DOCKER_DIR"

echo "Starting services..."
if [ -n "$BUILD_FLAG" ]; then
    echo "  (rebuilding images)"
fi

docker compose up $DETACH_FLAG $BUILD_FLAG $SERVICES

if [ -n "$DETACH_FLAG" ]; then
    echo ""
    echo "Devnet started successfully!"
    echo ""
    echo "Logs:     docker compose -f $DOCKER_DIR/docker-compose.yml logs -f"
    echo ""
    echo "To stop:  ./scripts/stop-devnet.sh"
    echo "To reset: ./scripts/reset-devnet.sh"
    echo ""
    echo "RPC endpoints:"

    NODE_INDEX=0
    for NODE_DIR in $NODES; do
        NODE_NAME=$(basename "$NODE_DIR")
        RPC_HTTP_PORT=$((8545 + NODE_INDEX * 10))
        echo "  $NODE_NAME: http://localhost:$RPC_HTTP_PORT"
        NODE_INDEX=$((NODE_INDEX + 1))
    done

    if [ "$MONITORING" = "true" ]; then
        echo ""
        echo "Monitoring:"
        echo "  Prometheus: http://localhost:9090"
        echo "  Grafana:    http://localhost:3000 (admin/admin)"
    fi
fi
