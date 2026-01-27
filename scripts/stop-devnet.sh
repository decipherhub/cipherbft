#!/bin/bash
# Stop all devnet validator nodes using Docker Compose
#
# Usage:
#   ./scripts/stop-devnet.sh [options]
#
# Options:
#   --remove-volumes  Also remove named volumes
#   --timeout N       Timeout in seconds for graceful shutdown (default: 10)
#
# Example:
#   ./scripts/stop-devnet.sh
#   ./scripts/stop-devnet.sh --remove-volumes

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DOCKER_DIR="$PROJECT_ROOT/docker"
COMPOSE_FILE="$DOCKER_DIR/docker-compose.yml"

# Parse arguments
VOLUMES_FLAG=""
TIMEOUT="10"

for arg in "$@"; do
    case $arg in
        --remove-volumes)
            VOLUMES_FLAG="-v"
            ;;
        --timeout)
            shift
            TIMEOUT="$1"
            ;;
        --timeout=*)
            TIMEOUT="${arg#*=}"
            ;;
        -*)
            echo "Unknown option: $arg"
            exit 1
            ;;
    esac
done

# Check if compose file exists
if [ ! -f "$COMPOSE_FILE" ]; then
    echo "No docker-compose.yml found at: $COMPOSE_FILE"
    echo "Devnet may not be running or was started differently."
    exit 0
fi

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "Error: Docker is not running."
    exit 1
fi

echo "Stopping devnet validators..."
echo ""

cd "$DOCKER_DIR"

# Check if any containers are running
RUNNING=$(docker compose ps -q 2>/dev/null || true)

if [ -z "$RUNNING" ]; then
    echo "No running containers found."
    exit 0
fi

# Stop and remove containers
docker compose down $VOLUMES_FLAG --timeout "$TIMEOUT"

echo ""
echo "Devnet stopped."

if [ -n "$VOLUMES_FLAG" ]; then
    echo "Named volumes have been removed."
fi
