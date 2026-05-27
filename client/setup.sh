#!/bin/bash
# Sets up the client — installs dependencies and builds the network module.
# Run once after cloning: ./client/setup.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Client Setup ==="

# 1. Install C++ dependencies for the network module
echo ""
echo "[1/2] Installing network dependencies..."
bash "$SCRIPT_DIR/network/install_deps.sh"

# 2. Build the network module
echo ""
echo "[2/2] Building client network module..."
cmake -B "$SCRIPT_DIR/network/build" -S "$SCRIPT_DIR/network"
cmake --build "$SCRIPT_DIR/network/build" --parallel

echo ""
echo "=== Client setup complete ==="
echo ""
echo "Binaries:"
echo "  $SCRIPT_DIR/network/build/secure_client"
echo ""
echo "To run the connection test:"
echo "  ctest --test-dir $SCRIPT_DIR/network/build --output-on-failure"
