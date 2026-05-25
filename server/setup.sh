#!/bin/bash
# Sets up the server — installs dependencies, initialises the database,
# and builds the network module.
# Run once after cloning: ./server/setup.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Server Setup ==="

# 1. Install C++ dependencies for the network module
echo ""
echo "[1/3] Installing network dependencies..."
bash "$SCRIPT_DIR/network/install_deps.sh"

# 2. Initialise the database (creates tables via setup.py)
echo ""
echo "[2/3] Setting up database..."
cd "$SCRIPT_DIR/database"
python3 setup.py
cd "$SCRIPT_DIR"

# 3. Build the network module
echo ""
echo "[3/3] Building server network module..."
cmake -B "$SCRIPT_DIR/network/build" -S "$SCRIPT_DIR/network"
cmake --build "$SCRIPT_DIR/network/build" --parallel

echo ""
echo "=== Server setup complete ==="
echo ""
echo "Binaries:"
echo "  $SCRIPT_DIR/network/build/secure_server"
echo ""
echo "To start the server:"
echo "  $SCRIPT_DIR/network/build/secure_server <cert.pem> <key.pem> <port>"
