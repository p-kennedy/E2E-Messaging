#!/bin/bash
# Sets up the client — installs dependencies and builds the network module.
# Run once after cloning: ./client/setup.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Client Setup ==="

# 1. Install C++ dependencies for the network module
echo ""
echo "[1/4] Installing network dependencies..."
bash "$SCRIPT_DIR/network/install_deps.sh"

# 2. Install crypto module dependencies
echo ""
echo "[2/4] Installing crypto module dependencies..."
cd "$SCRIPT_DIR/user_creation"
npm install
cd "$SCRIPT_DIR"

# 3. Build the C++ native addon
echo ""
echo "[3/4] Building client network module and N-API addon..."
cd "$SCRIPT_DIR/network"
npm install
npm run build
cd "$SCRIPT_DIR"

# 4. Install desktop app dependencies (runs electron-rebuild via postinstall)
echo ""
echo "[4/4] Installing desktop app dependencies..."
cd "$SCRIPT_DIR/desktop"
npm install
cd "$SCRIPT_DIR"

echo ""
echo "=== Client setup complete ==="
echo ""
echo "Copy the environment file and start the app:"
echo "  cp $SCRIPT_DIR/desktop/.env.example $SCRIPT_DIR/desktop/.env"
echo "  cd $SCRIPT_DIR/desktop && npm run dev"
