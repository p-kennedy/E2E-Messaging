#!/bin/bash
# Sets up the server — installs dependencies, initialises the database,
# and builds the network module.
# Run once after cloning: ./server/setup.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Server Setup ==="

# 1. Install C++ dependencies for the network module
echo ""
echo "[1/4] Installing network dependencies..."
bash "$SCRIPT_DIR/network/install_deps.sh"

# 2. Install Python dependencies for the API server
echo ""
echo "[2/4] Installing Python API dependencies..."
python3 -m venv "$SCRIPT_DIR/venv"
"$SCRIPT_DIR/venv/bin/pip" install -r "$SCRIPT_DIR/requirements.txt"

# 3. Initialise the database (creates tables via setup.py)
echo ""
echo "[3/4] Setting up database..."
cd "$SCRIPT_DIR/database"
"$SCRIPT_DIR/venv/bin/python3" setup.py
cd "$SCRIPT_DIR"

# 4. Build the network module
echo ""
echo "[4/4] Building server network module..."
cmake -B "$SCRIPT_DIR/network/build" -S "$SCRIPT_DIR/network"
cmake --build "$SCRIPT_DIR/network/build" --parallel

echo ""
echo "=== Server setup complete ==="
echo ""
echo "Start both processes to run the server:"
echo ""
echo "  # Terminal 1 — Python API (handles business logic + database)"
echo "  cd $SCRIPT_DIR && source venv/bin/activate && uvicorn api:app --host 127.0.0.1 --port 8000"
echo ""
echo "  # Terminal 2 — C++ TLS server (handles TLS, proxies to API)"
echo "  $SCRIPT_DIR/network/build/secure_server <cert.pem> <key.pem> <port>"
