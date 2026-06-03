#!/bin/bash
# Deploys the server on a fresh Ubuntu/Debian VM.
# Run once after cloning: ./server/vm-deploy.sh
#
# What this does:
#   1. Installs system packages (Docker, Python 3, cmake, build tools)
#   2. Generates a self-signed TLS certificate (valid 10 years)
#   3. Starts PostgreSQL via Docker
#   4. Runs server/setup.sh (Python deps, DB init, C++ build)
#   5. Prints the commands to start both server processes
#
# Usage:
#   ./server/vm-deploy.sh [TLS_PORT]
#   TLS_PORT defaults to 2213

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
TLS_PORT="${1:-2213}"
CERT_DIR="$SCRIPT_DIR/certs"

# ── 1. System packages ────────────────────────────────────────────────────────
echo "=== [1/5] Installing system packages ==="
sudo apt-get update -qq
sudo apt-get install -y \
    build-essential cmake libssl-dev pkg-config \
    python3 python3-pip python3-venv \
    docker.io docker-compose-plugin \
    curl

# Ensure Docker is running and the current user can use it
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER" || true

echo "System packages installed."

# ── 2. TLS certificate ────────────────────────────────────────────────────────
echo ""
echo "=== [2/5] Generating self-signed TLS certificate ==="
mkdir -p "$CERT_DIR"

VM_IP="$(hostname -I | awk '{print $1}')"

openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
    -keyout "$CERT_DIR/key.pem" \
    -out    "$CERT_DIR/cert.pem" \
    -subj   "/CN=$VM_IP" \
    -addext "subjectAltName=IP:$VM_IP"

chmod 600 "$CERT_DIR/key.pem"
echo "Certificate written to $CERT_DIR/"
echo "  VM IP detected as: $VM_IP"
echo "  Clients must trust this cert (copy cert.pem to the client machine)."

# ── 3. Environment file ───────────────────────────────────────────────────────
echo ""
echo "=== [3/5] Configuring environment ==="
if [ ! -f "$ROOT_DIR/.env" ]; then
    cp "$ROOT_DIR/.env.example" "$ROOT_DIR/.env"
    # Generate a random JWT secret
    JWT_SECRET="$(openssl rand -hex 32)"
    sed -i "s|JWT_SECRET=.*|JWT_SECRET=$JWT_SECRET|" "$ROOT_DIR/.env" 2>/dev/null || \
        echo "JWT_SECRET=$JWT_SECRET" >> "$ROOT_DIR/.env"
    echo ".env created with a random JWT_SECRET."
else
    echo ".env already exists — skipping."
fi

# ── 4. Database ───────────────────────────────────────────────────────────────
echo ""
echo "=== [4/5] Starting PostgreSQL ==="
cd "$ROOT_DIR"
# Use 'docker compose' (plugin) if available, fall back to 'docker-compose'
if docker compose version &>/dev/null 2>&1; then
    docker compose up -d
else
    docker-compose up -d
fi
echo "Waiting for PostgreSQL to be ready..."
sleep 5

# ── 5. Server setup ───────────────────────────────────────────────────────────
echo ""
echo "=== [5/5] Building server ==="
bash "$SCRIPT_DIR/setup.sh"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  VM deploy complete!"
echo "============================================================"
echo ""
echo "VM IP: $VM_IP"
echo "TLS cert: $CERT_DIR/cert.pem"
echo "TLS key:  $CERT_DIR/key.pem"
echo ""
echo "Open port $TLS_PORT in your firewall / VM security group:"
echo "  sudo ufw allow $TLS_PORT/tcp"
echo ""
echo "Start the server (two terminals, or use tmux):"
echo ""
echo "  # Terminal 1 — Python API (internal)"
echo "  cd $ROOT_DIR/server && uvicorn api:app --host 127.0.0.1 --port 8000"
echo ""
echo "  # Terminal 2 — C++ TLS frontend (public)"
echo "  $SCRIPT_DIR/network/build/secure_server $CERT_DIR/cert.pem $CERT_DIR/key.pem $TLS_PORT"
echo ""
echo "Client configuration:"
echo "  SERVER_HOST = $VM_IP"
echo "  SERVER_PORT = $TLS_PORT"
echo "  VITE_API_URL = https://$VM_IP:$TLS_PORT"
echo "  Copy $CERT_DIR/cert.pem to the client machine."
echo ""
