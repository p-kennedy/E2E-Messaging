# E2E Messaging

End-to-end encrypted messaging using X3DH + Double Ratchet (Signal protocol), TLS 1.3 transport, and blockchain digest anchoring.

---

## Prerequisites

- **Node.js** 18+
- **Python** 3.10+
- **Docker** (for the database)
- **cmake**, **gcc/g++**, **openssl-devel** (for the C++ network modules)

---

## Server setup

**1. Start the database**

```bash
docker compose up -d
```

**2. Copy and configure the environment file**

```bash
cp .env.example .env
```

Edit `.env` if your database credentials differ from the defaults.

**3. Run the server setup script**

```bash
./server/setup.sh
```

This installs Python dependencies, initialises the database tables, and builds the C++ TLS server module.

**4. Start the server**

Two processes are required, each in its own terminal.

```bash
# Terminal 1 — Python API
cd server && uvicorn api:app --host 127.0.0.1 --port 8000
```

```bash
# Terminal 2 — C++ TLS frontend (requires a TLS certificate)
server/network/build/secure_server <cert.pem> <key.pem> <port>
```

> For local development without a certificate you can skip Terminal 2 and point the client directly at the Python API over HTTP by setting `SERVER_URL=http://localhost:8000` in your environment.

---

## Client setup

**1. Run the client setup script**

```bash
./client/setup.sh
```

This installs all dependencies (crypto modules, C++ native addon, desktop app), builds the N-API addon against Electron's ABI, and runs `electron-rebuild` for native modules.

**2. Configure the API URL**

```bash
cp client/desktop/.env.example client/desktop/.env
```

For local development the default (`http://localhost:8000`) is correct. For production, set `VITE_API_URL` to the server address.

---

## Starting the client

```bash
cd client/desktop
npm run dev
```

This starts the Vite dev server and launches the Electron window. The app is ready when the login screen appears.

---

## Project structure

```
client/
  config.mjs         # central server host/port config
  network/           # C++ TLS client (SecureClientConnection + MessageClient + N-API addon)
  user_creation/     # crypto modules: X3DH, Double Ratchet, key storage
  desktop/           # Electron + React UI
server/
  api.py             # FastAPI REST API
  network/           # C++ TLS server
  database/          # PostgreSQL schema, migrations, CRUD
blockchain/          # Hardhat project + MessageDigest smart contract (Sepolia)
```
