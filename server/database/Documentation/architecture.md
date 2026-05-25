# Server Architecture

## Overview

The server is split into two processes that work together:

| Process | Language | Role |
|---|---|---|
| C++ TLS server (`secure_server`) | C++ / OpenSSL | Accepts client connections, handles TLS, proxies HTTP |
| Python API server (`api.py`) | Python / FastAPI | Business logic, authentication, database access |

The C++ server is the only process exposed to the internet. The Python API server binds to `127.0.0.1` only and is never directly reachable by clients.

---

## Request Flow

```
Client (C++)         C++ TLS Server        Python API (FastAPI)      PostgreSQL
     │                     │                       │                      │
     │─TLS: POST login────▶│                       │                      │
     │                     │─HTTP: forward────────▶│                      │
     │                     │                       │─get_user_by_username─▶│
     │                     │                       │─verify password       │
     │                     │◀─{"token":"..."}───────│                      │
     │◀─TLS: {"token":"..."}│                       │                      │
     │                     │                       │                      │
     │─TLS: POST /messages─▶│                       │                      │
     │                     │─HTTP: forward────────▶│                      │
     │                     │                       │─create_message()─────▶│
     │◀─TLS: {"status":...}─│◀──────────────────────│                      │
```

---

## API Endpoints

All endpoints are handled by `server/api.py` and backed by `server/database/crud.py`.

### POST /api/auth/register
Creates a new user account.

**Request body:**
```json
{
  "username": "alice",
  "password": "plaintext-password",
  "public_key": "base64-encoded-public-key"
}
```

**Response:**
```json
{ "user_id": "<uuid>", "username": "alice" }
```

---

### POST /api/auth/login
Authenticates a user and returns a JWT token.

**Request body:**
```json
{ "username": "alice", "password": "plaintext-password" }
```

**Response:**
```json
{ "token": "<jwt>" }
```

The token must be sent as `Authorization: Bearer <token>` on all subsequent requests.

---

### POST /api/messages
Stores an encrypted message. Requires authentication.

**Request body:**
```json
{
  "recipient": "bob",
  "ciphertext": "base64-encoded-ciphertext",
  "nonce": "base64-encoded-nonce",
  "digest": "base64-encoded-digest"
}
```

**Response:**
```json
{ "status": "queued" }
```

---

### GET /api/messages
Fetches all messages for the authenticated user.

**Response:**
```json
{
  "messages": [
    {
      "message_id":   "<uuid>",
      "sender_id":    "<uuid>",
      "recipient_id": "<uuid>",
      "ciphertext":   "base64-encoded-ciphertext",
      "nonce":        "base64-encoded-nonce",
      "digest":       "base64-encoded-digest",
      "created_at":   "2026-05-25 12:00:00"
    }
  ]
}
```

---

## Starting the Server

Run setup once after cloning:
```bash
./server/setup.sh
```

Then start both processes:
```bash
# Terminal 1 — Python API
cd server && uvicorn api:app --host 127.0.0.1 --port 8000

# Terminal 2 — C++ TLS server
./server/network/build/secure_server <cert.pem> <key.pem> <port>
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `JWT_SECRET` | `change-me-in-production` | Secret key for signing JWT tokens — must be set in production |
| `DB_HOST` | `localhost` | PostgreSQL host |
| `DB_NAME` | `messaging_db` | Database name |
| `DB_USER` | `messaging_app` | Database user |
| `DB_PASSWORD` | `password` | Database password |
