# C++ Network Module

TLS client library for the E2E Messaging app, plus an N-API addon that exposes it to Electron/Node.js.

---

## Components

| File | Class | Role |
|---|---|---|
| `src/SecureClientConnection.cpp` | `SecureClientConnection` | RAII TLS 1.3 socket (OpenSSL). Resolves hostname, performs certificate verification, send/receive. |
| `src/MessageClient.cpp` | `MessageClient` | High-level HTTP/HTTPS client. Wraps `SecureClientConnection` to call the REST API (register, login, send, fetch). |
| `src/MessageStore.cpp` | `MessageStore` | In-memory store for `Message` objects. Sorted retrieval and per-sender filtering using STL algorithms. |
| `src/addon.cpp` | — | N-API bridge. Exports `registerUser`, `login`, `sendMessage`, `fetchMessages` to Node.js. |
| `src/main.cpp` | — | Standalone CLI demo that exercises `MessageClient` and `MessageStore` directly. |

---

## Building

### Prerequisites

```bash
# Fedora / RHEL
sudo dnf install cmake gcc-c++ openssl-devel

# Debian / Ubuntu
sudo apt install cmake g++ libssl-dev
```

### Standalone library + demo binary

```bash
cd client/network
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Produces:
- `build/libclient_lib.a` — static library
- `build/secure_client` — standalone demo binary
- `build/test_connection` — TLS connectivity test

### N-API addon (for Electron)

```bash
cd client/network
npm install
npm run build
```

This links the addon against Electron's ABI. The output is `build/Release/messaging_client.node`, which is `require()`'d by `client/desktop/electron/main.js`.

---

## Running the tests

```bash
cmake --build build --target test_connection
./build/test_connection
```

Two tests run:
1. Connect to `example.com:443` — verifies TLS handshake and certificate chain
2. Connect to `expired.badssl.com` — verifies that expired certificates are rejected

---

## Running the demo

```bash
./build/secure_client
```

Logs in as `alice`, calls `fetchAndStore()` to download messages into the local `MessageStore`, prints each message's timestamp and sender, then demonstrates `getFrom()` (per-sender filter) and `remove()` (by id).

---

## Class design

### `SecureClientConnection`
RAII wrapper around an OpenSSL `SSL*` and a raw TCP socket. The constructor resolves the hostname with `getaddrinfo`, opens the socket, performs the TLS 1.3 handshake, and verifies the peer certificate against the system CA store. Move-only (copy is deleted). Resources are released in the destructor.

### `MessageClient`
Owns a `MessageStore` and an auth token. Each API call opens a new `SecureClientConnection` (HTTP/1.1 over TLS), sends the request, and reads the response. `fetchAndStore()` parses the JSON message array using brace-counting and populates the store.

### `MessageStore`
Wraps `std::vector<Message>`.

| Method | STL used |
|---|---|
| `getAll()` | `std::sort` + lambda (chronological order) |
| `getFrom(senderId)` | `std::copy_if` + lambda + `std::back_inserter` |
| `remove(id)` | `std::find_if` + lambda, then `erase` |

### `Message`
Plain struct with value-semantics constructor. Fields: `id`, `senderId`, `recipientId`, `ciphertext`, `createdAt`.

---

## Memory management

- No raw `new`/`delete`. OpenSSL objects (`SSL_CTX*`, `SSL*`) are freed in `SecureClientConnection::cleanup()`, called from the destructor and move-assignment operator.
- `MessageStore` and `MessageClient` use value semantics throughout (`std::string`, `std::vector`). No heap allocation beyond what the STL manages internally.
- `MessageClient` is non-copyable (deleted copy constructor/assignment) to prevent accidental duplication of the auth token and store.
