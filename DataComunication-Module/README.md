# Secure Messaging Client — C++ Module

C++ networking module for the CS4455 Epic Project. Handles TLS-secured communication
with the messaging backend using raw POSIX sockets and OpenSSL.

## What This Module Does

- Opens a raw TCP socket and resolves hostnames using `getaddrinfo()`
- Wraps the socket in a TLS 1.2+ session using OpenSSL (`libssl`)
- Explicitly verifies the server's SSL certificate (chain + hostname)
- Provides a `MessageClient` class for login, send, and fetch operations
- All message payloads are treated as opaque ciphertext — encryption is handled
  by the Cryptography module separately

## Class Structure

```
SecureConnection        — low-level TLS socket (RAII, not copyable)
MessageClient           — high-level API client, owns a SecureConnection per request
Message                 — plain struct representing a message
```

## Dependencies

| Dependency      | Purpose                        | Install via      |
|----------------|--------------------------------|------------------|
| OpenSSL         | TLS, certificate verification  | apt / system     |
| CMake ≥ 3.16    | Build system                   | apt              |
| C++17 compiler  | Language standard              | apt (gcc/clang)  |

## Quick Start

### 1. Install dependencies (Ubuntu / Debian)

```bash
chmod +x install_deps.sh
./install_deps.sh
```

### 2. Build

```bash
cmake -B build -S .
cmake --build build
```

### 3. Run the connection test

```bash
./build/test_connection
```

Expected output:
```
=== TLS Connection Test ===

[Test 1] Connecting to example.com:443...
  Connected: YES
  Certificate: /CN=www.example.org
  Response: HTTP/1.1 200 OK
  [PASS]

[Test 2] Connecting to expired.badssl.com (should fail)...
  Correctly rejected: Certificate verification failed: certificate has expired
  [PASS]

All tests passed.
```

### 4. Run the main client

```bash
./build/secure_client
```

> Edit `src/main.cpp` to set your team's server host and credentials.

## Project Structure

```
.
├── CMakeLists.txt
├── install_deps.sh
├── README.md
├── include/
│   ├── SecureConnection.hpp    # TLS socket wrapper
│   └── MessageClient.hpp      # API client + Message struct
├── src/
│   ├── SecureConnection.cpp
│   ├── MessageClient.cpp
│   └── main.cpp               # demo entry point
└── tests/
    └── test_connection.cpp    # TLS connection tests
```

## Security Notes

- TLS minimum version is enforced at **TLS 1.2** — older versions are rejected
- Certificate verification is **mandatory** — self-signed or expired certs throw
- Hostname verification is performed via `SSL_set1_host()` before the handshake
- The system CA store is used — no hardcoded certificates
- Connections are closed after each request (no keep-alive in this version)

## Integrating with the Crypto Module

`MessageClient::sendMessage()` accepts a pre-encrypted ciphertext string.
Your crypto module should:
1. Encrypt the plaintext using your AEAD scheme (e.g. AES-256-GCM)
2. Base64-encode the ciphertext
3. Pass it to `sendMessage()` — this module never sees plaintext
