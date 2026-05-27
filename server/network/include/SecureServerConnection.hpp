#pragma once

#include <string>
#include <stdexcept>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

// RAII TLS server connection.
// Owns the listen socket and one active client session at a time.
// Call acceptConnection() in a loop; send()/receive() operate on the current client.
class SecureServerConnection {
public:
    // Loads cert+key, binds to port, and starts listening.
    // certPath / keyPath: paths to PEM files for the server's identity.
    SecureServerConnection(const std::string& certPath, const std::string& keyPath, int port);
    ~SecureServerConnection();

    SecureServerConnection(const SecureServerConnection&) = delete;
    SecureServerConnection& operator=(const SecureServerConnection&) = delete;

    // Block until a client connects and the TLS handshake succeeds.
    // Returns false if accept() or the handshake fails (caller may retry).
    bool acceptConnection();

    void        send(const std::string& data);
    std::string receive();
    bool        isConnected() const;

    // Close the current client session; server remains listening for the next one.
    void closeClient();

private:
    std::string m_certPath;
    std::string m_keyPath;
    int         m_port;
    int         m_listenSockfd;
    int         m_clientSockfd;
    SSL_CTX*    m_ctx;
    SSL*        m_ssl;
    bool        m_connected;

    void initSSLContext();
    void bindAndListen();
    void cleanup();
};
