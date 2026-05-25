#pragma once

#include <string>
#include <stdexcept>
#include <memory>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

// RAII TLS client connection over a raw TCP socket.
// Resolves the hostname, performs certificate verification, and enforces TLS 1.3.
class SecureClientConnection {
public:
    // Connect to host:port over TLS. Throws std::runtime_error on failure.
    SecureClientConnection(const std::string& host, int port);
    ~SecureClientConnection();

    SecureClientConnection(const SecureClientConnection&) = delete;
    SecureClientConnection& operator=(const SecureClientConnection&) = delete;

    SecureClientConnection(SecureClientConnection&& other) noexcept;
    SecureClientConnection& operator=(SecureClientConnection&& other) noexcept;

    void        send(const std::string& data);
    std::string receive();
    bool        isConnected() const;
    std::string getCertificateSubject() const;

private:
    std::string m_host;
    int         m_port;
    int         m_sockfd;
    SSL_CTX*    m_ctx;
    SSL*        m_ssl;
    bool        m_connected;

    void initSSLContext();
    void connectSocket();
    void performHandshake();
    void verifyCertificate();
    void cleanup();
};
