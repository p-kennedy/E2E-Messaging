#pragma once

#include <string>
#include <vector>
#include <stdexcept>
#include <memory>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

/**
 * RAII wrapper around an OpenSSL TLS connection over a raw TCP socket.
 * Handles hostname resolution, certificate verification, and secure I/O.
 */
class SecureConnection {
public:
    /**
     * Construct and immediately connect to host:port over TLS.
     * Throws std::runtime_error if connection or cert verification fails.
     */
    SecureConnection(const std::string& host, int port);

    /**
     * Destructor — cleanly shuts down SSL and closes the socket.
     */
    ~SecureConnection();

    // Not copyable — owns the socket/SSL context
    SecureConnection(const SecureConnection&) = delete;
    SecureConnection& operator=(const SecureConnection&) = delete;

    // Moveable
    SecureConnection(SecureConnection&& other) noexcept;
    SecureConnection& operator=(SecureConnection&& other) noexcept;

    /**
     * Send raw bytes over the TLS connection.
     * Throws std::runtime_error on failure.
     */
    void send(const std::string& data);

    /**
     * Receive data from the TLS connection.
     * Returns the received string. Throws on error.
     */
    std::string receive();

    /**
     * Returns true if the connection is open and healthy.
     */
    bool isConnected() const;

    /**
     * Returns the verified server certificate subject (for logging/debugging).
     */
    std::string getCertificateSubject() const;

private:
    std::string         m_host;
    int                 m_port;
    int                 m_sockfd;       // raw TCP socket file descriptor
    SSL_CTX*            m_ctx;          // OpenSSL context (owns CA store, settings)
    SSL*                m_ssl;          // OpenSSL session (per-connection)
    bool                m_connected;

    // Internal helpers
    void        initSSLContext();
    void        connectSocket();
    void        performHandshake();
    void        verifyCertificate();    // Burkley requirement: explicit cert check
    std::string getOpenSSLError() const;
    void        cleanup();
};
