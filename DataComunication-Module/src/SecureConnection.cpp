#include "SecureConnection.hpp"

#include <iostream>
#include <sstream>
#include <cstring>

// POSIX socket headers
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>

static constexpr int RECV_BUFFER_SIZE = 4096;

// ─── Constructor / Destructor ─────────────────────────────────────────────────

SecureConnection::SecureConnection(const std::string& host, int port)
    : m_host(host)
    , m_port(port)
    , m_sockfd(-1)
    , m_ctx(nullptr)
    , m_ssl(nullptr)
    , m_connected(false)
{
    initSSLContext();   // set up CA store and TLS settings
    connectSocket();    // resolve hostname and open TCP socket
    performHandshake(); // TLS handshake
    verifyCertificate();// explicitly verify server cert (required by brief)
    m_connected = true;
}

SecureConnection::~SecureConnection() {
    cleanup();
}

SecureConnection::SecureConnection(SecureConnection&& other) noexcept
    : m_host(std::move(other.m_host))
    , m_port(other.m_port)
    , m_sockfd(other.m_sockfd)
    , m_ctx(other.m_ctx)
    , m_ssl(other.m_ssl)
    , m_connected(other.m_connected)
{
    // Null out the moved-from object so its destructor is a no-op
    other.m_sockfd    = -1;
    other.m_ctx       = nullptr;
    other.m_ssl       = nullptr;
    other.m_connected = false;
}

SecureConnection& SecureConnection::operator=(SecureConnection&& other) noexcept {
    if (this != &other) {
        cleanup();
        m_host      = std::move(other.m_host);
        m_port      = other.m_port;
        m_sockfd    = other.m_sockfd;
        m_ctx       = other.m_ctx;
        m_ssl       = other.m_ssl;
        m_connected = other.m_connected;

        other.m_sockfd    = -1;
        other.m_ctx       = nullptr;
        other.m_ssl       = nullptr;
        other.m_connected = false;
    }
    return *this;
}

// ─── Public Interface ─────────────────────────────────────────────────────────

void SecureConnection::send(const std::string& data) {
    if (!m_connected || !m_ssl) {
        throw std::runtime_error("SecureConnection::send — not connected");
    }

    int written = SSL_write(m_ssl, data.c_str(), static_cast<int>(data.size()));
    if (written <= 0) {
        throw std::runtime_error("SSL_write failed: " + getOpenSSLError());
    }
}

std::string SecureConnection::receive() {
    if (!m_connected || !m_ssl) {
        throw std::runtime_error("SecureConnection::receive — not connected");
    }

    std::string result;
    char buffer[RECV_BUFFER_SIZE];

    while (true) {
        int bytes = SSL_read(m_ssl, buffer, sizeof(buffer) - 1);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            result += buffer;

            // If we read less than the full buffer, assume no more data right now
            if (bytes < RECV_BUFFER_SIZE - 1) break;
        } else if (bytes == 0) {
            // Server closed connection cleanly
            m_connected = false;
            break;
        } else {
            int err = SSL_get_error(m_ssl, bytes);
            if (err == SSL_ERROR_WANT_READ) continue; // non-blocking retry
            throw std::runtime_error("SSL_read failed: " + getOpenSSLError());
        }
    }

    return result;
}

bool SecureConnection::isConnected() const {
    return m_connected;
}

std::string SecureConnection::getCertificateSubject() const {
    if (!m_ssl) return "";

    X509* cert = SSL_get_peer_certificate(m_ssl);
    if (!cert) return "(no certificate)";

    char subject[256];
    X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject));
    X509_free(cert);

    return std::string(subject);
}

// ─── Private Helpers ──────────────────────────────────────────────────────────

void SecureConnection::initSSLContext() {
    // Initialise OpenSSL — safe to call multiple times
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Use TLS — OpenSSL will negotiate the highest mutually supported version
    // TLS 1.0 and 1.1 are disabled below
    const SSL_METHOD* method = TLS_client_method();
    m_ctx = SSL_CTX_new(method);
    if (!m_ctx) {
        throw std::runtime_error("SSL_CTX_new failed: " + getOpenSSLError());
    }

    // Enforce TLS 1.2 minimum — rejects servers running older insecure versions
    SSL_CTX_set_min_proto_version(m_ctx, TLS1_2_VERSION);

    // Load the system CA certificate store so we can verify server certs
    if (!SSL_CTX_set_default_verify_paths(m_ctx)) {
        SSL_CTX_free(m_ctx);
        m_ctx = nullptr;
        throw std::runtime_error("Failed to load system CA store: " + getOpenSSLError());
    }

    // Require peer (server) certificate verification — this is the Burkley requirement
    SSL_CTX_set_verify(m_ctx, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_verify_depth(m_ctx, 4); // max cert chain depth
}

void SecureConnection::connectSocket() {
    // Resolve hostname using getaddrinfo — supports both IPv4 and IPv6
    // The brief specifically mentions resolving host names via socket calls
    addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;     // accept IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;   // TCP

    std::string portStr = std::to_string(m_port);
    addrinfo* results   = nullptr;

    int status = getaddrinfo(m_host.c_str(), portStr.c_str(), &hints, &results);
    if (status != 0) {
        throw std::runtime_error(
            "getaddrinfo failed for " + m_host + ": " + gai_strerror(status)
        );
    }

    // Iterate results and try each address until one connects
    // (getaddrinfo may return multiple addresses for a hostname)
    addrinfo* p = nullptr;
    for (p = results; p != nullptr; p = p->ai_next) {
        m_sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (m_sockfd == -1) continue;

        if (connect(m_sockfd, p->ai_addr, p->ai_addrlen) == 0) {
            break; // connected successfully
        }

        close(m_sockfd);
        m_sockfd = -1;
    }

    freeaddrinfo(results);

    if (m_sockfd == -1) {
        throw std::runtime_error(
            "Could not connect to " + m_host + ":" + portStr
        );
    }
}

void SecureConnection::performHandshake() {
    m_ssl = SSL_new(m_ctx);
    if (!m_ssl) {
        throw std::runtime_error("SSL_new failed: " + getOpenSSLError());
    }

    // Attach our TCP socket to the SSL session
    SSL_set_fd(m_ssl, m_sockfd);

    // Set SNI (Server Name Indication) — required for virtual hosting
    // Without this, servers with multiple certs on one IP may return the wrong one
    SSL_set_tlsext_host_name(m_ssl, m_host.c_str());

    // Also set for hostname verification post-handshake
    SSL_set1_host(m_ssl, m_host.c_str());

    // Perform the TLS handshake
    if (SSL_connect(m_ssl) != 1) {
        throw std::runtime_error("SSL_connect failed: " + getOpenSSLError());
    }
}

void SecureConnection::verifyCertificate() {
    // Step 1: Check the overall chain verification result
    long verifyResult = SSL_get_verify_result(m_ssl);
    if (verifyResult != X509_V_OK) {
        throw std::runtime_error(
            std::string("Certificate verification failed: ")
            + X509_verify_cert_error_string(verifyResult)
        );
    }

    // Step 2: Check the server actually sent a certificate
    X509* cert = SSL_get_peer_certificate(m_ssl);
    if (!cert) {
        throw std::runtime_error("Server did not present a certificate");
    }

    // Log the cert subject for debugging/audit purposes
    char subject[256];
    X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject));
    std::cout << "[TLS] Certificate verified: " << subject << "\n";

    X509_free(cert);

    // Note: hostname verification is handled automatically by OpenSSL when
    // SSL_set1_host() is called before the handshake (done in performHandshake)
}

std::string SecureConnection::getOpenSSLError() const {
    std::ostringstream oss;
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        oss << buf << " ";
    }
    return oss.str();
}

void SecureConnection::cleanup() {
    if (m_ssl) {
        SSL_shutdown(m_ssl);
        SSL_free(m_ssl);
        m_ssl = nullptr;
    }
    if (m_ctx) {
        SSL_CTX_free(m_ctx);
        m_ctx = nullptr;
    }
    if (m_sockfd != -1) {
        close(m_sockfd);
        m_sockfd = -1;
    }
    m_connected = false;
}
