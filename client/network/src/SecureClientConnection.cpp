#include "SecureClientConnection.hpp"

#include <iostream>
#include <sstream>
#include <cstring>

#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>

static constexpr int RECV_BUFFER_SIZE = 4096;

static void tlsGlobalInit() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
}

static std::string tlsGetError() {
    std::ostringstream oss;
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        oss << buf << " ";
    }
    return oss.str();
}

SecureClientConnection::SecureClientConnection(const std::string& host, int port)
    : m_host(host)
    , m_port(port)
    , m_sockfd(-1)
    , m_ctx(nullptr)
    , m_ssl(nullptr)
    , m_connected(false)
{
    initSSLContext();
    connectSocket();
    performHandshake();
    verifyCertificate();
    m_connected = true;
}

SecureClientConnection::~SecureClientConnection() {
    cleanup();
}

SecureClientConnection::SecureClientConnection(SecureClientConnection&& other) noexcept
    : m_host(std::move(other.m_host))
    , m_port(other.m_port)
    , m_sockfd(other.m_sockfd)
    , m_ctx(other.m_ctx)
    , m_ssl(other.m_ssl)
    , m_connected(other.m_connected)
{
    other.m_sockfd    = -1;
    other.m_ctx       = nullptr;
    other.m_ssl       = nullptr;
    other.m_connected = false;
}

SecureClientConnection& SecureClientConnection::operator=(SecureClientConnection&& other) noexcept {
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

void SecureClientConnection::send(const std::string& data) {
    if (!m_connected || !m_ssl)
        throw std::runtime_error("SecureClientConnection::send — not connected");

    int written = SSL_write(m_ssl, data.c_str(), static_cast<int>(data.size()));
    if (written <= 0)
        throw std::runtime_error("SSL_write failed: " + tlsGetError());
}

std::string SecureClientConnection::receive() {
    if (!m_connected || !m_ssl)
        throw std::runtime_error("SecureClientConnection::receive — not connected");

    std::string result;
    char buffer[RECV_BUFFER_SIZE];

    while (true) {
        int bytes = SSL_read(m_ssl, buffer, sizeof(buffer) - 1);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            result += buffer;
            if (bytes < RECV_BUFFER_SIZE - 1) break;
        } else if (bytes == 0) {
            m_connected = false;
            break;
        } else {
            int err = SSL_get_error(m_ssl, bytes);
            if (err == SSL_ERROR_WANT_READ) continue;
            throw std::runtime_error("SSL_read failed: " + tlsGetError());
        }
    }

    return result;
}

bool SecureClientConnection::isConnected() const {
    return m_connected;
}

std::string SecureClientConnection::getCertificateSubject() const {
    if (!m_ssl) return "";

    X509* cert = SSL_get_peer_certificate(m_ssl);
    if (!cert) return "(no certificate)";

    char subject[256];
    X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject));
    X509_free(cert);

    return std::string(subject);
}

void SecureClientConnection::initSSLContext() {
    tlsGlobalInit();

    const SSL_METHOD* method = TLS_client_method();
    m_ctx = SSL_CTX_new(method);
    if (!m_ctx)
        throw std::runtime_error("SSL_CTX_new failed: " + tlsGetError());

    SSL_CTX_set_min_proto_version(m_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(m_ctx, TLS1_3_VERSION);

    if (!SSL_CTX_set_default_verify_paths(m_ctx)) {
        SSL_CTX_free(m_ctx);
        m_ctx = nullptr;
        throw std::runtime_error("Failed to load system CA store: " + tlsGetError());
    }

    SSL_CTX_set_verify(m_ctx, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_verify_depth(m_ctx, 4);
}

void SecureClientConnection::connectSocket() {
    addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    std::string portStr = std::to_string(m_port);
    addrinfo* results   = nullptr;

    int status = getaddrinfo(m_host.c_str(), portStr.c_str(), &hints, &results);
    if (status != 0)
        throw std::runtime_error("getaddrinfo failed for " + m_host + ": " + gai_strerror(status));

    addrinfo* p = nullptr;
    for (p = results; p != nullptr; p = p->ai_next) {
        m_sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (m_sockfd == -1) continue;

        if (connect(m_sockfd, p->ai_addr, p->ai_addrlen) == 0) break;

        close(m_sockfd);
        m_sockfd = -1;
    }

    freeaddrinfo(results);

    if (m_sockfd == -1)
        throw std::runtime_error("Could not connect to " + m_host + ":" + portStr);
}

void SecureClientConnection::performHandshake() {
    m_ssl = SSL_new(m_ctx);
    if (!m_ssl)
        throw std::runtime_error("SSL_new failed: " + tlsGetError());

    SSL_set_fd(m_ssl, m_sockfd);
    SSL_set_tlsext_host_name(m_ssl, m_host.c_str());
    SSL_set1_host(m_ssl, m_host.c_str());

    if (SSL_connect(m_ssl) != 1)
        throw std::runtime_error("SSL_connect failed: " + tlsGetError());
}

void SecureClientConnection::verifyCertificate() {
    long verifyResult = SSL_get_verify_result(m_ssl);
    if (verifyResult != X509_V_OK)
        throw std::runtime_error(std::string("Certificate verification failed: ")
            + X509_verify_cert_error_string(verifyResult));

    X509* cert = SSL_get_peer_certificate(m_ssl);
    if (!cert)
        throw std::runtime_error("Server did not present a certificate");

    char subject[256];
    X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject));
    std::cout << "[TLS] Certificate verified: " << subject << "\n";

    X509_free(cert);
}

void SecureClientConnection::cleanup() {
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
