#include "SecureServerConnection.hpp"

#include <iostream>
#include <sstream>
#include <cstring>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>

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

SecureServerConnection::SecureServerConnection(
    const std::string& certPath, const std::string& keyPath, int port)
    : m_certPath(certPath)
    , m_keyPath(keyPath)
    , m_port(port)
    , m_listenSockfd(-1)
    , m_clientSockfd(-1)
    , m_ctx(nullptr)
    , m_ssl(nullptr)
    , m_connected(false)
{
    tlsGlobalInit();
    initSSLContext();
    bindAndListen();
}

SecureServerConnection::~SecureServerConnection() {
    cleanup();
}

bool SecureServerConnection::acceptConnection() {
    closeClient();

    sockaddr_storage clientAddr{};
    socklen_t addrLen = sizeof(clientAddr);
    m_clientSockfd = accept(m_listenSockfd,
                            reinterpret_cast<sockaddr*>(&clientAddr), &addrLen);
    if (m_clientSockfd < 0) return false;

    m_ssl = SSL_new(m_ctx);
    if (!m_ssl) {
        close(m_clientSockfd);
        m_clientSockfd = -1;
        return false;
    }

    SSL_set_fd(m_ssl, m_clientSockfd);

    if (SSL_accept(m_ssl) <= 0) {
        std::cerr << "[Server] TLS handshake failed: " << tlsGetError() << "\n";
        SSL_free(m_ssl);
        m_ssl = nullptr;
        close(m_clientSockfd);
        m_clientSockfd = -1;
        return false;
    }

    m_connected = true;
    std::cout << "[Server] Client connected\n";
    return true;
}

void SecureServerConnection::send(const std::string& data) {
    if (!m_connected || !m_ssl)
        throw std::runtime_error("SecureServerConnection::send — no client connected");

    int written = SSL_write(m_ssl, data.c_str(), static_cast<int>(data.size()));
    if (written <= 0)
        throw std::runtime_error("SSL_write failed: " + tlsGetError());
}

std::string SecureServerConnection::receive() {
    if (!m_connected || !m_ssl)
        throw std::runtime_error("SecureServerConnection::receive — no client connected");

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

bool SecureServerConnection::isConnected() const {
    return m_connected;
}

void SecureServerConnection::closeClient() {
    if (m_ssl) {
        SSL_shutdown(m_ssl);
        SSL_free(m_ssl);
        m_ssl = nullptr;
    }
    if (m_clientSockfd != -1) {
        close(m_clientSockfd);
        m_clientSockfd = -1;
    }
    m_connected = false;
}

void SecureServerConnection::initSSLContext() {
    const SSL_METHOD* method = TLS_server_method();
    m_ctx = SSL_CTX_new(method);
    if (!m_ctx)
        throw std::runtime_error("SSL_CTX_new failed: " + tlsGetError());

    SSL_CTX_set_min_proto_version(m_ctx, TLS1_2_VERSION);

    if (SSL_CTX_use_certificate_file(m_ctx, m_certPath.c_str(), SSL_FILETYPE_PEM) <= 0) {
        SSL_CTX_free(m_ctx);
        m_ctx = nullptr;
        throw std::runtime_error("Failed to load certificate: " + tlsGetError());
    }

    if (SSL_CTX_use_PrivateKey_file(m_ctx, m_keyPath.c_str(), SSL_FILETYPE_PEM) <= 0) {
        SSL_CTX_free(m_ctx);
        m_ctx = nullptr;
        throw std::runtime_error("Failed to load private key: " + tlsGetError());
    }

    if (!SSL_CTX_check_private_key(m_ctx)) {
        SSL_CTX_free(m_ctx);
        m_ctx = nullptr;
        throw std::runtime_error("Private key does not match certificate");
    }
}

void SecureServerConnection::bindAndListen() {
    // Try dual-stack IPv6 socket (accepts both IPv4 and IPv6 clients) first,
    // fall back to IPv4-only if the OS doesn't support it.
    m_listenSockfd = socket(AF_INET6, SOCK_STREAM, 0);

    if (m_listenSockfd >= 0) {
        int opt = 1;
        setsockopt(m_listenSockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        int off = 0;
        setsockopt(m_listenSockfd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));

        sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_port   = htons(m_port);
        addr.sin6_addr   = in6addr_any;

        if (bind(m_listenSockfd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            close(m_listenSockfd);
            m_listenSockfd = -1;
        }
    }

    if (m_listenSockfd < 0) {
        m_listenSockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (m_listenSockfd < 0)
            throw std::runtime_error("socket() failed");

        int opt = 1;
        setsockopt(m_listenSockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_port        = htons(m_port);
        addr.sin_addr.s_addr = INADDR_ANY;

        if (bind(m_listenSockfd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            close(m_listenSockfd);
            m_listenSockfd = -1;
            throw std::runtime_error("bind() failed on port " + std::to_string(m_port));
        }
    }

    if (listen(m_listenSockfd, SOMAXCONN) < 0) {
        close(m_listenSockfd);
        m_listenSockfd = -1;
        throw std::runtime_error("listen() failed");
    }

    std::cout << "[Server] Listening on port " << m_port << "\n";
}

void SecureServerConnection::cleanup() {
    closeClient();
    if (m_ctx) {
        SSL_CTX_free(m_ctx);
        m_ctx = nullptr;
    }
    if (m_listenSockfd != -1) {
        close(m_listenSockfd);
        m_listenSockfd = -1;
    }
}
