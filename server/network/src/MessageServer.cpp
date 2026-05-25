#include "MessageServer.hpp"

#include <iostream>
#include <stdexcept>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

static constexpr int  API_PORT        = 8000;
static constexpr int  RECV_BUF_SIZE   = 4096;

MessageServer::MessageServer(const std::string& certPath, const std::string& keyPath, int port)
    : m_conn(certPath, keyPath, port)
{}

void MessageServer::run() {
    std::cout << "[Server] Waiting for connections (proxying to localhost:" << API_PORT << ")...\n";

    while (true) {
        if (!m_conn.acceptConnection()) {
            std::cerr << "[Server] acceptConnection failed, retrying...\n";
            continue;
        }

        try {
            std::string request  = m_conn.receive();
            std::string response = forwardToApi(request);
            m_conn.send(response);
        } catch (const std::exception& e) {
            std::cerr << "[Server] Error: " << e.what() << "\n";
        }

        m_conn.closeClient();
    }
}

std::string MessageServer::forwardToApi(const std::string& rawRequest) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        throw std::runtime_error("forwardToApi: socket() failed");

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(API_PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (connect(sockfd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(sockfd);
        throw std::runtime_error(
            "forwardToApi: could not connect to API server on port "
            + std::to_string(API_PORT)
            + " — is server/api.py running?"
        );
    }

    ::send(sockfd, rawRequest.c_str(), rawRequest.size(), 0);

    std::string response;
    char buffer[RECV_BUF_SIZE];
    int bytes;
    while ((bytes = recv(sockfd, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytes] = '\0';
        response += buffer;
    }

    close(sockfd);
    return response;
}
