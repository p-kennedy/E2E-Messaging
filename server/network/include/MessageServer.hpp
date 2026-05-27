#pragma once

#include "SecureServerConnection.hpp"
#include <string>

// Accepts TLS connections and proxies HTTP requests to the Python API server
// (server/api.py) running on localhost:8000.
class MessageServer {
public:
    MessageServer(const std::string& certPath, const std::string& keyPath, int port);
    ~MessageServer() = default;

    MessageServer(const MessageServer&) = delete;
    MessageServer& operator=(const MessageServer&) = delete;

    void run();

private:
    SecureServerConnection m_conn;

    // Opens a plain TCP connection to localhost:8000, forwards the raw HTTP
    // request, and returns the raw HTTP response.
    std::string forwardToApi(const std::string& rawRequest);
};
