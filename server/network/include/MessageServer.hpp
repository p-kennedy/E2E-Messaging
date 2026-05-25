#pragma once

#include "SecureServerConnection.hpp"
#include <string>
#include <map>

struct HttpRequest {
    std::string method;
    std::string path;
    std::string body;
    std::map<std::string, std::string> headers;
};

struct HttpResponse {
    int         statusCode;
    std::string body;
};

// Accepts TLS connections and routes HTTP requests to handlers.
// Single-threaded: one request at a time. Wire handlers to the database layer
// (server/database/) by replacing the stub implementations in MessageServer.cpp.
class MessageServer {
public:
    MessageServer(const std::string& certPath, const std::string& keyPath, int port);
    ~MessageServer() = default;

    MessageServer(const MessageServer&) = delete;
    MessageServer& operator=(const MessageServer&) = delete;

    // Block and serve requests indefinitely.
    void run();

private:
    SecureServerConnection m_conn;

    HttpRequest  parseRequest(const std::string& raw) const;
    HttpResponse routeRequest(const HttpRequest& req);
    std::string  buildResponse(const HttpResponse& resp) const;

    // Route handlers — replace stubs with real database calls.
    HttpResponse handleLogin(const HttpRequest& req);
    HttpResponse handleSendMessage(const HttpRequest& req);
    HttpResponse handleFetchMessages(const HttpRequest& req);
};
