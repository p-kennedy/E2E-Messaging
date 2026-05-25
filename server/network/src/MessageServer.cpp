#include "MessageServer.hpp"
#include <iostream>
#include <sstream>

MessageServer::MessageServer(const std::string& certPath, const std::string& keyPath, int port)
    : m_conn(certPath, keyPath, port)
{}

void MessageServer::run() {
    std::cout << "[Server] Waiting for connections...\n";

    while (true) {
        if (!m_conn.acceptConnection()) {
            std::cerr << "[Server] acceptConnection failed, retrying...\n";
            continue;
        }

        try {
            std::string  raw  = m_conn.receive();
            HttpRequest  req  = parseRequest(raw);
            HttpResponse resp = routeRequest(req);
            m_conn.send(buildResponse(resp));
        } catch (const std::exception& e) {
            std::cerr << "[Server] Error handling request: " << e.what() << "\n";
        }

        m_conn.closeClient();
    }
}

HttpRequest MessageServer::parseRequest(const std::string& raw) const {
    HttpRequest req;
    std::istringstream stream(raw);
    std::string line;

    // First line: METHOD PATH HTTP/1.1
    if (std::getline(stream, line)) {
        std::istringstream firstLine(line);
        firstLine >> req.method >> req.path;
    }

    // Headers until blank line
    while (std::getline(stream, line) && line != "\r" && !line.empty()) {
        auto colon = line.find(':');
        if (colon != std::string::npos) {
            std::string key = line.substr(0, colon);
            std::string val = line.substr(colon + 2);
            if (!val.empty() && val.back() == '\r') val.pop_back();
            req.headers[key] = val;
        }
    }

    // Body
    std::string body;
    while (std::getline(stream, line)) body += line + "\n";
    req.body = body;

    return req;
}

HttpResponse MessageServer::routeRequest(const HttpRequest& req) {
    if (req.method == "POST" && req.path == "/api/auth/login")
        return handleLogin(req);
    if (req.method == "POST" && req.path == "/api/messages")
        return handleSendMessage(req);
    if (req.method == "GET"  && req.path == "/api/messages")
        return handleFetchMessages(req);

    return { 404, "{\"error\":\"Not found\"}" };
}

std::string MessageServer::buildResponse(const HttpResponse& resp) const {
    std::ostringstream out;
    out << "HTTP/1.1 " << resp.statusCode << " ";

    switch (resp.statusCode) {
        case 200: out << "OK";           break;
        case 201: out << "Created";      break;
        case 401: out << "Unauthorized"; break;
        case 404: out << "Not Found";    break;
        default:  out << "Unknown";      break;
    }

    out << "\r\nContent-Type: application/json\r\n"
        << "Content-Length: " << resp.body.size() << "\r\n"
        << "Connection: close\r\n\r\n"
        << resp.body;

    return out.str();
}

// ─── Route handlers ───────────────────────────────────────────────────────────
// These are stubs. Replace with calls to server/database/ (Python via subprocess
// or a C-extension) or move the DB logic to a C++ layer that links here.

HttpResponse MessageServer::handleLogin(const HttpRequest& req) {
    std::cout << "[Server] POST /api/auth/login\n";
    // TODO: validate credentials against the database
    return { 200, "{\"token\":\"stub-token-replace-with-real-auth\"}" };
}

HttpResponse MessageServer::handleSendMessage(const HttpRequest& req) {
    std::cout << "[Server] POST /api/messages\n";
    // TODO: persist ciphertext to the database
    return { 201, "{\"status\":\"queued\"}" };
}

HttpResponse MessageServer::handleFetchMessages(const HttpRequest& req) {
    std::cout << "[Server] GET /api/messages\n";
    // TODO: query the database for the authenticated user's messages
    return { 200, "{\"messages\":[]}" };
}
