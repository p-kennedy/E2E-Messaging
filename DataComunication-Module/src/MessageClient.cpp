#include "MessageClient.hpp"
#include <sstream>
#include <stdexcept>
#include <iostream>

MessageClient::MessageClient(const std::string& host, int port)
    : m_host(host)
    , m_port(port)
{}

// ─── Public Interface ─────────────────────────────────────────────────────────

void MessageClient::login(const std::string& username, const std::string& password) {
    // Build a simple JSON body
    // In your real project replace this with a proper JSON library (e.g. nlohmann/json)
    std::string body = "{\"username\":\"" + username + "\","
                       "\"password\":\"" + password + "\"}";

    std::string response = doRequest("POST", "/api/auth/login", body);

    // Very basic token extraction — replace with proper JSON parsing
    // Looks for: {"token":"<value>"}
    auto start = response.find("\"token\":\"");
    if (start == std::string::npos) {
        throw std::runtime_error("Login failed — no token in response");
    }
    start += 9; // skip past "token":"
    auto end = response.find("\"", start);
    if (end == std::string::npos) {
        throw std::runtime_error("Login failed — malformed token");
    }

    m_authToken = response.substr(start, end - start);
    std::cout << "[Auth] Logged in successfully\n";
}

void MessageClient::sendMessage(const std::string& recipient, const std::string& ciphertext) {
    if (!isAuthenticated()) {
        throw std::runtime_error("Not authenticated — call login() first");
    }

    std::string body = "{\"recipient\":\"" + recipient + "\","
                       "\"ciphertext\":\"" + ciphertext + "\"}";

    doRequest("POST", "/api/messages", body);
    std::cout << "[Message] Sent to " << recipient << "\n";
}

std::vector<Message> MessageClient::fetchMessages() {
    if (!isAuthenticated()) {
        throw std::runtime_error("Not authenticated — call login() first");
    }

    std::string response = doRequest("GET", "/api/messages");

    // Placeholder — in your real project parse the JSON array properly
    // This returns an empty vector; replace with nlohmann/json parsing
    std::vector<Message> messages;
    std::cout << "[Message] Raw response: " << response << "\n";
    return messages;
}

bool MessageClient::isAuthenticated() const {
    return !m_authToken.empty();
}

// ─── Private Helpers ──────────────────────────────────────────────────────────

std::string MessageClient::buildRequest(
    const std::string& method,
    const std::string& path,
    const std::string& body
) const {
    std::ostringstream req;
    req << method << " " << path << " HTTP/1.1\r\n";
    req << "Host: " << m_host << "\r\n";
    req << "Content-Type: application/json\r\n";
    req << "Connection: close\r\n";

    if (!m_authToken.empty()) {
        req << "Authorization: Bearer " << m_authToken << "\r\n";
    }

    if (!body.empty()) {
        req << "Content-Length: " << body.size() << "\r\n";
    }

    req << "\r\n"; // blank line separates headers from body
    req << body;

    return req.str();
}

std::string MessageClient::doRequest(
    const std::string& method,
    const std::string& path,
    const std::string& body
) {
    // Each request opens a fresh TLS connection
    // In a production client you'd want connection pooling / keep-alive
    SecureConnection conn(m_host, m_port);

    std::string request = buildRequest(method, path, body);
    conn.send(request);

    std::string response = conn.receive();
    return extractBody(response);
}

std::string MessageClient::extractBody(const std::string& httpResponse) const {
    // HTTP headers and body are separated by \r\n\r\n
    auto pos = httpResponse.find("\r\n\r\n");
    if (pos == std::string::npos) {
        return httpResponse; // no headers found, return as-is
    }
    return httpResponse.substr(pos + 4);
}
