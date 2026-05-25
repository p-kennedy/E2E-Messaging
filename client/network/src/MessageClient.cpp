#include "MessageClient.hpp"
#include <sstream>
#include <stdexcept>
#include <iostream>

MessageClient::MessageClient(const std::string& host, int port)
    : m_host(host)
    , m_port(port)
{}

void MessageClient::login(const std::string& username, const std::string& password) {
    std::string body = "{\"username\":\"" + username + "\","
                       "\"password\":\"" + password + "\"}";

    std::string response = doRequest("POST", "/api/auth/login", body);

    auto start = response.find("\"token\":\"");
    if (start == std::string::npos)
        throw std::runtime_error("Login failed — no token in response");
    start += 9;
    auto end = response.find("\"", start);
    if (end == std::string::npos)
        throw std::runtime_error("Login failed — malformed token");

    m_authToken = response.substr(start, end - start);
    std::cout << "[Auth] Logged in successfully\n";
}

void MessageClient::sendMessage(const std::string& recipient, const std::string& ciphertext) {
    if (!isAuthenticated())
        throw std::runtime_error("Not authenticated — call login() first");

    std::string body = "{\"recipient\":\"" + recipient + "\","
                       "\"ciphertext\":\"" + ciphertext + "\"}";

    doRequest("POST", "/api/messages", body);
    std::cout << "[Message] Sent to " << recipient << "\n";
}

std::vector<Message> MessageClient::fetchMessages() {
    if (!isAuthenticated())
        throw std::runtime_error("Not authenticated — call login() first");

    std::string response = doRequest("GET", "/api/messages");

    std::vector<Message> messages;
    std::cout << "[Message] Raw response: " << response << "\n";
    return messages;
}

bool MessageClient::isAuthenticated() const {
    return !m_authToken.empty();
}

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

    if (!m_authToken.empty())
        req << "Authorization: Bearer " << m_authToken << "\r\n";

    if (!body.empty())
        req << "Content-Length: " << body.size() << "\r\n";

    req << "\r\n";
    req << body;

    return req.str();
}

std::string MessageClient::doRequest(
    const std::string& method,
    const std::string& path,
    const std::string& body
) {
    SecureClientConnection conn(m_host, m_port);
    conn.send(buildRequest(method, path, body));
    return extractBody(conn.receive());
}

std::string MessageClient::extractBody(const std::string& httpResponse) const {
    auto pos = httpResponse.find("\r\n\r\n");
    if (pos == std::string::npos) return httpResponse;
    return httpResponse.substr(pos + 4);
}
