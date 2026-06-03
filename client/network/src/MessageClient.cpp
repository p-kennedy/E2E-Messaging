#include "MessageClient.hpp"
#include <sstream>
#include <stdexcept>
#include <iostream>

MessageClient::MessageClient(const std::string& host, int port)
    : m_host(host)
    , m_port(port)
{}

void MessageClient::registerUser(const std::string& username, const std::string& password,
                                 const std::string& publicKeyJson) {
    // publicKeyJson is already a JSON string — embed it as a JSON string value
    // by escaping any inner quotes, then wrap in the outer object.
    std::string escapedPubKey;
    escapedPubKey.reserve(publicKeyJson.size());
    for (char c : publicKeyJson) {
        if (c == '"')  escapedPubKey += "\\\"";
        else if (c == '\\') escapedPubKey += "\\\\";
        else escapedPubKey += c;
    }

    std::string body = "{\"username\":\"" + username + "\","
                       "\"password\":\"" + password + "\","
                       "\"public_key\":\"" + escapedPubKey + "\"}";

    doRequest("POST", "/api/auth/register", body);
    std::cout << "[Auth] Registered user: " << username << "\n";
}

void MessageClient::login(const std::string& username, const std::string& password) {
    std::string body = "{\"username\":\"" + username + "\","
                       "\"password\":\"" + password + "\"}";

    std::string response = doRequest("POST", "/api/auth/login", body);

    m_authToken = extractJsonString(response, "token");
    if (m_authToken.empty())
        throw std::runtime_error("Login failed — no token in response");

    std::cout << "[Auth] Logged in successfully\n";
}

std::string MessageClient::sendMessage(const std::string& recipient,
                                       const std::string& ciphertext,
                                       const std::string& nonce,
                                       const std::string& header,
                                       const std::string& signature,
                                       const std::string& digest) {
    if (!isAuthenticated())
        throw std::runtime_error("Not authenticated — call login() first");

    // header is a JSON object string — embed it directly (not as a quoted string)
    // so the server receives it as a proper JSON value.
    std::string body = "{\"recipient\":\"" + recipient  + "\","
                       "\"ciphertext\":\"" + ciphertext + "\","
                       "\"nonce\":\""      + nonce      + "\","
                       "\"header\":"       + header     + ","
                       "\"signature\":\""  + signature  + "\","
                       "\"digest\":\""     + digest     + "\"}";

    std::string response = doRequest("POST", "/api/messages", body);
    std::cout << "[Message] Sent to " << recipient << "\n";
    return response;
}

std::string MessageClient::fetchMessages() {
    if (!isAuthenticated())
        throw std::runtime_error("Not authenticated — call login() first");

    return doRequest("GET", "/api/messages");
}

std::vector<Message> MessageClient::fetchAndStore() {
    const std::string raw = fetchMessages();
    m_store.clear();

    for (const auto& obj : extractJsonObjects(raw)) {
        Message msg(
            extractJsonString(obj, "message_id"),
            extractJsonString(obj, "sender_id"),
            extractJsonString(obj, "recipient_id"),
            extractJsonString(obj, "ciphertext"),
            extractJsonString(obj, "created_at")
        );
        if (!msg.id.empty()) m_store.add(msg);
    }

    std::cout << "[Store] Loaded " << m_store.count() << " message(s).\n";
    return m_store.getAll();
}

const MessageStore& MessageClient::store() const {
    return m_store;
}

std::vector<std::string> MessageClient::extractJsonObjects(const std::string& json) const {
    std::vector<std::string> objects;
    int         depth = 0;
    bool        inStr = false;
    std::size_t start = 0;

    for (std::size_t i = 0; i < json.size(); ++i) {
        const char c = json[i];

        if (inStr) {
            // End of string, ignoring escaped quotes
            if (c == '"' && (i == 0 || json[i - 1] != '\\')) inStr = false;
            continue;
        }

        if (c == '"') { inStr = true; continue; }

        if (c == '{') {
            if (depth == 1) start = i;   // entering a message object (inside outer { })
            ++depth;
        } else if (c == '}') {
            --depth;
            if (depth == 1)              // just closed a message object
                objects.push_back(json.substr(start, i - start + 1));
        }
    }
    return objects;
}

bool MessageClient::isAuthenticated() const {
    return !m_authToken.empty();
}

void MessageClient::setAuthToken(const std::string& token) {
    m_authToken = token;
}

const std::string& MessageClient::getAuthToken() const {
    return m_authToken;
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

// Extracts the string value for a given key from a flat JSON object.
// Only handles string values (quoted). Returns empty string if not found.
std::string MessageClient::extractJsonString(const std::string& json,
                                              const std::string& key) const {
    const std::string needle = "\"" + key + "\":\"";
    auto start = json.find(needle);
    if (start == std::string::npos) return "";
    start += needle.size();
    auto end = json.find("\"", start);
    if (end == std::string::npos) return "";
    return json.substr(start, end - start);
}
