#pragma once

#include "SecureClientConnection.hpp"
#include <string>
#include <vector>
#include <memory>

struct Message {
    std::string id;
    std::string sender;
    std::string recipient;
    std::string ciphertext;  // encrypted payload — never stored as plaintext
    std::string timestamp;
};

// High-level client that uses SecureClientConnection to talk to the messaging API.
class MessageClient {
public:
    explicit MessageClient(const std::string& host, int port = 443);
    ~MessageClient() = default;

    MessageClient(const MessageClient&) = delete;
    MessageClient& operator=(const MessageClient&) = delete;

    // Authenticate with the server. Stores the returned auth token. Throws on failure.
    void login(const std::string& username, const std::string& password);

    // Send an encrypted message. ciphertext, nonce, and digest come from the crypto module.
    void sendMessage(const std::string& recipient, const std::string& ciphertext,
                     const std::string& nonce, const std::string& digest);

    // Fetch all messages for the logged-in user.
    std::vector<Message> fetchMessages();

    bool isAuthenticated() const;

private:
    std::string m_host;
    int         m_port;
    std::string m_authToken;

    std::string buildRequest(const std::string& method, const std::string& path,
                             const std::string& body = "") const;
    std::string doRequest(const std::string& method, const std::string& path,
                          const std::string& body = "");
    std::string extractBody(const std::string& httpResponse) const;
};
