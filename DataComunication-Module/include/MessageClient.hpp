#pragma once

#include "SecureConnection.hpp"
#include <string>
#include <vector>
#include <memory>
#include <map>

/**
 * Represents a single message in the system.
 */
struct Message {
    std::string id;
    std::string sender;
    std::string recipient;
    std::string ciphertext;     // encrypted payload — never stored as plaintext
    std::string timestamp;
};

/**
 * High-level client that uses SecureConnection to talk to the messaging API.
 * Handles login, sending, and receiving messages.
 */
class MessageClient {
public:
    explicit MessageClient(const std::string& host, int port = 443);
    ~MessageClient() = default;

    // Not copyable
    MessageClient(const MessageClient&) = delete;
    MessageClient& operator=(const MessageClient&) = delete;

    /**
     * Authenticate with the server. Stores the returned auth token.
     * Throws on failure.
     */
    void login(const std::string& username, const std::string& password);

    /**
     * Send an encrypted message to a recipient.
     * The caller is responsible for encrypting the payload before passing it here.
     */
    void sendMessage(const std::string& recipient, const std::string& ciphertext);

    /**
     * Fetch all messages for the logged-in user.
     */
    std::vector<Message> fetchMessages();

    /**
     * Returns true if the client has a valid auth token.
     */
    bool isAuthenticated() const;

private:
    std::string                     m_host;
    int                             m_port;
    std::string                     m_authToken;

    // Builds a minimal HTTP/1.1 request string
    std::string buildRequest(
        const std::string& method,
        const std::string& path,
        const std::string& body = ""
    ) const;

    // Opens a fresh SecureConnection, sends request, returns response body
    std::string doRequest(
        const std::string& method,
        const std::string& path,
        const std::string& body = ""
    );

    // Strips HTTP headers and returns just the body
    std::string extractBody(const std::string& httpResponse) const;
};
