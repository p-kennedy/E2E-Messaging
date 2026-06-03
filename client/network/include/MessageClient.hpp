#pragma once

#include "SecureClientConnection.hpp"
#include <string>
#include <vector>
#include <memory>

// High-level client that uses SecureClientConnection to talk to the messaging API.
class MessageClient {
public:
    explicit MessageClient(const std::string& host, int port = 443);
    ~MessageClient() = default;

    MessageClient(const MessageClient&) = delete;
    MessageClient& operator=(const MessageClient&) = delete;

    // Register a new user. publicKeyJson is the X3DH prekey bundle as a JSON string.
    void registerUser(const std::string& username, const std::string& password,
                      const std::string& publicKeyJson);

    // Authenticate with the server. Stores the returned auth token for subsequent calls.
    void login(const std::string& username, const std::string& password);

    // Send an encrypted message. Returns the raw JSON response body (contains message_id).
    std::string sendMessage(const std::string& recipient,
                            const std::string& ciphertext,
                            const std::string& nonce,
                            const std::string& header,
                            const std::string& signature,
                            const std::string& digest);

    // Fetch all messages for the logged-in user. Returns the raw JSON response body.
    std::string fetchMessages();

    bool isAuthenticated() const;

    // Inject a previously obtained token (e.g. from the JS layer after login).
    void setAuthToken(const std::string& token);
    const std::string& getAuthToken() const;

private:
    std::string m_host;
    int         m_port;
    std::string m_authToken;

    std::string buildRequest(const std::string& method, const std::string& path,
                             const std::string& body = "") const;
    std::string doRequest(const std::string& method, const std::string& path,
                          const std::string& body = "");
    std::string extractBody(const std::string& httpResponse) const;
    std::string extractJsonString(const std::string& json,
                                  const std::string& key) const;
};
