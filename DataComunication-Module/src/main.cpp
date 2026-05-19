#include "MessageClient.hpp"
#include <iostream>
#include <stdexcept>

/**
 * Simple demo entry point.
 * Replace the host/credentials with your team's actual server details.
 */
int main() {
    const std::string HOST = "sas.theburkenator.com"; // your team's virtual host
    const int         PORT = 443;

    try {
        std::cout << "=== Secure Messaging Client ===\n";

        MessageClient client(HOST, PORT);

        // Login — SecureConnection will verify the TLS cert automatically
        client.login("alice", "password123");

        // Send an encrypted message
        // In your real project the ciphertext comes from your crypto module
        std::string fakeCiphertext = "BASE64_ENCODED_CIPHERTEXT_HERE";
        client.sendMessage("bob", fakeCiphertext);

        // Fetch messages
        auto messages = client.fetchMessages();
        std::cout << "Fetched " << messages.size() << " messages\n";

    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << "\n";
        return 1;
    }

    return 0;
}
