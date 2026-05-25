#include "MessageClient.hpp"
#include <iostream>
#include <stdexcept>

int main() {
    const std::string HOST = "sas.theburkenator.com";
    const int         PORT = 443;

    try {
        std::cout << "=== Secure Messaging Client ===\n";

        MessageClient client(HOST, PORT);

        client.login("alice", "password123");

        std::string fakeCiphertext = "BASE64_ENCODED_CIPHERTEXT_HERE";
        client.sendMessage("bob", fakeCiphertext);

        auto messages = client.fetchMessages();
        std::cout << "Fetched " << messages.size() << " messages\n";

    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << "\n";
        return 1;
    }

    return 0;
}
