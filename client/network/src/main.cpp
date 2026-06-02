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

        // ciphertext, nonce, header, signature, digest come from the crypto module
        client.sendMessage("bob", "BASE64_CIPHERTEXT", "BASE64_NONCE",
                           "{\"ratchetPublic\":\"...\",\"Ns\":0,\"PN\":0}",
                           "BASE64_SIGNATURE", "0xDIGEST");

        std::string rawJson = client.fetchMessages();
        std::cout << "fetchMessages response: " << rawJson << "\n";

    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << "\n";
        return 1;
    }

    return 0;
}
