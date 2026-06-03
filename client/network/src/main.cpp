#include "MessageClient.hpp"
#include "MessageStore.hpp"
#include <iostream>
#include <stdexcept>

int main() {
    // Keep in sync with SERVER_HOST / SERVER_PORT in client/config.mjs
    const std::string HOST = "cpa-attack.theburkenator.com";
    const int         PORT = 443;

    try {
        std::cout << "=== Secure Messaging Client ===\n";

        MessageClient client(HOST, PORT);
        client.login("alice", "password123");

        // fetchAndStore() fetches messages over TLS, parses each JSON object into a
        // Message, stores them in the internal MessageStore, and returns the list
        // sorted chronologically by createdAt.
        auto messages = client.fetchAndStore();
        std::cout << "Inbox: " << messages.size() << " message(s)\n";

        for (const auto& msg : messages) {
            std::cout << "  [" << msg.createdAt << "] from " << msg.senderId
                      << "  (" << msg.ciphertext.size() << " bytes)\n";
        }

        // Per-sender filtering — internally uses std::copy_if with a lambda.
        if (!messages.empty()) {
            const std::string sender = messages.front().senderId;
            auto fromSender = client.store().getFrom(sender);
            std::cout << "Messages from " << sender << ": "
                      << fromSender.size() << "\n";
        }

        // Demonstrate MessageStore independently: add, remove (std::find_if + lambda),
        // and sorted retrieval (std::sort + lambda).
        MessageStore local;
        for (const auto& msg : messages) local.add(msg);
        std::cout << "Local store loaded: " << local.count() << " message(s)\n";

        if (!messages.empty()) {
            const std::string firstId = messages.front().id;
            bool removed = local.remove(firstId);
            std::cout << "Remove " << firstId.substr(0, 8) << "...: "
                      << (removed ? "ok" : "not found") << "\n";
            std::cout << "Store size after remove: " << local.count() << "\n";
        }

    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << "\n";
        return 1;
    }

    return 0;
}
