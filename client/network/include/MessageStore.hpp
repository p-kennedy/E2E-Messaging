#pragma once
#include "Message.hpp"
#include <cstddef>
#include <string>
#include <vector>

// In-memory store for messages received from the server.
// Retrieval methods return copies sorted chronologically by createdAt.
class MessageStore {
public:
    // Add a message. Duplicates (same id) are not checked — the caller should
    // call clear() before repopulating from a fresh server fetch.
    void add(const Message& msg);

    // Remove the message with the given id. Returns true if found and removed.
    bool remove(const std::string& id);

    // Return all stored messages sorted by createdAt (ascending).
    std::vector<Message> getAll() const;

    // Return messages whose senderId matches, preserving chronological order.
    std::vector<Message> getFrom(const std::string& senderId) const;

    std::size_t count() const;
    void        clear();

private:
    std::vector<Message> m_messages;
};
