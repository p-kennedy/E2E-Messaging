#include "MessageStore.hpp"
#include <algorithm>
#include <iterator>

void MessageStore::add(const Message& msg) {
    m_messages.push_back(msg);
}

bool MessageStore::remove(const std::string& id) {
    auto it = std::find_if(m_messages.begin(), m_messages.end(),
        [&id](const Message& m) { return m.id == id; });
    if (it == m_messages.end()) return false;
    m_messages.erase(it);
    return true;
}

std::vector<Message> MessageStore::getAll() const {
    std::vector<Message> sorted = m_messages;
    std::sort(sorted.begin(), sorted.end(),
        [](const Message& a, const Message& b) { return a.createdAt < b.createdAt; });
    return sorted;
}

std::vector<Message> MessageStore::getFrom(const std::string& senderId) const {
    std::vector<Message> result;
    std::copy_if(m_messages.begin(), m_messages.end(), std::back_inserter(result),
        [&senderId](const Message& m) { return m.senderId == senderId; });
    return result;
}

std::size_t MessageStore::count() const {
    return m_messages.size();
}

void MessageStore::clear() {
    m_messages.clear();
}
