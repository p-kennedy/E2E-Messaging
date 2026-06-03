#pragma once
#include <string>

// Wire-format representation of a single message as received from the server.
// Cryptographic fields (nonce, header, signature) are handled by the JS crypto
// layer; only the fields needed for routing and local storage are kept here.
struct Message {
    std::string id;
    std::string senderId;
    std::string recipientId;
    std::string ciphertext;
    std::string createdAt;

    Message() = default;
    Message(std::string id_, std::string sender, std::string recipient,
            std::string ct, std::string ts)
        : id(std::move(id_))
        , senderId(std::move(sender))
        , recipientId(std::move(recipient))
        , ciphertext(std::move(ct))
        , createdAt(std::move(ts))
    {}
};
