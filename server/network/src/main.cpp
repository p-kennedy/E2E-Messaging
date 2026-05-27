#include "MessageServer.hpp"
#include <iostream>
#include <stdexcept>

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <cert.pem> <key.pem> <port>\n";
        return 1;
    }

    const std::string certPath = argv[1];
    const std::string keyPath  = argv[2];
    const int         port     = std::stoi(argv[3]);

    try {
        std::cout << "=== Secure Messaging Server ===\n";
        MessageServer server(certPath, keyPath, port);
        server.run();
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << "\n";
        return 1;
    }

    return 0;
}
