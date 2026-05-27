#include "SecureClientConnection.hpp"
#include <iostream>
#include <stdexcept>

int main() {
    std::cout << "=== TLS Connection Test ===\n";

    // Test 1: Connect to a public server to verify TLS works
    try {
        std::cout << "\n[Test 1] Connecting to example.com:443...\n";
        SecureClientConnection conn("example.com", 443);

        std::cout << "  Connected: " << (conn.isConnected() ? "YES" : "NO") << "\n";
        std::cout << "  Certificate: " << conn.getCertificateSubject() << "\n";

        conn.send("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n");
        std::string response = conn.receive();

        auto firstLine = response.substr(0, response.find("\r\n"));
        std::cout << "  Response: " << firstLine << "\n";
        std::cout << "  [PASS]\n";

    } catch (const std::exception& e) {
        std::cerr << "  [FAIL] " << e.what() << "\n";
        return 1;
    }

    // Test 2: Verify that an expired cert is rejected
    try {
        std::cout << "\n[Test 2] Connecting to expired.badssl.com (should fail)...\n";
        SecureClientConnection conn("expired.badssl.com", 443);
        std::cerr << "  [FAIL] Should have thrown — expired cert was accepted!\n";
        return 1;
    } catch (const std::exception& e) {
        std::cout << "  Correctly rejected: " << e.what() << "\n";
        std::cout << "  [PASS]\n";
    }

    std::cout << "\nAll tests passed.\n";
    return 0;
}
