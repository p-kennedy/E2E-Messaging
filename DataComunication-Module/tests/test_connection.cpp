#include "SecureConnection.hpp"
#include <iostream>
#include <stdexcept>

/**
 * Simple test — connects to a known HTTPS server and prints the cert subject.
 * Good for verifying your build works before your team's server is ready.
 *
 * Run with: ./test_connection
 * Expected output: prints certificate subject of example.com
 */
int main() {
    std::cout << "=== TLS Connection Test ===\n";

    // Test 1: Connect to a public server to verify TLS works
    try {
        std::cout << "\n[Test 1] Connecting to example.com:443...\n";
        SecureConnection conn("example.com", 443);

        std::cout << "  Connected: " << (conn.isConnected() ? "YES" : "NO") << "\n";
        std::cout << "  Certificate: " << conn.getCertificateSubject() << "\n";

        // Send a minimal HTTP GET and read the response
        conn.send("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n");
        std::string response = conn.receive();

        // Just print the first line (the HTTP status line)
        auto firstLine = response.substr(0, response.find("\r\n"));
        std::cout << "  Response: " << firstLine << "\n";
        std::cout << "  [PASS]\n";

    } catch (const std::exception& e) {
        std::cerr << "  [FAIL] " << e.what() << "\n";
        return 1;
    }

    // Test 2: Verify that a bad hostname is rejected
    try {
        std::cout << "\n[Test 2] Connecting to expired.badssl.com (should fail)...\n";
        SecureConnection conn("expired.badssl.com", 443);
        std::cerr << "  [FAIL] Should have thrown — expired cert was accepted!\n";
        return 1;
    } catch (const std::exception& e) {
        std::cout << "  Correctly rejected: " << e.what() << "\n";
        std::cout << "  [PASS]\n";
    }

    std::cout << "\nAll tests passed.\n";
    return 0;
}
