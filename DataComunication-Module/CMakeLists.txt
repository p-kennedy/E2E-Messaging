cmake_minimum_required(VERSION 3.16)
project(SecureMessagingClient VERSION 0.1.0 LANGUAGES CXX)

# ── C++ Standard ──────────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── Compiler Warnings ─────────────────────────────────────────────────────────
add_compile_options(
    -Wall
    -Wextra
    -Wpedantic
    -Wshadow
    -Wno-unused-parameter
)

# ── Find OpenSSL ──────────────────────────────────────────────────────────────
find_package(OpenSSL 1.1.1 REQUIRED)
message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "OpenSSL include: ${OPENSSL_INCLUDE_DIR}")

# ── Shared Library (SecureConnection + MessageClient) ─────────────────────────
# Built as a library so both the main app and tests can link against it
add_library(messaging_lib
    src/SecureConnection.cpp
    src/MessageClient.cpp
)

target_include_directories(messaging_lib
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(messaging_lib
    PUBLIC OpenSSL::SSL OpenSSL::Crypto
)

# ── Main Executable ───────────────────────────────────────────────────────────
add_executable(secure_client src/main.cpp)
target_link_libraries(secure_client PRIVATE messaging_lib)

# ── Test Executables ──────────────────────────────────────────────────────────
add_executable(test_connection tests/test_connection.cpp)
target_link_libraries(test_connection PRIVATE messaging_lib)

# Register tests with CTest so `ctest` runs them automatically
enable_testing()
add_test(NAME ConnectionTest COMMAND test_connection)
