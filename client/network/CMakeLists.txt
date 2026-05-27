cmake_minimum_required(VERSION 3.16)
project(SecureMessagingClient VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -Wno-unused-parameter)

find_package(OpenSSL 1.1.1 REQUIRED)
message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")

add_library(client_lib
    src/SecureClientConnection.cpp
    src/MessageClient.cpp
)

target_include_directories(client_lib
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(client_lib
    PUBLIC OpenSSL::SSL OpenSSL::Crypto
)

add_executable(secure_client src/main.cpp)
target_link_libraries(secure_client PRIVATE client_lib)

add_executable(test_connection tests/test_connection.cpp)
target_link_libraries(test_connection PRIVATE client_lib)

enable_testing()
add_test(NAME ConnectionTest COMMAND test_connection)
