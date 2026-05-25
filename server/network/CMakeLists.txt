cmake_minimum_required(VERSION 3.16)
project(SecureMessagingServer VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -Wno-unused-parameter)

find_package(OpenSSL 1.1.1 REQUIRED)
message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")

add_library(server_lib
    src/SecureServerConnection.cpp
    src/MessageServer.cpp
)

target_include_directories(server_lib
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(server_lib
    PUBLIC OpenSSL::SSL OpenSSL::Crypto
)

add_executable(secure_server src/main.cpp)
target_link_libraries(secure_server PRIVATE server_lib)
