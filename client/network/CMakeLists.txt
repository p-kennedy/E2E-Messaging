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
    src/MessageStore.cpp
)

target_include_directories(client_lib
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(client_lib
    PUBLIC OpenSSL::SSL OpenSSL::Crypto
)

# Required when client_lib is linked into the shared .node addon.
set_target_properties(client_lib PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_executable(secure_client src/main.cpp)
target_link_libraries(secure_client PRIVATE client_lib)

add_executable(test_connection tests/test_connection.cpp)
target_link_libraries(test_connection PRIVATE client_lib)

enable_testing()
add_test(NAME ConnectionTest COMMAND test_connection)

# ── N-API native addon (built by cmake-js, not plain cmake) ──────────────────
# cmake-js sets CMAKE_JS_INC and CMAKE_JS_LIB; skip this target in plain builds.
if(DEFINED CMAKE_JS_INC)
    # Locate node-addon-api headers via node
    execute_process(
        COMMAND node -p "require('node-addon-api').include"
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        OUTPUT_VARIABLE NODE_ADDON_API_DIR
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    # Strip surrounding quotes that node -p may add
    string(REPLACE "\"" "" NODE_ADDON_API_DIR "${NODE_ADDON_API_DIR}")

    add_library(messaging_client_addon SHARED src/addon.cpp)

    target_include_directories(messaging_client_addon PRIVATE
        ${CMAKE_JS_INC}
        ${NODE_ADDON_API_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${OPENSSL_INCLUDE_DIR}
    )

    target_link_libraries(messaging_client_addon PRIVATE client_lib ${CMAKE_JS_LIB})

    # NAPI_DISABLE_CPP_EXCEPTIONS — let the wrapper handle all exceptions explicitly
    target_compile_definitions(messaging_client_addon PRIVATE
        NAPI_VERSION=8
        NAPI_DISABLE_CPP_EXCEPTIONS
    )

    set_target_properties(messaging_client_addon PROPERTIES
        PREFIX  ""
        SUFFIX  ".node"
        OUTPUT_NAME "messaging_client"
    )
endif()
