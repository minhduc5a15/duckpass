# CMake version requirement
cmake_minimum_required(VERSION 3.16)
# Project definition
project(duckpass VERSION 1.0)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# This tells CMake to find the OpenSSL library on your system.
# It will throw an error if OpenSSL is not found.
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
find_package(CURL REQUIRED)
pkg_check_modules(ARGON2 REQUIRED libargon2)

# Include zxcvbn-c
add_library(zxcvbn STATIC vendor/zxcvbn-c/zxcvbn.c)
target_include_directories(zxcvbn PUBLIC vendor/zxcvbn-c)
target_compile_definitions(zxcvbn PUBLIC USE_DICT_FILE)

# Explicitly list core source files (excluding main.cpp)
set(CORE_SOURCES
        src/add_command.cpp
        src/agent_command.cpp
        src/agent_server.cpp
        src/audit_command.cpp
        src/audit_engine.cpp
        src/clipboard_handler.cpp
        src/completion_command.cpp
        src/config_handler.cpp
        src/crypto.cpp
        src/delete_command.cpp
        src/entropy_evaluator.cpp
        src/export_command.cpp
        src/generate_command.cpp
        src/get_command.cpp
        src/hibp_checker.cpp
        src/init_command.cpp
        src/ipc.cpp
        src/list_command.cpp
        src/local_storage.cpp
        src/otp_command.cpp
        src/protected_string.cpp
        src/rekey_command.cpp
        src/shell_command.cpp
        src/terminal_utils.cpp
        src/totp.cpp
        src/utils.cpp
        src/vault.cpp
        src/vault_service.cpp
)

# Core static library
add_library(duckpass_core STATIC ${CORE_SOURCES})
target_include_directories(duckpass_core PUBLIC
        "${CMAKE_SOURCE_DIR}/include"
        "${CMAKE_SOURCE_DIR}/vendor"
        ${ARGON2_INCLUDE_DIRS}
)
target_link_libraries(duckpass_core PUBLIC OpenSSL::Crypto ${ARGON2_LIBRARIES} CURL::libcurl zxcvbn)

# Create the main executable from our core library + main.cpp
add_executable(duckpass src/main.cpp)
target_link_libraries(duckpass PRIVATE duckpass_core)

# Create the background agent daemon executable
add_executable(duckpass-agent src/daemon_main.cpp)
target_link_libraries(duckpass-agent PRIVATE duckpass_core)

# Legacy test executable
add_executable(audit_tests
        tests/audit_tests.cpp
)
target_link_libraries(audit_tests PRIVATE duckpass_core)

# --- GoogleTest Integration via FetchContent ---
include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.14.0
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

set(UNIT_TEST_SOURCES
        tests/test_main.cpp
        tests/crypto_test.cpp
        tests/storage_test.cpp
        tests/protected_string_test.cpp
        tests/vault_service_test.cpp
        tests/audit_test.cpp
        tests/totp_test.cpp
        tests/ipc_test.cpp
)

add_executable(duckpass_unit_tests ${UNIT_TEST_SOURCES})
target_link_libraries(duckpass_unit_tests PRIVATE duckpass_core GTest::gtest)
add_test(NAME duckpass_unit_tests COMMAND duckpass_unit_tests)
add_test(NAME legacy_audit_tests COMMAND audit_tests)

# Copy dictionary to build directory and test working directory
configure_file(vendor/zxcvbn-c/zxcvbn.dict zxcvbn.dict COPYONLY)

# A small message after a successful build
add_custom_command(TARGET duckpass POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E echo "Build complete. You can run the program now."
)