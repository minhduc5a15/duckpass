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
target_compile_definitions(zxcvbn PRIVATE USE_DICT_FILE)

# Explicitly list all source files
set(SOURCES
        src/add_command.cpp
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
        src/list_command.cpp
        src/local_storage.cpp
        src/main.cpp
        src/rekey_command.cpp
        src/shell_command.cpp
        src/terminal_utils.cpp
        src/utils.cpp
        src/vault.cpp
)

# Create the executable from our source files
add_executable(duckpass ${SOURCES})

# Test executable
add_executable(audit_tests
        tests/audit_tests.cpp
        src/crypto.cpp
        src/entropy_evaluator.cpp
        src/audit_engine.cpp
        src/vault.cpp
        src/hibp_checker.cpp
        src/local_storage.cpp
)

# Tell the 'duckpass' executable where to find its public header files
# and vendor libraries.
target_include_directories(duckpass PUBLIC
        "${CMAKE_SOURCE_DIR}/include"
        "${CMAKE_SOURCE_DIR}/vendor"
        ${ARGON2_INCLUDE_DIRS}
)
target_include_directories(audit_tests PUBLIC
        "${CMAKE_SOURCE_DIR}/include"
        "${CMAKE_SOURCE_DIR}/vendor"
        ${ARGON2_INCLUDE_DIRS}
)

# We need to link against the 'Crypto' component of OpenSSL.
target_link_libraries(duckpass PRIVATE OpenSSL::Crypto ${ARGON2_LIBRARIES} CURL::libcurl zxcvbn)
target_link_libraries(audit_tests PRIVATE OpenSSL::Crypto ${ARGON2_LIBRARIES} CURL::libcurl zxcvbn)

# Copy dictionary to build directory
configure_file(vendor/zxcvbn-c/zxcvbn.dict zxcvbn.dict COPYONLY)

# A small message after a successful build
add_custom_command(TARGET duckpass POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E echo "Build complete. You can run the program now."
)