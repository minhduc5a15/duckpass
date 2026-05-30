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
pkg_check_modules(ARGON2 REQUIRED libargon2)

# Explicitly list all source files
set(SOURCES
    src/add_command.cpp
    src/clipboard_handler.cpp
    src/config_handler.cpp
    src/crypto.cpp
    src/delete_command.cpp
    src/export_command.cpp
    src/generate_command.cpp
    src/get_command.cpp
    src/list_command.cpp
    src/local_storage.cpp
    src/main.cpp
    src/utils.cpp
    src/vault.cpp
)

# Create the executable from our source files
add_executable(duckpass ${SOURCES})

# Tell the 'duckpass' executable where to find its public header files
# and vendor libraries.
target_include_directories(duckpass PUBLIC
        "${CMAKE_SOURCE_DIR}/include"
        "${CMAKE_SOURCE_DIR}/vendor"
        ${ARGON2_INCLUDE_DIRS}
)

# We need to link against the 'Crypto' component of OpenSSL.
target_link_libraries(duckpass PRIVATE OpenSSL::Crypto ${ARGON2_LIBRARIES})

# A small message after a successful build
add_custom_command(TARGET duckpass POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E echo "Build complete. You can run the program now."
)
