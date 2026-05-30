#pragma once

#include <stdexcept>
#include <string>

namespace duckpass {

    class duckpass_error : public std::runtime_error {
    public:
        explicit duckpass_error(const std::string& message) : std::runtime_error(message) {}
    };

    class wrong_password_error : public duckpass_error {
    public:
        wrong_password_error() : duckpass_error("Invalid master password.") {}
    };

    class vault_corrupted_error : public duckpass_error {
    public:
        explicit vault_corrupted_error(const std::string& detail = "") 
            : duckpass_error("Vault data is corrupted or has an invalid structure. " + detail) {}
    };

    class vault_io_error : public duckpass_error {
    public:
        explicit vault_io_error(const std::string& path) 
            : duckpass_error("Failed to read or write vault file: " + path) {}
    };

} // namespace duckpass
