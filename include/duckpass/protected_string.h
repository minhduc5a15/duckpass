#pragma once

#include <vector>

#include "duckpass/secure_allocator.h"

namespace duckpass {

    /**
     * @brief A string class that keeps its contents encrypted in RAM.
     *
     * Uses a globally initialized, randomly generated session key to encrypt data upon construction,
     * and only decrypts to a temporary SecureString when explicitly requested via unprotect().
     */
    class ProtectedString {
    public:
        // Default constructor creates an empty protected string
        ProtectedString();

        // Encrypts the provided secure string immediately using the session key
        explicit ProtectedString(const SecureString& plaintext);

        // Constructor that takes a string view and encrypts it
        explicit ProtectedString(std::string_view plaintext);

        // Decrypts and returns the original string as a SecureString (which will be zeroed when destroyed)
        SecureString unprotect() const;

        // Returns true if the string is empty
        bool empty() const;

        // Static initialization for the Session Key. Must be called once at application startup.
        // However, we can initialize it lazily on first use.
        static void initialize_session_key();

    private:
        std::vector<unsigned char> iv_;
        std::vector<unsigned char> ciphertext_;

        // Generates the Session Key lazily if it hasn't been generated yet
        static void ensure_session_key_initialized();
    };

}  // namespace duckpass
