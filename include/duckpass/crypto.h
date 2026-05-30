#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "duckpass/secure_allocator.h"

namespace crypto_handler {
    using duckpass::SecureString;
    using duckpass::SecureBytes;

    /**
     * @brief KDF parameters for Argon2id.
     * Stored in the vault header for backward compatibility.
     */
    struct KdfParams {
        uint32_t time_cost;
        uint32_t memory_cost;
        uint32_t parallelism;
    };

    // Default Argon2 constants
    const uint32_t DEFAULT_TIME_COST = 2; 
    const uint32_t DEFAULT_MEMORY_COST = 65536; // 64 MB
    const uint32_t DEFAULT_PARALLELISM = 1;

    // Constants for AES-GCM
    const int SALT_BYTES = 16;
    const int KEY_BYTES = 32; // 256-bit key
    const int IV_BYTES = 12; // GCM standard is 12 bytes (96 bits) for IV
    const int TAG_BYTES = 16; // GCM authentication tag

    // Generates a vector of cryptographically secure random bytes.
    std::vector<unsigned char> generate_random_bytes(int num_bytes);

    // Derives a 256-bit key from a password and salt using Argon2id.
    SecureBytes derive_key_from_password(const SecureString &password, 
                                       const std::vector<unsigned char> &salt,
                                       const KdfParams &params = {DEFAULT_TIME_COST, DEFAULT_MEMORY_COST, DEFAULT_PARALLELISM});

    // Encrypts plaintext using AES-256-GCM.
    // Returns a single vector containing [ciphertext + authentication_tag].
    std::vector<unsigned char> encrypt_data(const SecureBytes &plaintext, const SecureBytes &key, const std::vector<unsigned char> &iv);

    // Decrypts data using AES-256-GCM.
    // Expects a single vector containing [ciphertext + authentication_tag].
    // Throws an exception if authentication fails.
    SecureBytes decrypt_data(const std::vector<unsigned char> &encrypted_blob, const SecureBytes &key, const std::vector<unsigned char> &iv);
} // namespace crypto_handler
