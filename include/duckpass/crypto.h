#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace crypto_handler {
    // Constants for Argon2
    const uint32_t ARGON2_TIME_COST = 2; // t_cost
    const uint32_t ARGON2_MEMORY_COST = 65536; // m_cost (64 MB)
    const uint32_t ARGON2_PARALLELISM = 1; // p_cost

    // Constants for AES-GCM
    const int SALT_BYTES = 16;
    const int KEY_BYTES = 32; // 256-bit key
    const int IV_BYTES = 12; // GCM standard is 12 bytes (96 bits) for IV
    const int TAG_BYTES = 16; // GCM authentication tag

    // Generates a vector of cryptographically secure random bytes.
    std::vector<unsigned char> generate_random_bytes(int num_bytes);

    // Derives a 256-bit key from a password and salt using Argon2id.
    std::vector<unsigned char> derive_key_from_password(const std::string &password, const std::vector<unsigned char> &salt);

    // Encrypts plaintext using AES-256-GCM.
    // Returns a single vector containing [ciphertext + authentication_tag].
    std::vector<unsigned char> encrypt_data(const std::string &plaintext, const std::vector<unsigned char> &key, const std::vector<unsigned char> &iv);

    // Decrypts data using AES-256-GCM.
    // Expects a single vector containing [ciphertext + authentication_tag].
    // Throws an exception if authentication fails.
    std::string decrypt_data(const std::vector<unsigned char> &encrypted_blob, const std::vector<unsigned char> &key, const std::vector<unsigned char> &iv);
} // namespace crypto_handler
