#pragma once

#include <string>
#include <vector>

namespace crypto_handler {

    // Define constants for our crypto operations
    const int SALT_BYTES = 16;
    const int KEY_BYTES = 32; // 32 bytes = 256 bits for AES-256
    const int IV_BYTES = 16;  // 16 bytes = 128 bits for AES block size
    const int PBKDF2_ITERATIONS = 100000;

    // Generates a vector of cryptographically secure random bytes.
    std::vector<unsigned char> generate_random_bytes(int num_bytes);

    // Derives a 256-bit key from a password and salt using PBKDF2.
    std::vector<unsigned char> derive_key_from_password(const std::string& password, const std::vector<unsigned char>& salt);

    // Encrypts plaintext using AES-256-CBC.
    // Returns ciphertext. Throws std::runtime_error on failure.
    std::vector<unsigned char> encrypt_data(const std::string& plaintext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv);

    // Decrypts ciphertext using AES-256-CBC.
    // Returns plaintext. Throws std::runtime_error on failure.
    std::string decrypt_data(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv);

} // namespace crypto_handler