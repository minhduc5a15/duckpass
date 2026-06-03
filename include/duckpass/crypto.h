#pragma once

#include <span>
#include <vector>

#include "duckpass/secure_allocator.h"

namespace crypto_handler {
    using duckpass::SecureBytes;
    using duckpass::SecureString;

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
    const uint32_t DEFAULT_MEMORY_COST = 65536;  // 64 MB
    const uint32_t DEFAULT_PARALLELISM = 1;

    // Constants for AES-GCM
    const int SALT_BYTES = 16;
    const int KEY_BYTES = 32;  // 256-bit key
    const int IV_BYTES = 12;   // GCM standard is 12 bytes (96 bits) for IV
    const int TAG_BYTES = 16;  // GCM authentication tag

    // Generates a vector of cryptographically secure random bytes.
    std::vector<unsigned char> generate_random_bytes(int num_bytes);

    // Derives a 256-bit key from a password and salt using Argon2id.
    SecureBytes derive_key_from_password(const SecureString &password, std::span<const uint8_t> salt,
                                         const KdfParams &params = {DEFAULT_TIME_COST, DEFAULT_MEMORY_COST, DEFAULT_PARALLELISM});

    // Encrypts plaintext using AES-256-GCM.
    // Returns a single vector containing [ciphertext + authentication_tag].
    std::vector<unsigned char> encrypt_data(std::span<const uint8_t> plaintext, std::span<const uint8_t> key, std::span<const uint8_t> iv,
                                            std::span<const uint8_t> aad = {});

    // Decrypts data using AES-256-GCM.
    // Expects a single vector containing [ciphertext + authentication_tag].
    // Throws an exception if authentication fails.
    SecureBytes decrypt_data(std::span<const uint8_t> encrypted_blob, std::span<const uint8_t> key, std::span<const uint8_t> iv,
                             std::span<const uint8_t> aad = {});

    // Computes SHA-1 hash of the input string and returns it as an uppercase hex string.
    // Used for HaveIBeenPwned API (K-Anonymity).
    std::string compute_sha1(const SecureString &input);

    // Computes SHA-256 hash of the input string and returns it as a hex string.
    // Used for internal reuse detection without storing plaintext in RAM.
    std::string compute_sha256(const SecureString &input);
}  // namespace crypto_handler
