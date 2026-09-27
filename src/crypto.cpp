#include "duckpass/crypto.h"

#include <limits>
#include <memory>
#include <span>
#include <vector>

#include "duckpass/exceptions.h"

// OpenSSL for AES-GCM
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

// Argon2 for key derivation
#include <argon2.h>

#include <iomanip>

namespace crypto_handler {

    /**
     * @brief RAII wrapper for OpenSSL's EVP_CIPHER_CTX.
     * Ensures the context is freed automatically on destruction.
     */
    using CipherContextPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

    /**
     * @brief Generates cryptographically strong random bytes.
     * @param num_bytes The number of bytes to generate.
     * @return A vector containing the random bytes.
     * @throws duckpass::crypto_error if the OpenSSL CSPRNG fails.
     */
    std::vector<unsigned char> generate_random_bytes(const int num_bytes) {
        std::vector<unsigned char> buffer(num_bytes);
        if (RAND_bytes(buffer.data(), num_bytes) != 1) {
            ERR_clear_error();
            throw duckpass::crypto_error("Failed to generate random bytes.");
        }
        return buffer;
    }

    /**
     * @brief Derives a fixed-length cryptographic key from a password using Argon2id.
     * @param password The user's master password.
     * @param salt Random salt to prevent rainbow table attacks.
     * @param params Argon2 parameters (iterations, memory, parallelism).
     * @return A SecureBytes object containing the derived key.
     * @throws duckpass::crypto_error if Argon2 derivation fails.
     */
    SecureBytes derive_key_from_password(const SecureString& password, const std::span<const uint8_t> salt, const KdfParams& params) {
        SecureBytes key(KEY_BYTES);
        const int result = argon2id_hash_raw(params.time_cost, params.memory_cost, params.parallelism, password.c_str(), password.length(),
                                             salt.data(), salt.size(), key.data(), key.size());

        if (result != ARGON2_OK) {
            throw duckpass::crypto_error("Failed to derive key from password (Argon2). Error: " + std::string(argon2_error_message(result)));
        }
        return key;
    }

    /**
     * @brief Encrypts data using AES-256-GCM.
     * @param plaintext The data to encrypt.
     * @param key The 256-bit encryption key.
     * @param iv The initialization vector (nonce).
     * @param aad Additional Authenticated Data (not encrypted, but authenticated).
     * @return A vector containing [ciphertext + 16-byte authentication tag].
     * @throws duckpass::crypto_error if encryption fails or data is too large.
     */
    std::vector<unsigned char> encrypt_data(const std::span<const uint8_t> plaintext, const std::span<const uint8_t> key,
                                            const std::span<const uint8_t> iv, const std::span<const uint8_t> aad) {
        // Integer overflow protection for OpenSSL API (uses int for size)
        if (plaintext.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
            throw duckpass::crypto_error("Vault data size exceeds OpenSSL's encryption limit (2.1GB).");
        }

        // Initialize OpenSSL cipher context
        const CipherContextPtr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
        if (!ctx) {
            ERR_clear_error();
            throw duckpass::crypto_error("Failed to create cipher context.");
        }

        // Initialize AES-256-GCM encryption
        if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, key.data(), iv.data()) != 1) {
            ERR_clear_error();
            throw duckpass::crypto_error("Failed to initialize GCM encryption.");
        }

        // Provide AAD for GCM. AAD is authenticated but not encrypted.
        if (!aad.empty()) {
            int out_len;
            if (EVP_EncryptUpdate(ctx.get(), nullptr, &out_len, aad.data(), static_cast<int>(aad.size())) != 1) {
                ERR_clear_error();
                throw duckpass::crypto_error("Failed to set AAD for GCM encryption.");
            }
        }

        // Perform encryption
        std::vector<unsigned char> ciphertext(plaintext.size());
        int len = 0;
        if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len, plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
            ERR_clear_error();
            throw duckpass::crypto_error("Failed during GCM encryption update.");
        }
        int ciphertext_len = len;

        // Finalize encryption (GCM doesn't use padding, but this is required by API)
        if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + len, &len) != 1) {
            ERR_clear_error();
            throw duckpass::crypto_error("Failed during GCM encryption finalization.");
        }
        ciphertext_len += len;
        ciphertext.resize(ciphertext_len);

        // Retrieve the 16-byte authentication tag
        std::vector<unsigned char> tag(TAG_BYTES);
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, TAG_BYTES, tag.data()) != 1) {
            ERR_clear_error();
            throw duckpass::crypto_error("Failed to get GCM authentication tag.");
        }

        // Append the tag to the ciphertext
        ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());
        return ciphertext;
    }

    /**
     * @brief Decrypts data using AES-256-GCM and verifies the authentication tag.
     * @param encrypted_blob The combined [ciphertext + tag].
     * @param key The 256-bit encryption key.
     * @param iv The initialization vector (nonce) used during encryption.
     * @param aad Additional Authenticated Data (must match encryption AAD).
     * @return The decrypted plaintext as SecureBytes.
     * @throws duckpass::wrong_password_error if the tag verification fails (wrong key/tampered data).
     * @throws duckpass::vault_corrupted_error if the input blob is malformed.
     */
    SecureBytes decrypt_data(const std::span<const uint8_t> encrypted_blob, const std::span<const uint8_t> key, const std::span<const uint8_t> iv,
                             const std::span<const uint8_t> aad) {
        if (encrypted_blob.size() < TAG_BYTES) {
            throw duckpass::vault_corrupted_error("Encrypted data is too short.");
        }

        // Extract ciphertext and tag from the combined blob
        const std::span<const uint8_t> ciphertext = encrypted_blob.subspan(0, encrypted_blob.size() - TAG_BYTES);
        const std::span<const uint8_t> tag = encrypted_blob.subspan(encrypted_blob.size() - TAG_BYTES, TAG_BYTES);

        // Initialize OpenSSL cipher context
        const CipherContextPtr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
        if (!ctx) {
            ERR_clear_error();
            throw duckpass::crypto_error("Failed to create cipher context.");
        }

        // Initialize AES-256-GCM decryption
        if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, key.data(), iv.data()) != 1) {
            ERR_clear_error();
            throw duckpass::crypto_error("Failed to initialize GCM decryption.");
        }

        // Set the expected authentication tag. This is crucial for verification.
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, TAG_BYTES, const_cast<uint8_t*>(tag.data())) != 1) {
            ERR_clear_error();
            throw duckpass::crypto_error("Failed to set GCM authentication tag.");
        }

        // Provide AAD for GCM. AAD must match the one used during encryption.
        if (!aad.empty()) {
            int out_len;
            if (EVP_DecryptUpdate(ctx.get(), nullptr, &out_len, aad.data(), static_cast<int>(aad.size())) != 1) {
                ERR_clear_error();
                throw duckpass::crypto_error("Failed to set AAD for GCM decryption.");
            }
        }

        // Perform decryption
        SecureBytes plaintext_bytes(ciphertext.size());
        int len = 0;
        if (EVP_DecryptUpdate(ctx.get(), plaintext_bytes.data(), &len, ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
            ERR_clear_error();
            throw duckpass::crypto_error("Failed during GCM decryption update. Data may be corrupted.");
        }
        int plaintext_len = len;

        // The final check happens here. If the tag is invalid, this call will fail.
        if (EVP_DecryptFinal_ex(ctx.get(), plaintext_bytes.data() + len, &len) != 1) {
            ERR_clear_error();
            throw duckpass::wrong_password_error();
        }
        plaintext_len += len;

        plaintext_bytes.resize(plaintext_len);
        return plaintext_bytes;
    }

    /**
     * @brief Helper to compute a message digest (hash) using OpenSSL EVP.
     */
    static SecureString compute_hash(const SecureString& input, const EVP_MD* md, const bool uppercase) {
        using MdContextPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
        const MdContextPtr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        if (!ctx) {
            throw duckpass::crypto_error("Failed to create message digest context.");
        }

        if (EVP_DigestInit_ex(ctx.get(), md, nullptr) != 1) {
            throw duckpass::crypto_error("Failed to initialize message digest.");
        }

        if (EVP_DigestUpdate(ctx.get(), input.data(), input.size()) != 1) {
            throw duckpass::crypto_error("Failed to update message digest.");
        }

        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hash_len = 0;
        if (EVP_DigestFinal_ex(ctx.get(), hash, &hash_len) != 1) {
            throw duckpass::crypto_error("Failed to finalize message digest.");
        }

        SecureString result;
        result.reserve(hash_len * 2);

        const char* hex_chars = uppercase ? "0123456789ABCDEF" : "0123456789abcdef";
        for (unsigned int i = 0; i < hash_len; ++i) {
            result.push_back(hex_chars[(hash[i] >> 4) & 0x0F]);
            result.push_back(hex_chars[hash[i] & 0x0F]);
        }

        OPENSSL_cleanse(hash, sizeof(hash));
        return result;
    }

    SecureString compute_sha1(const SecureString& input) { return compute_hash(input, EVP_sha1(), true); }

    SecureString compute_sha256(const SecureString& input) { return compute_hash(input, EVP_sha256(), false); }

    SecureString generate_password(const int length) {
        if (length <= 0) {
            throw std::invalid_argument("Password length must be positive.");
        }

        constexpr std::string_view chars =
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789"
            "!@#$%^&*()-_=+[]{}|;:',.<>?/";

        const size_t charset_len = chars.length();
        // Rejection sampling bound: reject any byte >= max_usable to guarantee zero modulo bias
        const auto max_usable = static_cast<uint8_t>((256 / charset_len) * charset_len);

        SecureString password;
        password.reserve(static_cast<size_t>(length));

        while (static_cast<int>(password.size()) < length) {
            const int needed = length - static_cast<int>(password.size());
            const int batch_size = std::max(needed * 2, 16);
            std::vector<unsigned char> random_bytes = generate_random_bytes(batch_size);

            for (const unsigned char b : random_bytes) {
                if (b < max_usable) {
                    password.push_back(chars[b % charset_len]);
                    if (static_cast<int>(password.size()) == length) {
                        break;
                    }
                }
            }
            OPENSSL_cleanse(random_bytes.data(), random_bytes.size());
        }

        return password;
    }

}  // namespace crypto_handler
