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

namespace crypto_handler {

    /**
     * @brief RAII wrapper for OpenSSL's EVP_CIPHER_CTX.
     * Ensures the context is freed automatically on destruction.
     */
    using CipherContextPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

    std::vector<unsigned char> generate_random_bytes(const int num_bytes) {
        std::vector<unsigned char> buffer(num_bytes);
        if (RAND_bytes(buffer.data(), num_bytes) != 1) {
            ERR_clear_error();
            throw duckpass::crypto_error("Failed to generate random bytes.");
        }
        return buffer;
    }

    SecureBytes derive_key_from_password(const SecureString &password, std::span<const uint8_t> salt, const KdfParams &params) {
        SecureBytes key(KEY_BYTES);
        int result = argon2id_hash_raw(params.time_cost, params.memory_cost, params.parallelism, password.c_str(), password.length(), salt.data(),
                                       salt.size(), key.data(), key.size());

        if (result != ARGON2_OK) {
            throw duckpass::crypto_error("Failed to derive key from password (Argon2). Error: " + std::string(argon2_error_message(result)));
        }
        return key;
    }

    std::vector<unsigned char> encrypt_data(std::span<const uint8_t> plaintext, std::span<const uint8_t> key, std::span<const uint8_t> iv,
                                            std::span<const uint8_t> aad) {
        // Integer overflow protection for OpenSSL API (uses int for size)
        if (plaintext.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
            throw duckpass::crypto_error("Vault data size exceeds OpenSSL's encryption limit (2.1GB).");
        }

        CipherContextPtr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
        if (!ctx) {
            ERR_clear_error();
            throw duckpass::crypto_error("Failed to create cipher context.");
        }

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

        std::vector<unsigned char> ciphertext(plaintext.size());
        int len = 0;
        if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len, plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
            ERR_clear_error();
            throw duckpass::crypto_error("Failed during GCM encryption update.");
        }
        int ciphertext_len = len;

        if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + len, &len) != 1) {
            ERR_clear_error();
            throw duckpass::crypto_error("Failed during GCM encryption finalization.");
        }
        ciphertext_len += len;
        ciphertext.resize(ciphertext_len);

        std::vector<unsigned char> tag(TAG_BYTES);
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, TAG_BYTES, tag.data()) != 1) {
            ERR_clear_error();
            throw duckpass::crypto_error("Failed to get GCM authentication tag.");
        }

        // Append the tag to the ciphertext
        ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());
        return ciphertext;
    }

    SecureBytes decrypt_data(std::span<const uint8_t> encrypted_blob, std::span<const uint8_t> key, std::span<const uint8_t> iv,
                             std::span<const uint8_t> aad) {
        if (encrypted_blob.size() < TAG_BYTES) {
            throw duckpass::vault_corrupted_error("Encrypted data is too short.");
        }

        // Extract ciphertext and tag from the combined blob
        std::span<const uint8_t> ciphertext = encrypted_blob.subspan(0, encrypted_blob.size() - TAG_BYTES);
        std::span<const uint8_t> tag = encrypted_blob.subspan(encrypted_blob.size() - TAG_BYTES, TAG_BYTES);

        CipherContextPtr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
        if (!ctx) {
            ERR_clear_error();
            throw duckpass::crypto_error("Failed to create cipher context.");
        }

        if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, key.data(), iv.data()) != 1) {
            ERR_clear_error();
            throw duckpass::crypto_error("Failed to initialize GCM decryption.");
        }

        // Set the expected authentication tag. This is crucial for verification.
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, TAG_BYTES, const_cast<uint8_t *>(tag.data())) != 1) {
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
}  // namespace crypto_handler
