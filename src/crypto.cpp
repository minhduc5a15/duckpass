#include "duckpass/crypto.h"
#include <stdexcept>
#include <vector>

// OpenSSL for AES-GCM
#include <openssl/evp.h>
#include <openssl/rand.h>

// Argon2 for key derivation
#include <argon2.h>

namespace crypto_handler {
    std::vector<unsigned char> generate_random_bytes(const int num_bytes) {
        std::vector<unsigned char> buffer(num_bytes);
        if (RAND_bytes(buffer.data(), num_bytes) != 1) {
            throw std::runtime_error("Failed to generate random bytes.");
        }
        return buffer;
    }

    std::vector<unsigned char> derive_key_from_password(const std::string &password, const std::vector<unsigned char> &salt) {
        std::vector<unsigned char> key(KEY_BYTES);
        int result = argon2id_hash_raw(
            ARGON2_TIME_COST,
            ARGON2_MEMORY_COST,
            ARGON2_PARALLELISM,
            password.c_str(),
            password.length(),
            salt.data(),
            salt.size(),
            key.data(),
            key.size()
        );

        if (result != ARGON2_OK) {
            throw std::runtime_error("Failed to derive key from password (Argon2). Error: " + std::string(argon2_error_message(result)));
        }
        return key;
    }

    std::vector<unsigned char> encrypt_data(const std::string &plaintext, const std::vector<unsigned char> &key, const std::vector<unsigned char> &iv) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("Failed to create cipher context.");

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize GCM encryption.");
        }

        std::vector<unsigned char> ciphertext(plaintext.length());
        int len = 0;
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char *>(plaintext.c_str()), plaintext.length()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed during GCM encryption update.");
        }
        int ciphertext_len = len;

        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed during GCM encryption finalization.");
        }
        ciphertext_len += len;
        ciphertext.resize(ciphertext_len);

        std::vector<unsigned char> tag(TAG_BYTES);
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_BYTES, tag.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to get GCM authentication tag.");
        }

        EVP_CIPHER_CTX_free(ctx);

        // Append the tag to the ciphertext
        ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());
        return ciphertext;
    }

    std::string decrypt_data(const std::vector<unsigned char> &encrypted_blob, const std::vector<unsigned char> &key, const std::vector<unsigned char> &iv) {
        if (encrypted_blob.size() < TAG_BYTES) {
            throw std::runtime_error("Invalid encrypted data: too short to contain a tag.");
        }

        // Extract ciphertext and tag from the combined blob
        std::vector<unsigned char> ciphertext(encrypted_blob.begin(), encrypted_blob.end() - TAG_BYTES);
        std::vector<unsigned char> tag(encrypted_blob.end() - TAG_BYTES, encrypted_blob.end());

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("Failed to create cipher context.");

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize GCM decryption.");
        }

        // Set the expected authentication tag. This is crucial for verification.
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_BYTES, tag.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to set GCM authentication tag.");
        }

        std::vector<unsigned char> plaintext(ciphertext.size());
        int len = 0;
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed during GCM decryption update. Data may be corrupted.");
        }
        int plaintext_len = len;

        // The final check happens here. If the tag is invalid, this call will fail.
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("GCM authentication failed. Data is corrupted or password is wrong.");
        }
        plaintext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        return std::string(plaintext.begin(), plaintext.begin() + plaintext_len);
    }
} // namespace crypto_handler
