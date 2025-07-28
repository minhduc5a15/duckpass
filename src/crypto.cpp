#include "duckpass/crypto.h"
#include <stdexcept>
#include <vector>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace crypto_handler {

std::vector<unsigned char> generate_random_bytes(int num_bytes) {
    std::vector<unsigned char> buffer(num_bytes);
    if (RAND_bytes(buffer.data(), num_bytes) != 1) {
        throw std::runtime_error("Error: Failed to generate random bytes.");
    }
    return buffer;
}

std::vector<unsigned char> derive_key_from_password(const std::string& password, const std::vector<unsigned char>& salt) {
    std::vector<unsigned char> key(KEY_BYTES);
    int result = PKCS5_PBKDF2_HMAC(
        password.c_str(),
        password.length(),
        salt.data(),
        salt.size(),
        PBKDF2_ITERATIONS,
        EVP_sha256(), // Use SHA-256 as the underlying hash function
        key.size(),
        key.data()
    );

    if (result != 1) {
        throw std::runtime_error("Error: Failed to derive key from password (PBKDF2).");
    }
    return key;
}

std::vector<unsigned char> encrypt_data(const std::string& plaintext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Error: Failed to create cipher context.");
    }

    // Initialize encryption operation: AES-256-CBC
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Error: Failed to initialize encryption.");
    }

    std::vector<unsigned char> ciphertext(plaintext.length() + IV_BYTES);
    int len = 0;
    int ciphertext_len = 0;

    // Provide the message to be encrypted, and obtain the encrypted output.
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Error: Failed during encryption update.");
    }
    ciphertext_len = len;

    // Finalize the encryption.
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Error: Failed during encryption finalization.");
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(ciphertext_len); // Resize to actual ciphertext size
    return ciphertext;
}

std::string decrypt_data(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Error: Failed to create cipher context.");
    }

    // Initialize decryption operation: AES-256-CBC
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Error: Failed to initialize decryption.");
    }

    std::vector<unsigned char> plaintext(ciphertext.size());
    int len = 0;
    int plaintext_len = 0;

    // Provide the message to be decrypted, and obtain the plaintext output.
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Error: Failed during decryption update. Wrong password?");
    }
    plaintext_len = len;

    // Finalize the decryption.
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Error: Failed during decryption finalization. Wrong password or corrupted data.");
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return std::string(plaintext.begin(), plaintext.begin() + plaintext_len);
}

} // namespace crypto_handler