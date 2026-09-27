#include "duckpass/crypto.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "duckpass/exceptions.h"

TEST(CryptoTest, GenerateRandomBytesReturnsRequestedLength) {
    auto b1 = crypto_handler::generate_random_bytes(16);
    EXPECT_EQ(b1.size(), 16);

    auto b2 = crypto_handler::generate_random_bytes(32);
    EXPECT_EQ(b2.size(), 32);

    // Two independent random calls should produce distinct bytes
    EXPECT_NE(b1, crypto_handler::generate_random_bytes(16));
}

TEST(CryptoTest, Argon2KeyDerivationIsDeterministic) {
    duckpass::SecureString password("StrongMasterPassword123!");
    auto salt = crypto_handler::generate_random_bytes(crypto_handler::SALT_BYTES);

    crypto_handler::KdfParams params{1, 8192, 1};  // Lower cost for fast unit test
    auto key1 = crypto_handler::derive_key_from_password(password, salt, params);
    auto key2 = crypto_handler::derive_key_from_password(password, salt, params);

    EXPECT_EQ(key1.size(), crypto_handler::KEY_BYTES);
    EXPECT_EQ(key1, key2);

    duckpass::SecureString wrong_password("DifferentPassword456!");
    auto key_diff = crypto_handler::derive_key_from_password(wrong_password, salt, params);
    EXPECT_NE(key1, key_diff);
}

TEST(CryptoTest, AesGcmEncryptDecryptRoundTrip) {
    std::string secret = "MySuperSecretDataToEncrypt";
    std::vector<uint8_t> plaintext(secret.begin(), secret.end());

    auto key = crypto_handler::generate_random_bytes(crypto_handler::KEY_BYTES);
    auto iv = crypto_handler::generate_random_bytes(crypto_handler::IV_BYTES);
    std::vector<uint8_t> aad = {'D', 'U', 'C', 'K', 2, 0, 0, 0};

    auto encrypted = crypto_handler::encrypt_data(plaintext, key, iv, aad);
    EXPECT_EQ(encrypted.size(), plaintext.size() + crypto_handler::TAG_BYTES);

    auto decrypted = crypto_handler::decrypt_data(encrypted, key, iv, aad);
    std::string decrypted_str(decrypted.begin(), decrypted.end());
    EXPECT_EQ(secret, decrypted_str);
}

TEST(CryptoTest, AesGcmTamperedCiphertextFails) {
    std::string secret = "SensitiveData";
    std::vector<uint8_t> plaintext(secret.begin(), secret.end());
    auto key = crypto_handler::generate_random_bytes(crypto_handler::KEY_BYTES);
    auto iv = crypto_handler::generate_random_bytes(crypto_handler::IV_BYTES);
    std::vector<uint8_t> aad = {'D', 'U', 'C', 'K'};

    auto encrypted = crypto_handler::encrypt_data(plaintext, key, iv, aad);

    // Tamper with one byte in the ciphertext payload
    encrypted[0] ^= 0x55;

    EXPECT_THROW({ crypto_handler::decrypt_data(encrypted, key, iv, aad); }, duckpass::wrong_password_error);
}

TEST(CryptoTest, AesGcmTamperedAadFails) {
    std::string secret = "SensitiveData";
    std::vector<uint8_t> plaintext(secret.begin(), secret.end());
    auto key = crypto_handler::generate_random_bytes(crypto_handler::KEY_BYTES);
    auto iv = crypto_handler::generate_random_bytes(crypto_handler::IV_BYTES);
    std::vector<uint8_t> aad = {'D', 'U', 'C', 'K'};

    auto encrypted = crypto_handler::encrypt_data(plaintext, key, iv, aad);

    std::vector<uint8_t> tampered_aad = {'D', 'U', 'C', 'X'};

    EXPECT_THROW({ crypto_handler::decrypt_data(encrypted, key, iv, tampered_aad); }, duckpass::wrong_password_error);
}

TEST(CryptoTest, AesGcmWrongKeyFails) {
    std::string secret = "SensitiveData";
    std::vector<uint8_t> plaintext(secret.begin(), secret.end());
    auto key1 = crypto_handler::generate_random_bytes(crypto_handler::KEY_BYTES);
    auto key2 = crypto_handler::generate_random_bytes(crypto_handler::KEY_BYTES);
    auto iv = crypto_handler::generate_random_bytes(crypto_handler::IV_BYTES);

    auto encrypted = crypto_handler::encrypt_data(plaintext, key1, iv);

    EXPECT_THROW({ crypto_handler::decrypt_data(encrypted, key2, iv); }, duckpass::wrong_password_error);
}

TEST(CryptoTest, AesGcmTooShortBlobThrowsCorrupted) {
    auto key = crypto_handler::generate_random_bytes(crypto_handler::KEY_BYTES);
    auto iv = crypto_handler::generate_random_bytes(crypto_handler::IV_BYTES);
    std::vector<uint8_t> short_blob(crypto_handler::TAG_BYTES - 1, 0xAA);

    EXPECT_THROW({ crypto_handler::decrypt_data(short_blob, key, iv); }, duckpass::vault_corrupted_error);
}

TEST(CryptoTest, Sha1AndSha256KnownVectors) {
    duckpass::SecureString password("password123");

    auto sha1 = crypto_handler::compute_sha1(password);
    EXPECT_EQ(sha1, duckpass::SecureString("CBFDAC6008F9CAB4083784CBD1874F76618D2A97"));

    auto sha256 = crypto_handler::compute_sha256(password);
    EXPECT_EQ(sha256, duckpass::SecureString("ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f"));
}

TEST(CryptoTest, GeneratePasswordRespectsLengthAndCharset) {
    constexpr std::string_view valid_chars =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "!@#$%^&*()-_=+[]{}|;:',.<>?/";

    auto pwd16 = crypto_handler::generate_password(16);
    EXPECT_EQ(pwd16.size(), 16);

    auto pwd64 = crypto_handler::generate_password(64);
    EXPECT_EQ(pwd64.size(), 64);

    for (char c : pwd64) {
        EXPECT_NE(valid_chars.find(c), std::string_view::npos);
    }

    EXPECT_THROW({ crypto_handler::generate_password(0); }, std::invalid_argument);

    EXPECT_THROW({ crypto_handler::generate_password(-5); }, std::invalid_argument);
}
