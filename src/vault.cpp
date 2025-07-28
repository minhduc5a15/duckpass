#include "duckpass/vault.h"
#include "duckpass/crypto.h"
#include <fstream>
#include <vector>
#include <iterator>
#include <stdexcept>

namespace vault_handler {
    bool vault_exists(const std::filesystem::path &vault_path) {
        std::ifstream file(vault_path);
        return file.good();
    }

    nlohmann::json load_vault(const std::filesystem::path &vault_path, const std::string &master_password) {
        // 1. Open file in binary mode
        std::ifstream file(vault_path, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Error: Could not open vault file.");
        }

        // 2. Read salt, iv, and ciphertext
        std::vector<unsigned char> salt(crypto_handler::SALT_BYTES);
        file.read(reinterpret_cast<char *>(salt.data()), crypto_handler::SALT_BYTES);

        std::vector<unsigned char> iv(crypto_handler::IV_BYTES);
        file.read(reinterpret_cast<char *>(iv.data()), crypto_handler::IV_BYTES);

        // Read the rest of the file into ciphertext
        std::vector<unsigned char> ciphertext(
            (std::istreambuf_iterator<char>(file)),
            std::istreambuf_iterator<char>()
        );
        file.close();

        // 3. Derive key and decrypt
        std::vector<unsigned char> key = crypto_handler::derive_key_from_password(master_password, salt);
        std::string plaintext = crypto_handler::decrypt_data(ciphertext, key, iv);

        // 4. Parse plaintext to JSON
        return nlohmann::json::parse(plaintext);
    }

    void save_vault(const std::filesystem::path &vault_path, const nlohmann::json &vault_data, const std::string &master_password) {
        // 1. Serialize JSON data to string
        std::string plaintext = vault_data.dump();

        // 2. Generate a new salt and IV for this save operation
        std::vector<unsigned char> salt = crypto_handler::generate_random_bytes(crypto_handler::SALT_BYTES);
        std::vector<unsigned char> iv = crypto_handler::generate_random_bytes(crypto_handler::IV_BYTES);

        // 3. Derive key and encrypt
        std::vector<unsigned char> key = crypto_handler::derive_key_from_password(master_password, salt);
        std::vector<unsigned char> ciphertext = crypto_handler::encrypt_data(plaintext, key, iv);

        // 4. Write salt, iv, and ciphertext to file
        std::ofstream file(vault_path, std::ios::binary | std::ios::trunc);
        if (!file) {
            throw std::runtime_error("Error: Could not open vault file for writing.");
        }

        file.write(reinterpret_cast<const char *>(salt.data()), salt.size());
        file.write(reinterpret_cast<const char *>(iv.data()), iv.size());
        file.write(reinterpret_cast<const char *>(ciphertext.data()), ciphertext.size());
        file.close();
    }
} // namespace vault_handler
