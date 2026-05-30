#include "duckpass/vault.h"

#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <vector>

#include "duckpass/crypto.h"
#include "duckpass/exceptions.h"

namespace vault_handler {
    bool vault_exists(const std::filesystem::path &vault_path) {
        const std::ifstream file(vault_path);
        return file.good();
    }

    duckpass::SecureJson load_vault(const std::filesystem::path &vault_path, const SecureString &master_password) {
        // 1. Open file in binary mode
        std::ifstream file(vault_path, std::ios::binary);
        if (!file) {
            throw duckpass::vault_io_error(vault_path.string());
        }

        // Get file size
        file.seekg(0, std::ios::end);
        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        if (size < static_cast<std::streamsize>(crypto_handler::SALT_BYTES + crypto_handler::IV_BYTES + crypto_handler::TAG_BYTES)) {
            throw duckpass::vault_corrupted_error("File is too small to be a valid vault.");
        }

        // 2. Read salt, iv, and ciphertext
        std::vector<unsigned char> salt(crypto_handler::SALT_BYTES);
        file.read(reinterpret_cast<char *>(salt.data()), crypto_handler::SALT_BYTES);

        std::vector<unsigned char> iv(crypto_handler::IV_BYTES);
        file.read(reinterpret_cast<char *>(iv.data()), crypto_handler::IV_BYTES);

        // Read the rest of the file into ciphertext
        std::vector<unsigned char> ciphertext((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();

        // 3. Derive key and decrypt
        crypto_handler::SecureBytes key = crypto_handler::derive_key_from_password(master_password, salt);
        crypto_handler::SecureBytes plaintext_bytes = crypto_handler::decrypt_data(ciphertext, key, iv);

        // 4. Parse binary MessagePack to JSON
        return duckpass::SecureJson::from_msgpack(plaintext_bytes.begin(), plaintext_bytes.end());
    }

    void save_vault(const std::filesystem::path &vault_path, const duckpass::SecureJson &vault_data, const SecureString &master_password) {
        // Serialize JSON data to MessagePack (binary) directly into SecureBytes.
        // This ensures that any reallocations during serialization are wiped by our secure_allocator.
        crypto_handler::SecureBytes msgpack;
        duckpass::SecureJson::to_msgpack(vault_data, msgpack);

        // Generate a new salt and IV for this save operation
        std::vector<unsigned char> salt = crypto_handler::generate_random_bytes(crypto_handler::SALT_BYTES);
        std::vector<unsigned char> iv = crypto_handler::generate_random_bytes(crypto_handler::IV_BYTES);

        std::filesystem::path tmp_path = vault_path;
        tmp_path.replace_extension(vault_path.extension().string() + ".tmp");

        // Derive key and encrypt
        crypto_handler::SecureBytes key = crypto_handler::derive_key_from_password(master_password, salt);
        std::vector<unsigned char> ciphertext = crypto_handler::encrypt_data(msgpack, key, iv);

        {
            std::ofstream file(tmp_path, std::ios::binary | std::ios::trunc);
            if (!file) {
                throw duckpass::vault_io_error(tmp_path.string());
            }

            file.write(reinterpret_cast<const char *>(salt.data()), static_cast<long>(salt.size()));
            file.write(reinterpret_cast<const char *>(iv.data()), static_cast<long>(iv.size()));
            file.write(reinterpret_cast<const char *>(ciphertext.data()), static_cast<long>(ciphertext.size()));
            file.flush();
        }

        try {
            std::filesystem::rename(tmp_path, vault_path);
        } catch (const std::filesystem::filesystem_error &e) {
            std::filesystem::remove(tmp_path);  // Clean up temp file if rename fails
            throw std::runtime_error("Error: Failed to safely replace the vault file: " + std::string(e.what()));
        }
    }
}  // namespace vault_handler
