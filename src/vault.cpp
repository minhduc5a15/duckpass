#include "duckpass/vault.h"

#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <vector>
#include <algorithm>

#include "duckpass/crypto.h"
#include "duckpass/exceptions.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <fcntl.h>
#endif

namespace vault_handler {

    // --- Vault Class Implementation ---

    void Vault::add_entry(VaultEntry entry) {
        // If entry with same service exists, replace it
        auto it = std::ranges::find_if(entries, [&](const VaultEntry& e) {
            return e.service == entry.service;
        });

        if (it != entries.end()) {
            *it = std::move(entry);
        } else {
            entries.push_back(std::move(entry));
        }
    }

    bool Vault::remove_entry(const SecureString& service) {
        auto it = std::ranges::remove_if(entries, [&](const VaultEntry &e) { return e.service == service; }).begin();

        if (it != entries.end()) {
            entries.erase(it, entries.end());
            return true;
        }
        return false;
    }

    std::optional<VaultEntry> Vault::get_entry(const SecureString& service) const {
        auto it = std::ranges::find_if(entries, [&](const VaultEntry& e) {
            return e.service == service;
        });

        if (it != entries.end()) {
            return *it;
        }
        return std::nullopt;
    }

    SecureJson Vault::to_json() const {
        SecureJson json = SecureJson::array();
        for (const auto& entry : entries) {
            SecureJson item;
            item["service"] = std::string(entry.service.begin(), entry.service.end());
            item["username"] = std::string(entry.username.begin(), entry.username.end());
            
            // Binary Hack: Store password as binary to ensure secure_allocator manages the memory
            duckpass::SecureBytes pwd_bytes(entry.password.begin(), entry.password.end());
            item["password"] = SecureJson::binary(pwd_bytes);
            
            json.push_back(std::move(item));
        }
        return json;
    }

    Vault Vault::from_json(const SecureJson& json) {
        Vault vault;
        if (!json.is_array()) return vault;

        for (const auto& item : json) {
            VaultEntry entry;
            if (item.contains("service") && item["service"].is_string()) {
                std::string s = item["service"];
                entry.service = SecureString(s.begin(), s.end());
            }
            if (item.contains("username") && item["username"].is_string()) {
                std::string u = item["username"];
                entry.username = SecureString(u.begin(), u.end());
            }
            if (item.contains("password")) {
                if (item["password"].is_binary()) {
                    auto bin = item["password"].get_binary();
                    entry.password = SecureString(bin.begin(), bin.end());
                } else if (item["password"].is_string()) {
                    // Fallback for older versions or exports
                    std::string p = item["password"];
                    entry.password = SecureString(p.begin(), p.end());
                }
            }
            vault.add_entry(std::move(entry));
        }
        return vault;
    }

    // --- Vault File Operations ---

    bool vault_exists(const std::filesystem::path &vault_path) {
        const std::ifstream file(vault_path);
        return file.good();
    }

    Vault load_vault(const std::filesystem::path &vault_path, const SecureString &master_password) {
        // 1. Open file in binary mode
        std::ifstream file(vault_path, std::ios::binary);
        if (!file) {
            throw duckpass::vault_io_error(vault_path.string());
        }

        // Get file size
        file.seekg(0, std::ios::end);
        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        const size_t min_size = 3 * sizeof(uint32_t) + crypto_handler::SALT_BYTES + crypto_handler::IV_BYTES + crypto_handler::TAG_BYTES;
        if (size < static_cast<std::streamsize>(min_size)) {
            throw duckpass::vault_corrupted_error("File is too small to be a valid vault.");
        }

        // 2. Read KDF parameters, salt, iv, and ciphertext
        crypto_handler::KdfParams kdf_params;
        file.read(reinterpret_cast<char *>(&kdf_params.time_cost), sizeof(uint32_t));
        file.read(reinterpret_cast<char *>(&kdf_params.memory_cost), sizeof(uint32_t));
        file.read(reinterpret_cast<char *>(&kdf_params.parallelism), sizeof(uint32_t));

        std::vector<unsigned char> salt(crypto_handler::SALT_BYTES);
        file.read(reinterpret_cast<char *>(salt.data()), crypto_handler::SALT_BYTES);

        std::vector<unsigned char> iv(crypto_handler::IV_BYTES);
        file.read(reinterpret_cast<char *>(iv.data()), crypto_handler::IV_BYTES);

        // Read the rest of the file into ciphertext
        std::vector<unsigned char> ciphertext((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();

        // 3. Derive key and decrypt
        crypto_handler::SecureBytes key = crypto_handler::derive_key_from_password(master_password, salt, kdf_params);
        crypto_handler::SecureBytes plaintext_bytes = crypto_handler::decrypt_data(ciphertext, key, iv);

        // 4. Parse binary MessagePack to JSON
        SecureJson json = duckpass::SecureJson::from_msgpack(plaintext_bytes.begin(), plaintext_bytes.end());
        
        // 5. Convert JSON to Vault Object
        return Vault::from_json(json);
    }

    void save_vault(const std::filesystem::path &vault_path, const Vault &vault, const SecureString &master_password) {
        // Convert Vault Object back to SecureJson
        SecureJson vault_data = vault.to_json();

        // Serialize JSON data to MessagePack (binary) directly into SecureBytes.
        crypto_handler::SecureBytes msgpack;
        duckpass::SecureJson::to_msgpack(vault_data, msgpack);

        // 1. Prepare KDF parameters, salt, and IV
        crypto_handler::KdfParams kdf_params = {
            crypto_handler::DEFAULT_TIME_COST,
            crypto_handler::DEFAULT_MEMORY_COST,
            crypto_handler::DEFAULT_PARALLELISM
        };
        std::vector<unsigned char> salt = crypto_handler::generate_random_bytes(crypto_handler::SALT_BYTES);
        std::vector<unsigned char> iv = crypto_handler::generate_random_bytes(crypto_handler::IV_BYTES);

        std::filesystem::path tmp_path = vault_path;
        tmp_path.replace_extension(vault_path.extension().string() + ".tmp");

        // 2. Derive key and encrypt
        crypto_handler::SecureBytes key = crypto_handler::derive_key_from_password(master_password, salt, kdf_params);
        std::vector<unsigned char> ciphertext = crypto_handler::encrypt_data(msgpack, key, iv);

        {
            std::ofstream file(tmp_path, std::ios::binary | std::ios::trunc);
            if (!file) {
                throw duckpass::vault_io_error(tmp_path.string());
            }

            // Write Header: KDF Params -> Salt -> IV -> Ciphertext
            file.write(reinterpret_cast<const char *>(&kdf_params.time_cost), sizeof(uint32_t));
            file.write(reinterpret_cast<const char *>(&kdf_params.memory_cost), sizeof(uint32_t));
            file.write(reinterpret_cast<const char *>(&kdf_params.parallelism), sizeof(uint32_t));
            file.write(reinterpret_cast<const char *>(salt.data()), static_cast<long>(salt.size()));
            file.write(reinterpret_cast<const char *>(iv.data()), static_cast<long>(iv.size()));
            file.write(reinterpret_cast<const char *>(ciphertext.data()), static_cast<long>(ciphertext.size()));
            file.flush();

            // Crucial: Use fsync to ensure data is physically written to disk before renaming.
            // This prevents data loss or corruption in case of power failure.
#ifdef _WIN32
            // On Windows, use FlushFileBuffers. 
            // Note: std::ofstream doesn't provide easy access to the native handle.
            // For simplicity in this cross-platform implementation, we close and use WinAPI if needed, 
            // but closing the file often triggers a partial flush.
            // A truly robust Windows version would use CreateFile and FlushFileBuffers.
#else
            // On Unix-like systems, get the file descriptor and call fsync.
            // Unfortunately, std::ofstream doesn't have a standard way to get fd.
            // We'll close the file first to ensure standard library buffers are flushed.
#endif
        }

#ifndef _WIN32
        // Truly durable way: open the file again just to fsync or use lower-level I/O.
        // For portability and maximum safety, we ensure the OS-level sync is triggered.
        int fd = open(tmp_path.c_str(), O_RDWR);
        if (fd != -1) {
            fsync(fd);
            close(fd);
        }
#endif

        try {
            std::filesystem::rename(tmp_path, vault_path);
        } catch (const std::filesystem::filesystem_error &e) {
            std::filesystem::remove(tmp_path);  // Clean up temp file if rename fails
            throw std::runtime_error("Error: Failed to safely replace the vault file: " + std::string(e.what()));
        }
    }
}  // namespace vault_handler
