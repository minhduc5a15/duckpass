#include "duckpass/vault.h"

#include <iostream>
#include <iterator>
#include <stdexcept>
#include <vector>
#include <algorithm>
#include <cstring>
#include <span>

#include "duckpass/crypto.h"
#include "duckpass/exceptions.h"

#include <unistd.h>
#include <fcntl.h>

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

    // --- Binary Serialization Module ---

    // Helper to append binary data into SecureBytes
    void write_uint32(duckpass::SecureBytes& buffer, uint32_t value) {
        uint8_t bytes[4];
        std::memcpy(bytes, &value, 4);
        buffer.insert(buffer.end(), bytes, bytes + 4);
    }

    void write_string(duckpass::SecureBytes& buffer, const duckpass::SecureString& str) {
        write_uint32(buffer, static_cast<uint32_t>(str.length()));
        buffer.insert(buffer.end(), str.begin(), str.end());
    }

    // Serializes vault data into a binary format without external libraries
    duckpass::SecureBytes Vault::serialize() const {
        duckpass::SecureBytes buffer;
        
        // Write entry count at the beginning (4 bytes)
        write_uint32(buffer, static_cast<uint32_t>(entries.size()));

        // Iterate through entries and push raw bytes into the buffer
        for (const auto& entry : entries) {
            write_string(buffer, entry.service);
            write_string(buffer, entry.username);
            write_string(buffer, entry.password);
        }
        return buffer; // Returns memory protected by secure_allocator
    }

    // Helper to read data from a byte span
    uint32_t read_uint32(std::span<const uint8_t>& bytes, size_t& offset) {
        if (offset + 4 > bytes.size()) throw std::runtime_error("Malformed vault data");
        uint32_t value;
        std::memcpy(&value, bytes.data() + offset, 4);
        offset += 4;
        return value;
    }

    duckpass::SecureString read_string(std::span<const uint8_t>& bytes, size_t& offset) {
        uint32_t length = read_uint32(bytes, offset);
        if (offset + length > bytes.size()) throw std::runtime_error("Malformed vault data");
        
        // Initialize a secure string directly from raw memory using span
        duckpass::SecureString str;
        str.reserve(length);
        const uint8_t* start = bytes.data() + offset;
        str.assign(reinterpret_cast<const char*>(start), length);
        
        offset += length;
        return str;
    }

    // Deserializes binary data back into a Vault object using C++20 span
    Vault Vault::deserialize(std::span<const uint8_t> bytes) {
        Vault vault;
        size_t offset = 0;
        if (bytes.empty()) return vault;

        uint32_t num_entries = read_uint32(bytes, offset);
        for (uint32_t i = 0; i < num_entries; ++i) {
            VaultEntry entry;
            entry.service = read_string(bytes, offset);
            entry.username = read_string(bytes, offset);
            entry.password = read_string(bytes, offset);
            vault.add_entry(std::move(entry));
        }
        return vault;
    }

    // --- Vault File Operations ---

    bool vault_exists(const std::filesystem::path &vault_path) {
        return std::filesystem::exists(vault_path);
    }

    Vault load_vault(const std::filesystem::path &vault_path, const SecureString &master_password) {
        // Use POSIX open instead of std::ifstream
        int fd = open(vault_path.c_str(), O_RDONLY);
        if (fd == -1) throw duckpass::vault_io_error(vault_path.string());

        // Get file size
        off_t size = lseek(fd, 0, SEEK_END);
        lseek(fd, 0, SEEK_SET);

        const size_t min_size = 3 * sizeof(uint32_t) + crypto_handler::SALT_BYTES + crypto_handler::IV_BYTES + crypto_handler::TAG_BYTES;
        if (size < static_cast<off_t>(min_size)) {
            close(fd);
            throw duckpass::vault_corrupted_error("File is too small.");
        }

        // Read KDF parameters, salt, and IV from the file descriptor
        crypto_handler::KdfParams kdf_params;
        read(fd, &kdf_params.time_cost, sizeof(uint32_t));
        read(fd, &kdf_params.memory_cost, sizeof(uint32_t));
        read(fd, &kdf_params.parallelism, sizeof(uint32_t));

        std::vector<unsigned char> salt(crypto_handler::SALT_BYTES);
        read(fd, salt.data(), crypto_handler::SALT_BYTES);

        std::vector<unsigned char> iv(crypto_handler::IV_BYTES);
        read(fd, iv.data(), crypto_handler::IV_BYTES);

        // Ciphertext size includes the tag at the end (for AES-GCM)
        std::vector<unsigned char> ciphertext(size - (3 * sizeof(uint32_t) + crypto_handler::SALT_BYTES + crypto_handler::IV_BYTES));
        read(fd, ciphertext.data(), ciphertext.size());
        close(fd);

        // Derive key and decrypt data
        crypto_handler::SecureBytes key = crypto_handler::derive_key_from_password(master_password, salt, kdf_params);
        crypto_handler::SecureBytes plaintext_bytes = crypto_handler::decrypt_data(ciphertext, key, iv);

        // Pass raw byte array into C++20 span to reconstruct the Vault object
        std::span<const uint8_t> data_span(reinterpret_cast<const uint8_t*>(plaintext_bytes.data()), plaintext_bytes.size());
        return Vault::deserialize(data_span);
    }

    void save_vault(const std::filesystem::path &vault_path, const Vault &vault, const SecureString &master_password) {
        // Serialize directly into SecureBytes (secure memory)
        duckpass::SecureBytes plaintext = vault.serialize();

        crypto_handler::KdfParams kdf_params = {
            crypto_handler::DEFAULT_TIME_COST,
            crypto_handler::DEFAULT_MEMORY_COST,
            crypto_handler::DEFAULT_PARALLELISM
        };
        std::vector<unsigned char> salt = crypto_handler::generate_random_bytes(crypto_handler::SALT_BYTES);
        std::vector<unsigned char> iv = crypto_handler::generate_random_bytes(crypto_handler::IV_BYTES);

        crypto_handler::SecureBytes key = crypto_handler::derive_key_from_password(master_password, salt, kdf_params);
        std::vector<unsigned char> ciphertext = crypto_handler::encrypt_data(plaintext, key, iv);

        std::filesystem::path tmp_path = vault_path;
        tmp_path.replace_extension(vault_path.extension().string() + ".tmp");

        // POSIX C: Manage File Descriptor from start to finish to prevent race conditions
        int fd = open(tmp_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd == -1) throw duckpass::vault_io_error(tmp_path.string());

        write(fd, &kdf_params.time_cost, sizeof(uint32_t));
        write(fd, &kdf_params.memory_cost, sizeof(uint32_t));
        write(fd, &kdf_params.parallelism, sizeof(uint32_t));
        write(fd, salt.data(), salt.size());
        write(fd, iv.data(), iv.size());
        write(fd, ciphertext.data(), ciphertext.size());

        // Force physical write to disk before closing
        fsync(fd);
        close(fd);

        try {
            std::filesystem::rename(tmp_path, vault_path);
        } catch (const std::filesystem::filesystem_error &e) {
            std::filesystem::remove(tmp_path);
            throw std::runtime_error("Failed to safely replace vault file.");
        }
    }
}  // namespace vault_handler
