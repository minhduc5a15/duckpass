#include "duckpass/vault.h"

#include <algorithm>
#include <cerrno>
#include <concepts>
#include <cstring>
#include <iostream>
#include <iterator>
#include <span>
#include <stdexcept>
#include <vector>

#include "duckpass/crypto.h"
#include "duckpass/exceptions.h"
#include "duckpass/local_storage.h"

namespace vault_handler {

    // --- Endian-Aware Binary Serialization Helpers (Little-Endian) ---

    /**
     * @brief Writes a uint32_t to the buffer in Little-Endian format.
     */
    void write_uint32(duckpass::SecureBytes& buffer, uint32_t value) {
        buffer.push_back(static_cast<uint8_t>(value & 0xFF));
        buffer.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
        buffer.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
        buffer.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
    }

    /**
     * @brief Writes a string to the buffer: [length (4 bytes, LE)] + [raw data].
     */
    void write_string(duckpass::SecureBytes& buffer, const duckpass::SecureString& str) {
        write_uint32(buffer, static_cast<uint32_t>(str.length()));
        buffer.insert(buffer.end(), str.begin(), str.end());
    }

    /**
     * @brief Reads a uint32_t from a span in Little-Endian format.
     */
    uint32_t read_uint32(std::span<const uint8_t> bytes, size_t& offset) {
        if (offset + 4 > bytes.size()) throw std::runtime_error("Malformed vault data");
        uint32_t value = 0;
        value |= static_cast<uint32_t>(bytes[offset]);
        value |= static_cast<uint32_t>(bytes[offset + 1]) << 8;
        value |= static_cast<uint32_t>(bytes[offset + 2]) << 16;
        value |= static_cast<uint32_t>(bytes[offset + 3]) << 24;
        offset += 4;
        return value;
    }

    /**
     * @brief Reads a string from a span.
     */
    duckpass::SecureString read_string(std::span<const uint8_t> bytes, size_t& offset) {
        uint32_t length = read_uint32(bytes, offset);
        if (offset + length > bytes.size()) throw std::runtime_error("Malformed vault data");

        duckpass::SecureString str;
        str.reserve(length);
        const uint8_t* start = bytes.data() + offset;
        str.assign(reinterpret_cast<const char*>(start), length);

        offset += length;
        return str;
    }

    // --- Vault Class Implementation ---

    void Vault::add_entry(VaultEntry entry) {
        auto it = std::ranges::find_if(entries, [&](const VaultEntry& e) { return e.service == entry.service; });

        if (it != entries.end()) {
            *it = std::move(entry);
        } else {
            entries.push_back(std::move(entry));
        }
    }

    bool Vault::remove_entry(const SecureString& service) {
        auto it = std::ranges::remove_if(entries, [&](const VaultEntry& e) { return e.service == service; }).begin();

        if (it != entries.end()) {
            entries.erase(it, entries.end());
            return true;
        }
        return false;
    }

    std::optional<VaultEntry> Vault::get_entry(const SecureString& service) const {
        auto it = std::ranges::find_if(entries, [&](const VaultEntry& e) { return e.service == service; });

        if (it != entries.end()) {
            return *it;
        }
        return std::nullopt;
    }

    // Serializes vault entries into a binary format
    duckpass::SecureBytes Vault::serialize() const {
        duckpass::SecureBytes buffer;
        write_uint32(buffer, static_cast<uint32_t>(entries.size()));

        for (const auto& entry : entries) {
            write_string(buffer, entry.service);
            write_string(buffer, entry.username);
            write_string(buffer, entry.password);
        }
        return buffer;
    }

    // Deserializes binary data back into a Vault object
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

    // --- Vault Orchestration (Crypto + Storage) ---

    bool vault_exists(const std::filesystem::path& vault_path) { return std::filesystem::exists(vault_path); }

    Vault load_vault(const std::filesystem::path& vault_path, const SecureString& master_password) {
        // 1. Read the entire blob using the storage layer
        duckpass::SecureBytes full_blob = duckpass::storage::read_file(vault_path);

        // Header (8 bytes: MAGIC + VERSION) + KDF (12 bytes) + Salt (16) + IV (12) + Tag (16)
        const size_t min_header_size = 8 + 3 * sizeof(uint32_t) + crypto_handler::SALT_BYTES + crypto_handler::IV_BYTES;
        if (full_blob.size() < min_header_size + crypto_handler::TAG_BYTES) {
            throw duckpass::vault_corrupted_error("Vault file is truncated.");
        }

        std::span<const uint8_t> bytes(full_blob.data(), full_blob.size());
        size_t offset = 0;

        // 2. Check Magic Bytes and Version
        if (bytes[offset] != 'D' || bytes[offset + 1] != 'U' || bytes[offset + 2] != 'C' || bytes[offset + 3] != 'K') {
            throw duckpass::vault_corrupted_error("Invalid file format: Not a DuckPass vault.");
        }
        offset += 4;

        uint32_t version = read_uint32(bytes, offset);
        if (version != 1) {
            throw duckpass::vault_corrupted_error("Unsupported vault version: " + std::to_string(version));
        }

        // 3. Parse KDF parameters, Salt, and IV
        crypto_handler::KdfParams kdf_params;
        kdf_params.time_cost = read_uint32(bytes, offset);
        kdf_params.memory_cost = read_uint32(bytes, offset);
        kdf_params.parallelism = read_uint32(bytes, offset);

        const uint32_t MAX_MEMORY_COST = 1024 * 1024;
        const uint32_t MAX_TIME_COST = 100;
        const uint32_t MAX_PARALLELISM = 64;

        if (kdf_params.memory_cost > MAX_MEMORY_COST || kdf_params.time_cost > MAX_TIME_COST || kdf_params.parallelism > MAX_PARALLELISM) {
            throw duckpass::vault_corrupted_error("KDF parameters exceed safe limits. File may have been tampered with to cause DoS.");
        }

        if (kdf_params.memory_cost > MAX_MEMORY_COST || kdf_params.time_cost > MAX_TIME_COST) {
            throw duckpass::vault_corrupted_error("KDF parameters exceed safe hardware limits. File may be tampered.");
        }

        std::vector<uint8_t> salt(bytes.data() + offset, bytes.data() + offset + crypto_handler::SALT_BYTES);
        offset += crypto_handler::SALT_BYTES;

        std::vector<uint8_t> iv(bytes.data() + offset, bytes.data() + offset + crypto_handler::IV_BYTES);
        offset += crypto_handler::IV_BYTES;

        // 4. Extract Ciphertext (including Tag)
        std::span<const uint8_t> ciphertext = bytes.subspan(offset);

        // 5. Decrypt and Deserialize
        crypto_handler::SecureBytes key = crypto_handler::derive_key_from_password(master_password, salt, kdf_params);
        crypto_handler::SecureBytes plaintext_bytes = crypto_handler::decrypt_data(ciphertext, key, iv);

        return Vault::deserialize(plaintext_bytes);
    }

    void save_vault(const std::filesystem::path& vault_path, const Vault& vault, const SecureString& master_password) {
        // 1. Serialize entries
        duckpass::SecureBytes plaintext = vault.serialize();

        // 2. Prepare Crypto
        crypto_handler::KdfParams kdf_params = {crypto_handler::DEFAULT_TIME_COST, crypto_handler::DEFAULT_MEMORY_COST,
                                                crypto_handler::DEFAULT_PARALLELISM};
        std::vector<uint8_t> salt = crypto_handler::generate_random_bytes(crypto_handler::SALT_BYTES);
        std::vector<uint8_t> iv = crypto_handler::generate_random_bytes(crypto_handler::IV_BYTES);

        crypto_handler::SecureBytes key = crypto_handler::derive_key_from_password(master_password, salt, kdf_params);
        std::vector<uint8_t> ciphertext = crypto_handler::encrypt_data(plaintext, key, iv);

        // 3. Package the full blob [MAGIC][VERSION][KDF_PARAMS][SALT][IV][CIPHERTEXT+TAG]
        duckpass::SecureBytes full_package;
        full_package.reserve(8 + 3 * sizeof(uint32_t) + salt.size() + iv.size() + ciphertext.size());

        // Magic Bytes "DUCK"
        full_package.push_back('D');
        full_package.push_back('U');
        full_package.push_back('C');
        full_package.push_back('K');

        // Version 1
        write_uint32(full_package, 1);

        // KDF Params
        write_uint32(full_package, kdf_params.time_cost);
        write_uint32(full_package, kdf_params.memory_cost);
        write_uint32(full_package, kdf_params.parallelism);

        // Salt and IV
        full_package.insert(full_package.end(), salt.begin(), salt.end());
        full_package.insert(full_package.end(), iv.begin(), iv.end());

        // Ciphertext (includes authentication tag)
        full_package.insert(full_package.end(), ciphertext.begin(), ciphertext.end());

        // 4. Delegate disk I/O to storage layer
        duckpass::storage::write_file_atomic(vault_path, full_package);
    }
}  // namespace vault_handler
