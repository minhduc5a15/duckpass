#include "duckpass/vault.h"

#include <algorithm>
#include <cerrno>
#include <concepts>
#include <ctime>
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
     * @brief Writes a uint64_t to the buffer in Little-Endian format.
     */
    void write_uint64(duckpass::SecureBytes& buffer, uint64_t value) {
        for (int i = 0; i < 8; ++i) {
            buffer.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
        }
    }

    /**
     * @brief Writes a string to the buffer: [length (4 bytes, LE)] + [raw data].
     *
     * This helper ensures that strings are stored with their length prefixed,
     * allowing for safe deserialization of arbitrary binary data or strings.
     */
    void write_string(duckpass::SecureBytes& buffer, const duckpass::SecureString& str) {
        write_uint32(buffer, static_cast<uint32_t>(str.length()));
        buffer.insert(buffer.end(), str.begin(), str.end());
    }

    /**
     * @brief Reads a uint32_t from a span in Little-Endian format.
     */
    uint32_t read_uint32(std::span<const uint8_t> bytes, size_t& offset) {
        if (offset + 4 > bytes.size()) throw std::runtime_error("Malformed vault data: uint32 overflow");
        uint32_t value = 0;
        value |= static_cast<uint32_t>(bytes[offset]);
        value |= static_cast<uint32_t>(bytes[offset + 1]) << 8;
        value |= static_cast<uint32_t>(bytes[offset + 2]) << 16;
        value |= static_cast<uint32_t>(bytes[offset + 3]) << 24;
        offset += 4;
        return value;
    }

    /**
     * @brief Reads a uint64_t from a span in Little-Endian format.
     */
    uint64_t read_uint64(std::span<const uint8_t> bytes, size_t& offset) {
        if (offset + 8 > bytes.size()) throw std::runtime_error("Malformed vault data: uint64 overflow");
        uint64_t value = 0;
        for (int i = 0; i < 8; ++i) {
            value |= static_cast<uint64_t>(bytes[offset + i]) << (i * 8);
        }
        offset += 8;
        return value;
    }

    /**
     * @brief Reads a string from a span.
     */
    duckpass::SecureString read_string(std::span<const uint8_t> bytes, size_t& offset) {
        uint32_t length = read_uint32(bytes, offset);
        if (bytes.size() - offset < length) throw std::runtime_error("Malformed vault data: string overflow");

        duckpass::SecureString str;
        str.reserve(length);
        const uint8_t* start = bytes.data() + offset;
        str.assign(reinterpret_cast<const char*>(start), length);

        offset += length;
        return str;
    }

    // --- Vault Class Implementation ---

    void Vault::add_entry(VaultEntry entry) {
        // Update last_updated if not set (e.g., from new entry)
        if (entry.last_updated == 0) {
            entry.last_updated = static_cast<uint64_t>(std::time(nullptr));
        }

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
            write_uint64(buffer, entry.last_updated);
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

            // Backward compatibility: check if there's enough data for last_updated
            if (offset + 8 <= bytes.size()) {
                entry.last_updated = read_uint64(bytes, offset);
            } else {
                entry.last_updated = 0;  // Or some default
            }

            vault.add_entry(std::move(entry));
        }
        return vault;
    }

    // --- Vault Orchestration (Crypto + Storage) ---

    bool vault_exists(const std::filesystem::path& vault_path) { return std::filesystem::exists(vault_path); }

    /**
     * @brief Loads and decrypts a vault file.
     *
     * Process:
     * 1. Read binary blob from disk.
     * 2. Validate magic bytes ("DUCK") and version.
     * 3. Extract KDF parameters (Argon2id) and Salt.
     * 4. Derive encryption key from master password using Argon2id.
     * 5. Decrypt ciphertext using AES-256-GCM.
     * 6. Deserialize decrypted plaintext into Vault entries.
     */
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
        if (version != 1 && version != 2) {
            throw duckpass::vault_corrupted_error("Unsupported vault version: " + std::to_string(version));
        }

        // For version 2, the entire header is protected by GCM AAD.
        const size_t header_size = 8 + 3 * sizeof(uint32_t) + crypto_handler::SALT_BYTES + crypto_handler::IV_BYTES;
        std::span<const uint8_t> aad;
        if (version == 2) {
            aad = bytes.subspan(0, header_size);
        }

        // 3. Parse KDF parameters, Salt, and IV
        crypto_handler::KdfParams kdf_params{};
        kdf_params.time_cost = read_uint32(bytes, offset);
        kdf_params.memory_cost = read_uint32(bytes, offset);
        kdf_params.parallelism = read_uint32(bytes, offset);

        const uint32_t MAX_MEMORY_COST = 1024 * 1024;
        const uint32_t MAX_TIME_COST = 100;
        const uint32_t MAX_PARALLELISM = 64;

        if (kdf_params.memory_cost > MAX_MEMORY_COST || kdf_params.time_cost > MAX_TIME_COST || kdf_params.parallelism > MAX_PARALLELISM) {
            throw duckpass::vault_corrupted_error("KDF parameters exceed safe limits. File may have been tampered with to cause DoS.");
        }

        std::vector<uint8_t> salt(bytes.data() + offset, bytes.data() + offset + crypto_handler::SALT_BYTES);
        offset += crypto_handler::SALT_BYTES;

        std::vector<uint8_t> iv(bytes.data() + offset, bytes.data() + offset + crypto_handler::IV_BYTES);
        offset += crypto_handler::IV_BYTES;

        // 4. Extract Ciphertext (including Tag)
        std::span<const uint8_t> ciphertext = bytes.subspan(offset);

        // 5. Decrypt and Deserialize
        crypto_handler::SecureBytes key = crypto_handler::derive_key_from_password(master_password, salt, kdf_params);
        crypto_handler::SecureBytes plaintext_bytes = crypto_handler::decrypt_data(ciphertext, key, iv, aad);

        return Vault::deserialize(plaintext_bytes);
    }

    /**
     * @brief Serializes and encrypts a vault to disk.
     *
     * Process:
     * 1. Serialize all vault entries into a packed binary format.
     * 2. Generate cryptographically secure random salt and IV.
     * 3. Derive encryption key from master password using Argon2id.
     * 4. Encrypt serialized data using AES-256-GCM.
     * 5. Package [Magic][Version][KDF Params][Salt][IV][Ciphertext+Tag] into a single blob.
     * 6. Atomically write the blob to disk.
     */
    void save_vault(const std::filesystem::path& vault_path, const Vault& vault, const SecureString& master_password) {
        // 1. Serialize entries
        duckpass::SecureBytes plaintext = vault.serialize();

        // 2. Prepare Crypto
        crypto_handler::KdfParams kdf_params = {crypto_handler::DEFAULT_TIME_COST, crypto_handler::DEFAULT_MEMORY_COST,
                                                crypto_handler::DEFAULT_PARALLELISM};
        std::vector<uint8_t> salt = crypto_handler::generate_random_bytes(crypto_handler::SALT_BYTES);
        std::vector<uint8_t> iv = crypto_handler::generate_random_bytes(crypto_handler::IV_BYTES);

        // 3. Package the Header [MAGIC][VERSION][KDF_PARAMS][SALT][IV]
        // This header will be used as AAD (Additional Authenticated Data) for GCM.
        duckpass::SecureBytes header;
        const size_t header_size = 4 + sizeof(uint32_t) + 3 * sizeof(uint32_t) + crypto_handler::SALT_BYTES + crypto_handler::IV_BYTES;
        header.reserve(header_size);

        // Magic Bytes "DUCK"
        header.push_back('D');
        header.push_back('U');
        header.push_back('C');
        header.push_back('K');

        // Version 2 (uses AAD for the header)
        write_uint32(header, 2);

        // KDF Params
        write_uint32(header, kdf_params.time_cost);
        write_uint32(header, kdf_params.memory_cost);
        write_uint32(header, kdf_params.parallelism);

        // Salt and IV
        header.insert(header.end(), salt.begin(), salt.end());
        header.insert(header.end(), iv.begin(), iv.end());

        crypto_handler::SecureBytes key = crypto_handler::derive_key_from_password(master_password, salt, kdf_params);
        std::vector<uint8_t> ciphertext = crypto_handler::encrypt_data(plaintext, key, iv, header);

        // 4. Final Blob: [HEADER][CIPHERTEXT+TAG]
        duckpass::SecureBytes full_package = std::move(header);
        full_package.insert(full_package.end(), ciphertext.begin(), ciphertext.end());

        // =================================================================
        // AUTOMATIC BACKUP: Create a (.bak) copy before overwriting
        // =================================================================
        if (std::filesystem::exists(vault_path)) {
            std::filesystem::path backup_path = vault_path;
            backup_path.replace_extension(vault_path.extension().string() + ".bak");
            std::error_code ec;

            // Vulnerability 2.2 Fix: Prevent Symlink Attack (CWE-59).
            // Explicitly remove the backup path if it exists or is a symlink.
            if (std::filesystem::exists(backup_path, ec) || std::filesystem::is_symlink(backup_path, ec)) {
                std::filesystem::remove(backup_path, ec);
            }

            // Use std::filesystem::copy_file for safe copying.
            // Since we removed the target, we don't need overwrite_existing.
            std::filesystem::copy_file(vault_path, backup_path, std::filesystem::copy_options::none, ec);

            // If backup fails (e.g., permission error), warn but don't block main write (Fail-safe)
            if (ec) {
                std::cerr << "[Warning] Could not create backup (.bak): " << ec.message() << "\n";
            }
        }
        // =================================================================

        // 4. Delegate disk I/O to storage layer
        duckpass::storage::write_file_atomic(vault_path, full_package);
    }
}  // namespace vault_handler
