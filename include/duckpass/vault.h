#pragma once

#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "duckpass/secure_allocator.h"

namespace vault_handler {
    using duckpass::secure_allocator;
    using duckpass::SecureString;

    const std::string VAULT_PATH = ".duckvault";

    /**
     * @brief Represents a single account entry in the vault.
     * Encapsulates data to avoid raw string key access.
     */
    struct VaultEntry {
        SecureString service;
        SecureString username;
        SecureString password;
    };

    /**
     * @brief The Vault class encapsulates the entire collection of entries.
     * Provides a clean API for searching, adding, and removing entries.
     */
    class Vault {
    public:
        using EntryContainer = std::vector<VaultEntry, secure_allocator<VaultEntry>>;

        void add_entry(VaultEntry entry);
        bool remove_entry(const SecureString &service);
        std::optional<VaultEntry> get_entry(const SecureString &service) const;
        const EntryContainer &get_all_entries() const { return entries; }

        // Serialization methods
        duckpass::SecureBytes serialize() const;
        static Vault deserialize(std::span<const uint8_t> bytes);

    private:
        EntryContainer entries;
    };

    // Checks if the vault file exists.
    bool vault_exists(const std::filesystem::path &vault_path);

    // Loads, decrypts, and parses the vault file into a Vault object.
    Vault load_vault(const std::filesystem::path &vault_path, const SecureString &master_password);

    // Encrypts and saves the Vault object to the vault file.
    void save_vault(const std::filesystem::path &vault_path, const Vault &vault, const SecureString &master_password);

}  // namespace vault_handler
