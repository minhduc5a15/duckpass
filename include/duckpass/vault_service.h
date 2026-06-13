#pragma once

#include <filesystem>
#include <optional>
#include <string_view>
#include <vector>

#include "duckpass/audit_engine.h"
#include "duckpass/crypto.h"
#include "duckpass/vault.h"

namespace duckpass::service {

    class VaultService {
    public:
        /**
         * @brief Initialize the service with the vault path and master password.
         * This will load and decrypt the vault from disk.
         * Throws an exception if loading fails (e.g., wrong password, missing file, corrupted data).
         */
        VaultService(std::filesystem::path path, duckpass::SecureString master_password);

        /**
         * @brief Save the current state of the vault back to disk.
         * Throws an exception on failure.
         */
        void save() const;

        /**
         * @brief Adds a new entry to the vault and automatically saves to disk.
         * Throws std::invalid_argument if service name is empty or already exists.
         */
        void add_entry(duckpass::SecureString service, duckpass::SecureString username, duckpass::SecureString password);

        /**
         * @brief Deletes an entry from the vault and automatically saves to disk.
         * Throws std::invalid_argument if the service is not found.
         */
        void delete_entry(const duckpass::SecureString& service);

        /**
         * @brief Retrieves an entry by service name.
         */
        std::optional<vault_handler::VaultEntry> get_entry(const duckpass::SecureString& service) const;

        /**
         * @brief Lists entries. If query is provided, performs fuzzy search.
         */
        std::vector<vault_handler::VaultEntry> list_entries(std::string_view query = "") const;

        /**
         * @brief Performs a security audit of the vault.
         */
        audit::AuditReport audit_vault(const audit::AuditEngine::Config& config) const;

        /**
         * @brief Retrieves all entries (e.g., for auto-completion).
         */
        const vault_handler::Vault::EntryContainer& get_all_entries() const;

    private:
        std::filesystem::path vault_path_;
        duckpass::SecureString master_password_;
        vault_handler::Vault vault_;
    };

}  // namespace duckpass::service
