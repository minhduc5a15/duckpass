#pragma once

#include <string>
#include <filesystem>
#include "duckpass/json_secure.h"
#include "duckpass/secure_allocator.h"

namespace vault_handler {
    using duckpass::SecureString;
    using duckpass::SecureJson;
    const std::string VAULT_PATH = ".duckvault";

    // Checks if the vault file exists.
    bool vault_exists(const std::filesystem::path &vault_path);

    // Loads, decrypts, and parses the vault file into a JSON object.
    // Throws std::runtime_error on failure (e.g., wrong password, corrupted file).
    SecureJson load_vault(const std::filesystem::path &vault_path, const SecureString &master_password);

    // Encrypts and saves the JSON object to the vault file.
    void save_vault(const std::filesystem::path &vault_path, const SecureJson &vault_data, const SecureString &master_password);
} // namespace vault_handler
