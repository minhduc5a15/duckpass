#pragma once

#include <string>
#include <filesystem>
#include "nlohmann/json.hpp"
#include "duckpass/secure_allocator.h"

namespace vault_handler {
    using duckpass::SecureString;
    const std::string VAULT_PATH = ".duckvault";

    // Checks if the vault file exists.
    bool vault_exists(const std::filesystem::path &vault_path);

    // Loads, decrypts, and parses the vault file into a JSON object.
    // Throws std::runtime_error on failure (e.g., wrong password, corrupted file).
    nlohmann::json load_vault(const std::filesystem::path &vault_path, const SecureString &master_password);

    // Encrypts and saves the JSON object to the vault file.
    void save_vault(const std::filesystem::path &vault_path, const nlohmann::json &vault_data, const SecureString &master_password);
} // namespace vault_handler
