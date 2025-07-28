#pragma once

#include <string>
#include "nlohmann/json.hpp"

namespace vault_handler {
    const std::string VAULT_PATH = ".duckvault";

    // Checks if the vault file exists.
    bool vault_exists();

    // Loads, decrypts, and parses the vault file into a JSON object.
    // Throws std::runtime_error on failure (e.g., wrong password, corrupted file).
    nlohmann::json load_vault(const std::string &master_password);

    // Encrypts and saves the JSON object to the vault file.
    void save_vault(const nlohmann::json &vault_data, const std::string &master_password);
} // namespace vault_handler
