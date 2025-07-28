#pragma once

#include "nlohmann/json.hpp"
#include <filesystem>

class config_handler {
public:
    config_handler();

    // Get the full, absolute path to the vault file
    std::filesystem::path get_vault_path() const;

private:
    void load_or_create_default();
    void create_default_config();

    std::filesystem::path config_file_path_;
    nlohmann::json config_data_;
};