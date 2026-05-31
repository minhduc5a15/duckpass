#pragma once

#include <filesystem>

class config_handler {
public:
    config_handler();

    // Get the full, absolute path to the vault file
    std::filesystem::path get_vault_path() const;

private:
    std::filesystem::path vault_path_;
};
