#include "duckpass/config_handler.h"

#include "duckpass/utils.h"
#include "duckpass/vault.h"

config_handler::config_handler() {
    // For simplicity and to remove JSON dependency, we use the default path.
    // In a real scenario, we could parse a simple key=value file here.
    vault_path_ = get_config_directory() / vault_handler::VAULT_PATH;
}

std::filesystem::path config_handler::get_vault_path() const { return vault_path_; }
