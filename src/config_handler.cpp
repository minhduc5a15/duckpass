#include "duckpass/config_handler.h"
#include "duckpass/utils.h"
#include <fstream>

config_handler::config_handler() {
    // Determine the path to config.json
    config_file_path_ = get_config_directory() / "config.json";
    load_or_create_default();
}

void config_handler::load_or_create_default() {
    if (std::filesystem::exists(config_file_path_)) {
        std::ifstream file(config_file_path_);
        config_data_ = nlohmann::json::parse(file);
    } else {
        create_default_config();
    }
}

void config_handler::create_default_config() {
    config_data_ = {
        {"version", "1.0"},
        {"vault_filename", ".duckvault"} // The name of the vault file
    };
    std::ofstream file(config_file_path_);
    file << config_data_.dump(4); // pretty-print with 4-space indent
}

std::filesystem::path config_handler::get_vault_path() const {
    // Combine the config directory with the vault filename from the config data
    return get_config_directory() / config_data_.value("vault_filename", ".duckvault");
}