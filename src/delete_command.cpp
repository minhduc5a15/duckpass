#include "duckpass/delete_command.h"
#include "duckpass/vault.h"
#include "duckpass/utils.h"
#include "duckpass/config_handler.h"
#include "CLI/CLI.hpp"
#include <iostream>

CLI::App* delete_command::setup(CLI::App& app) {
    CLI::App* del_cmd = app.add_subcommand("delete", "Delete an entry from the vault");
    del_cmd->add_option("name", "The name of the entry to delete")->required();
    return del_cmd;
}

delete_command::delete_command(CLI::App* app) {
    app->get_option("name")->results(name_);
}

void delete_command::execute() {
    config_handler config;
    auto vault_path = config.get_vault_path();

    if (!vault_handler::vault_exists(vault_path)) {
        std::cerr << "Error: Vault file not found." << std::endl;
        return;
    }

    std::string master_password = get_password_silent("Enter master password: ");
    nlohmann::json vault_data;
    try {
        vault_data = vault_handler::load_vault(vault_path, master_password);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return;
    }

    if (!vault_data.contains(name_)) {
        std::cerr << "Error: Entry '" << name_ << "' not found." << std::endl;
        return;
    }

    vault_data.erase(name_);
    std::cout << "Success: Entry '" << name_ << "' has been deleted." << std::endl;

    try {
        vault_handler::save_vault(vault_path, vault_data, master_password);
        std::cout << "Vault saved successfully." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error saving vault: " << e.what() << std::endl;
    }
}