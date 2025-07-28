#include "duckpass/list_command.h"
#include "duckpass/vault.h"
#include "duckpass/utils.h"
#include "duckpass/config_handler.h"
#include "CLI/CLI.hpp"
#include <iostream>

CLI::App* list_command::setup(CLI::App& app) {
    return app.add_subcommand("list", "List all entries in the vault");
}

list_command::list_command(CLI::App* app) {
    // No arguments to parse
}

void list_command::execute() {
    config_handler config;
    auto vault_path = config.get_vault_path();

    if (!vault_handler::vault_exists(vault_path)) {
        std::cerr << "Error: Vault file not found. Nothing to list." << std::endl;
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

    if (vault_data.empty()) {
        std::cout << "Vault is empty." << std::endl;
        return;
    }

    std::cout << "Listing all entries:" << std::endl;
    for (auto& entry : vault_data.items()) {
        std::cout << "- " << entry.key() << std::endl;
    }
}