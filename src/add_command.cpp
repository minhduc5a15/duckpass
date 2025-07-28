#include "duckpass/add_command.h"
#include "duckpass/vault.h"
#include "duckpass/utils.h"
#include "CLI/CLI.hpp"
#include <iostream>

CLI::App *add_command::setup(CLI::App &app) {
    CLI::App *add_cmd = app.add_subcommand("add", "Add a new entry to the vault");
    add_cmd->add_option("name", "The name of the entry (e.g., gmail, facebook)")->required();
    add_cmd->add_option("username", "Username or email")->required();
    add_cmd->add_option("password", "Password for the entry")->required();
    return add_cmd;
}

add_command::add_command(CLI::App *app) {
    app->get_option("name")->results(name_);
    app->get_option("username")->results(username_);
    app->get_option("password")->results(password_);
}

void add_command::execute() {
    nlohmann::json vault_data;
    std::string master_password;
    bool is_new_vault = !vault_handler::vault_exists();

    if (is_new_vault) {
        std::cout << "Creating a new vault..." << std::endl;
        master_password = get_password_silent("Enter a new master password: ");
        std::string confirm_password = get_password_silent("Confirm master password: ");
        if (master_password.empty() || master_password != confirm_password) {
            std::cerr << "Error: Passwords do not match or are empty." << std::endl;
            return;
        }
    }
    else {
        master_password = get_password_silent("Enter master password: ");
        try {
            vault_data = vault_handler::load_vault(master_password);
        } catch (const std::exception &e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return;
        }
    }

    if (vault_data.contains(name_)) {
        std::cout << "Error: Entry '" << name_ << "' already exists." << std::endl;
        return;
    }
    vault_data[name_] = {
        {"username", username_},
        {"password", password_}
    };
    std::cout << "Success: Entry '" << name_ << "' added." << std::endl;

    try {
        vault_handler::save_vault(vault_data, master_password);
        std::cout << "Vault saved successfully." << std::endl;
    } catch (const std::exception &e) {
        std::cerr << "Error saving vault: " << e.what() << std::endl;
    }
}
