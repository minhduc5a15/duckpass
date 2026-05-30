#include "duckpass/add_command.h"
#include "duckpass/vault.h"
#include "duckpass/utils.h"
#include "duckpass/config_handler.h"
#include "duckpass/exceptions.h"
#include "CLI/CLI.hpp"
#include <iostream>

void add_command::setup(CLI::App &app) {
    auto add_cmd = app.add_subcommand("add", "Add a new entry to the vault");
    
    auto name = std::make_shared<std::string>();
    auto username = std::make_shared<std::string>();
    auto password_raw = std::make_shared<std::string>();

    add_cmd->add_option("name", *name, "The name of the entry (e.g., gmail, facebook)")->required();
    add_cmd->add_option("username", *username, "Username or email")->required();
    add_cmd->add_option("password", *password_raw, "Password for the entry")->required();

    add_cmd->callback([name, username, password_raw]() {
        duckpass::SecureString password(password_raw->begin(), password_raw->end());
        OPENSSL_cleanse(password_raw->data(), password_raw->length());

        config_handler config;
        auto vault_path = config.get_vault_path();

        vault_handler::Vault vault;
        duckpass::SecureString master_password;
        bool is_new_vault = !vault_handler::vault_exists(vault_path);

        if (is_new_vault) {
            std::cout << "Info: No vault found. Creating a new one..." << std::endl;
            master_password = get_password_silent("Enter a new master password: ");
            duckpass::SecureString confirm_password = get_password_silent("Confirm master password: ");
            if (master_password.empty() || master_password != confirm_password) {
                std::cerr << "Error: Passwords do not match or are empty." << std::endl;
                return;
            }
        }
        else {
            master_password = get_password_silent("Enter master password: ");
            try {
                vault = vault_handler::load_vault(vault_path, master_password);
            } catch (const duckpass::wrong_password_error &e) {
                std::cerr << "Error: " << e.what() << std::endl;
                return;
            } catch (const duckpass::vault_corrupted_error &e) {
                std::cerr << "Critical Error: " << e.what() << std::endl;
                return;
            } catch (const duckpass::vault_io_error &e) {
                std::cerr << "I/O Error: " << e.what() << std::endl;
                return;
            } catch (const std::exception &e) {
                std::cerr << "An unexpected error occurred: " << e.what() << std::endl;
                return;
            }
        }

        duckpass::SecureString service_name(name->begin(), name->end());
        if (vault.get_entry(service_name)) {
            std::cout << "Error: Entry '" << *name << "' already exists." << std::endl;
            return;
        }

        vault_handler::VaultEntry entry;
        entry.service = std::move(service_name);
        entry.username = duckpass::SecureString(username->begin(), username->end());
        entry.password = std::move(password);

        vault.add_entry(std::move(entry));
        
        std::cout << "Success: Entry '" << *name << "' added." << std::endl;

        try {
            vault_handler::save_vault(vault_path, vault, master_password);
            std::cout << "Vault saved successfully to " << vault_path.string() << std::endl;
        } catch (const std::exception &e) {
            std::cerr << "Error saving vault: " << e.what() << std::endl;
        }
    });
}
