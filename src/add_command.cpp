#include "duckpass/add_command.h"

#include <iostream>
#include <unistd.h>

#include "CLI/CLI.hpp"
#include "duckpass/config_handler.h"
#include "duckpass/exceptions.h"
#include "duckpass/terminal_utils.h"
#include "duckpass/utils.h"
#include "duckpass/vault.h"

void add_command::setup(CLI::App &app) {
    auto add_cmd = app.add_subcommand("add", "Add a new entry to the vault");

    auto name = std::make_shared<std::string>();
    auto username = std::make_shared<std::string>();

    add_cmd->add_option("name", *name, "The name of the entry (e.g., gmail, facebook)")->required();
    add_cmd->add_option("username", *username, "Username or email")->required();

    add_cmd->callback([name, username]() {
        config_handler config;
        auto vault_path = config.get_vault_path();

        if (!vault_handler::vault_exists(vault_path)) {
            std::cerr << "Error: Vault has not been initialized.\n"
                      << "Please run 'duckpass init' to create a new storage.\n";
            return;
        }

        duckpass::SecureString master_password = utils::get_password_silent("Enter master password: ");

        vault_handler::Vault vault;
        try {
            vault = vault_handler::load_vault(vault_path, master_password);
        } catch (const duckpass::wrong_password_error& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return;
        } catch (const duckpass::vault_corrupted_error& e) {
            std::cerr << "Critical Error: " << e.what() << std::endl;
            return;
        } catch (const duckpass::vault_io_error& e) {
            std::cerr << "I/O Error: " << e.what() << std::endl;
            return;
        } catch (const std::exception& e) {
            std::cerr << "An unexpected error occurred: " << e.what() << std::endl;
            return;
        }

        duckpass::SecureString service_name(name->begin(), name->end());
        if (vault.get_entry(service_name)) {
            std::cout << "Error: Entry '" << *name << "' already exists." << std::endl;
            return;
        }

        duckpass::SecureString password;
        if (isatty(STDIN_FILENO)) {
            duckpass::SecureString p1 = terminal_utils::read_password("Enter password for '" + *name + "': ");
            duckpass::SecureString p2 = terminal_utils::read_password("Retype password for '" + *name + "': ");

            if (p1 != p2) {
                std::cerr << "Error: Passwords do not match. Entry not added." << std::endl;
                return;
            }
            password = std::move(p1);
        } else {
            // Read from STDIN if not a TTY (for piping)
            char c;
            while (std::cin.get(c) && c != '\n' && c != '\r') {
                password.push_back(c);
            }
        }

        if (password.empty()) {
            std::cerr << "Error: Password cannot be empty." << std::endl;
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
