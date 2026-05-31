#include "duckpass/delete_command.h"

#include <iostream>

#include "CLI/CLI.hpp"
#include "duckpass/config_handler.h"
#include "duckpass/exceptions.h"
#include "duckpass/utils.h"
#include "duckpass/vault.h"

void delete_command::setup(CLI::App& app) {
    auto del_cmd = app.add_subcommand("delete", "Delete an entry from the vault");

    auto name = std::make_shared<std::string>();
    del_cmd->add_option("name", *name, "The name of the entry to delete")->required();

    del_cmd->callback([name]() {
        config_handler config;
        auto vault_path = config.get_vault_path();

        if (!vault_handler::vault_exists(vault_path)) {
            std::cerr << "Error: Vault file not found." << std::endl;
            return;
        }

        duckpass::SecureString master_password = get_password_silent("Enter master password: ");
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
        if (vault.remove_entry(service_name)) {
            std::cout << "Success: Entry '" << *name << "' has been deleted." << std::endl;

            try {
                vault_handler::save_vault(vault_path, vault, master_password);
                std::cout << "Vault saved successfully to " << vault_path.string() << std::endl;
            } catch (const std::exception& e) {
                std::cerr << "Error saving vault: " << e.what() << std::endl;
            }
        } else {
            std::cerr << "Error: Entry '" << *name << "' not found." << std::endl;
        }
    });
}
