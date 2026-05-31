#include "duckpass/list_command.h"

#include <iostream>

#include "CLI/CLI.hpp"
#include "duckpass/config_handler.h"
#include "duckpass/exceptions.h"
#include "duckpass/utils.h"
#include "duckpass/vault.h"

void list_command::setup(CLI::App& app) {
    auto list_cmd = app.add_subcommand("list", "List all entries in the vault");

    list_cmd->callback([]() {
        config_handler config;
        auto vault_path = config.get_vault_path();

        if (!vault_handler::vault_exists(vault_path)) {
            std::cerr << "Error: Vault file not found. Nothing to list." << std::endl;
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

        const auto& entries = vault.get_all_entries();
        if (entries.empty()) {
            std::cout << "Vault is empty." << std::endl;
            return;
        }

        std::cout << "Listing all entries:" << std::endl;
        for (const auto& entry : entries) {
            std::string temp_service(entry.service.begin(), entry.service.end());
            std::cout << "- " << temp_service << std::endl;
            OPENSSL_cleanse(temp_service.data(), temp_service.length());
        }
    });
}
