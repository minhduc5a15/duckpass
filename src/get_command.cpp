#include "duckpass/get_command.h"

#include <chrono>
#include <iostream>

#include "CLI/CLI.hpp"
#include "duckpass/clipboard_handler.h"
#include "duckpass/config_handler.h"
#include "duckpass/exceptions.h"
#include "duckpass/utils.h"
#include "duckpass/vault.h"

void get_command::setup(CLI::App &app) {
    auto get_cmd = app.add_subcommand("get", "Get an entry from the vault");

    auto name = std::make_shared<std::string>();
    auto copy_to_clipboard = std::make_shared<bool>(false);

    get_cmd->add_option("name", *name, "The name of the entry to retrieve")->required();
    get_cmd->add_flag("-c,--copy", *copy_to_clipboard, "Copy the password to clipboard");

    get_cmd->callback([name, copy_to_clipboard]() {
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

        duckpass::SecureString service_name(name->begin(), name->end());
        auto entry_opt = vault.get_entry(service_name);

        if (!entry_opt) {
            std::cerr << "Error: Entry '" << *name << "' not found." << std::endl;
            return;
        }

        const auto &entry = *entry_opt;
        const duckpass::SecureString &username = entry.username;
        const duckpass::SecureString &password = entry.password;

        if (*copy_to_clipboard) {
            if (clipboard_handler::set_text(password)) {
                std::cout << "Password for '" << *name << "' copied to clipboard." << std::endl;

                const int delay_seconds = 30;
                std::cout << "It will be cleared automatically in " << delay_seconds << " seconds." << std::endl;
                clipboard_handler::clear_after_delay(std::chrono::seconds(delay_seconds));
            } else {
                std::cerr << "Error: Could not copy to clipboard." << std::endl;
            }
        } else {
            std::cout << "Entry: " << std::string_view(entry.service.data(), entry.service.size()) << std::endl;
            std::cout << "  Username: " << std::string_view(username.data(), username.size()) << std::endl;
            std::cout << "  Password: " << std::string_view(password.data(), password.size()) << std::endl;
        }
    });
}
