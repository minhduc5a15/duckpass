#include "duckpass/get_command.h"
#include "duckpass/vault.h"
#include "duckpass/utils.h"
#include "duckpass/config_handler.h"
#include "duckpass/clipboard_handler.h"
#include "duckpass/exceptions.h"
#include "duckpass/json_secure.h"
#include "CLI/CLI.hpp"
#include <iostream>
#include <chrono>

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
            std::cerr << "Error: Vault file not found. Nothing to get." << std::endl;
            return;
        }

        duckpass::SecureString master_password = get_password_silent("Enter master password: ");
        duckpass::SecureJson vault_data;
        try {
            vault_data = vault_handler::load_vault(vault_path, master_password);
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

        if (!vault_data.contains(*name)) {
            std::cerr << "Error: Entry '" << *name << "' not found." << std::endl;
            return;
        }

        const auto &entry = vault_data[*name];
        
        // Extract from binary format
        const auto& username_bin = entry.at("username").get_binary();
        const auto& password_bin = entry.at("password").get_binary();

        const duckpass::SecureString username(username_bin.begin(), username_bin.end());
        const duckpass::SecureString password(password_bin.begin(), password_bin.end());

        if (*copy_to_clipboard) {
            std::string temp_pass = std::string(password.begin(), password.end());
            if (clipboard_handler::set_text(temp_pass)) {
                OPENSSL_cleanse(temp_pass.data(), temp_pass.length());
                std::cout << "Password for '" << *name << "' copied to clipboard." << std::endl;

                const int delay_seconds = 30;
                std::cout << "It will be cleared automatically in " << delay_seconds << " seconds." << std::endl;
                clipboard_handler::clear_after_delay(std::chrono::seconds(delay_seconds));
            }
            else {
                OPENSSL_cleanse(temp_pass.data(), temp_pass.length());
                std::cerr << "Error: Could not copy to clipboard." << std::endl;
            }
        }
        else {
            std::string temp_pass = std::string(password.begin(), password.end());
            std::string temp_user = std::string(username.begin(), username.end());
            std::cout << "Entry: " << *name << std::endl;
            std::cout << "  Username: " << temp_user << std::endl;
            std::cout << "  Password: " << temp_pass << std::endl;
            OPENSSL_cleanse(temp_pass.data(), temp_pass.length());
            OPENSSL_cleanse(temp_user.data(), temp_user.length());
        }
    });
}
