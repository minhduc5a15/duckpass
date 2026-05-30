#include "duckpass/get_command.h"
#include "duckpass/vault.h"
#include "duckpass/utils.h"
#include "duckpass/config_handler.h"
#include "duckpass/clipboard_handler.h"
#include "CLI/CLI.hpp"
#include <iostream>
#include <chrono>

CLI::App *get_command::setup(CLI::App &app) {
    CLI::App *get_cmd = app.add_subcommand("get", "Get an entry from the vault");
    get_cmd->add_option("name", "The name of the entry to retrieve")->required();
    get_cmd->add_flag("-c,--copy", "Copy the password to clipboard");
    return get_cmd;
}

get_command::get_command(CLI::App *app) {
    app->get_option("name")->results(name_);
    copy_to_clipboard_ = app->get_option("--copy")->as<bool>();
}

void get_command::execute() {
    config_handler config;
    auto vault_path = config.get_vault_path();

    if (!vault_handler::vault_exists(vault_path)) {
        std::cerr << "Error: Vault file not found. Nothing to get." << std::endl;
        return;
    }

    duckpass::SecureString master_password = get_password_silent("Enter master password: ");
    nlohmann::json vault_data;
    try {
        vault_data = vault_handler::load_vault(vault_path, master_password);
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return;
    }

    if (!vault_data.contains(name_)) {
        std::cerr << "Error: Entry '" << name_ << "' not found." << std::endl;
        return;
    }

    const auto &entry = vault_data[name_];
    const std::string username = entry.value("username", "");
    std::string password_raw = entry.value("password", "");
    duckpass::SecureString password(password_raw.begin(), password_raw.end());
    OPENSSL_cleanse(password_raw.data(), password_raw.length());

    if (copy_to_clipboard_) {
        std::string temp_pass = std::string(password.begin(), password.end());
        if (clipboard_handler::set_text(temp_pass)) {
            OPENSSL_cleanse(temp_pass.data(), temp_pass.length());
            std::cout << "Password for '" << name_ << "' copied to clipboard." << std::endl;

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
        std::cout << "Entry: " << name_ << std::endl;
        std::cout << "  Username: " << username << std::endl;
        std::cout << "  Password: " << temp_pass << std::endl;
        OPENSSL_cleanse(temp_pass.data(), temp_pass.length());
    }
}
