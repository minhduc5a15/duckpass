#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>

#include "CLI/CLI.hpp"
#include "nlohmann/json.hpp"
#include "duckpass/commands.h"
#include "duckpass/vault.h"

#include <termios.h>
#include <unistd.h>

// Helper function to get password without showing it on screen (for Linux/macOS)
std::string get_password_silent(const std::string& prompt) {
    std::cout << prompt;
    termios old_term;
    tcgetattr(STDIN_FILENO, &old_term);
    termios new_term = old_term;
    new_term.c_lflag &= ~ECHO; // Turn off echo
    tcsetattr(STDIN_FILENO, TCSANOW, &new_term);

    std::string password;
    std::getline(std::cin, password);

    tcsetattr(STDIN_FILENO, TCSANOW, &old_term); // Restore terminal settings
    std::cout << std::endl;
    return password;
}

int main(int argc, char** argv) {
    CLI::App app{"duckpass: A simple command-line password manager"};
    app.require_subcommand(1);
    app.allow_windows_style_options();

    // Command definitions (same as before)
    // ... (copy/paste the command definitions from the previous main.cpp here)
    // --- add command ---
    CLI::App* add_cmd = app.add_subcommand("add", "Add a new entry to the vault");
    std::string add_name, add_username, add_password;
    add_cmd->add_option("name", add_name, "The name of the entry (e.g., gmail, facebook)")->required();
    add_cmd->add_option("username", add_username, "Username or email")->required();
    add_cmd->add_option("password", add_password, "Password for the entry")->required();

    // --- get command ---
    CLI::App* get_cmd = app.add_subcommand("get", "Get an entry from the vault");
    std::string get_name;
    bool copy_to_clipboard = false;
    get_cmd->add_option("name", get_name, "The name of the entry to retrieve")->required();
    get_cmd->add_flag("-c,--copy", copy_to_clipboard, "Copy the password to clipboard");

    // --- list command ---
    CLI::App* list_cmd = app.add_subcommand("list", "List all entries in the vault");

    // --- delete command ---
    CLI::App* delete_cmd = app.add_subcommand("delete", "Delete an entry from the vault");
    std::string delete_name;
    delete_cmd->add_option("name", delete_name, "The name of the entry to delete")->required();

    // --- generate command ---
    CLI::App* generate_cmd = app.add_subcommand("generate", "Generate a random password");
    int password_length = 16;
    generate_cmd->add_option("-l,--length", password_length, "The desired password length");

    CLI11_PARSE(app, argc, argv);

    // --- Main Application Logic ---
    nlohmann::json vault_data;
    std::string master_password;
    bool is_new_vault = !vault_handler::vault_exists();

    if (is_new_vault) {
        if (!(*add_cmd)) {
            std::cerr << "Error: Vault file '" << vault_handler::VAULT_PATH << "' not found." << std::endl;
            std::cerr << "Please create a new entry with the 'add' command to start." << std::endl;
            return 1;
        }
        std::cout << "Creating a new vault..." << std::endl;
        master_password = get_password_silent("Enter a new master password: ");
        std::string confirm_password = get_password_silent("Confirm master password: ");
        if (master_password != confirm_password) {
            std::cerr << "Error: Passwords do not match." << std::endl;
            return 1;
        }
        std::cout << "New vault created." << std::endl;
    } else {
        master_password = get_password_silent("Enter master password: ");
    }

    // Load vault data if it's not a new vault
    if (!is_new_vault) {
        try {
            vault_data = vault_handler::load_vault(master_password);
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return 1;
        }
    }

    bool data_modified = false;

    // --- Dispatch to command handlers ---
    if (*add_cmd) {
        if (command_handler::handle_add(vault_data, add_name, add_username, add_password)) {
            data_modified = true;
        }
    } else if (*get_cmd) {
        command_handler::handle_get(vault_data, get_name, copy_to_clipboard);
    } else if (*list_cmd) {
        command_handler::handle_list(vault_data);
    } else if (*delete_cmd) {
        if (command_handler::handle_delete(vault_data, delete_name)) {
            data_modified = true;
        }
    } else if (*generate_cmd) {
        command_handler::handle_generate(password_length);
    }

    // Save the vault if it was modified
    if (data_modified) {
        try {
            vault_handler::save_vault(vault_data, master_password);
            std::cout << "Vault saved successfully." << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "Error saving vault: " << e.what() << std::endl;
            return 1;
        }
    }

    return 0;
}