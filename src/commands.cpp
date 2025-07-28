#include "duckpass/commands.h"
#include <iostream>
#include <random>

// NOTE: We don't implement clipboard logic yet. It will be added in a later part.

namespace command_handler {
    bool handle_add(nlohmann::json &vault_data, const std::string &name, const std::string &username, const std::string &password) {
        if (vault_data.contains(name)) {
            std::cout << "Error: Entry '" << name << "' already exists." << std::endl;
            return false; // No modification
        }
        // ... (logic thêm entry giữ nguyên)
        vault_data[name] = {
            {"username", username},
            {"password", password}
        };
        std::cout << "Success: Entry '" << name << "' added." << std::endl;
        return true; // Data was modified
    }

    void handle_get(const nlohmann::json &vault_data, const std::string &name, bool copy_to_clipboard) {
        if (!vault_data.contains(name)) {
            std::cout << "Error: Entry '" << name << "' not found." << std::endl;
            return;
        }

        const auto &entry = vault_data[name];
        const std::string username = entry["username"];
        const std::string password = entry["password"];

        if (copy_to_clipboard) {
            // Clipboard functionality will be implemented in a later part.
            std::cout << "Password for '" << name << "' copied to clipboard." << std::endl;
            std::cout << "DEBUG: Password is \"" << password << "\"" << std::endl;
        }
        else {
            std::cout << "Entry: " << name << std::endl;
            std::cout << "  Username: " << username << std::endl;
            std::cout << "  Password: " << password << std::endl;
        }
    }

    void handle_list(const nlohmann::json &vault_data) {
        if (vault_data.empty()) {
            std::cout << "Vault is empty." << std::endl;
            return;
        }

        std::cout << "Listing all entries:" << std::endl;
        for (auto &el: vault_data.items()) {
            std::cout << "- " << el.key() << std::endl;
        }
    }

    bool handle_delete(nlohmann::json &vault_data, const std::string &name) {
        if (!vault_data.contains(name)) {
            std::cout << "Error: Entry '" << name << "' not found." << std::endl;
            return false; // No modification
        }
        vault_data.erase(name);
        std::cout << "Success: Entry '" << name << "' has been deleted." << std::endl;
        return true; // Data was modified
    }

    void handle_generate(int length) {
        const std::string chars =
                "abcdefghijklmnopqrstuvwxyz"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "0123456789"
                "!@#$%^&*()-_=+[]{}|;:',.<>?/";

        std::random_device rd;
        std::mt19937 generator(rd());
        std::uniform_int_distribution<int> distribution(0, chars.length() - 1);

        std::string password;
        password.reserve(length);

        for (int i = 0; i < length; ++i) {
            password += chars[distribution(generator)];
        }

        std::cout << "Generated Password: " << password << std::endl;
    }
} // namespace command_handler
