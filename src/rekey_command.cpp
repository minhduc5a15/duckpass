#include "duckpass/rekey_command.h"

#include <iostream>

#include "CLI/CLI.hpp"
#include "duckpass/config_handler.h"
#include "duckpass/terminal_utils.h"
#include "duckpass/vault.h"

namespace rekey_command {
    void setup(CLI::App& app) {
        auto rekey_cmd = app.add_subcommand("rekey", "Change master password and re-encrypt the entire Vault");

        rekey_cmd->callback([]() {
            config_handler config;
            auto vault_path = config.get_vault_path();

            if (!vault_handler::vault_exists(vault_path)) {
                std::cerr << "Error: No Vault found. Please run 'duckpass init' first.\n";
                return;
            }

            duckpass::SecureString old_pwd = terminal_utils::read_password("Enter CURRENT Master Password: ");

            try {
                // Try to load vault with old password. Throws exception if wrong password.
                auto vault = vault_handler::load_vault(vault_path, old_pwd);

                duckpass::SecureString new_pwd1 = terminal_utils::read_password("Enter NEW Master Password: ");
                duckpass::SecureString new_pwd2 = terminal_utils::read_password("Re-enter NEW Master Password: ");

                if (new_pwd1 != new_pwd2) {
                    std::cerr << "Error: New passwords do not match. Operation cancelled.\n";
                    return;
                }

                if (new_pwd1.empty()) {
                    std::cerr << "Error: New master password cannot be empty.\n";
                    return;
                }

                // Save vault with new password. save_vault ensures new cryptographic parameters are generated.
                vault_handler::save_vault(vault_path, vault, new_pwd1);
                std::cout << "[✓] Master password changed successfully! Vault has been re-encrypted.\n";
            } catch (const std::exception& e) {
                std::cerr << "Error: " << e.what() << "\n";
            }
        });
    }
}  // namespace rekey_command
