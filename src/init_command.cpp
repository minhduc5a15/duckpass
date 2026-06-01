#include "duckpass/init_command.h"

#include <iostream>

#include "CLI/CLI.hpp"
#include "duckpass/config_handler.h"
#include "duckpass/terminal_utils.h"
#include "duckpass/vault.h"

namespace init_command {
    void setup(CLI::App& app) {
        auto init_cmd = app.add_subcommand("init", "Initialize a new secure vault");

        init_cmd->callback([]() {
            config_handler config;
            auto vault_path = config.get_vault_path();

            if (vault_handler::vault_exists(vault_path)) {
                std::cerr << "Vault already exists at: " << vault_path << "\n"
                          << "Hint: Use 'duckpass rekey' if you want to change the master password.\n";
                return;
            }

            duckpass::SecureString pwd1 = terminal_utils::read_password("Create new Master Password: ");
            duckpass::SecureString pwd2 = terminal_utils::read_password("Re-enter Master Password: ");

            if (pwd1 != pwd2) {
                std::cerr << "Error: Passwords do not match. Initialization aborted.\n";
                return;
            }

            if (pwd1.empty()) {
                std::cerr << "Error: Master password cannot be empty.\n";
                return;
            }

            try {
                // Create an empty vault. save_vault will automatically generate safe Salt & IV.
                vault_handler::Vault empty_vault;
                vault_handler::save_vault(vault_path, empty_vault, pwd1);
                std::cout << "Success! Your vault has been initialized.\n";
            } catch (const std::exception& e) {
                std::cerr << "System error during vault initialization: " << e.what() << "\n";
            }
        });
    }
}  // namespace init_command
