#include "duckpass/rekey_command.h"

#include <iostream>

#include "CLI/CLI.hpp"
#include "duckpass/config_handler.h"
#include "duckpass/exceptions.h"
#include "duckpass/ipc.h"
#include "duckpass/terminal_utils.h"
#include "duckpass/vault_service.h"

namespace rekey_command {
    void setup(CLI::App& app) {
        const auto rekey_cmd = app.add_subcommand("rekey", "Change master password and re-encrypt the entire Vault");

        rekey_cmd->callback([]() {
            config_handler const config;
            const auto vault_path = config.get_vault_path();

            if (!vault_handler::vault_exists(vault_path)) {
                std::cerr << "Error: No Vault found. Please run 'duckpass init' first.\n";
                return;
            }

            duckpass::SecureString const old_pwd = terminal_utils::read_password("Enter CURRENT Master Password: ");

            try {
                duckpass::service::VaultService vault_service(vault_path, old_pwd);

                duckpass::SecureString const new_pwd1 = terminal_utils::read_password("Enter NEW Master Password: ");
                duckpass::SecureString const new_pwd2 = terminal_utils::read_password("Re-enter NEW Master Password: ");

                if (new_pwd1 != new_pwd2) {
                    std::cerr << "Error: New passwords do not match. Operation cancelled.\n";
                    return;
                }

                vault_service.rekey(new_pwd1);
                std::cout << "[✓] Master password changed successfully! Vault has been re-encrypted.\n";

                // Lock agent to purge old master keys and cache from memory
                duckpass::ipc::IpcClient client;
                if (client.is_agent_available()) {
                    client.lock();
                }
            } catch (const duckpass::wrong_password_error& e) {
                std::cerr << "Error: " << e.what() << "\n";
            } catch (const std::exception& e) {
                std::cerr << "Error: " << e.what() << "\n";
            }
        });
    }
}  // namespace rekey_command
