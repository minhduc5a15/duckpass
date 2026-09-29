#include "duckpass/delete_command.h"

#include <iostream>

#include "CLI/CLI.hpp"
#include "duckpass/config_handler.h"
#include "duckpass/exceptions.h"
#include "duckpass/ipc.h"
#include "duckpass/terminal_utils.h"
#include "duckpass/utils.h"
#include "duckpass/vault_service.h"
void delete_command::setup(CLI::App& app) {
    const auto del_cmd = app.add_subcommand("delete", "Delete an entry from the vault");

    const auto name = std::make_shared<std::string>();
    del_cmd->add_option("name", *name, "The name of the entry to delete")->required();

    del_cmd->callback([name]() {
        const config_handler config;
        const auto vault_path = config.get_vault_path();

        if (!vault_handler::vault_exists(vault_path)) {
            std::cerr << "Error: Vault has not been initialized.\n"
                      << "Please run 'duckpass init' to create a new storage.\n";
            return;
        }

        duckpass::ipc::IpcClient client;
        if (client.is_agent_available()) {
            auto status = client.get_status();
            if (status && !status->is_unlocked) {
                const duckpass::SecureString master_password = terminal_utils::read_password("Agent is locked. Enter Master Password: ");
                std::string unlock_err;
                if (!client.unlock(master_password, unlock_err)) {
                    std::cerr << "Error: " << unlock_err << std::endl;
                    return;
                }
            }

            duckpass::SecureString const service_name(name->begin(), name->end());
            std::string err;
            if (client.delete_entry(service_name, err)) {
                std::cout << "Success: Entry '" << *name << "' has been deleted." << std::endl;
            } else {
                std::cerr << "Error: " << err << std::endl;
            }
            return;
        }

        const duckpass::SecureString master_password = utils::get_password_silent("Enter master password: ");
        try {
            duckpass::service::VaultService vault_service(vault_path, master_password);
            const duckpass::SecureString service_name(name->begin(), name->end());

            vault_service.delete_entry(service_name);

            std::cout << "Success: Entry '" << *name << "' has been deleted." << std::endl;
            std::cout << "Vault saved successfully to " << vault_path.string() << std::endl;
        } catch (const duckpass::wrong_password_error& e) {
            std::cerr << "Error: " << e.what() << std::endl;
        } catch (const std::invalid_argument& e) {
            std::cerr << "Error: " << e.what() << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
        }
    });
}
