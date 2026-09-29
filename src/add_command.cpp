#include "duckpass/add_command.h"

#include <unistd.h>

#include <iostream>

#include "CLI/CLI.hpp"
#include "duckpass/config_handler.h"
#include "duckpass/exceptions.h"
#include "duckpass/ipc.h"
#include "duckpass/terminal_utils.h"
#include "duckpass/utils.h"
#include "duckpass/vault_service.h"

void add_command::setup(CLI::App& app) {
    const auto add_cmd = app.add_subcommand("add", "Add a new entry to the vault");

    const auto name = std::make_shared<std::string>();
    const auto username = std::make_shared<std::string>();

    add_cmd->add_option("name", *name, "The name of the entry (e.g., gmail, facebook)")->required();
    add_cmd->add_option("username", *username, "Username or email")->required();

    add_cmd->callback([name, username]() {
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

            duckpass::SecureString password;
            if (isatty(STDIN_FILENO)) {
                const duckpass::SecureString p1 = terminal_utils::read_password("Enter password for '" + *name + "': ");
                const duckpass::SecureString p2 = terminal_utils::read_password("Retype password for '" + *name + "': ");

                if (p1 != p2) {
                    std::cerr << "Error: Passwords do not match. Entry not added." << std::endl;
                    return;
                }
                password = p1;
            } else {
                // Read from STDIN if not a TTY (for piping)
                char c;
                while (std::cin.get(c) && c != '\n' && c != '\r') {
                    password.push_back(c);
                }
            }

            duckpass::ipc::EntryData entry;
            entry.service.assign(name->data(), name->size());
            entry.username.assign(username->data(), username->size());
            entry.password = std::move(password);
            std::string err;
            if (client.add_entry(entry, err)) {
                std::cout << "Success: Entry '" << *name << "' added." << std::endl;
            } else {
                std::cerr << "Error: " << err << std::endl;
            }
            return;
        }

        duckpass::SecureString password;
        if (isatty(STDIN_FILENO)) {
            const duckpass::SecureString p1 = terminal_utils::read_password("Enter password for '" + *name + "': ");
            const duckpass::SecureString p2 = terminal_utils::read_password("Retype password for '" + *name + "': ");

            if (p1 != p2) {
                std::cerr << "Error: Passwords do not match. Entry not added." << std::endl;
                return;
            }
            password = p1;
        } else {
            // Read from STDIN if not a TTY (for piping)
            char c;
            while (std::cin.get(c) && c != '\n' && c != '\r') {
                password.push_back(c);
            }
        }

        const duckpass::SecureString master_password = utils::get_password_silent("Enter master password: ");

        try {
            duckpass::service::VaultService vault_service(vault_path, master_password);
            duckpass::SecureString service_name(name->begin(), name->end());
            duckpass::SecureString s_username(username->begin(), username->end());

            vault_service.add_entry(std::move(service_name), std::move(s_username), std::move(password));

            std::cout << "Success: Entry '" << *name << "' added." << std::endl;
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
