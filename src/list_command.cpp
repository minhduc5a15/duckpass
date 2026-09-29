#include "duckpass/list_command.h"

#include <iostream>
#include <vector>

#include "CLI/CLI.hpp"
#include "duckpass/config_handler.h"
#include "duckpass/exceptions.h"
#include "duckpass/ipc.h"
#include "duckpass/terminal_utils.h"
#include "duckpass/vault_service.h"

namespace list_command {

    void setup(CLI::App& app) {
        const auto list_cmd = app.add_subcommand("list", "List or fuzzy search stored accounts");

        static std::string query;
        list_cmd->add_option("query", query, "Fuzzy search query");

        list_cmd->callback([]() {
            // 1. Try DuckPass Agent if active
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

                auto entries = client.list_entries(query);
                if (entries.empty()) {
                    if (query.empty()) {
                        std::cout << "The vault is currently empty.\n";
                    } else {
                        std::cout << "No services found matching the query '" << query << "'.\n";
                    }
                    return;
                }

                if (query.empty()) {
                    std::cout << "--- List of all services ---\n";
                }
                for (const auto& [svc, usr] : entries) {
                    std::cout << "Service: " << svc << " | Username: " << usr << "\n";
                }
                return;
            }

            // 2. Standalone fallback
            const duckpass::SecureString master_password = terminal_utils::read_password("Enter Master Password: ");

            try {
                const config_handler config;
                const auto vault_path = config.get_vault_path();

                if (!vault_handler::vault_exists(vault_path)) {
                    std::cerr << "Error: Vault has not been initialized.\n"
                              << "Please run 'duckpass init' to create a new storage.\n";
                    return;
                }

                const duckpass::service::VaultService vault_service(vault_path, master_password);
                const auto entries = vault_service.list_entries(query);

                if (entries.empty()) {
                    if (query.empty()) {
                        std::cout << "The vault is currently empty.\n";
                    } else {
                        std::cout << "No services found matching the query '" << query << "'.\n";
                    }
                    return;
                }

                if (query.empty()) {
                    std::cout << "--- List of all services ---\n";
                    for (const auto& entry : entries) {
                        std::cout << "Service: " << entry.service.unprotect() << " | Username: " << entry.username.unprotect() << "\n";
                    }
                } else {
                    for (const auto& res : entries) {
                        std::cout << "Service: " << res.service.unprotect() << " | Username: " << res.username.unprotect() << "\n";
                    }
                }
            } catch (const duckpass::wrong_password_error& e) {
                std::cerr << "Error: " << e.what() << std::endl;
            } catch (const std::exception& e) {
                std::cerr << "Error: " << e.what() << "\n";
            }
        });
    }
}  // namespace list_command
