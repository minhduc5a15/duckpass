#include "duckpass/get_command.h"

#include <chrono>
#include <iostream>

#include "CLI/CLI.hpp"
#include "duckpass/clipboard_handler.h"
#include "duckpass/config_handler.h"
#include "duckpass/exceptions.h"
#include "duckpass/ipc.h"
#include "duckpass/utils.h"
#include "duckpass/vault_service.h"
void get_command::setup(CLI::App &app) {
    const auto get_cmd = app.add_subcommand("get", "Get an entry from the vault");

    const auto name = std::make_shared<std::string>();
    const auto show_password = std::make_shared<bool>(false);

    get_cmd->add_option("name", *name, "The name of the entry to retrieve")->required();
    get_cmd->add_flag("-s,--show", *show_password, "Show the password in terminal instead of copying to clipboard");

    get_cmd->callback([name, show_password]() {
        const duckpass::SecureString service_name(name->begin(), name->end());

        // 1. Try resolving via DuckPass Agent if active
        duckpass::ipc::IpcClient client;
        if (client.is_agent_available()) {
            auto status = client.get_status();
            if (status && !status->is_unlocked) {
                const duckpass::SecureString master_password = utils::get_password_silent("Agent is locked. Enter master password: ");
                std::string unlock_err;
                if (!client.unlock(master_password, unlock_err)) {
                    std::cerr << "Error: " << unlock_err << std::endl;
                    return;
                }
            }

            std::string err;
            auto entry_opt = client.get_entry(service_name, err);
            if (!entry_opt) {
                std::cerr << "Error: " << (err.empty() ? "Entry '" + *name + "' not found." : err) << std::endl;
                return;
            }

            if (*show_password) {
                std::cout << "Entry: " << entry_opt->service << std::endl;
                std::cout << "  Username: " << entry_opt->username << std::endl;
                std::cout << "  Password: " << entry_opt->password << std::endl;
            } else {
                if (clipboard_handler::set_text(entry_opt->password)) {
                    std::cout << "Password for '" << *name << "' copied to clipboard." << std::endl;
                    constexpr int delay_seconds = 30;
                    std::cout << "It will be cleared automatically in " << delay_seconds << " seconds." << std::endl;
                    clipboard_handler::clear_after_delay(std::chrono::seconds(delay_seconds));
                } else {
                    std::cerr << "Error: Could not copy to clipboard." << std::endl;
                    std::cout << "Use --show to print to terminal instead." << std::endl;
                }
            }
            return;
        }

        // 2. Standalone fallback (direct vault file access)
        const config_handler config;
        const auto vault_path = config.get_vault_path();

        if (!vault_handler::vault_exists(vault_path)) {
            std::cerr << "Error: Vault has not been initialized.\n"
                      << "Please run 'duckpass init' to create a new storage.\n";
            return;
        }

        const duckpass::SecureString master_password = utils::get_password_silent("Enter master password: ");
        try {
            const duckpass::service::VaultService vault_service(vault_path, master_password);
            const duckpass::SecureString service_name(name->begin(), name->end());
            const auto entry_opt = vault_service.get_entry(service_name);

            if (!entry_opt) {
                std::cerr << "Error: Entry '" << *name << "' not found." << std::endl;
                return;
            }

            const auto &entry = *entry_opt;
            const duckpass::SecureString service_unprotected = entry.service.unprotect();
            const duckpass::SecureString username = entry.username.unprotect();
            const duckpass::SecureString password = entry.password.unprotect();

            if (*show_password) {
                std::cout << "Entry: " << std::string_view(service_unprotected.data(), service_unprotected.size()) << std::endl;
                std::cout << "  Username: " << std::string_view(username.data(), username.size()) << std::endl;
                std::cout << "  Password: " << std::string_view(password.data(), password.size()) << std::endl;
            } else {
                if (clipboard_handler::set_text(password)) {
                    std::cout << "Password for '" << *name << "' copied to clipboard." << std::endl;

                    constexpr int delay_seconds = 30;
                    std::cout << "It will be cleared automatically in " << delay_seconds << " seconds." << std::endl;
                    clipboard_handler::clear_after_delay(std::chrono::seconds(delay_seconds));
                } else {
                    std::cerr << "Error: Could not copy to clipboard." << std::endl;
                    std::cout << "Use --show to print to terminal instead." << std::endl;
                }
            }
        } catch (const duckpass::wrong_password_error &e) {
            std::cerr << "Error: " << e.what() << std::endl;
        } catch (const std::exception &e) {
            std::cerr << "Error: " << e.what() << std::endl;
        }
    });
}
