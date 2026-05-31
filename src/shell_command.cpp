#include "duckpass/shell_command.h"

#include <iostream>
#include <string_view>
#include <vector>

#include "duckpass/config_handler.h"
#include "duckpass/terminal_utils.h"
#include "duckpass/utils.h"
#include "duckpass/vault.h"

namespace duckpass::shell {

    /**
     * @brief Sets up the 'shell' subcommand for the application.
     * 
     * This subcommand enables an interactive shell mode, allowing users
     * to perform multiple vault operations without restarting the program.
     * It features tab-based auto-completion for commands and service names.
     */
    void setup(CLI::App& app) {
        auto shell_cmd = app.add_subcommand("shell", "Start an interactive shell with auto-completion");

        shell_cmd->callback([]() {
            config_handler config;
            auto vault_path = config.get_vault_path();

            // Verify vault existence before entering interactive mode
            if (!vault_handler::vault_exists(vault_path)) {
                std::cerr << "Error: Vault file not found. Please create a vault first using 'add'." << std::endl;
                return;
            }

            // Prompt for master password once at the start of the session
            duckpass::SecureString master_password = get_password_silent("Enter master password: ");
            run_interactive_shell(vault_path, master_password);
        });
    }

    /**
     * @brief Runs the main interactive shell loop.
     * 
     * @param vault_path Path to the vault file.
     * @param master_password Authenticated master password.
     */
    void run_interactive_shell(const std::filesystem::path& vault_path, const duckpass::SecureString& master_password) {
        vault_handler::Vault vault;
        try {
            // Load and decrypt the vault into memory
            vault = vault_handler::load_vault(vault_path, master_password);
        } catch (const std::exception& e) {
            std::cerr << "Error loading vault: " << e.what() << std::endl;
            return;
        }

        std::vector<duckpass::SecureString> commands;
        std::vector<duckpass::SecureString> services;

        // Helper to refresh the service list for auto-completion
        auto refresh_services = [&]() {
            services.clear();
            for (const auto& entry : vault.get_all_entries()) {
                services.push_back(entry.service);
            }
        };

        // Initialize supported shell commands
        const char* base_cmds[] = {"add", "get", "delete", "list", "exit", "help", "clear"};
        for (const char* cmd : base_cmds) {
            duckpass::SecureString s_cmd;
            s_cmd.append(cmd);
            commands.push_back(s_cmd);
        }

        refresh_services();

        // Main command-response loop
        while (true) {
            // Read input line with custom terminal handling (supports TAB completion)
            duckpass::SecureString input = duckpass::terminal::read_line_interactive("duckpass> ", commands, services);
            std::string_view input_view(input.data(), input.size());

            // Trim leading/trailing whitespace
            while (!input_view.empty() && std::isspace(input_view.front())) {
                input_view.remove_prefix(1);
            }
            while (!input_view.empty() && std::isspace(input_view.back())) {
                input_view.remove_suffix(1);
            }

            if (input_view.empty()) {
                continue;
            }

            // Command dispatching logic
            if (input_view == "exit") {
                break;
            } else if (input_view == "clear") {
                std::cout << "\033[H\033[J" << std::flush;  // ANSI Escape Sequence to clear screen
            } else if (input_view == "help") {
                std::cout << "Available commands:\n"
                          << "  list             List all services\n"
                          << "  get <service>    Get password for a service\n"
                          << "  delete <service> Delete a service entry\n"
                          << "  add              Add a new entry (use main CLI)\n"
                          << "  clear            Clear screen\n"
                          << "  exit             Exit interactive shell\n";
            } else if (input_view == "list") {
                auto entries = vault.get_all_entries();
                if (entries.empty()) {
                    std::cout << "Vault is empty." << std::endl;
                } else {
                    for (const auto& entry : entries) {
                        std::cout << "- ";
                        std::cout.write(entry.service.data(), entry.service.size());
                        std::cout << "\n";
                    }
                }
            } else if (input_view.starts_with("get ")) {
                // Parse service name from 'get <service>'
                std::string_view service = input_view.substr(4);
                while (!service.empty() && std::isspace(service.front())) {
                    service.remove_prefix(1);
                }

                auto entry = vault.get_entry(duckpass::SecureString(service.data(), service.size()));
                if (entry) {
                    std::cout << "Password: ";
                    std::cout.write(entry->password.data(), entry->password.size());
                    std::cout << "\n";
                } else {
                    std::cout << "Service not found." << std::endl;
                }
            } else if (input_view.starts_with("delete ")) {
                // Parse service name from 'delete <service>'
                std::string_view service = input_view.substr(7);
                while (!service.empty() && std::isspace(service.front())) {
                    service.remove_prefix(1);
                }

                if (vault.remove_entry(duckpass::SecureString(service.data(), service.size()))) {
                    try {
                        // Persist changes back to disk
                        vault_handler::save_vault(vault_path, vault, master_password);
                        std::cout << "Entry deleted successfully." << std::endl;
                        refresh_services();  // Update completion candidates
                    } catch (const std::exception& e) {
                        std::cerr << "Error saving vault: " << e.what() << std::endl;
                    }
                } else {
                    std::cout << "Service not found." << std::endl;
                }
            } else if (input_view == "add") {
                // Placeholder for complex input handling
                std::cout << "Adding new entry. Please use the 'add' command from the main CLI for now." << std::endl;
            } else {
                std::cout << "Unknown command: " << input_view << ". Type 'help' for a list of commands." << std::endl;
            }
        }
    }

}  // namespace duckpass::shell
