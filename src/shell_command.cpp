#include "duckpass/shell_command.h"

#include <algorithm>
#include <iostream>
#include <string_view>
#include <vector>

#include "duckpass/audit_engine.h"
#include "duckpass/clipboard_handler.h"
#include "duckpass/config_handler.h"
#include "duckpass/terminal_utils.h"
#include "duckpass/utils.h"
#include "duckpass/vault_service.h"

namespace duckpass::shell {

    /**
     * @brief Sets up the 'shell' subcommand for the application.
     *
     * This subcommand enables an interactive shell mode, allowing users
     * to perform multiple vault operations without restarting the program.
     * It features tab-based auto-completion for commands and service names.
     */
    void setup(CLI::App& app) {
        const auto shell_cmd = app.add_subcommand("shell", "Start an interactive shell with auto-completion");

        shell_cmd->callback([]() {
            const config_handler config;
            const auto vault_path = config.get_vault_path();

            // Verify vault existence before entering interactive mode
            if (!vault_handler::vault_exists(vault_path)) {
                std::cerr << "Error: Vault file not found. Please use 'init' command to create a new vault." << std::endl;
                return;
            }

            // Prompt for master password once at the start of the session
            const duckpass::SecureString master_password = utils::get_password_silent("Enter master password: ");
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
        std::unique_ptr<duckpass::service::VaultService> vault_service;
        try {
            vault_service = std::make_unique<duckpass::service::VaultService>(vault_path, master_password);
        } catch (const std::exception& e) {
            std::cerr << "Error loading vault: " << e.what() << std::endl;
            return;
        }

        std::vector<duckpass::SecureString> commands;
        std::vector<duckpass::SecureString> services;

        // Helper to refresh the service list for auto-completion
        const auto refresh_services = [&]() {
            services.clear();
            for (const auto& entry : vault_service->get_all_entries()) {
                services.push_back(entry.service);
            }
        };

        // Initialize supported shell commands
        const char* base_cmds[] = {"add", "get", "delete", "list", "audit", "exit", "help", "clear"};
        for (const char* cmd : base_cmds) {
            duckpass::SecureString s_cmd;
            s_cmd.append(cmd);
            commands.push_back(s_cmd);
        }

        refresh_services();

        // Main command-response loop
        while (true) {
            // Read input line with custom terminal handling (supports TAB completion)
            const duckpass::SecureString input = duckpass::terminal::read_line_interactive("duckpass> ", commands, services);
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
                          << "  list [query]     List all services or fuzzy search\n"
                          << "  get <service>    Copy password for a service to clipboard\n"
                          << "  get --show <svc> Show password in terminal\n"
                          << "  delete <service> Delete a service entry\n"
                          << "  add              Add a new entry interactively\n"
                          << "  audit [--online] Perform a security audit of your vault\n"
                          << "  clear            Clear screen\n"
                          << "  exit             Exit interactive shell\n";
            } else if (input_view == "list" || input_view.starts_with("list ")) {
                std::string_view query = "";
                if (input_view.starts_with("list ")) {
                    query = input_view.substr(5);
                    while (!query.empty() && std::isspace(query.front())) query.remove_prefix(1);
                }

                const auto entries = vault_service->list_entries(query);
                if (entries.empty()) {
                    if (query.empty()) {
                        std::cout << "Vault is empty." << std::endl;
                    } else {
                        std::cout << "No services found matching '" << query << "'.\n";
                    }
                } else {
                    if (query.empty()) {
                        std::cout << "--- List of all services ---\n";
                    } else {
                        std::cout << "--- Fuzzy Search Results ---\n";
                    }
                    for (const auto& entry : entries) {
                        std::cout << "- ";
                        std::cout.write(entry.service.data(), entry.service.size());
                        std::cout << "\n";
                    }
                }
            } else if (input_view.starts_with("get ")) {
                // Parse service name from 'get <service>' or 'get --show <service>'
                std::string_view args = input_view.substr(4);
                while (!args.empty() && std::isspace(args.front())) {
                    args.remove_prefix(1);
                }

                bool show = false;
                if (args.starts_with("--show ")) {
                    show = true;
                    args = args.substr(7);
                    while (!args.empty() && std::isspace(args.front())) {
                        args.remove_prefix(1);
                    }
                }

                const auto entry = vault_service->get_entry(duckpass::SecureString(args.data(), args.size()));
                if (entry) {
                    if (show) {
                        std::cout << "Password: ";
                        std::cout.write(entry->password.data(), entry->password.size());
                        std::cout << "\n";
                    } else {
                        if (clipboard_handler::set_text(entry->password)) {
                            std::cout << "Password copied to clipboard. It will be cleared in 30 seconds." << std::endl;
                            clipboard_handler::clear_after_delay(std::chrono::seconds(30));
                        } else {
                            std::cerr << "Error: Could not copy to clipboard. Use 'get --show <service>' to print." << std::endl;
                        }
                    }
                } else {
                    std::cout << "Service not found." << std::endl;
                }
            } else if (input_view.starts_with("delete ")) {
                // Parse service name from 'delete <service>'
                std::string_view service = input_view.substr(7);
                while (!service.empty() && std::isspace(service.front())) {
                    service.remove_prefix(1);
                }

                try {
                    vault_service->delete_entry(duckpass::SecureString(service.data(), service.size()));
                    std::cout << "Entry deleted successfully." << std::endl;
                    refresh_services();  // Update completion candidates
                } catch (const std::invalid_argument&) {
                    std::cout << "Service not found." << std::endl;
                } catch (const std::exception& e) {
                    std::cerr << "Error saving vault: " << e.what() << std::endl;
                }
            } else if (input_view == "add") {
                duckpass::SecureString s_service, s_username, s_password;

                auto trim_secure = [](duckpass::SecureString& s) {
                    s.erase(s.begin(), std::ranges::find_if(s, [](const unsigned char ch) { return !std::isspace(ch); }));
                    s.erase(std::ranges::find_if(s.rbegin(), s.rend(), [](const unsigned char ch) { return !std::isspace(ch); }).base(), s.end());
                };

                // 1. Validation loop for Service Name
                while (true) {
                    s_service = duckpass::terminal::read_line_interactive("Service: ", {}, {});
                    trim_secure(s_service);

                    if (s_service.empty()) {
                        std::cerr << "\033[31mError: Service name cannot be empty or just spaces.\033[0m" << std::endl;
                        continue;
                    }

                    if (vault_service->get_entry(s_service)) {
                        std::cerr << "\033[31mError: Service '" << std::string(s_service.begin(), s_service.end())
                                  << "' already exists. Please delete it first if you want to update.\033[0m" << std::endl;
                        continue;  // Go back to the main shell prompt
                    }
                    break;
                }

                // 2. Validation loop for Username
                while (true) {
                    s_username = duckpass::terminal::read_line_interactive("Username: ", {}, {});
                    trim_secure(s_username);

                    if (s_username.empty()) {
                        std::cerr << "\033[31mError: Username cannot be empty or just spaces. Please try again.\033[0m" << std::endl;
                        continue;
                    }
                    break;
                }

                // 3. Validation loop for Password
                while (true) {
                    s_password = utils::get_password_silent("Password: ");
                    // We don't trim password as spaces might be intentional parts of a passphrase
                    if (s_password.empty()) {
                        std::cerr << "\033[31mError: Password cannot be empty. Please try again.\033[0m" << std::endl;
                        continue;
                    }
                    break;
                }

                try {
                    std::string const display_name(s_service.begin(), s_service.end());
                    vault_service->add_entry(std::move(s_service), std::move(s_username), std::move(s_password));

                    std::cout << "\033[32mSuccessfully added entry for " << display_name << "!\033[0m" << std::endl;

                    refresh_services();
                } catch (const std::exception& e) {
                    std::cerr << "\033[31mError adding entry: " << e.what() << "\033[0m" << std::endl;
                }
            } else if (input_view == "audit" || input_view.starts_with("audit ")) {
                audit::AuditEngine::Config config;
                config.check_online = input_view.find("--online") != std::string_view::npos;
                config.stale_threshold_seconds = 365 * 24 * 3600;

                try {
                    const audit::ScopedZxcvbn zxcvbn;
                    std::cout << "Auditing " << vault_service->get_all_entries().size() << " entries...\n";
                    if (config.check_online) {
                        std::cout << "(Online check enabled. This may take a moment...)\n";
                    }
                    const auto report = vault_service->audit_vault(config);
                    std::cout << report;
                } catch (const std::exception& e) {
                    std::cerr << "Audit failed: " << e.what() << "\n";
                }
            } else {
                std::cout << "Unknown command: " << input_view << ". Type 'help' for a list of commands." << std::endl;
            }
        }
    }

}  // namespace duckpass::shell
