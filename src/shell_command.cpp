#include "duckpass/shell_command.h"

#include <algorithm>
#include <iostream>
#include <string_view>
#include <vector>

#include "duckpass/audit_engine.h"
#include "duckpass/clipboard_handler.h"
#include "duckpass/config_handler.h"
#include "duckpass/crypto.h"
#include "duckpass/terminal_utils.h"
#include "duckpass/totp.h"
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
                services.push_back(entry.service.unprotect());
            }
        };

        // Initialize supported shell commands
        const char* base_cmds[] = {"add", "get", "delete", "list", "otp", "generate", "edit", "update", "rekey", "audit", "exit", "help", "clear"};
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
                          << "  list [query]       List all services or fuzzy search\n"
                          << "  get <service>      Copy password for a service to clipboard\n"
                          << "  get --show <svc>   Show password in terminal\n"
                          << "  otp <service>      Display and copy current 2FA TOTP code\n"
                          << "  delete <service>   Delete a service entry\n"
                          << "  add                Add a new entry interactively\n"
                          << "  edit <service>     Edit an existing entry interactively\n"
                          << "  generate [length]  Generate a cryptographically strong password\n"
                          << "  rekey              Change master password for the vault\n"
                          << "  audit [--online]   Perform a security audit of your vault\n"
                          << "  clear              Clear screen\n"
                          << "  exit               Exit interactive shell\n";
            } else if (input_view == "list" || input_view.starts_with("list ")) {
                std::string_view query;
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
                        duckpass::SecureString s = entry.service.unprotect();
                        std::cout.write(s.data(), s.size());
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
                    duckpass::SecureString p = entry->password.unprotect();
                    if (show) {
                        std::cout << "Password: ";
                        std::cout.write(p.data(), p.size());
                        std::cout << "\n";
                    } else {
                        if (clipboard_handler::set_text(p)) {
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

                // 4. Optional 2FA Secret
                duckpass::SecureString s_totp =
                    duckpass::terminal::read_line_interactive("2FA Secret (Base32, optional - press ENTER to skip): ", {}, {});
                trim_secure(s_totp);

                try {
                    std::string const display_name(s_service.begin(), s_service.end());
                    vault_service->add_entry(std::move(s_service), std::move(s_username), std::move(s_password), std::move(s_totp));

                    std::cout << "\033[32mSuccessfully added entry for " << display_name << "!\033[0m" << std::endl;

                    refresh_services();
                } catch (const std::exception& e) {
                    std::cerr << "\033[31mError adding entry: " << e.what() << "\033[0m" << std::endl;
                }
            } else if (input_view.starts_with("otp ")) {
                std::string_view service = input_view.substr(4);
                while (!service.empty() && std::isspace(service.front())) service.remove_prefix(1);
                duckpass::SecureString s_name(service.data(), service.size());
                try {
                    uint32_t remaining = 0;
                    std::string code = vault_service->get_totp_code(s_name, &remaining);
                    std::cout << "2FA Code for '" << service << "': \033[1;32m" << code << "\033[0m" << " (expires in " << remaining << "s)\n";
                    duckpass::SecureString code_sec(code.c_str());
                    if (clipboard_handler::set_text(code_sec)) {
                        std::cout << "[✓] 2FA code copied to clipboard (clearing in 15s).\n";
                        clipboard_handler::clear_after_delay(std::chrono::seconds(15));
                    }
                } catch (const std::exception& e) {
                    std::cerr << "\033[31mError: " << e.what() << "\033[0m\n";
                }
            } else if (input_view == "generate" || input_view.starts_with("generate ")) {
                int length = 16;
                if (input_view.starts_with("generate ")) {
                    std::string_view arg = input_view.substr(9);
                    while (!arg.empty() && std::isspace(arg.front())) arg.remove_prefix(1);
                    try {
                        length = std::stoi(std::string(arg));
                    } catch (...) {
                        std::cerr << "\033[31mInvalid length. Defaulting to 16.\033[0m\n";
                        length = 16;
                    }
                }
                try {
                    auto pwd = crypto_handler::generate_password(length);
                    std::cout << "Generated Password: \033[1;36m";
                    std::cout.write(pwd.data(), pwd.size());
                    std::cout << "\033[0m\n";
                    if (clipboard_handler::set_text(pwd)) {
                        std::cout << "[✓] Password copied to clipboard (clearing in 30s).\n";
                        clipboard_handler::clear_after_delay(std::chrono::seconds(30));
                    }
                } catch (const std::exception& e) {
                    std::cerr << "\033[31mError: " << e.what() << "\033[0m\n";
                }
            } else if (input_view.starts_with("edit ") || input_view.starts_with("update ")) {
                size_t prefix_len = input_view.starts_with("edit ") ? 5 : 7;
                std::string_view service = input_view.substr(prefix_len);
                while (!service.empty() && std::isspace(service.front())) service.remove_prefix(1);
                duckpass::SecureString s_service(service.data(), service.size());
                auto entry_opt = vault_service->get_entry(s_service);
                if (!entry_opt) {
                    std::cout << "\033[31mService not found.\033[0m\n";
                } else {
                    auto trim_sec = [](duckpass::SecureString& s) {
                        s.erase(s.begin(), std::ranges::find_if(s, [](const unsigned char ch) { return !std::isspace(ch); }));
                        s.erase(std::ranges::find_if(s.rbegin(), s.rend(), [](const unsigned char ch) { return !std::isspace(ch); }).base(), s.end());
                    };
                    std::cout << "Editing '" << service << "'. (Press ENTER to keep current value)\n";
                    duckpass::SecureString current_user = entry_opt->username.unprotect();
                    std::cout << "Current username: " << current_user << "\n";
                    duckpass::SecureString new_user = duckpass::terminal::read_line_interactive("New username: ", {}, {});
                    trim_sec(new_user);

                    std::cout << "Enter new password (or leave empty to keep current, or 'g' to auto-generate):\n";
                    duckpass::SecureString new_pass = utils::get_password_silent("New password: ");

                    duckpass::SecureString current_totp = entry_opt->totp_secret.unprotect();
                    if (!current_totp.empty()) {
                        std::cout << "Current 2FA secret is configured.\n";
                    }
                    duckpass::SecureString new_totp = duckpass::terminal::read_line_interactive("New 2FA Secret (Base32, optional): ", {}, {});
                    trim_sec(new_totp);

                    std::optional<duckpass::SecureString> opt_user = new_user.empty() ? std::nullopt : std::make_optional(new_user);
                    std::optional<duckpass::SecureString> opt_pass;
                    if (!new_pass.empty()) {
                        if (std::string_view(new_pass.data(), new_pass.size()) == "g") {
                            auto gen_pw = crypto_handler::generate_password(20);
                            std::cout << "[✓] Auto-generated secure password: " << gen_pw << "\n";
                            opt_pass = std::move(gen_pw);
                        } else {
                            opt_pass = std::move(new_pass);
                        }
                    }
                    std::optional<duckpass::SecureString> opt_totp = new_totp.empty() ? std::nullopt : std::make_optional(new_totp);

                    try {
                        vault_service->update_entry(s_service, opt_user, opt_pass, opt_totp);
                        std::cout << "\033[32mSuccessfully updated entry for " << service << "!\033[0m\n";
                    } catch (const std::exception& e) {
                        std::cerr << "\033[31mError updating entry: " << e.what() << "\033[0m\n";
                    }
                }
            } else if (input_view == "rekey") {
                duckpass::SecureString curr_pwd = utils::get_password_silent("Enter CURRENT Master Password: ");
                duckpass::SecureString new_pwd1 = utils::get_password_silent("Enter NEW Master Password: ");
                duckpass::SecureString new_pwd2 = utils::get_password_silent("Re-enter NEW Master Password: ");
                if (new_pwd1 != new_pwd2) {
                    std::cerr << "\033[31mError: Passwords do not match. Rekey cancelled.\033[0m\n";
                } else if (new_pwd1.empty()) {
                    std::cerr << "\033[31mError: New master password cannot be empty.\033[0m\n";
                } else {
                    try {
                        vault_service->rekey(new_pwd1);
                        std::cout << "\033[32m[✓] Master password changed and vault re-encrypted successfully!\033[0m\n";
                    } catch (const std::exception& e) {
                        std::cerr << "\033[31mError rekeying vault: " << e.what() << "\033[0m\n";
                    }
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
