#include "duckpass/list_command.h"

#include <algorithm>
#include <iostream>
#include <vector>

#include "CLI/CLI.hpp"
#include "duckpass/config_handler.h"
#include "duckpass/exceptions.h"
#include "duckpass/terminal_utils.h"
#include "duckpass/utils.h"
#include "duckpass/vault.h"

namespace list_command {

    struct MatchResult {
        vault_handler::VaultEntry entry;
        int score;
    };

    void setup(CLI::App& app) {
        auto list_cmd = app.add_subcommand("list", "List or fuzzy search stored accounts");

        static std::string query;
        list_cmd->add_option("query", query, "Fuzzy search query");

        list_cmd->callback([]() {
            duckpass::SecureString master_password = terminal_utils::read_password("Enter Master Password: ");

            try {
                config_handler config;
                auto vault_path = config.get_vault_path();

                if (!vault_handler::vault_exists(vault_path)) {
                    std::cerr << "Error: Vault has not been initialized.\n"
                              << "Please run 'duckpass init' to create a new storage.\n";
                    return;
                }

                auto vault = vault_handler::load_vault(vault_path, master_password);
                const auto& entries = vault.get_all_entries();

                if (entries.empty()) {
                    std::cout << "The vault is currently empty.\n";
                    return;
                }

                if (query.empty()) {
                    std::cout << "--- List of all services ---\n";
                    for (const auto& entry : entries) {
                        std::cout << "Service: " << entry.service << " | Username: " << entry.username << "\n";
                    }
                } else {
                    std::vector<MatchResult> filtered_results;

                    for (const auto& entry : entries) {
                        std::string service_str(entry.service.begin(), entry.service.end());
                        int score = utils::fuzzy_match(query, service_str);

                        if (score > 0) {
                            filtered_results.push_back({entry, score});
                        }
                    }

                    if (filtered_results.empty()) {
                        std::cout << "No services found matching the query '" << query << "'.\n";
                        return;
                    }

                    std::ranges::sort(filtered_results, [](const MatchResult& a, const MatchResult& b) { return a.score > b.score; });
                    for (const auto& res : filtered_results) {
                        std::cout << "[Score: " << res.score << "] " << "Service: " << res.entry.service << " | Username: " << res.entry.username
                                  << "\n";
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
