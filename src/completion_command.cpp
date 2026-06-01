#include "duckpass/completion_command.h"

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "duckpass/config_handler.h"
#include "duckpass/vault.h"

namespace completion_command {

    /**
     * @brief Generates a Bash completion script by inspecting the CLI11 App structure.
     */
    void generate_bash_completion(const CLI::App* app) {
        std::string app_name = app->get_name();
        if (app_name.empty()) app_name = "duckpass";

        std::cout << "_" << app_name << "_completion() {\n"
                  << "    local cur prev opts\n"
                  << "    COMPREPLY=()\n"
                  << "    cur=\"${COMP_WORDS[COMP_CWORD]}\"\n"
                  << "    prev=\"${COMP_WORDS[COMP_CWORD-1]}\"\n"
                  << "    opts=\"";

        // Collect top-level subcommands
        for (const auto* sub : app->get_subcommands({})) {
            if (!sub->get_name().empty()) {
                std::cout << sub->get_name() << " ";
            }
        }

        // Collect top-level options
        for (const auto* opt : app->get_options({})) {
            for (const auto& s : opt->get_snames()) std::cout << "-" << s << " ";
            for (const auto& l : opt->get_lnames()) std::cout << "--" << l << " ";
        }

        std::cout << "\"\n\n"
                  << "    case \"$prev\" in\n";

        // Generate cases for each subcommand to provide their specific options
        for (const auto* sub : app->get_subcommands({})) {
            if (sub->get_name().empty()) continue;

            std::cout << "        " << sub->get_name() << ")\n"
                      << "            local subopts=\"";
            for (const auto* opt : sub->get_options({})) {
                for (const auto& s : opt->get_snames()) std::cout << "-" << s << " ";
                for (const auto& l : opt->get_lnames()) std::cout << "--" << l << " ";
            }
            std::cout << "\"\n"
                      << "            COMPREPLY=( $(compgen -W \"$subopts\" -- \"$cur\") )\n"
                      << "            return 0\n"
                      << "            ;;\n";
        }

        std::cout << "        *)\n"
                  << "            ;;\n"
                  << "    esac\n\n"
                  << "    COMPREPLY=( $(compgen -W \"$opts\" -- \"$cur\") )\n"
                  << "    return 0\n"
                  << "}\n"
                  << "complete -F _" << app_name << "_completion " << app_name << "\n";
    }

    void setup(CLI::App& app) {
        auto completion_cmd = app.add_subcommand("completion", "Generate shell completion script");

        auto shell_type = std::make_shared<std::string>("bash");
        completion_cmd->add_option("shell", *shell_type, "The shell type (bash)")->check(CLI::IsMember({"bash"}));

        completion_cmd->callback([&app, shell_type]() {
            if (*shell_type == "bash") {
                generate_bash_completion(&app);
            }
        });

        auto raw_list_cmd = app.add_subcommand("__list_services_raw", "Internal command for auto-completion")->group("");

        raw_list_cmd->callback([]() {
            const char* env_p = std::getenv("DUCKPASS_MASTER_PASSWORD");
            if (!env_p) return;

            duckpass::SecureString master_password(env_p);
            try {
                config_handler config;
                auto vault_path = config.get_vault_path();

                if (!vault_handler::vault_exists(vault_path)) return;

                auto vault = vault_handler::load_vault(vault_path, master_password);
                for (const auto& entry : vault.get_all_entries()) {
                    std::cout << entry.service << "\n";
                }
            } catch (...) {
                // Suppress all exceptions
            }
        });
    }
}  // namespace completion_command
