#include "duckpass/audit_command.h"

#include <iostream>

#include "duckpass/audit_engine.h"
#include "duckpass/config_handler.h"
#include "duckpass/terminal_utils.h"
#include "duckpass/vault_service.h"

namespace audit {

    void setup_audit_command(CLI::App& app) {
        const auto config = std::make_shared<AuditEngine::Config>();
        const auto stale_days = std::make_shared<int>(365);
        const auto audit_cmd = app.add_subcommand("audit", "Perform a security audit of your vault.");

        audit_cmd->add_flag("--online", config->check_online, "Check passwords against HaveIBeenPwned API (requires internet).");
        audit_cmd->add_option("--stale-days", *stale_days, "Number of days before a password is considered stale.")->capture_default_str();

        audit_cmd->callback([config, stale_days]() {
            try {
                config->stale_threshold_seconds = static_cast<uint64_t>(*stale_days) * 24 * 3600;

                const config_handler cfg;
                const auto vault_path = cfg.get_vault_path();
                if (!vault_handler::vault_exists(vault_path)) {
                    std::cerr << "Vault not found. Please initialize it first with 'init'.\n";
                    throw CLI::RuntimeError(1);
                }

                const auto master_password = terminal_utils::read_password("Enter master password: ");
                const duckpass::service::VaultService vault_service(vault_path, master_password);

                const ScopedZxcvbn zxcvbn;

                std::cout << "Auditing " << vault_service.get_all_entries().size() << " entries...\n";
                if (config->check_online) {
                    std::cout << "(Online check enabled. This may take a moment...)\n";
                }

                const auto report = vault_service.audit_vault(*config);
                std::cout << report;

            } catch (const CLI::RuntimeError&) {
                throw;
            } catch (const std::exception& e) {
                std::cerr << "Error: " << e.what() << "\n";
                throw CLI::RuntimeError(1);
            }
        });
    }

}  // namespace audit
