#include "duckpass/audit_command.h"
#include "duckpass/audit_engine.h"
#include "duckpass/terminal_utils.h"
#include "duckpass/utils.h"
#include "duckpass/vault.h"
#include "duckpass/config_handler.h"
#include "zxcvbn.h"

#include <iostream>
#include <iomanip>
#include <filesystem>
#include <unistd.h>
#include <limits.h>

namespace audit {

    void setup_audit_command(CLI::App& app) {
        auto config = std::make_shared<AuditEngine::Config>();
        auto stale_days = std::make_shared<int>(365);
        auto audit_cmd = app.add_subcommand("audit", "Perform a security audit of your vault.");

        audit_cmd->add_flag("--online", config->check_online, "Check passwords against HaveIBeenPwned API (requires internet).");
        audit_cmd->add_option("--stale-days", *stale_days, "Number of days before a password is considered stale.")
            ->capture_default_str();

        audit_cmd->callback([config, stale_days]() {
            try {
                config->stale_threshold_seconds = static_cast<uint64_t>(*stale_days) * 24 * 3600;

                config_handler cfg;
                auto vault_path = cfg.get_vault_path();
                if (!vault_handler::vault_exists(vault_path)) {
                    std::cerr << "Vault not found. Please initialize it first with 'init'.\n";
                    throw CLI::RuntimeError(1);
                }

                auto master_password = terminal_utils::read_password("Enter master password: ");
                auto vault = vault_handler::load_vault(vault_path, master_password);

                // Initialize zxcvbn with absolute path relative to executable
                std::string dict_path = "zxcvbn.dict"; 
                char exe_path[PATH_MAX];
                ssize_t count = readlink("/proc/self/exe", exe_path, PATH_MAX);
                if (count != -1) {
                    std::filesystem::path p(std::string(exe_path, count));
                    dict_path = (p.parent_path() / "zxcvbn.dict").string();
                }

                if (!ZxcvbnInit(dict_path.c_str())) {
                    std::cerr << "Error: Failed to load zxcvbn dictionary at: " << dict_path << "\n";
                    std::cerr << "Please ensure 'zxcvbn.dict' is located in the same directory as the duckpass executable.\n";
                    throw CLI::RuntimeError(1);
                }

                struct ZxcvbnGuard {
                    ~ZxcvbnGuard() { ZxcvbnUnInit(); }
                } zxcvbn_guard;

                std::cout << "Auditing " << vault.get_all_entries().size() << " entries...\n";
                if (config->check_online) {
                    std::cout << "(Online check enabled. This may take a moment...)\n";
                }

                auto report = AuditEngine::run_audit(vault, *config);

                std::cout << "\n--- AUDIT REPORT ---\n";
                std::cout << std::left << std::setw(20) << "Service" << std::setw(20) << "User" << std::setw(10) << "Score" << "Issues\n";
                std::cout << std::string(60, '-') << "\n";

                for (const auto& res : report.entries) {
                    std::cout << std::left << std::setw(20) << res.service << std::setw(20) << res.username << std::setw(10) << res.entropy.score;

                    std::vector<std::string> issues;
                    if (res.entropy.is_weak) issues.push_back("WEAK");
                    if (res.hibp.is_pwned) issues.push_back("PWNED(" + std::to_string(res.hibp.breach_count) + ")");
                    if (res.is_reused) issues.push_back("REUSED");
                    if (res.is_stale) issues.push_back("STALE");

                    if (issues.empty()) {
                        std::cout << "Secure";
                    } else {
                        for (size_t i = 0; i < issues.size(); ++i) {
                            std::cout << (i > 0 ? ", " : "") << issues[i];
                        }
                    }
                    std::cout << "\n";
                }

                std::cout << "\nSummary:\n";
                std::cout << "  - Total entries:    " << report.total_entries << "\n";
                std::cout << "  - Weak passwords:   " << report.weak_passwords << "\n";
                std::cout << "  - Pwned passwords:  " << report.pwned_passwords << "\n";
                std::cout << "  - Reused passwords: " << report.reused_passwords << "\n";
                std::cout << "  - Stale passwords:  " << report.stale_passwords << "\n";

            } catch (const CLI::RuntimeError&) {
                throw;
            } catch (const std::exception& e) {
                std::cerr << "Error: " << e.what() << "\n";
                throw CLI::RuntimeError(1);
            }
        });
    }

}  // namespace audit
