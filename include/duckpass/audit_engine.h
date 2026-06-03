#pragma once

#include "duckpass/vault.h"
#include "duckpass/entropy_evaluator.h"
#include "duckpass/hibp_checker.h"

#include <map>
#include <string>
#include <vector>

namespace audit {
    using vault_handler::Vault;
    using vault_handler::VaultEntry;

    struct EntryAuditResult {
        std::string service;
        std::string username;
        EntropyScore entropy;
        HibpResult hibp;
        bool is_reused;
        std::vector<std::string> reused_with;
        bool is_stale;
        uint64_t last_updated;
    };

    struct AuditReport {
        std::vector<EntryAuditResult> entries;
        int total_entries;
        int weak_passwords;
        int pwned_passwords;
        int reused_passwords;
        int stale_passwords;
    };

    class AuditEngine {
    public:
        struct Config {
            bool check_online = false;
            uint64_t stale_threshold_seconds = 31536000; // 1 year
        };

        static AuditReport run_audit(const Vault &vault, const Config &config);

    private:
        // Helper to check for reuses
        static void analyze_reuses(AuditReport &report);
    };

}  // namespace audit
