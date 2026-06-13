#include "duckpass/vault_service.h"

#include <algorithm>
#include <stdexcept>

#include "duckpass/utils.h"

namespace duckpass::service {

    VaultService::VaultService(std::filesystem::path path, duckpass::SecureString master_password)
        : vault_path_(std::move(path)), master_password_(std::move(master_password)) {
        vault_ = vault_handler::load_vault(vault_path_, master_password_);
    }

    void VaultService::save() const { vault_handler::save_vault(vault_path_, vault_, master_password_); }

    void VaultService::add_entry(duckpass::SecureString service, duckpass::SecureString username, duckpass::SecureString password) {
        if (service.empty()) {
            throw std::invalid_argument("Service name cannot be empty.");
        }
        if (vault_.get_entry(service)) {
            throw std::invalid_argument("Service already exists. Please delete it first if you want to update.");
        }
        if (username.empty()) {
            throw std::invalid_argument("Username cannot be empty.");
        }
        if (password.empty()) {
            throw std::invalid_argument("Password cannot be empty.");
        }

        vault_handler::VaultEntry entry;
        entry.service = std::move(service);
        entry.username = std::move(username);
        entry.password = std::move(password);

        vault_.add_entry(std::move(entry));
        save();
    }

    void VaultService::delete_entry(const duckpass::SecureString& service) {
        if (vault_.remove_entry(service)) {
            save();
        } else {
            throw std::invalid_argument("Service not found.");
        }
    }

    std::optional<vault_handler::VaultEntry> VaultService::get_entry(const duckpass::SecureString& service) const {
        return vault_.get_entry(service);
    }

    std::vector<vault_handler::VaultEntry> VaultService::list_entries(const std::string_view query) const {
        const auto& all_entries = vault_.get_all_entries();
        if (query.empty()) {
            std::vector<vault_handler::VaultEntry> vec;
            vec.reserve(all_entries.size());
            for (const auto& e : all_entries) {
                vec.push_back(e);
            }
            return vec;
        }

        struct MatchResult {
            vault_handler::VaultEntry entry;
            int score;
        };
        std::vector<MatchResult> filtered_results;

        for (const auto& entry : all_entries) {
            const int score = utils::fuzzy_match(query, std::string_view(entry.service.data(), entry.service.size()));
            if (score > 0) {
                filtered_results.push_back({entry, score});
            }
        }

        std::ranges::sort(filtered_results, [](const MatchResult& a, const MatchResult& b) { return a.score > b.score; });

        std::vector<vault_handler::VaultEntry> final_results;
        final_results.reserve(filtered_results.size());
        for (auto& [entry, score] : filtered_results) {
            final_results.push_back(std::move(entry));
        }
        return final_results;
    }

    audit::AuditReport VaultService::audit_vault(const audit::AuditEngine::Config& config) const {
        return audit::AuditEngine::run_audit(vault_, config);
    }

    const vault_handler::Vault::EntryContainer& VaultService::get_all_entries() const { return vault_.get_all_entries(); }

}  // namespace duckpass::service
