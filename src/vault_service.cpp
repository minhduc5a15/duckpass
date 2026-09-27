#include "duckpass/vault_service.h"

#include <algorithm>
#include <ctime>
#include <stdexcept>

#include "duckpass/totp.h"
#include "duckpass/utils.h"

namespace duckpass::service {

    VaultService::VaultService(std::filesystem::path path, duckpass::SecureString master_password)
        : vault_path_(std::move(path)), master_password_(master_password) {
        vault_ = vault_handler::load_vault(vault_path_, master_password);
    }

    void VaultService::save() const { vault_handler::save_vault(vault_path_, vault_, master_password_.unprotect()); }

    void VaultService::rekey(duckpass::SecureString new_master_password) {
        if (new_master_password.empty()) {
            throw std::invalid_argument("New master password cannot be empty.");
        }
        master_password_ = duckpass::ProtectedString(new_master_password);
        save();
    }

    void VaultService::add_entry(duckpass::SecureString service, duckpass::SecureString username, duckpass::SecureString password,
                                 duckpass::SecureString totp_secret) {
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

        if (!totp_secret.empty()) {
            // Validate Base32 syntax
            totp::decode_base32(std::string_view(totp_secret.data(), totp_secret.size()));
        }

        vault_handler::VaultEntry entry;
        entry.service = duckpass::ProtectedString(service);
        entry.username = duckpass::ProtectedString(username);
        entry.password = duckpass::ProtectedString(password);
        entry.totp_secret = duckpass::ProtectedString(totp_secret);

        vault_.add_entry(std::move(entry));
        save();
    }

    void VaultService::update_entry(const duckpass::SecureString& service, std::optional<duckpass::SecureString> new_username,
                                    std::optional<duckpass::SecureString> new_password, std::optional<duckpass::SecureString> new_totp_secret) {
        auto existing = vault_.get_entry(service);
        if (!existing) {
            throw std::invalid_argument("Service not found.");
        }

        vault_handler::VaultEntry updated = *existing;

        if (new_username.has_value()) {
            if (new_username->empty()) throw std::invalid_argument("Username cannot be empty.");
            updated.username = duckpass::ProtectedString(*new_username);
        }
        if (new_password.has_value()) {
            if (new_password->empty()) throw std::invalid_argument("Password cannot be empty.");
            updated.password = duckpass::ProtectedString(*new_password);
        }
        if (new_totp_secret.has_value()) {
            if (!new_totp_secret->empty()) {
                totp::decode_base32(std::string_view(new_totp_secret->data(), new_totp_secret->size()));
            }
            updated.totp_secret = duckpass::ProtectedString(*new_totp_secret);
        }

        updated.last_updated = static_cast<uint64_t>(std::time(nullptr));
        vault_.add_entry(std::move(updated));
        save();
    }

    std::string VaultService::get_totp_code(const duckpass::SecureString& service, uint32_t* out_remaining_seconds) const {
        auto entry = vault_.get_entry(service);
        if (!entry) {
            throw std::invalid_argument("Service not found.");
        }
        auto secret = entry->totp_secret.unprotect();
        if (secret.empty()) {
            throw std::invalid_argument("Service '" + std::string(service.data(), service.size()) + "' does not have a 2FA TOTP secret configured.");
        }
        return totp::generate_totp(secret, 0, 30, 6, out_remaining_seconds);
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
            duckpass::SecureString s = entry.service.unprotect();
            const int score = utils::fuzzy_match(query, std::string_view(s.data(), s.size()));
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
