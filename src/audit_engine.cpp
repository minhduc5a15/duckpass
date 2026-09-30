#include "duckpass/audit_engine.h"

#include <unistd.h>

#include <ctime>
#include <future>
#include <iomanip>
#include <iostream>
#include <ranges>
#include <semaphore>
#include <unordered_map>

#include "duckpass/crypto.h"

namespace audit {

    AuditReport AuditEngine::run_audit(const Vault& vault, const Config& config) {
        AuditReport report{};
        const auto& entries = vault.get_all_entries();
        report.total_entries = static_cast<int>(entries.size());

        const auto now = static_cast<uint64_t>(std::time(nullptr));

        // Semaphore to limit concurrent network requests (Batching)
        // Only 8 threads can acquire the semaphore at the same time.
        auto network_sem = std::make_shared<std::counting_semaphore<8>>(8);

        std::vector<std::future<HibpResult>> hibp_futures;

        // Maps SHA-256 hash to a list of indices in the report.entries vector
        std::unordered_map<duckpass::SecureString, std::vector<size_t>> hash_to_indices;

        for (size_t i = 0; i < entries.size(); ++i) {
            const auto& [service, username, password, totp_secret, last_updated] = entries[i];
            duckpass::SecureString s = service.unprotect();
            duckpass::SecureString u = username.unprotect();
            duckpass::SecureString p = password.unprotect();

            EntryAuditResult result;
            result.service = std::string(s.c_str());
            result.username = std::string(u.c_str());
            result.last_updated = last_updated;

            // 1. Entropy Evaluation
            result.entropy = EntropyEvaluator::evaluate(p);
            if (result.entropy.is_weak) report.weak_passwords++;

            // 2. Stale Detection
            result.is_stale = (last_updated > 0 && (now - last_updated) > config.stale_threshold_seconds);
            if (result.is_stale) report.stale_passwords++;

            // 3. Reuse Tracking (Prepare hashes)
            const duckpass::SecureString hash256 = crypto_handler::compute_sha256(p);
            hash_to_indices[hash256].push_back(i);

            // 4. HIBP Online Check (if enabled)
            if (config.check_online) {
                // SAFE DATA CAPTURE: Compute SHA-1 on the main thread and pass the hash, avoiding plaintext exposure in the thread.
                const duckpass::SecureString sha1 = crypto_handler::compute_sha1(p);

                // BATCHING: Acquire slot BEFORE spawning thread to prevent thread explosion
                network_sem->acquire();
                try {
                    hibp_futures.push_back(std::async(std::launch::async, [sha1, network_sem]() {
                        struct PermitGuard {
                            std::shared_ptr<std::counting_semaphore<8>> sem;
                            ~PermitGuard() {
                                if (sem) {
                                    sem->release();
                                }
                            }
                        } guard{network_sem};

                        return HibpChecker::check_password(sha1);
                    }));
                } catch (...) {
                    network_sem->release();
                    throw;
                }
            } else {
                result.hibp = {false, 0, "Online check disabled"};
            }

            report.entries.push_back(std::move(result));
        }

        // 5. Finalize Reuses
        for (const auto& indices : hash_to_indices | std::views::values) {
            if (indices.size() > 1) {
                report.reused_passwords++;
                for (size_t const idx : indices) {
                    report.entries[idx].is_reused = true;
                    for (size_t const other_idx : indices) {
                        if (idx != other_idx) {
                            report.entries[idx].reused_with.push_back(report.entries[other_idx].service);
                        }
                    }
                }
            }
        }

        // 6. Finalize HIBP
        if (config.check_online) {
            for (size_t i = 0; i < hibp_futures.size(); ++i) {
                try {
                    report.entries[i].hibp = hibp_futures[i].get();
                    if (report.entries[i].hibp.is_pwned) {
                        report.pwned_passwords++;
                    }
                } catch (const std::exception& e) {
                    report.entries[i].hibp = {false, 0, std::string("HIBP check error: ") + e.what()};
                } catch (...) {
                    report.entries[i].hibp = {false, 0, "HIBP check error: unknown exception"};
                }
            }
        }

        return report;
    }

    std::ostream& operator<<(std::ostream& os, const AuditReport& report) {
        os << "\n--- AUDIT REPORT ---\n";
        os << std::left << std::setw(20) << "Service" << std::setw(20) << "User" << std::setw(10) << "Score" << "Issues\n";
        os << std::string(60, '-') << "\n";

        for (const auto& res : report.entries) {
            os << std::left << std::setw(20) << res.service << std::setw(20) << res.username << std::setw(10) << res.entropy.score;

            std::vector<std::string> issues;
            if (res.entropy.is_weak) issues.emplace_back("WEAK");
            if (res.hibp.is_pwned) issues.emplace_back("PWNED(" + std::to_string(res.hibp.breach_count) + ")");
            if (res.is_reused) issues.emplace_back("REUSED");
            if (res.is_stale) issues.emplace_back("STALE");

            if (issues.empty()) {
                os << "Secure";
            } else {
                for (size_t i = 0; i < issues.size(); ++i) {
                    os << (i > 0 ? ", " : "") << issues[i];
                }
            }
            os << "\n";
        }

        os << "\nSummary:\n";
        os << "  - Total entries:    " << report.total_entries << "\n";
        os << "  - Weak passwords:   " << report.weak_passwords << "\n";
        os << "  - Pwned passwords:  " << report.pwned_passwords << "\n";
        os << "  - Reused passwords: " << report.reused_passwords << "\n";
        os << "  - Stale passwords:  " << report.stale_passwords << "\n";

        return os;
    }

}  // namespace audit
