#include "duckpass/audit_engine.h"

#include <ctime>
#include <semaphore>
#include <unordered_map>

#include "duckpass/crypto.h"

namespace audit {

    AuditReport AuditEngine::run_audit(const Vault& vault, const Config& config) {
        AuditReport report{};
        const auto& entries = vault.get_all_entries();
        report.total_entries = static_cast<int>(entries.size());

        uint64_t now = static_cast<uint64_t>(std::time(nullptr));

        // Semaphore to limit concurrent network requests (Batching)
        // Only 8 threads can acquire the semaphore at the same time.
        static std::counting_semaphore<8> network_sem(8);

        std::vector<std::future<HibpResult>> hibp_futures;

        // Maps SHA-256 hash to a list of indices in the report.entries vector
        std::unordered_map<std::string, std::vector<size_t>> hash_to_indices;

        for (size_t i = 0; i < entries.size(); ++i) {
            const auto& entry = entries[i];
            EntryAuditResult result;
            result.service = std::string(entry.service.c_str());
            result.username = std::string(entry.username.c_str());
            result.last_updated = entry.last_updated;

            // 1. Entropy Evaluation
            result.entropy = EntropyEvaluator::evaluate(entry.password);
            if (result.entropy.is_weak) report.weak_passwords++;

            // 2. Stale Detection
            result.is_stale = (entry.last_updated > 0 && (now - entry.last_updated) > config.stale_threshold_seconds);
            if (result.is_stale) report.stale_passwords++;

            // 3. Reuse Tracking (Prepare hashes)
            std::string hash256 = crypto_handler::compute_sha256(entry.password);
            hash_to_indices[hash256].push_back(i);

            // 4. HIBP Online Check (if enabled)
            if (config.check_online) {
                // SAFE DATA CAPTURE: Copy password into the lambda [pw = entry.password]
                // BATCHING: Acquire slot BEFORE spawning thread to prevent thread explosion
                network_sem.acquire();
                hibp_futures.push_back(std::async(std::launch::async, [pw = entry.password]() {
                    try {
                        auto res = HibpChecker::check_password(pw);
                        network_sem.release();
                        return res;
                    } catch (...) {
                        network_sem.release();  // Ensure release on error to prevent deadlock
                        throw;
                    }
                }));
            } else {
                result.hibp = {false, 0, "Online check disabled"};
            }

            report.entries.push_back(std::move(result));
        }

        // 5. Finalize Reuses
        for (const auto& [hash, indices] : hash_to_indices) {
            if (indices.size() > 1) {
                report.reused_passwords++;
                for (size_t idx : indices) {
                    report.entries[idx].is_reused = true;
                    for (size_t other_idx : indices) {
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
                report.entries[i].hibp = hibp_futures[i].get();
                if (report.entries[i].hibp.is_pwned) {
                    report.pwned_passwords++;
                }
            }
        }

        return report;
    }

}  // namespace audit
