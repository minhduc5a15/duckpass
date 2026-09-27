#include <gtest/gtest.h>

#include <ctime>

#include "duckpass/audit_engine.h"
#include "duckpass/crypto.h"
#include "duckpass/entropy_evaluator.h"
#include "duckpass/vault.h"
#include "zxcvbn.h"

TEST(AuditTest, EntropyEvaluatorIdentifiesWeakAndStrongPasswords) {
    auto score_weak = audit::EntropyEvaluator::evaluate(duckpass::SecureString("123"));
    EXPECT_LT(score_weak.score, 3);
    EXPECT_TRUE(score_weak.is_weak);

    auto score_strong = audit::EntropyEvaluator::evaluate(duckpass::SecureString("CorrectHorseBatteryStaple123!"));
    EXPECT_GE(score_strong.score, 3);
    EXPECT_FALSE(score_strong.is_weak);
}

TEST(AuditTest, AuditEngineOfflineReuseAndStaleDetection) {
    vault_handler::Vault vault;

    vault_handler::VaultEntry e1;
    e1.service = duckpass::ProtectedString(duckpass::SecureString("service1"));
    e1.username = duckpass::ProtectedString(duckpass::SecureString("user1"));
    e1.password = duckpass::ProtectedString(duckpass::SecureString("shared_pass_123"));
    e1.last_updated = 100;  // Very old timestamp

    vault_handler::VaultEntry e2;
    e2.service = duckpass::ProtectedString(duckpass::SecureString("service2"));
    e2.username = duckpass::ProtectedString(duckpass::SecureString("user2"));
    e2.password = duckpass::ProtectedString(duckpass::SecureString("shared_pass_123"));  // Reused!
    e2.last_updated = static_cast<uint64_t>(std::time(nullptr));

    vault.add_entry(std::move(e1));
    vault.add_entry(std::move(e2));

    audit::AuditEngine::Config config;
    config.check_online = false;
    config.stale_threshold_seconds = 3600;  // 1 hour

    auto report = audit::AuditEngine::run_audit(vault, config);

    EXPECT_EQ(report.total_entries, 2);
    EXPECT_EQ(report.reused_passwords, 1);
    EXPECT_TRUE(report.entries[0].is_reused);
    EXPECT_TRUE(report.entries[1].is_reused);
    EXPECT_EQ(report.stale_passwords, 1);
    EXPECT_TRUE(report.entries[0].is_stale);
    EXPECT_FALSE(report.entries[1].is_stale);
}

TEST(AuditTest, VaultBackwardCompatibilityDeserialization) {
    std::vector<uint8_t> old_vault_data;
    auto add_uint32 = [&](uint32_t v) {
        old_vault_data.push_back(v & 0xFF);
        old_vault_data.push_back((v >> 8) & 0xFF);
        old_vault_data.push_back((v >> 16) & 0xFF);
        old_vault_data.push_back((v >> 24) & 0xFF);
    };
    auto add_string = [&](const std::string& s) {
        add_uint32(static_cast<uint32_t>(s.length()));
        for (char c : s) old_vault_data.push_back(static_cast<uint8_t>(c));
    };

    add_uint32(1);  // 1 entry
    add_string("legacy_service");
    add_string("legacy_user");
    add_string("legacy_pass");

    auto vault = vault_handler::Vault::deserialize(old_vault_data);

    ASSERT_EQ(vault.get_all_entries().size(), 1);
    auto entry = vault.get_entry(duckpass::SecureString("legacy_service"));
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->username.unprotect(), duckpass::SecureString("legacy_user"));
    EXPECT_EQ(entry->password.unprotect(), duckpass::SecureString("legacy_pass"));
    EXPECT_GT(entry->last_updated, 0);
}
