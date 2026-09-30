#include <gtest/gtest.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <ctime>

#include "duckpass/audit_engine.h"
#include "duckpass/entropy_evaluator.h"
#include "duckpass/vault.h"

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

TEST(AuditTest, WorkerProcessLifecycleAndSanity) {
    // 1. Evaluate multiple passwords through worker
    auto const weak_score = audit::EntropyEvaluator::evaluate(duckpass::SecureString("qwerty"));
    EXPECT_LT(weak_score.score, 3);
    EXPECT_TRUE(weak_score.is_weak);

    auto const strong_score = audit::EntropyEvaluator::evaluate(duckpass::SecureString("SuperTr0ng#Passw0rd!2026"));
    EXPECT_GE(strong_score.score, 3);
    EXPECT_FALSE(strong_score.is_weak);

    // 2. Verify no zombie worker processes remain
    int status = 0;
    pid_t const zombie = waitpid(-1, &status, WNOHANG);
    EXPECT_TRUE(zombie == -1 || zombie == 0) << "Found uncollected zombie process: " << zombie;
}

TEST(AuditTest, SigpipeBlockerConsumesPendingSignalOnEpipe) {
    int fds[2];
    ASSERT_EQ(pipe(fds), 0);
    close(fds[0]);  // Close read end so write triggers EPIPE

    sigset_t pending_before;
    sigpending(&pending_before);
    bool const was_pending_before = (sigismember(&pending_before, SIGPIPE) == 1);

    {
        // Block SIGPIPE on this thread
        sigset_t set;
        sigset_t old_set;
        sigemptyset(&set);
        sigaddset(&set, SIGPIPE);
        ASSERT_EQ(pthread_sigmask(SIG_BLOCK, &set, &old_set), 0);

        char const dummy = 'Z';
        ssize_t const w = write(fds[1], &dummy, 1);
        EXPECT_EQ(w, -1);
        EXPECT_EQ(errno, EPIPE);

        // Kernel has marked SIGPIPE as pending for this thread
        sigset_t pending_now;
        sigpending(&pending_now);
        EXPECT_EQ(sigismember(&pending_now, SIGPIPE), 1);

        // Consume pending signal before restoring mask
        if (!was_pending_before) {
            sigset_t sigpipe_set;
            sigemptyset(&sigpipe_set);
            sigaddset(&sigpipe_set, SIGPIPE);
            timespec timeout{0, 0};
            int const waited = sigtimedwait(&sigpipe_set, nullptr, &timeout);
            EXPECT_EQ(waited, SIGPIPE);
        }

        // Unblock mask: thread must NOT terminate
        ASSERT_EQ(pthread_sigmask(SIG_SETMASK, &old_set, nullptr), 0);
    }

    close(fds[1]);

    // Thread survived unblocking without dying from SIGPIPE!
    sigset_t pending_after;
    sigpending(&pending_after);
    EXPECT_EQ(sigismember(&pending_after, SIGPIPE), 0);
}
