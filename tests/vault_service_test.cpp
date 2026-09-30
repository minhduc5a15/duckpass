#include "duckpass/vault_service.h"

#include <gtest/gtest.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <filesystem>
#include <thread>

#include "duckpass/exceptions.h"
#include "duckpass/local_storage.h"

class VaultServiceTest : public ::testing::Test {
protected:
    std::filesystem::path test_dir;
    std::filesystem::path vault_path;
    duckpass::SecureString master_password{"MasterSecretKey123!"};

    void SetUp() override {
        test_dir = std::filesystem::temp_directory_path() / ("duckpass_vs_test_" + std::to_string(std::time(nullptr)) + "_" + std::to_string(rand()));
        std::filesystem::create_directories(test_dir);
        vault_path = test_dir / ".duckvault";

        // Create initial empty vault
        vault_handler::Vault empty_vault;
        vault_handler::save_vault(vault_path, empty_vault, master_password);
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(test_dir, ec);
    }
};

TEST_F(VaultServiceTest, AddAndGetEntrySuccess) {
    duckpass::service::VaultService service(vault_path, master_password);

    service.add_entry(duckpass::SecureString("github.com"), duckpass::SecureString("octocat"), duckpass::SecureString("gh_token_xyz"));

    auto entry_opt = service.get_entry(duckpass::SecureString("github.com"));
    ASSERT_TRUE(entry_opt.has_value());
    EXPECT_EQ(entry_opt->service.unprotect(), duckpass::SecureString("github.com"));
    EXPECT_EQ(entry_opt->username.unprotect(), duckpass::SecureString("octocat"));
    EXPECT_EQ(entry_opt->password.unprotect(), duckpass::SecureString("gh_token_xyz"));
}

TEST_F(VaultServiceTest, AddEntryValidationErrors) {
    duckpass::service::VaultService service(vault_path, master_password);

    // Empty service
    EXPECT_THROW(
        { service.add_entry(duckpass::SecureString(""), duckpass::SecureString("user"), duckpass::SecureString("pass")); }, std::invalid_argument);

    // Empty username
    EXPECT_THROW(
        { service.add_entry(duckpass::SecureString("service"), duckpass::SecureString(""), duckpass::SecureString("pass")); }, std::invalid_argument);

    // Empty password
    EXPECT_THROW(
        { service.add_entry(duckpass::SecureString("service"), duckpass::SecureString("user"), duckpass::SecureString("")); }, std::invalid_argument);

    // Duplicate service
    service.add_entry(duckpass::SecureString("service"), duckpass::SecureString("user"), duckpass::SecureString("pass"));
    EXPECT_THROW(
        { service.add_entry(duckpass::SecureString("service"), duckpass::SecureString("user2"), duckpass::SecureString("pass2")); },
        std::invalid_argument);
}

TEST_F(VaultServiceTest, DeleteEntryRemovesFromVault) {
    duckpass::service::VaultService service(vault_path, master_password);

    service.add_entry(duckpass::SecureString("gitlab.com"), duckpass::SecureString("user"), duckpass::SecureString("pass"));

    EXPECT_TRUE(service.get_entry(duckpass::SecureString("gitlab.com")).has_value());

    service.delete_entry(duckpass::SecureString("gitlab.com"));
    EXPECT_FALSE(service.get_entry(duckpass::SecureString("gitlab.com")).has_value());

    // Deleting again should throw
    EXPECT_THROW({ service.delete_entry(duckpass::SecureString("gitlab.com")); }, std::invalid_argument);
}

TEST_F(VaultServiceTest, ListEntriesFuzzySearch) {
    duckpass::service::VaultService service(vault_path, master_password);

    service.add_entry(duckpass::SecureString("google.com"), duckpass::SecureString("u1"), duckpass::SecureString("p1"));
    service.add_entry(duckpass::SecureString("github.com"), duckpass::SecureString("u2"), duckpass::SecureString("p2"));
    service.add_entry(duckpass::SecureString("amazon.com"), duckpass::SecureString("u3"), duckpass::SecureString("p3"));

    // Empty query returns all
    auto all = service.list_entries("");
    EXPECT_EQ(all.size(), 3);

    // Fuzzy query "git" matches github
    auto git_matches = service.list_entries("git");
    ASSERT_FALSE(git_matches.empty());
    EXPECT_EQ(git_matches[0].service.unprotect(), duckpass::SecureString("github.com"));
}

TEST_F(VaultServiceTest, PersistenceAcrossInstances) {
    {
        duckpass::service::VaultService s1(vault_path, master_password);
        s1.add_entry(duckpass::SecureString("persisted.org"), duckpass::SecureString("admin"), duckpass::SecureString("superpass"));
    }

    // New instance loads from disk
    duckpass::service::VaultService s2(vault_path, master_password);
    auto entry = s2.get_entry(duckpass::SecureString("persisted.org"));
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->password.unprotect(), duckpass::SecureString("superpass"));

    // Wrong password throws wrong_password_error
    duckpass::SecureString wrong_pw("WrongPassword123!");
    EXPECT_THROW({ duckpass::service::VaultService s_wrong(vault_path, wrong_pw); }, duckpass::wrong_password_error);
}

TEST_F(VaultServiceTest, AddEntryWithTotpAndRetrieveOtp) {
    duckpass::service::VaultService service(vault_path, master_password);

    // RFC 6238 Secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    service.add_entry(duckpass::SecureString("github_2fa"), duckpass::SecureString("dev"), duckpass::SecureString("pass"),
                      duckpass::SecureString("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"));

    uint32_t remaining = 0;
    std::string code = service.get_totp_code(duckpass::SecureString("github_2fa"), &remaining);
    EXPECT_EQ(code.length(), 6);
    EXPECT_GT(remaining, 0);
    EXPECT_LE(remaining, 30);

    // Entry without TOTP secret throws
    service.add_entry(duckpass::SecureString("plain_service"), duckpass::SecureString("u"), duckpass::SecureString("p"));
    EXPECT_THROW({ service.get_totp_code(duckpass::SecureString("plain_service")); }, std::invalid_argument);
}

TEST_F(VaultServiceTest, UpdateEntryModifiesFields) {
    duckpass::service::VaultService service(vault_path, master_password);

    service.add_entry(duckpass::SecureString("service_to_edit"), duckpass::SecureString("old_user"), duckpass::SecureString("old_pass"));

    // Update password only
    service.update_entry(duckpass::SecureString("service_to_edit"), std::nullopt, duckpass::SecureString("new_pass_456"), std::nullopt);

    auto entry = service.get_entry(duckpass::SecureString("service_to_edit"));
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->username.unprotect(), duckpass::SecureString("old_user"));
    EXPECT_EQ(entry->password.unprotect(), duckpass::SecureString("new_pass_456"));

    // Updating non-existent throws
    EXPECT_THROW(
        { service.update_entry(duckpass::SecureString("non_existent"), duckpass::SecureString("u"), std::nullopt, std::nullopt); },
        std::invalid_argument);
}

#define private public
#include "duckpass/export_command.h"
#undef private

TEST_F(VaultServiceTest, ExportCsvShieldsFormulasAndPreservesTotp) {
    vault_handler::Vault vault;
    vault_handler::VaultEntry entry;
    entry.service = duckpass::ProtectedString("=calc");
    entry.username = duckpass::ProtectedString("admin");
    entry.password = duckpass::ProtectedString("pass");
    entry.totp_secret = duckpass::ProtectedString("JBSWY3DPEHPK3PXP");
    vault.add_entry(entry);

    std::stringstream ss;
    export_command::write_csv(ss, vault);
    std::string csv = ss.str();

    EXPECT_NE(csv.find("\"'=calc\""), std::string::npos);
    EXPECT_NE(csv.find("JBSWY3DPEHPK3PXP"), std::string::npos);
}

TEST_F(VaultServiceTest, ExportJsonEscapesQuotesAndPreservesTotp) {
    vault_handler::Vault vault;
    vault_handler::VaultEntry entry;
    entry.service = duckpass::ProtectedString("bank");
    entry.username = duckpass::ProtectedString("admin");
    entry.password = duckpass::ProtectedString("p@ss\"word\nnext");
    entry.totp_secret = duckpass::ProtectedString("JBSWY3DPEHPK3PXP");
    vault.add_entry(entry);

    std::stringstream ss;
    export_command::write_json(ss, vault);
    std::string json = ss.str();

    EXPECT_NE(json.find(R"("p@ss\"word\nnext")"), std::string::npos);
    EXPECT_NE(json.find("JBSWY3DPEHPK3PXP"), std::string::npos);
}

TEST_F(VaultServiceTest, ConcurrentUpdatesPreserveNewestTimestampOnMerge) {
    // 1. Initial entry
    {
        duckpass::service::VaultService init_service(vault_path, master_password);
        init_service.add_entry(duckpass::SecureString("gmail"), duckpass::SecureString("user@gmail.com"), duckpass::SecureString("old_pwd"));
    }

    // 2. Open two service instances
    duckpass::service::VaultService service_a(vault_path, master_password);
    duckpass::service::VaultService service_b(vault_path, master_password);

    // Ensure timestamp distinction
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));

    // 3. Service A updates "gmail" password on disk
    service_a.update_entry(duckpass::SecureString("gmail"), std::nullopt, duckpass::SecureString("updated_pwd_from_a"));

    // 4. Service B adds another entry and saves
    service_b.add_entry(duckpass::SecureString("gitlab"), duckpass::SecureString("gituser"), duckpass::SecureString("gitpwd"));

    // 5. Verify that Service B did not clobber Service A's update
    duckpass::service::VaultService verify_service(vault_path, master_password);
    auto gmail_entry = verify_service.get_entry(duckpass::SecureString("gmail"));
    ASSERT_TRUE(gmail_entry.has_value());
    EXPECT_EQ(gmail_entry->password.unprotect(), duckpass::SecureString("updated_pwd_from_a"));

    auto gitlab_entry = verify_service.get_entry(duckpass::SecureString("gitlab"));
    ASSERT_TRUE(gitlab_entry.has_value());
    EXPECT_EQ(gitlab_entry->password.unprotect(), duckpass::SecureString("gitpwd"));
}

TEST_F(VaultServiceTest, RekeyTransactionSuccessAndNoDeadlock) {
    // 1. Initial entry
    {
        duckpass::service::VaultService init_service(vault_path, master_password);
        init_service.add_entry(duckpass::SecureString("github"), duckpass::SecureString("user"), duckpass::SecureString("gh_token"));
    }

    duckpass::SecureString new_password("CompletelyNewMasterPassword789!");

    // Run rekey in a child process with a hard 10-second timeout
    pid_t const pid = fork();
    ASSERT_GE(pid, 0);

    if (pid == 0) {
        try {
            duckpass::service::VaultService child_service(vault_path, master_password);
            child_service.rekey(new_password);
            _exit(0);
        } catch (...) {
            _exit(2);
        }
    }

    // Parent monitors child with 10-second hard deadline
    auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    int status = 0;
    bool completed = false;

    while (std::chrono::steady_clock::now() < deadline) {
        pid_t const res = waitpid(pid, &status, WNOHANG);
        if (res == pid) {
            completed = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    if (!completed) {
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
        FAIL() << "VaultService::rekey() DEADLOCKED! Hard timeout exceeded (10s).";
    }

    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0);

    // Verify current vault decrypts with new password
    EXPECT_NO_THROW({
        duckpass::service::VaultService verify_service(vault_path, new_password);
        auto entry = verify_service.get_entry(duckpass::SecureString("github"));
        ASSERT_TRUE(entry.has_value());
        EXPECT_EQ(entry->password.unprotect(), duckpass::SecureString("gh_token"));
    });

    // Verify current vault throws wrong_password_error with old password
    EXPECT_THROW({ vault_handler::load_vault(vault_path, master_password); }, duckpass::wrong_password_error);

    // Verify .bak decrypts with new password
    std::filesystem::path backup_path = vault_path;
    backup_path.replace_extension(vault_path.extension().string() + ".bak");
    ASSERT_TRUE(std::filesystem::exists(backup_path));
    EXPECT_NO_THROW({
        auto bak_vault = vault_handler::load_vault(backup_path, new_password);
        auto entry = bak_vault.get_entry(duckpass::SecureString("github"));
        ASSERT_TRUE(entry.has_value());
    });

    // Verify .bak throws wrong_password_error with old password
    EXPECT_THROW({ vault_handler::load_vault(backup_path, master_password); }, duckpass::wrong_password_error);
}

TEST_F(VaultServiceTest, TransactionRollbackOnDiskWriteFailure) {
    // 1. Initial entry
    {
        duckpass::service::VaultService init_service(vault_path, master_password);
        init_service.add_entry(duckpass::SecureString("test_service"), duckpass::SecureString("user"), duckpass::SecureString("pwd1"));
    }

    duckpass::service::VaultService service(vault_path, master_password);
    duckpass::SecureString new_password("BrandNewKey456!");

    // Set fault injector on vault_path (current file) to simulate write failure after backup has been written
    duckpass::storage::s_test_write_fault_injector = [&](const std::filesystem::path& target) {
        if (target == vault_path) {
            throw duckpass::vault_io_error("Injected disk write failure on current vault");
        }
    };

    EXPECT_THROW({ service.rekey(new_password); }, duckpass::vault_io_error);

    // Reset hook
    duckpass::storage::s_test_write_fault_injector = nullptr;

    // Verify Crash-Safe / Recoverable state:
    // 1. Current vault (.duckvault) remains OLD ciphertext (loads with old password)
    EXPECT_NO_THROW({
        auto current_vault = vault_handler::load_vault(vault_path, master_password);
        auto entry = current_vault.get_entry(duckpass::SecureString("test_service"));
        ASSERT_TRUE(entry.has_value());
    });
    EXPECT_THROW({ vault_handler::load_vault(vault_path, new_password); }, duckpass::wrong_password_error);

    // 2. Backup (.duckvault.bak) was written with NEW ciphertext
    std::filesystem::path backup_path = vault_path;
    backup_path.replace_extension(vault_path.extension().string() + ".bak");
    ASSERT_TRUE(std::filesystem::exists(backup_path));
    EXPECT_NO_THROW({
        auto bak_vault = vault_handler::load_vault(backup_path, new_password);
        auto entry = bak_vault.get_entry(duckpass::SecureString("test_service"));
        ASSERT_TRUE(entry.has_value());
    });
    EXPECT_THROW({ vault_handler::load_vault(backup_path, master_password); }, duckpass::wrong_password_error);

    // 3. In-memory master_password_ was NOT updated (remains old password)
    // Verify by adding an entry with service, which should still encrypt using master_password
    EXPECT_NO_THROW({ service.add_entry(duckpass::SecureString("service_after_fail"), duckpass::SecureString("u"), duckpass::SecureString("p")); });

    // 4. Ensure no .tmp files were left behind in test_dir
    for (const auto& entry : std::filesystem::directory_iterator(test_dir)) {
        std::string const filename = entry.path().filename().string();
        EXPECT_EQ(filename.find(".tmp."), std::string::npos) << "Found orphan temp file: " << filename;
    }
}
