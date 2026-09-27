#include "duckpass/vault_service.h"

#include <gtest/gtest.h>

#include <filesystem>

#include "duckpass/exceptions.h"

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
