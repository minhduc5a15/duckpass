#include <gtest/gtest.h>
#include <sys/stat.h>

#include <filesystem>

#include "duckpass/exceptions.h"
#include "duckpass/local_storage.h"

class StorageTest : public ::testing::Test {
protected:
    std::filesystem::path test_dir;
    std::filesystem::path test_file;

    void SetUp() override {
        test_dir = std::filesystem::temp_directory_path() / ("duckpass_test_" + std::to_string(std::time(nullptr)) + "_" + std::to_string(rand()));
        std::filesystem::create_directories(test_dir);
        test_file = test_dir / "vault.bin";
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(test_dir, ec);
    }
};

TEST_F(StorageTest, WriteAndReadFileRoundTrip) {
    std::vector<uint8_t> data = {'H', 'E', 'L', 'L', 'O', '_', 'V', 'A', 'U', 'L', 'T'};

    duckpass::storage::write_file_atomic(test_file, data);
    EXPECT_TRUE(std::filesystem::exists(test_file));

    auto read_back = duckpass::storage::read_file(test_file);
    EXPECT_EQ(read_back.size(), data.size());
    std::vector<uint8_t> read_vec(read_back.begin(), read_back.end());
    EXPECT_EQ(data, read_vec);
}

TEST_F(StorageTest, ReadNonExistentFileThrows) {
    auto non_existent = test_dir / "non_existent.bin";
    EXPECT_THROW({ duckpass::storage::read_file(non_existent); }, duckpass::vault_io_error);
}

TEST_F(StorageTest, ReadEmptyFileReturnsEmptyBuffer) {
    std::vector<uint8_t> empty_data;
    duckpass::storage::write_file_atomic(test_file, empty_data);

    auto read_back = duckpass::storage::read_file(test_file);
    EXPECT_TRUE(read_back.empty());
}

#if defined(__linux__) || defined(__APPLE__)
TEST_F(StorageTest, FileCreatedWithRestrictivePermissions) {
    std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    duckpass::storage::write_file_atomic(test_file, data);

    struct stat st {};
    ASSERT_EQ(stat(test_file.c_str(), &st), 0);
    // Mode should be 0600 (S_IRUSR | S_IWUSR)
    EXPECT_TRUE(st.st_mode & S_IRUSR);
    EXPECT_TRUE(st.st_mode & S_IWUSR);
    EXPECT_FALSE(st.st_mode & S_IRGRP);
    EXPECT_FALSE(st.st_mode & S_IWGRP);
    EXPECT_FALSE(st.st_mode & S_IROTH);
    EXPECT_FALSE(st.st_mode & S_IWOTH);
}

TEST_F(StorageTest, AtomicWriteWithBackupPreservesCanonicalAndCreatesBackup) {
    std::vector<uint8_t> data1 = {'I', 'N', 'I', 'T', 'I', 'A', 'L'};
    duckpass::storage::write_file_atomic(test_file, data1, false);
    EXPECT_TRUE(std::filesystem::exists(test_file));

    std::vector<uint8_t> data2 = {'U', 'P', 'D', 'A', 'T', 'E', 'D'};
    duckpass::storage::write_file_atomic(test_file, data2, true);

    EXPECT_TRUE(std::filesystem::exists(test_file));
    std::filesystem::path backup_file = test_file;
    backup_file += ".bak";
    EXPECT_TRUE(std::filesystem::exists(backup_file));

    auto read_back = duckpass::storage::read_file(test_file);
    EXPECT_EQ(data2, std::vector<uint8_t>(read_back.begin(), read_back.end()));

    auto read_bak = duckpass::storage::read_file(backup_file);
    EXPECT_EQ(data1, std::vector<uint8_t>(read_bak.begin(), read_bak.end()));
}

TEST_F(StorageTest, FileLockGuardAcquiresAndReleasesCleanly) {
    {
        auto lock = duckpass::storage::acquire_file_lock(test_file);
        EXPECT_TRUE(std::filesystem::exists(test_file.string() + ".lock"));
    }
    // Lock released on destruction
    { auto lock2 = duckpass::storage::acquire_file_lock(test_file); }
}
#endif
