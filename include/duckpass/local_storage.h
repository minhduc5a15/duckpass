#pragma once

#include <filesystem>
#include <span>
#include <vector>

#include "duckpass/secure_allocator.h"

namespace duckpass::storage {

    /**
     * @brief Reads the entire content of a file into a secure buffer.
     * Uses POSIX I/O for robustness and consistency.
     */
    SecureBytes read_file(const std::filesystem::path& path);

    /**
     * @brief RAII File Lock Guard to serialize concurrent database transactions.
     */
    class FileLockGuard {
    private:
        int fd_ = -1;

    public:
        explicit FileLockGuard(int fd) noexcept : fd_(fd) {}
        ~FileLockGuard();
        FileLockGuard(const FileLockGuard&) = delete;
        FileLockGuard& operator=(const FileLockGuard&) = delete;
        FileLockGuard(FileLockGuard&& other) noexcept : fd_(other.fd_) { other.fd_ = -1; }
        FileLockGuard& operator=(FileLockGuard&& other) noexcept;
        void release();
    };

    /**
     * @brief Acquires an exclusive advisory file lock for the given vault path.
     */
    FileLockGuard acquire_file_lock(const std::filesystem::path& path);

    /**
     * @brief Writes data to a file atomically using a temporary file and rename.
     * Ensures data durability using fsync.
     * Optionally creates a safe backup (.bak) of the target file if it already exists.
     */
    void write_file_atomic(const std::filesystem::path& path, std::span<const uint8_t> data, bool create_backup = false);

}  // namespace duckpass::storage
