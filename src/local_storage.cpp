#include "duckpass/local_storage.h"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <iostream>
#include <system_error>

#include "duckpass/exceptions.h"

namespace duckpass::storage {

    // --- Internal Low-Level Robust POSIX I/O Helpers ---

    /**
     * @brief Writes all data from a buffer to a file descriptor.
     * Handles partial writes and EINTR signal interruptions.
     */
    static void write_all(const int fd, const void* buf, const size_t count) {
        size_t total_written = 0;
        const auto* p = static_cast<const uint8_t*>(buf);
        while (total_written < count) {
            // Try to write remaining bytes. write() may write fewer bytes than
            // requested (partial write) so we loop until all bytes are written.
            // If write() returns -1 we must check errno: EINTR means the call
            // was interrupted by a signal, and it's safe to retry; other errors
            // are fatal and are reported as a vault_io_error.
            ssize_t const written = write(fd, p + total_written, count - total_written);
            if (written == -1) {
                if (errno == EINTR) continue;  // retry on signal interruption
                throw vault_io_error(std::string("POSIX write failed: ") + std::strerror(errno));
            }
            total_written += static_cast<size_t>(written);
        }
    }

    /**
     * @brief Reads exactly 'count' bytes from a file descriptor.
     * Handles partial reads and EINTR signal interruptions.
     */
    static void read_all(const int fd, void* buf, const size_t count) {
        size_t total_read = 0;
        auto* p = static_cast<uint8_t*>(buf);
        while (total_read < count) {
            // read() can return fewer bytes than requested or be interrupted
            // by a signal (EINTR). On EOF (0) before we've read the expected
            // number of bytes treat the file as corrupted. Other errors are
            // converted to vault_io_error so callers get a meaningful
            // exception type.
            ssize_t const bytes_read = read(fd, p + total_read, count - total_read);
            if (bytes_read == -1) {
                if (errno == EINTR) continue;  // retry on signal interruption
                throw vault_io_error(std::string("POSIX read failed: ") + std::strerror(errno));
            }
            if (bytes_read == 0) {
                // Premature EOF: the file doesn't contain as many bytes as
                // expected which indicates corruption or truncation.
                throw vault_corrupted_error("Unexpected EOF while reading storage");
            }
            total_read += static_cast<size_t>(bytes_read);
        }
    }

    SecureBytes read_file(const std::filesystem::path& path) {
        // Use open() first to get a file descriptor.
        // This avoids TOCTOU (Time-of-Check to Time-of-Use) race conditions
        // compared to checking existence/size before opening.
        int const fd = open(path.c_str(), O_RDONLY);
        if (fd == -1) throw vault_io_error(std::string("Failed to open file: ") + path.string() + " (" + std::strerror(errno) + ")");

        // Use fstat() on the file descriptor to get the most accurate and safe file size.
        struct stat st {};
        if (fstat(fd, &st) == -1) {
            close(fd);
            throw vault_io_error(std::string("Failed to stat file: ") + path.string() + " (" + std::strerror(errno) + ")");
        }

        // Use st_size from fstat() (on the opened fd) to determine the file
        // size. Guard against absurdly large sizes which may indicate
        // tampering or an attempt to exhaust resources; here we cap at 500MB.
        uintmax_t const file_size = st.st_size;
        if (file_size > 500 * 1024 * 1024) {
            throw vault_io_error("Vault file is too large (over 500MB). Possible tampering.");
        }
        if (file_size == 0) {
            close(fd);
            return {};
        }

        SecureBytes buffer(file_size);
        try {
            read_all(fd, buffer.data(), file_size);
        } catch (...) {
            close(fd);
            throw;
        }

        close(fd);
        return buffer;
    }

    FileLockGuard::~FileLockGuard() { release(); }

    FileLockGuard& FileLockGuard::operator=(FileLockGuard&& other) noexcept {
        if (this != &other) {
            if (fd_ != -1) release();
            fd_ = other.fd_;
            other.fd_ = -1;
        }
        return *this;
    }

    void FileLockGuard::release() {
        if (fd_ != -1) {
            flock(fd_, LOCK_UN);
            close(fd_);
            fd_ = -1;
        }
    }

    FileLockGuard acquire_file_lock(const std::filesystem::path& path) {
        std::filesystem::path const lock_path = path.string() + ".lock";
        int const lock_fd = open(lock_path.c_str(), O_RDWR | O_CREAT, 0600);
        if (lock_fd != -1) {
            flock(lock_fd, LOCK_EX);
        }
        return FileLockGuard(lock_fd);
    }

    void write_file_atomic(const std::filesystem::path& path, const std::span<const uint8_t> data, const bool create_backup) {
        // 1. Generate a truly collision-free unique temporary path in the target directory
        static std::atomic<uint64_t> s_temp_counter{0};
        const auto now_ns = std::chrono::steady_clock::now().time_since_epoch().count();
        const std::string unique_tmp_name =
            path.filename().string() + ".tmp." + std::to_string(getpid()) + "." + std::to_string(now_ns) + "." + std::to_string(++s_temp_counter);
        std::filesystem::path parent_dir = path.parent_path();
        if (parent_dir.empty()) parent_dir = ".";
        std::filesystem::path const tmp_path = parent_dir / unique_tmp_name;

        // Use O_CREAT | O_EXCL to ensure atomic unique creation without symlink vulnerabilities
        int const fd = open(tmp_path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd == -1) {
            throw vault_io_error(std::string("Failed to create temporary file: ") + tmp_path.string() + " (" + std::strerror(errno) + ")");
        }

        try {
            write_all(fd, data.data(), data.size());
            // Force physical write to the storage medium
            if (fsync(fd) == -1) throw vault_io_error(std::string("Failed to sync file to disk: ") + std::strerror(errno));
        } catch (...) {
            close(fd);
            std::error_code ec;
            std::filesystem::remove(tmp_path, ec);
            throw;
        }

        close(fd);

        // 2. Safe Backup: Only create/update backup AFTER the new data is fully synced to disk.
        // The original file is preserved completely in case of any prior write failure.
        if (create_backup && std::filesystem::exists(path)) {
            std::filesystem::path backup_path = path;
            backup_path.replace_extension(path.extension().string() + ".bak");
            std::error_code ec;
            std::filesystem::copy_file(path, backup_path, std::filesystem::copy_options::overwrite_existing, ec);
            if (ec) {
                std::cerr << "[Warning] Could not create backup (.bak): " << ec.message() << "\n";
            }
        }

        // 3. Atomically rename the verified temporary file over the target path
        std::error_code ec;
        std::filesystem::rename(tmp_path, path, ec);
        if (ec) {
            std::filesystem::remove(tmp_path);
            throw vault_io_error("Failed to atomically rename vault file: " + ec.message());
        }

        // 4. Directory metadata sync to guarantee entry persistence
        int const dir_fd = open(parent_dir.c_str(), O_RDONLY | O_DIRECTORY);
        if (dir_fd != -1) {
            fsync(dir_fd);
            close(dir_fd);
        }
    }

}  // namespace duckpass::storage
