#include "duckpass/local_storage.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <system_error>

#include "duckpass/exceptions.h"

namespace duckpass::storage {

    // --- Internal Low-Level Robust POSIX I/O Helpers ---

    /**
     * @brief Writes all data from a buffer to a file descriptor.
     * Handles partial writes and EINTR signal interruptions.
     */
    static void write_all(int fd, const void* buf, size_t count) {
        size_t total_written = 0;
        const uint8_t* p = static_cast<const uint8_t*>(buf);
        while (total_written < count) {
            ssize_t written = write(fd, p + total_written, count - total_written);
            if (written == -1) {
                if (errno == EINTR) continue;
                throw vault_io_error(std::string("POSIX write failed: ") + std::strerror(errno));
            }
            total_written += static_cast<size_t>(written);
        }
    }

    /**
     * @brief Reads exactly 'count' bytes from a file descriptor.
     * Handles partial reads and EINTR signal interruptions.
     */
    static void read_all(int fd, void* buf, size_t count) {
        size_t total_read = 0;
        uint8_t* p = static_cast<uint8_t*>(buf);
        while (total_read < count) {
            ssize_t bytes_read = read(fd, p + total_read, count - total_read);
            if (bytes_read == -1) {
                if (errno == EINTR) continue;
                throw vault_io_error(std::string("POSIX read failed: ") + std::strerror(errno));
            }
            if (bytes_read == 0) {
                throw vault_corrupted_error("Unexpected EOF while reading storage");
            }
            total_read += static_cast<size_t>(bytes_read);
        }
    }

    SecureBytes read_file(const std::filesystem::path& path) {
        // Use open() first to get a file descriptor.
        // This avoids TOCTOU (Time-of-Check to Time-of-Use) race conditions
        // compared to checking existence/size before opening.
        int fd = open(path.c_str(), O_RDONLY);
        if (fd == -1) throw vault_io_error(std::string("Failed to open file: ") + path.string() + " (" + std::strerror(errno) + ")");

        // Use fstat() on the file descriptor to get the most accurate and safe file size.
        struct stat st{};
        if (fstat(fd, &st) == -1) {
            close(fd);
            throw vault_io_error(std::string("Failed to stat file: ") + path.string() + " (" + std::strerror(errno) + ")");
        }

        uintmax_t file_size = st.st_size;
        if (file_size == 0) {
            close(fd);
            return SecureBytes();
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

    void write_file_atomic(const std::filesystem::path& path, std::span<const uint8_t> data) {
        // Atomic write pattern: Write to a temp file, then rename to target.
        std::filesystem::path tmp_path = path;
        tmp_path.replace_extension(path.extension().string() + ".tmp");

        // Use O_CREAT | O_TRUNC with restrictive permissions (0600) for security.
        int fd = open(tmp_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd == -1) throw vault_io_error(std::string("Failed to create temporary file: ") + tmp_path.string() + " (" + std::strerror(errno) + ")");

        try {
            write_all(fd, data.data(), data.size());
            // Force physical write to the storage medium.
            if (fsync(fd) == -1) throw vault_io_error(std::string("Failed to sync file to disk: ") + std::strerror(errno));
        } catch (...) {
            close(fd);
            std::filesystem::remove(tmp_path);
            throw;
        }

        close(fd);

        // Rename is atomic on POSIX-compliant file systems.
        std::error_code ec;
        std::filesystem::rename(tmp_path, path, ec);
        if (ec) {
            std::filesystem::remove(tmp_path);
            throw vault_io_error("Failed to atomically rename vault file: " + ec.message());
        }

        // IMPORTANT: On many file systems, the parent directory metadata must be synced
        // to ensure the rename entry itself is persisted to disk and survives a crash.
        std::filesystem::path parent_dir = path.parent_path();
        if (parent_dir.empty()) parent_dir = ".";
        int dir_fd = open(parent_dir.c_str(), O_RDONLY | O_DIRECTORY);
        if (dir_fd != -1) {
            fsync(dir_fd);
            close(dir_fd);
        }
    }

}  // namespace duckpass::storage
