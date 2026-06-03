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
            // Try to write remaining bytes. write() may write fewer bytes than
            // requested (partial write) so we loop until all bytes are written.
            // If write() returns -1 we must check errno: EINTR means the call
            // was interrupted by a signal, and it's safe to retry; other errors
            // are fatal and are reported as a vault_io_error.
            ssize_t written = write(fd, p + total_written, count - total_written);
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
    static void read_all(int fd, void* buf, size_t count) {
        size_t total_read = 0;
        uint8_t* p = static_cast<uint8_t*>(buf);
        while (total_read < count) {
            // read() can return fewer bytes than requested or be interrupted
            // by a signal (EINTR). On EOF (0) before we've read the expected
            // number of bytes treat the file as corrupted. Other errors are
            // converted to vault_io_error so callers get a meaningful
            // exception type.
            ssize_t bytes_read = read(fd, p + total_read, count - total_read);
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
        int fd = open(path.c_str(), O_RDONLY);
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
        uintmax_t file_size = st.st_size;
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

    void write_file_atomic(const std::filesystem::path& path, std::span<const uint8_t> data) {
        // Atomic write pattern: Write to a temp file, then rename to target.
        // Create a temporary path for atomic write. We use a predictable
        // ".tmp" suffix on the same directory so that rename() remains
        // atomic on the same filesystem.
        std::filesystem::path tmp_path = path;
        tmp_path.replace_extension(path.extension().string() + ".tmp");

        // Vulnerability 2.1 Fix: Use O_EXCL to prevent Symlink attacks (CWE-377/59).
        // If the .tmp file exists (e.g., from a crash), we must remove it first,
        // but we MUST ensure we don't follow a symlink to delete a system file.
        std::error_code ec;
        if (std::filesystem::exists(tmp_path, ec) || std::filesystem::is_symlink(tmp_path, ec)) {
            std::filesystem::remove(tmp_path, ec);
        }

        // Use O_CREAT | O_EXCL to ensure we never follow an existing symlink
        // when creating the temporary file (mitigates TOCTOU/symlink attacks).
        // Create with restrictive permissions (owner read/write only) to
        // avoid leaking file contents to other users.
        int fd = open(tmp_path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd == -1) {
            throw vault_io_error(std::string("Failed to create temporary file (possible symlink attack or permission issue): ") + tmp_path.string() +
                                 " (" + std::strerror(errno) + ")");
        }

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

        // Rename is atomic on POSIX-compliant file systems. If rename fails
        // remove the temp file and report an error to avoid leaving stale
        // temporary files behind.
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
        // Sync the parent directory to ensure the rename is persisted. If
        // open() for the directory fails we can't do anything useful; this
        // is a best-effort sync to improve durability.
        if (dir_fd != -1) {
            fsync(dir_fd);
            close(dir_fd);
        }
    }

}  // namespace duckpass::storage
