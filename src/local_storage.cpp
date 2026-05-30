#include "duckpass/local_storage.h"
#include "duckpass/exceptions.h"
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>
#include <cstring>
#include <system_error>

namespace duckpass::storage {

    // --- Internal Low-Level Robust POSIX I/O Helpers ---

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
        if (!std::filesystem::exists(path)) {
            throw vault_io_error("File does not exist: " + path.string());
        }

        uintmax_t file_size = std::filesystem::file_size(path);
        
        int fd = open(path.c_str(), O_RDONLY);
        if (fd == -1) throw vault_io_error(std::string("Failed to open file: ") + path.string() + " (" + std::strerror(errno) + ")");

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
        std::filesystem::path tmp_path = path;
        tmp_path.replace_extension(path.extension().string() + ".tmp");

        int fd = open(tmp_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd == -1) throw vault_io_error(std::string("Failed to create temporary file: ") + tmp_path.string() + " (" + std::strerror(errno) + ")");

        try {
            write_all(fd, data.data(), data.size());
            if (fsync(fd) == -1) throw vault_io_error(std::string("Failed to sync file to disk: ") + std::strerror(errno));
        } catch (...) {
            close(fd);
            std::filesystem::remove(tmp_path);
            throw;
        }

        close(fd);

        std::error_code ec;
        std::filesystem::rename(tmp_path, path, ec);
        if (ec) {
            std::filesystem::remove(tmp_path);
            throw vault_io_error("Failed to atomically rename vault file: " + ec.message());
        }
    }

} // namespace duckpass::storage
