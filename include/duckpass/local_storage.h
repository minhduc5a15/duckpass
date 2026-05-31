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
     * @brief Writes data to a file atomically using a temporary file and rename.
     * Ensures data durability using fsync.
     */
    void write_file_atomic(const std::filesystem::path& path, std::span<const uint8_t> data);

}  // namespace duckpass::storage
