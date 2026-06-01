#pragma once

#include <filesystem>
#include <string>
#include <string_view>

#include "duckpass/secure_allocator.h"

namespace utils {
    // Declares our shared utility function.
    duckpass::SecureString get_password_silent(const std::string &prompt);
    std::filesystem::path get_config_directory();

    /**
     * @brief Thực hiện tìm kiếm mờ giữa chuỗi truy vấn và chuỗi mục tiêu.
     * @param query Chuỗi tìm kiếm do người dùng nhập.
     * @param target Chuỗi tên dịch vụ (service) trong vault.
     * @return int Điểm số độ khớp (Score). Trả về 0 nếu không khớp cấu trúc subsequence.
     */
    int fuzzy_match(std::string_view query, std::string_view target);
}  // namespace utils
