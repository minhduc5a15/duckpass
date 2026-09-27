#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "duckpass/secure_allocator.h"

namespace duckpass::totp {

    /**
     * @brief Decodes an RFC 4648 Base32 encoded secret into raw bytes.
     * Automatically strips spaces, hyphens, and padding ('='). Case-insensitive.
     * @throws std::invalid_argument if invalid Base32 characters are encountered.
     */
    duckpass::SecureBytes decode_base32(std::string_view base32_secret);

    /**
     * @brief Generates a Time-based One-Time Password (TOTP) per RFC 6238 using HMAC-SHA1.
     * @param base32_secret The Base32 encoded secret key.
     * @param timestamp Unix epoch timestamp in seconds. Default is 0 (which triggers current time).
     * @param time_step_seconds Time step in seconds (default: 30).
     * @param digits Number of OTP digits (default: 6).
     * @param out_remaining_seconds Optional pointer to receive remaining seconds in current period.
     * @return Formatted OTP string (e.g., "123456").
     * @throws std::invalid_argument on malformed secret or parameters.
     */
    std::string generate_totp(const duckpass::SecureString& base32_secret, uint64_t timestamp = 0, uint32_t time_step_seconds = 30,
                              uint32_t digits = 6, uint32_t* out_remaining_seconds = nullptr);

    /**
     * @brief Overload taking string_view for easy verification and tests.
     */
    std::string generate_totp(std::string_view base32_secret, uint64_t timestamp = 0, uint32_t time_step_seconds = 30, uint32_t digits = 6,
                              uint32_t* out_remaining_seconds = nullptr);

}  // namespace duckpass::totp
