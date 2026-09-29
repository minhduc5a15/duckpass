#include "duckpass/totp.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <ctime>
#include <stdexcept>

namespace duckpass::totp {

    duckpass::SecureBytes decode_base32(std::string_view base32_secret) {
        duckpass::SecureBytes result;
        uint32_t buffer = 0;
        int bits_left = 0;

        for (const char ch : base32_secret) {
            if (ch == ' ' || ch == '-' || ch == '=') {
                continue;
            }

            int val = -1;
            if (ch >= 'A' && ch <= 'Z') {
                val = ch - 'A';
            } else if (ch >= 'a' && ch <= 'z') {
                val = ch - 'a';
            } else if (ch >= '2' && ch <= '7') {
                val = ch - '2' + 26;
            } else {
                throw std::invalid_argument(std::string("Invalid Base32 character encountered: '") + ch + "'");
            }

            buffer = (buffer << 5) | static_cast<uint32_t>(val);
            bits_left += 5;

            if (bits_left >= 8) {
                bits_left -= 8;
                result.push_back(static_cast<uint8_t>((buffer >> bits_left) & 0xFF));
            }
        }

        if (result.empty()) {
            throw std::invalid_argument("Base32 secret is empty or contains no valid data.");
        }

        return result;
    }

    std::string generate_totp(std::string_view base32_secret, uint64_t timestamp, uint32_t time_step_seconds, uint32_t digits,
                              uint32_t* out_remaining_seconds) {
        if (time_step_seconds == 0) {
            throw std::invalid_argument("Time step seconds must be greater than zero.");
        }
        if (digits < 6 || digits > 8) {
            throw std::invalid_argument("TOTP digits must be between 6 and 8.");
        }

        if (timestamp == 0) {
            timestamp = static_cast<uint64_t>(std::time(nullptr));
        }

        if (out_remaining_seconds) {
            *out_remaining_seconds = time_step_seconds - static_cast<uint32_t>(timestamp % time_step_seconds);
        }

        duckpass::SecureBytes key = decode_base32(base32_secret);

        uint64_t time_step = timestamp / time_step_seconds;

        // Convert time step to 8-byte big-endian buffer
        uint8_t time_bytes[8];
        for (int i = 7; i >= 0; --i) {
            time_bytes[i] = static_cast<uint8_t>(time_step & 0xFF);
            time_step >>= 8;
        }

        // HMAC-SHA1
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int md_len = 0;

        if (!HMAC(EVP_sha1(), key.data(), static_cast<int>(key.size()), time_bytes, sizeof(time_bytes), md, &md_len)) {
            throw std::runtime_error("HMAC-SHA1 computation failed.");
        }

        // Dynamic truncation (RFC 4226 Section 5.4)
        int offset = md[md_len - 1] & 0x0F;
        uint32_t binary_code = ((static_cast<uint32_t>(md[offset]) & 0x7F) << 24) | ((static_cast<uint32_t>(md[offset + 1]) & 0xFF) << 16) |
                               ((static_cast<uint32_t>(md[offset + 2]) & 0xFF) << 8) | (static_cast<uint32_t>(md[offset + 3]) & 0xFF);

        uint32_t mod = 1;
        for (uint32_t d = 0; d < digits; ++d) {
            mod *= 10;
        }

        uint32_t otp = binary_code % mod;

        std::string otp_str = std::to_string(otp);
        if (otp_str.length() < digits) {
            otp_str.insert(0, digits - otp_str.length(), '0');
        }

        OPENSSL_cleanse(md, sizeof(md));
        return otp_str;
    }

    std::string generate_totp(const duckpass::SecureString& base32_secret, uint64_t timestamp, uint32_t time_step_seconds, uint32_t digits,
                              uint32_t* out_remaining_seconds) {
        return generate_totp(std::string_view(base32_secret.data(), base32_secret.size()), timestamp, time_step_seconds, digits,
                             out_remaining_seconds);
    }

}  // namespace duckpass::totp
