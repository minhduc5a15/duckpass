#include <openssl/crypto.h>
#include <unistd.h>

#include <bit>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

#include "zxcvbn.h"

namespace {

    bool read_all(int fd, void* buf, size_t size) {
        auto* ptr = static_cast<uint8_t*>(buf);
        while (size > 0) {
            ssize_t const res = read(fd, ptr, size);
            if (res > 0) {
                ptr += res;
                size -= res;
            } else if (res < 0) {
                if (errno == EINTR) continue;
                return false;
            } else {
                return false;  // EOF
            }
        }
        return true;
    }

    bool write_all(int fd, const void* buf, size_t size) {
        const auto* ptr = static_cast<const uint8_t*>(buf);
        while (size > 0) {
            ssize_t const res = write(fd, ptr, size);
            if (res > 0) {
                ptr += res;
                size -= res;
            } else if (res < 0) {
                if (errno == EINTR) continue;
                return false;
            } else {
                return false;
            }
        }
        return true;
    }

    std::string find_dictionary_path() {
        std::error_code ec;
#if defined(__linux__)
        auto self = std::filesystem::read_symlink("/proc/self/exe", ec);
        if (!ec) {
            auto candidate = self.parent_path() / "zxcvbn.dict";
            if (std::filesystem::exists(candidate)) {
                return candidate.string();
            }
        }
#endif
        if (std::filesystem::exists("zxcvbn.dict")) {
            return "zxcvbn.dict";
        }
        if (std::filesystem::exists("vendor/zxcvbn-c/zxcvbn.dict")) {
            return "vendor/zxcvbn-c/zxcvbn.dict";
        }
        if (std::filesystem::exists("/usr/local/share/duckpass/zxcvbn.dict")) {
            return "/usr/local/share/duckpass/zxcvbn.dict";
        }
        if (std::filesystem::exists("/usr/share/duckpass/zxcvbn.dict")) {
            return "/usr/share/duckpass/zxcvbn.dict";
        }
        return "zxcvbn.dict";
    }

}  // namespace

int main() {
    // 1. Initialize dedicated secure heap (1 MB, 32-byte alignment)
    CRYPTO_secure_malloc_init(1048576, 32);

    // 2. Initialize zxcvbn dictionary
    std::string const dict_path = find_dictionary_path();
    if (!ZxcvbnInit(dict_path.c_str())) {
        return 2;
    }

    // 3. Read password length (4 bytes Little-Endian)
    uint32_t len = 0;
    if (!read_all(STDIN_FILENO, &len, sizeof(len)) || len == 0 || len > 4096) {
        ZxcvbnUnInit();
        return 3;
    }

    // 4. Read password bytes
    std::vector<char> pwd(len + 1, 0);
    if (!read_all(STDIN_FILENO, pwd.data(), len)) {
        OPENSSL_cleanse(pwd.data(), pwd.size());
        ZxcvbnUnInit();
        return 4;
    }

    // 5. Evaluate entropy
    ZxcMatch_t* info = nullptr;
    double const entropy = ZxcvbnMatch(pwd.data(), nullptr, &info);
    if (info) {
        ZxcvbnFreeInfo(info);
    }

    // Cleanse sensitive password buffer immediately
    OPENSSL_cleanse(pwd.data(), pwd.size());

    // 6. Calculate score and crack time
    int32_t score = 0;
    if (entropy < 10.0)
        score = 0;
    else if (entropy < 20.0)
        score = 1;
    else if (entropy < 27.0)
        score = 2;
    else if (entropy < 33.0)
        score = 3;
    else
        score = 4;

    double const crack_time_seconds = std::pow(2.0, entropy) / 10000.0;
    uint8_t const is_weak = (score < 3) ? 1 : 0;

    // 7. Serialize to Canonical Wire Protocol (21 bytes):
    // [0..3]: int32_t score (Little-Endian)
    // [4..11]: double entropy_bits (std::bit_cast<uint64_t> Little-Endian)
    // [12..19]: double crack_time_seconds (std::bit_cast<uint64_t> Little-Endian)
    // [20]: uint8_t is_weak (1 or 0)
    uint8_t wire_buf[21]{};

    auto u_score = static_cast<uint32_t>(score);
    wire_buf[0] = static_cast<uint8_t>(u_score & 0xFF);
    wire_buf[1] = static_cast<uint8_t>((u_score >> 8) & 0xFF);
    wire_buf[2] = static_cast<uint8_t>((u_score >> 16) & 0xFF);
    wire_buf[3] = static_cast<uint8_t>((u_score >> 24) & 0xFF);

    uint64_t const entropy_u64 = std::bit_cast<uint64_t>(entropy);
    for (int i = 0; i < 8; ++i) {
        wire_buf[4 + i] = static_cast<uint8_t>((entropy_u64 >> (i * 8)) & 0xFF);
    }

    uint64_t const crack_u64 = std::bit_cast<uint64_t>(crack_time_seconds);
    for (int i = 0; i < 8; ++i) {
        wire_buf[12 + i] = static_cast<uint8_t>((crack_u64 >> (i * 8)) & 0xFF);
    }

    wire_buf[20] = is_weak;

    // 8. Write serialized response to STDOUT
    if (!write_all(STDOUT_FILENO, wire_buf, sizeof(wire_buf))) {
        ZxcvbnUnInit();
        return 5;
    }

    ZxcvbnUnInit();
    _exit(0);
}
