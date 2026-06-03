#pragma once

#include "duckpass/secure_allocator.h"
#include <string>
#include <vector>
#include <future>

namespace audit {
    using duckpass::SecureString;

    struct HibpResult {
        bool is_pwned;
        long breach_count;
        std::string error_message;
    };

    /**
     * @brief Checks if a password has been leaked in data breaches using HaveIBeenPwned API.
     * Implements K-Anonymity to ensure the full password never leaves the local machine.
     */
    class HibpChecker {
    public:
        /**
         * @brief Checks a single password synchronously.
         */
        static HibpResult check_password(const SecureString &password);

    private:
        /**
         * @brief Curl callback to write response to a string.
         */
        static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp);
    };

}  // namespace audit
