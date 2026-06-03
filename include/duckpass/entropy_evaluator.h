#pragma once

#include "duckpass/secure_allocator.h"

namespace audit {
    using duckpass::SecureString;

    struct EntropyScore {
        int score;                // 0-4 (zxcvbn scale)
        double entropy_bits;      // Raw entropy in bits
        double crack_time_seconds;
        bool is_weak;
    };

    /**
     * @brief Evaluates password strength using the zxcvbn-c library.
     * Provides a thread-safe RAII wrapper around the C API.
     */
    class EntropyEvaluator {
    public:
        /**
         * @brief Calculates the entropy score for a given password.
         * @param password The password to evaluate.
         * @return An EntropyScore structure containing the results.
         */
        static EntropyScore evaluate(const SecureString &password);

    private:
        // Internal helper to convert zxcvbn score to human-readable text if needed later.
    };

}  // namespace audit
