#include "duckpass/entropy_evaluator.h"
#include "zxcvbn.h"

#include <algorithm>
#include <cmath>

namespace audit {

    EntropyScore EntropyEvaluator::evaluate(const SecureString& password) {
        if (password.empty()) {
            return {0, 0.0, 0.0, true};
        }

        ZxcMatch_t* info = nullptr;

        // =====================================================================
        // WARNING: SECURITY DATA REMNANT RISK
        // The zxcvbn-c library internally creates copies of the password
        // on the standard system heap to perform pattern matching.
        // While we call ZxcvbnFreeInfo, the underlying 'free()' call 
        // DOES NOT zero-fill/wipe the memory. Plaintext fragments may 
        // persist in the heap until overwritten by other allocations.
        // =====================================================================

        // zxcvbnMatch returns entropy in bits.
        // It also allocates a linked list in 'info' if not null.
        double entropy = ZxcvbnMatch(password.c_str(), nullptr, &info);

        EntropyScore result;
        result.entropy_bits = entropy;
        
        // Convert entropy bits to a 0-4 score similar to the original JS zxcvbn
        if (entropy < 10.0) result.score = 0;
        else if (entropy < 20.0) result.score = 1;
        else if (entropy < 27.0) result.score = 2;
        else if (entropy < 33.0) result.score = 3;
        else result.score = 4;

        // Roughly estimate crack time (very simplified)
        // Assume 10k guesses/sec (throttled online)
        result.crack_time_seconds = std::pow(2.0, entropy) / 10000.0;
        
        result.is_weak = (result.score < 3);

        if (info) {
            ZxcvbnFreeInfo(info);
        }

        return result;
    }

}  // namespace audit
