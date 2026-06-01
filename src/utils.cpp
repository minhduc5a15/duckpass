#include "duckpass/utils.h"

#include <algorithm>
#include <cctype>
#include <iostream>

// For get_password_silent on Linux/macOS
#include <termios.h>
#include <unistd.h>

namespace utils {

    duckpass::SecureString get_password_silent(const std::string& prompt) {
        std::cout << prompt << std::flush;
        termios old_term{};
        tcgetattr(STDIN_FILENO, &old_term);
        termios new_term = old_term;
        new_term.c_lflag &= ~ECHO;  // Turn off terminal echo
        tcsetattr(STDIN_FILENO, TCSANOW, &new_term);

        duckpass::SecureString password;
        char c;
        // Read byte-by-byte from stdin
        while (read(STDIN_FILENO, &c, 1) == 1 && c != '\n' && c != '\r') {
            if (c == '\b' || c == 127) {  // Handle Backspace (ASCII 127 is DEL/Backspace on Unix)
                if (!password.empty()) {
                    password.pop_back();
                }
            } else {
                password.push_back(c);  // Uses secure_allocator
            }
        }

        tcsetattr(STDIN_FILENO, TCSANOW, &old_term);  // Restore terminal settings
        std::cout << std::endl;

        return password;
    }

    std::filesystem::path get_config_directory() {
        std::filesystem::path config_path;
#ifdef _WIN32
        // On Windows, use %APPDATA%/duckpass
        const char* appdata = std::getenv("APPDATA");
        if (appdata == nullptr) {
            throw std::runtime_error("Error: APPDATA environment variable not set.");
        }
        config_path = std::filesystem::path(appdata) / "duckpass";
#else
        // On Linux/macOS, use ~/.duckpass
        const char* home = std::getenv("HOME");
        if (home == nullptr) {
            throw std::runtime_error("Error: HOME environment variable not set.");
        }
        config_path = std::filesystem::path(home) / ".duckpass";
#endif

        // Create the directory if it doesn't exist
        if (!std::filesystem::exists(config_path)) {
            std::filesystem::create_directories(config_path);
        }
        return config_path;
    }

    int fuzzy_match(std::string_view query, std::string_view target) {
        if (query.empty()) return 1;  // Empty query always matches with basic score
        if (target.empty()) return 0;

        size_t query_idx = 0;
        size_t target_idx = 0;
        int score = 0;
        int consecutive_matches = 0;

        while (query_idx < query.size() && target_idx < target.size()) {
            // Convert to lowercase for case-insensitive matching
            char q_char = std::tolower(static_cast<unsigned char>(query[query_idx]));
            char t_char = std::tolower(static_cast<unsigned char>(target[target_idx]));

            if (q_char == t_char) {
                query_idx++;
                consecutive_matches++;

                // Base points for each matching character
                score += 10;

                // Bonus for consecutive matches
                if (consecutive_matches > 1) {
                    score += (consecutive_matches - 1) * 5;
                }

                // Bonus for matching word boundaries (first character or after '.', '-', '_')
                if (target_idx == 0 || target[target_idx - 1] == '.' || target[target_idx - 1] == '-' || target[target_idx - 1] == '_') {
                    score += 25;
                }
            } else {
                consecutive_matches = 0;  // Reset consecutive matches on mismatch
            }
            target_idx++;
        }

        // Check if the entire query was found as a subsequence
        if (query_idx == query.size()) {
            // Length penalty: shorter target strings are preferred
            int length_difference = static_cast<int>(target.size() - query.size());
            score -= length_difference * 2;

            return std::max(1, score);
        }

        return 0;  // Does not satisfy subsequence requirement
    }
}  // namespace utils
