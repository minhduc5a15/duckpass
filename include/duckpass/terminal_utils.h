#pragma once

#include <termios.h>

#include <string>
#include <vector>

#include "duckpass/secure_allocator.h"

namespace duckpass::terminal {

    /**
     * @brief RAII guard to manage terminal raw mode.
     *
     * Ensures the terminal is restored to its original state when the object
     * goes out of scope or on process termination (via signals).
     */
    class TerminalModeGuard {
    public:
        TerminalModeGuard();
        ~TerminalModeGuard();

        // Prevent copying to ensure exclusive resource management
        TerminalModeGuard(const TerminalModeGuard&) = delete;
        TerminalModeGuard& operator=(const TerminalModeGuard&) = delete;

        /**
         * @brief Manually restore the terminal to its original state.
         * Useful for signal handlers.
         */
        static void restore_terminal();

    private:
        static termios orig_termios;
        static bool is_raw_mode_active;
    };

    /**
     * @brief Reads a line from stdin in an interactive way with auto-completion.
     *
     * @param prompt The prompt to display.
     * @param commands List of base commands for completion.
     * @param services List of vault services for completion.
     * @return The input line as a SecureString.
     */
    SecureString read_line_interactive(const std::string& prompt, const std::vector<SecureString>& commands,
                                       const std::vector<SecureString>& services);

    /**
     * @brief Reads a password from stdin without echoing.
     *
     * @param prompt The prompt to display.
     * @return The password as a SecureString.
     */
    SecureString read_password(const std::string& prompt);

}  // namespace duckpass::terminal

namespace terminal_utils = duckpass::terminal;
