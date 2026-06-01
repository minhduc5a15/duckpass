#include "duckpass/terminal_utils.h"

#include <unistd.h>

#include <cctype>
#include <csignal>
#include <iostream>
#include <stdexcept>
#include <string_view>

namespace duckpass::terminal {

    termios TerminalModeGuard::orig_termios;
    bool TerminalModeGuard::is_raw_mode_active = false;

    /**
     * @brief Signal handler to ensure terminal restoration on process interruption.
     */
    void handle_signal(int /*signum*/) {
        TerminalModeGuard::restore_terminal();
        _exit(1);
    }

    /**
     * @brief Constructor that puts the terminal into raw mode.
     *
     * Disables canonical mode (line buffering), echo, and various control signals
     * to allow character-by-character processing and custom input handling (like TAB).
     */
    TerminalModeGuard::TerminalModeGuard() {
        if (!isatty(STDIN_FILENO)) {
            return;
        }
        if (tcgetattr(STDIN_FILENO, &orig_termios) == -1) {
            throw std::runtime_error("Failed to get terminal attributes.");
        }

        termios raw = orig_termios;
        // Disable ECHO (input display), ICANON (canonical mode), ISIG (Ctrl-C/Z), IEXTEN (extended features)
        raw.c_lflag &= ~(ECHO | ICANON | ISIG | IEXTEN);
        // Disable BRKINT, ICRNL (Map CR to NL), INPCK, ISTRIP, IXON (Software flow control)
        raw.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
        raw.c_cc[VMIN] = 1;
        raw.c_cc[VTIME] = 0;

        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) == -1) {
            throw std::runtime_error("Failed to set terminal to raw mode.");
        }
        is_raw_mode_active = true;

        // Register signal handlers to prevent terminal from being stuck in raw mode on crash/exit
        std::signal(SIGINT, handle_signal);
        std::signal(SIGTERM, handle_signal);
    }

    TerminalModeGuard::~TerminalModeGuard() { restore_terminal(); }

    /**
     * @brief Restores the terminal to its original (canonical) state.
     */
    void TerminalModeGuard::restore_terminal() {
        if (is_raw_mode_active && isatty(STDIN_FILENO)) {
            tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
            is_raw_mode_active = false;
        }
    }

    /**
     * @brief Reads a line of input with interactive features like auto-completion.
     *
     * @param prompt The prompt string to display.
     * @param commands List of available commands for completion.
     * @param services List of vault services for completion.
     * @return The resulting input line.
     */
    SecureString read_line_interactive(const std::string& prompt, const std::vector<SecureString>& commands,
                                       const std::vector<SecureString>& services) {
        // Fallback to standard getline if not running in a TTY
        if (!isatty(STDIN_FILENO)) {
            std::string line;
            if (!std::getline(std::cin, line)) {
                return {};
            }
            return SecureString(line.begin(), line.end());
        }

        TerminalModeGuard guard;

        SecureString buffer;
        char c;
        std::cout << prompt << std::flush;

        // Character-by-character input loop
        while (read(STDIN_FILENO, &c, 1) == 1) {
            if (c == '\r' || c == '\n') {  // ENTER key
                std::cout << "\r\n";
                break;
            } else if (c == '\t') {  // TAB key - Auto-completion logic
                std::vector<std::string_view> matches;
                std::string_view buffer_view(buffer.data(), buffer.size());

                // 1. Analyze context to decide whether to complete commands or services
                size_t space_pos = buffer_view.find(' ');

                std::string_view prefix_to_match;
                const std::vector<SecureString>* current_candidates = nullptr;
                std::string_view base_input = "";  // Stable part of the input (e.g., "get ")

                if (space_pos == std::string_view::npos) {
                    // Context 1: No spaces -> Completing a Command
                    prefix_to_match = buffer_view;
                    current_candidates = &commands;
                } else {
                    // Context 2: At least one space -> Completing an Argument (Service name)
                    std::string_view cmd = buffer_view.substr(0, space_pos);

                    // Only suggest services for specific commands
                    if (cmd == "get" || cmd == "delete") {
                        size_t arg_start = buffer_view.find_first_not_of(' ', space_pos);
                        if (arg_start == std::string_view::npos) {
                            prefix_to_match = "";  // Just typed "get "
                            base_input = buffer_view;
                        } else {
                            prefix_to_match = buffer_view.substr(arg_start);  // Partial service name "get go"
                            base_input = buffer_view.substr(0, arg_start);
                        }
                        current_candidates = &services;
                    }
                }

                // 2. Perform prefix matching against candidates
                if (current_candidates) {
                    for (const auto& s : *current_candidates) {
                        std::string_view s_view(s.data(), s.size());
                        if (s_view.length() >= prefix_to_match.length() && s_view.substr(0, prefix_to_match.length()) == prefix_to_match) {
                            matches.push_back(s_view);
                        }
                    }
                }

                // 3. Render completion results
                if (matches.size() == 1) {
                    // Unique match: Complete the word automatically
                    buffer.assign(base_input.begin(), base_input.end());
                    buffer.append(matches[0].begin(), matches[0].end());

                    std::cout << "\r\033[K" << prompt;
                    std::cout.write(buffer.data(), buffer.size());
                    std::cout << std::flush;
                } else if (matches.size() > 1) {
                    // Multiple matches: Show possibilities
                    std::cout << "\r\n";
                    for (const auto& m : matches) {
                        std::cout.write(m.data(), m.size());
                        std::cout << "  ";
                    }
                    std::cout << "\r\n" << prompt;
                    std::cout.write(buffer.data(), buffer.size());
                    std::cout << std::flush;
                }

            } else if (c == 0x7F || c == '\b') {  // BACKSPACE handling
                if (!buffer.empty()) {
                    buffer.pop_back();
                    std::cout << "\b \b" << std::flush;
                }
            } else if (c == '\033') {  // Escape sequences (Arrows, etc.)
                char seq[2];
                if (read(STDIN_FILENO, &seq[0], 1) == 1 && read(STDIN_FILENO, &seq[1], 1) == 1) {
                    // Arrows and other multi-char keys are currently ignored to keep buffer clean
                    continue;
                }
            } else if (!std::iscntrl(static_cast<unsigned char>(c))) {
                // Regular character: Add to buffer and echo
                buffer += c;
                std::cout << c << std::flush;
            }
        }

        return buffer;
    }

    SecureString read_password(const std::string& prompt) {
        std::cout << prompt;
        termios old_term{};
        tcgetattr(STDIN_FILENO, &old_term);
        termios new_term = old_term;
        new_term.c_lflag &= ~ECHO;  // Turn off terminal echo
        tcsetattr(STDIN_FILENO, TCSANOW, &new_term);

        std::string password;
        std::getline(std::cin, password);

        tcsetattr(STDIN_FILENO, TCSANOW, &old_term);  // Restore terminal settings
        std::cout << std::endl;

        SecureString secure_password(password.begin(), password.end());
        // Wipe the temporary std::string
        OPENSSL_cleanse(password.data(), password.length());
        return secure_password;
    }

}  // namespace duckpass::terminal
