#include "duckpass/clipboard_handler.h"
#include <string>
#include <cstdlib>
#include <sstream>
#include <iostream>

// --- ADD NEW INCLUDES FOR LINUX/MACOS ---
#if defined(__linux__) || defined(__APPLE__)
#include <unistd.h>
#include <thread>
#include <chrono>
#endif

// Helper function to escape single quotes for shell commands
std::string escape_for_shell(const std::string& text) {
    std::string escaped_text;
    escaped_text.reserve(text.length());
    for (char c : text) {
        if (c == '\'') {
            escaped_text += "'\\''"; // The shell trick to embed a single quote
        } else {
            escaped_text += c;
        }
    }
    return escaped_text;
}

namespace clipboard_handler {

    bool set_text(const std::string& text) {
        std::stringstream command_stream;
#if defined(_WIN32)
        command_stream << "echo | set /p=\"" << text << "\" | clip";
#elif defined(__APPLE__)
        command_stream << "echo '" << escape_for_shell(text) << "' | pbcopy";
#elif defined(__linux__)
        command_stream << "echo '" << escape_for_shell(text) << "' | xclip -selection clipboard";
#else
        return false;
#endif
        return system(command_stream.str().c_str()) == 0;
    }

    void clear_after_delay(std::chrono::seconds delay) {
#if defined(__linux__) || defined(__APPLE__)
        // "Double fork" technique to create a daemon
        pid_t pid = fork();

        if (pid < 0) {
            // Fork error, do nothing
            return;
        }

        if (pid > 0) {
            // 1. Parent process exits immediately
            // Returns control to the user's terminal
            return;
        }

        // --- This is the code of the first child process ---

        // 2. Become a session leader to be independent of the terminal
        if (setsid() < 0) {
            exit(1);
        }

        // 3. Fork a second time
        pid = fork();
        if (pid < 0) {
            exit(1);
        }
        if (pid > 0) {
            // 4. The first child process exits
            exit(0);
        }

        // --- This is the code of the grandchild process (daemon) ---
        // It is now completely independent of the terminal

        // 5. Sleep for the specified duration
        std::this_thread::sleep_for(delay);

        // 6. Clear the clipboard and exit
        set_text("");
        exit(0);
#else
        // Other operating systems do not yet support this technique
        // (Windows has a different, more complex way)
        (void)delay; // Tránh warning unused variable
        return;
#endif
    }

} // namespace clipboard_handler