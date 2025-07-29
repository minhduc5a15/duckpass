#include "duckpass/clipboard_handler.h"
#include <string>
#include <cstdlib> // For system()
#include <sstream> // For std::stringstream

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
        // On Windows, use the 'clip' command. The echo | set /p=... trick avoids newlines.
        command_stream << "echo | set /p=\"" << text << "\" | clip";
#elif defined(__APPLE__)
        // On macOS, use the 'pbcopy' command.
        command_stream << "echo '" << escape_for_shell(text) << "' | pbcopy";
#elif defined(__linux__)
        // On Linux, use the 'xclip' command.
        command_stream << "echo '" << escape_for_shell(text) << "' | xclip -selection clipboard";
#else
        // Unsupported platform
        return false;
#endif

        // Execute the command. system() returns 0 on success.
        return system(command_stream.str().c_str()) == 0;
    }

} // namespace clipboard_handler