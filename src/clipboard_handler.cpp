#include "duckpass/clipboard_handler.h"

#include <cstdio>
#include <iostream>
#include <string>

// --- ADD NEW INCLUDES FOR LINUX/MACOS ---
#if defined(__linux__) || defined(__APPLE__)
#include <unistd.h>

#include <chrono>
#include <thread>
#endif

namespace clipboard_handler {

    bool set_text(const duckpass::SecureString& text) {
        const char* command = nullptr;

#if defined(_WIN32)
        command = "C:\\Windows\\System32\\clip.exe";
#elif defined(__APPLE__)
        command = "/usr/bin/pbcopy";
#elif defined(__linux__)
        command = "/usr/bin/xclip -selection clipboard";
#else
        return false;
#endif

        if (command == nullptr) {
            return false;
        }

#if defined(_WIN32)
        FILE* pipe = _popen(command, "w");
#else
        FILE* pipe = popen(command, "w");
#endif

        if (!pipe) {
            return false;
        }

        size_t written = std::fwrite(text.data(), 1, text.size(), pipe);
        bool success = (written == text.size());

#if defined(_WIN32)
        int status = _pclose(pipe);
#else
        int status = pclose(pipe);
#endif

        return success && (status == 0);
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

        // 5. Replace memory with a non-sensitive shell process to avoid memory leaks (CWE-404 / CWE-316)
        // This process will sleep and then clear the clipboard.
        const std::string delay_str = std::to_string(delay.count());
#if defined(__APPLE__)
        const std::string shell_cmd = "/usr/bin/sleep " + delay_str + " && /usr/bin/pbcopy < /dev/null";
#else
        const std::string shell_cmd = "/usr/bin/sleep " + delay_str + " && /usr/bin/xclip -selection clipboard /dev/null";
#endif
        execl("/usr/bin/sh", "sh", "-c", shell_cmd.c_str(), nullptr);

        // If execl fails, exit
        exit(1);
#else
        // Other operating systems do not yet support this technique
        // (Windows has a different, more complex way)
        (void)delay;  // Tránh warning unused variable
        return;
#endif
    }

}  // namespace clipboard_handler