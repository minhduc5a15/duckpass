#pragma once

#include <string>
#include <chrono>

namespace clipboard_handler {
    // Sets the content of the system clipboard.
    // Returns true on success, false on failure.
    bool set_text(const std::string &text);

    // Creates a detached thread to clear the clipboard after a specified delay.
    void clear_after_delay(std::chrono::seconds delay);
} // namespace clipboard_handler
