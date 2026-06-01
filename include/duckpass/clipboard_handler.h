#pragma once

#include <chrono>
#include <string>

#include "duckpass/secure_allocator.h"

namespace clipboard_handler {
    // Sets the content of the system clipboard.
    // Returns true on success, false on failure.
    bool set_text(const duckpass::SecureString &text);

    // Creates a detached thread to clear the clipboard after a specified delay.
    void clear_after_delay(std::chrono::seconds delay);
}  // namespace clipboard_handler
