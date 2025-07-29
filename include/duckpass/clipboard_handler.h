#pragma once

#include <string>

namespace clipboard_handler {

    // Sets the content of the system clipboard.
    // Returns true on success, false on failure.
    bool set_text(const std::string& text);

} // namespace clipboard_handler