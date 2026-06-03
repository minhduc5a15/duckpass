#pragma once

#include "CLI/CLI.hpp"

namespace audit {
    /**
     * @brief Setup the 'audit' command in the CLI application.
     */
    void setup_audit_command(CLI::App &app);
}  // namespace audit
