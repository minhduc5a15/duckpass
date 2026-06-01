#pragma once

#include "CLI/CLI.hpp"

namespace completion_command {
    /**
     * @brief Sets up the 'completion' subcommand.
     *
     * This command generates shell completion scripts for Bash/Zsh.
     */
    void setup(CLI::App& app);
}  // namespace completion_command
